use super::schema::{
    POSTGRES_RELATION_MIGRATION, POSTGRES_SCHEMA, SQLITE_RELATION_MIGRATION, SQLITE_SCHEMA,
};
use anyhow::{anyhow, bail, Context, Result};
use std::sync::Arc;

pub enum PlatformDb {
    Sqlite(rusqlite::Connection),
    Postgres(postgres::Client),
}

impl PlatformDb {
    pub fn connect(url: &str) -> Result<Self> {
        if let Some(path) = url.strip_prefix("sqlite:") {
            let path = if path.is_empty() {
                "layerfault-platform.db"
            } else {
                path
            };
            let conn = rusqlite::Connection::open(path)
                .with_context(|| format!("unable to open SQLite database '{path}'"))?;
            conn.busy_timeout(std::time::Duration::from_secs(10))?;
            conn.pragma_update(None, "foreign_keys", "ON")?;
            conn.pragma_update(None, "journal_mode", "WAL")?;
            Ok(Self::Sqlite(conn))
        } else if url.starts_with("postgres://") || url.starts_with("postgresql://") {
            let mut parsed = url::Url::parse(url).context("invalid PostgreSQL URL")?;
            if let Some(password) = crate::paths::secret_from_env("LAYERFAULT_DB_PASSWORD")? {
                if parsed.password().is_none() {
                    parsed
                        .set_password(Some(&password))
                        .map_err(|_| anyhow!("unable to apply PostgreSQL password secret"))?;
                }
            }
            let use_tls = enforce_postgres_transport(&mut parsed)?;
            let effective = parsed.to_string();
            let client = if use_tls {
                postgres::Client::connect(&effective, postgres_tls_connector()?)
                    .context("unable to connect to PostgreSQL with verified TLS")?
            } else {
                postgres::Client::connect(&effective, postgres::NoTls)
                    .context("unable to connect to local/insecure PostgreSQL")?
            };
            Ok(Self::Postgres(client))
        } else {
            bail!("database must use sqlite:/path or postgres:// URL")
        }
    }

    pub fn migrate(&mut self) -> Result<()> {
        match self {
            Self::Sqlite(conn) => {
                conn.execute_batch(SQLITE_SCHEMA)?;
                if !sqlite_column_exists(conn, "jobs", "lease_token")? {
                    conn.execute("ALTER TABLE jobs ADD COLUMN lease_token TEXT", [])?;
                }
                migrate_sqlite_relations(conn)?;
            }
            Self::Postgres(client) => {
                client.batch_execute(POSTGRES_SCHEMA)?;
                client
                    .batch_execute("ALTER TABLE jobs ADD COLUMN IF NOT EXISTS lease_token TEXT")?;
                let mut transaction = client.transaction()?;
                transaction.batch_execute(POSTGRES_RELATION_MIGRATION)?;
                transaction.commit()?;
            }
        }
        Ok(())
    }
}

fn enforce_postgres_transport(parsed: &mut url::Url) -> Result<bool> {
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow!("PostgreSQL URL must include a host"))?;
    let local = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    let sslmode = parsed
        .query_pairs()
        .find(|(key, _)| key == "sslmode")
        .map(|(_, value)| value.into_owned());
    if sslmode.as_deref() == Some("disable") {
        if local || insecure_remote_db_allowed() {
            return Ok(false);
        }
        bail!(
            "remote PostgreSQL requires verified TLS; remove sslmode=disable or set LAYERFAULT_ALLOW_INSECURE_DB=1 only for an explicitly accepted development risk"
        );
    }
    if !local && sslmode.as_deref() != Some("require") {
        replace_query_pair(parsed, "sslmode", "require");
    }
    Ok(true)
}

fn replace_query_pair(parsed: &mut url::Url, key: &str, value: &str) {
    let mut pairs = parsed
        .query_pairs()
        .filter(|(candidate, _)| candidate != key)
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    pairs.push((key.to_owned(), value.to_owned()));
    parsed.query_pairs_mut().clear().extend_pairs(pairs);
}

fn insecure_remote_db_allowed() -> bool {
    std::env::var("LAYERFAULT_ALLOW_INSECURE_DB").is_ok_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes"
        )
    })
}

fn postgres_tls_connector() -> Result<postgres_rustls::MakeTlsConnector> {
    let mut roots =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Ok(path) = std::env::var("LAYERFAULT_DB_CA_FILE") {
        let file = crate::safeio::open_readonly_nofollow(std::path::Path::new(&path))
            .with_context(|| format!("unable to open PostgreSQL CA file '{path}'"))?;
        let mut added = 0usize;
        for certificate in rustls::pki_types::pem::PemObject::pem_reader_iter(file) {
            roots
                .add(certificate.context("invalid PostgreSQL CA certificate")?)
                .context("unable to add PostgreSQL CA certificate")?;
            added = added.saturating_add(1);
        }
        if added == 0 {
            bail!("PostgreSQL CA file '{path}' contains no certificates");
        }
    }
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    postgres_rustls::set_postgresql_alpn(&mut config);
    Ok(postgres_rustls::MakeTlsConnector::new(
        tokio_rustls::TlsConnector::from(Arc::new(config)),
    ))
}

fn sqlite_column_exists(
    connection: &rusqlite::Connection,
    table: &str,
    column: &str,
) -> Result<bool> {
    let sql = format!(
        "SELECT COUNT(*) FROM pragma_table_info('{}') WHERE name=?1",
        table
    );
    let count: i64 = connection.query_row(&sql, rusqlite::params![column], |row| row.get(0))?;
    Ok(count > 0)
}

fn migrate_sqlite_relations(connection: &rusqlite::Connection) -> Result<()> {
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM pragma_foreign_key_list('model_revisions')",
        [],
        |row| row.get(0),
    )?;
    if count > 0 {
        connection.execute(
            "INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(2,strftime('%s','now'))",
            [],
        )?;
        return Ok(());
    }

    connection.pragma_update(None, "foreign_keys", "OFF")?;
    let migration = connection.execute_batch(SQLITE_RELATION_MIGRATION);
    if migration.is_err() {
        let _ = connection.execute_batch("ROLLBACK");
    }
    let restore = connection.pragma_update(None, "foreign_keys", "ON");
    migration.context(
        "unable to add platform foreign keys; inspect and repair orphaned relational rows before retrying",
    )?;
    restore?;
    let violations: i64 =
        connection.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })?;
    if violations != 0 {
        bail!("platform database contains {violations} foreign-key violation(s) after migration");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sqlite_test_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "layerfault-platform-{label}-{}-{}",
            std::process::id(),
            crate::paths::now_unix()
        ))
    }

    #[test]
    fn remote_postgres_defaults_to_required_tls() -> Result<()> {
        let mut url = url::Url::parse("postgres://user@example.com/db?application_name=lf")?;
        assert!(enforce_postgres_transport(&mut url)?);
        assert_eq!(
            url.query_pairs()
                .find(|(key, _)| key == "sslmode")
                .map(|(_, value)| value.into_owned())
                .as_deref(),
            Some("require")
        );
        assert!(url
            .query_pairs()
            .any(|(key, value)| key == "application_name" && value == "lf"));
        Ok(())
    }

    #[test]
    fn local_postgres_can_explicitly_disable_tls() -> Result<()> {
        let mut url = url::Url::parse("postgres://user@127.0.0.1/db?sslmode=disable")?;
        assert!(!enforce_postgres_transport(&mut url)?);
        Ok(())
    }

    #[test]
    fn sqlite_v1_schema_is_upgraded_with_foreign_keys() -> Result<()> {
        let path = sqlite_test_path("relations");
        let _ = std::fs::remove_file(&path);
        {
            let connection = rusqlite::Connection::open(&path)?;
            connection.execute_batch(
                "CREATE TABLE model_revisions(id TEXT PRIMARY KEY,model_id TEXT NOT NULL,revision TEXT NOT NULL,observed_at BIGINT NOT NULL,metadata_json TEXT NOT NULL,UNIQUE(model_id,revision));",
            )?;
        }
        let mut database = PlatformDb::connect(&format!("sqlite:{}", path.display()))?;
        database.migrate()?;
        let PlatformDb::Sqlite(connection) = &database else {
            unreachable!();
        };
        let count: i64 = connection.query_row(
            "SELECT COUNT(*) FROM pragma_foreign_key_list('model_revisions')",
            [],
            |row| row.get(0),
        )?;
        assert!(count > 0);
        assert!(connection
            .execute(
                "INSERT INTO reviews(id,revision_id,final_decision,created_at,body_json) VALUES('review','missing','PASS',0,'{}')",
                [],
            )
            .is_err());
        drop(database);
        let _ = std::fs::remove_file(path);
        Ok(())
    }
}
