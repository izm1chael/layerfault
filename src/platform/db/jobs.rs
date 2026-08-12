use super::connection::PlatformDb;
use super::types::{now_i64, stable_id, truncate, Job};
use anyhow::{bail, Result};
use rusqlite::OptionalExtension;

impl PlatformDb {
    pub fn enqueue(
        &mut self,
        kind: &str,
        idempotency_key: &str,
        payload: &serde_json::Value,
        priority: i64,
    ) -> Result<String> {
        if kind.len() > 128 || idempotency_key.len() > 1024 {
            bail!("job kind/idempotency key too long");
        }
        let id = stable_id("lfjob", &[kind.as_bytes(), idempotency_key.as_bytes()]);
        let now = now_i64();
        let payload = serde_json::to_string(payload)?;
        if payload.len() > 4 * 1024 * 1024 {
            bail!("job payload exceeds 4 MiB cap");
        }
        match self {
            Self::Sqlite(conn) => {
                conn.execute("INSERT OR IGNORE INTO jobs(id,kind,idempotency_key,state,priority,attempts,max_attempts,payload_json,created_at) VALUES(?1,?2,?3,'READY',?4,0,5,?5,?6)",rusqlite::params![id,kind,idempotency_key,priority,payload,now])?;
            }
            Self::Postgres(client) => {
                client.execute("INSERT INTO jobs(id,kind,idempotency_key,state,priority,attempts,max_attempts,payload_json,created_at) VALUES($1,$2,$3,'READY',$4,0,5,$5,$6) ON CONFLICT(idempotency_key) DO NOTHING", &[&id,&kind,&idempotency_key,&priority,&payload,&now])?;
            }
        }
        Ok(id)
    }

    pub fn claim(&mut self, worker: &str, lease_seconds: i64) -> Result<Option<Job>> {
        let now = now_i64();
        let lease_until = now.saturating_add(lease_seconds.clamp(10, 86_400));
        let token = lease_token(worker, now);
        match self {
            Self::Sqlite(conn) => {
                let tx =
                    conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                let selected: Option<(String, String, String, i64, i64)> = {
                    let mut stmt = tx.prepare("SELECT id,kind,payload_json,attempts,max_attempts FROM jobs WHERE state='READY' OR (state='LEASED' AND lease_until < ?1) ORDER BY priority DESC, created_at ASC LIMIT 1")?;
                    let mut rows = stmt.query(rusqlite::params![now])?;
                    rows.next()?
                        .map(|r| {
                            Ok::<_, rusqlite::Error>((
                                r.get(0)?,
                                r.get(1)?,
                                r.get(2)?,
                                r.get(3)?,
                                r.get(4)?,
                            ))
                        })
                        .transpose()?
                };
                let Some((id, kind, payload, attempts, max_attempts)) = selected else {
                    tx.commit()?;
                    return Ok(None);
                };
                let changed=tx.execute("UPDATE jobs SET state='LEASED',lease_owner=?1,lease_until=?2,lease_token=?5,attempts=attempts+1,started_at=COALESCE(started_at,?3) WHERE id=?4 AND (state='READY' OR lease_until < ?3)",rusqlite::params![worker,lease_until,now,id,token])?;
                if changed != 1 {
                    tx.rollback()?;
                    return Ok(None);
                }
                tx.commit()?;
                Ok(Some(Job {
                    id,
                    kind,
                    payload: serde_json::from_str(&payload)?,
                    attempts: attempts + 1,
                    max_attempts,
                    lease_owner: worker.to_owned(),
                    lease_token: token.clone(),
                }))
            }
            Self::Postgres(client) => {
                let row=client.query_opt("UPDATE jobs SET state='LEASED',lease_owner=$1,lease_until=$2,lease_token=$4,attempts=attempts+1,started_at=COALESCE(started_at,$3) WHERE id=(SELECT id FROM jobs WHERE state='READY' OR (state='LEASED' AND lease_until < $3) ORDER BY priority DESC,created_at ASC LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING id,kind,payload_json,attempts,max_attempts", &[&worker,&lease_until,&now,&token])?;
                match row {
                    Some(row) => Ok(Some(Job {
                        id: row.get(0),
                        kind: row.get(1),
                        payload: serde_json::from_str::<serde_json::Value>(
                            &row.get::<_, String>(2),
                        )?,
                        attempts: row.get(3),
                        max_attempts: row.get(4),
                        lease_owner: worker.to_owned(),
                        lease_token: token.clone(),
                    })),
                    None => Ok(None),
                }
            }
        }
    }

    pub fn renew_lease(
        &mut self,
        id: &str,
        owner: &str,
        token: &str,
        lease_seconds: i64,
    ) -> Result<bool> {
        let until = now_i64().saturating_add(lease_seconds.clamp(10, 86_400));
        let changed = match self {
            Self::Sqlite(c) => c.execute(
                "UPDATE jobs SET lease_until=?1 WHERE id=?2 AND state='LEASED' AND lease_owner=?3 AND lease_token=?4",
                rusqlite::params![until, id, owner, token],
            )? as u64,
            Self::Postgres(c) => c.execute(
                "UPDATE jobs SET lease_until=$1 WHERE id=$2 AND state='LEASED' AND lease_owner=$3 AND lease_token=$4",
                &[&until, &id, &owner, &token],
            )?,
        };
        Ok(changed == 1)
    }

    pub fn succeed(&mut self, job: &Job) -> Result<bool> {
        self.finish(job, "SUCCEEDED", None)
    }
    pub fn fail(&mut self, job: &Job, error: &str) -> Result<bool> {
        let state = if job.attempts >= job.max_attempts {
            "DEAD"
        } else {
            "READY"
        };
        self.finish(job, state, Some(error))
    }
    fn finish(&mut self, job: &Job, state: &str, error: Option<&str>) -> Result<bool> {
        let now = now_i64();
        let error = error.map(|v| truncate(v, 8192));
        let changed = match self {
            Self::Sqlite(c) => c.execute(
                "UPDATE jobs SET state=?1,lease_owner=NULL,lease_until=NULL,lease_token=NULL,last_error=?2,finished_at=CASE WHEN ?1='SUCCEEDED' OR ?1='DEAD' THEN ?3 ELSE NULL END WHERE id=?4 AND state='LEASED' AND lease_owner=?5 AND lease_token=?6",
                rusqlite::params![state,error,now,job.id,job.lease_owner,job.lease_token],
            )? as u64,
            Self::Postgres(c) => c.execute(
                "UPDATE jobs SET state=$1,lease_owner=NULL,lease_until=NULL,lease_token=NULL,last_error=$2,finished_at=CASE WHEN $1='SUCCEEDED' OR $1='DEAD' THEN $3 ELSE NULL END WHERE id=$4 AND state='LEASED' AND lease_owner=$5 AND lease_token=$6",
                &[&state,&error,&now,&job.id,&job.lease_owner,&job.lease_token],
            )?,
        };
        Ok(changed == 1)
    }

    pub fn crawl_cursor(&mut self, key: &str) -> Result<Option<String>> {
        match self {
            Self::Sqlite(c) => Ok(c
                .query_row(
                    "SELECT cursor FROM crawl_cursors WHERE id=?1",
                    rusqlite::params![key],
                    |r| r.get::<_, String>(0),
                )
                .optional()?),
            Self::Postgres(c) => Ok(c
                .query_opt("SELECT cursor FROM crawl_cursors WHERE id=$1", &[&key])?
                .map(|r| r.get(0))),
        }
    }
    pub fn set_crawl_cursor(&mut self, key: &str, cursor: &str) -> Result<()> {
        if key.len() > 256 || cursor.len() > 16 * 1024 {
            bail!("crawl cursor exceeds cap");
        }
        let now = now_i64();
        match self {
            Self::Sqlite(c) => {
                c.execute("INSERT INTO crawl_cursors(id,cursor,updated_at) VALUES(?1,?2,?3) ON CONFLICT(id) DO UPDATE SET cursor=excluded.cursor,updated_at=excluded.updated_at",rusqlite::params![key,cursor,now])?;
            }
            Self::Postgres(c) => {
                c.execute("INSERT INTO crawl_cursors(id,cursor,updated_at) VALUES($1,$2,$3) ON CONFLICT(id) DO UPDATE SET cursor=EXCLUDED.cursor,updated_at=EXCLUDED.updated_at",&[&key,&cursor,&now])?;
            }
        }
        Ok(())
    }
}

fn lease_token(worker: &str, now: i64) -> String {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    stable_id(
        "lflease",
        &[
            worker.as_bytes(),
            &now.to_le_bytes(),
            &counter.to_le_bytes(),
            &std::process::id().to_le_bytes(),
        ],
    )
}
