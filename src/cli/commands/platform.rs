use super::super::{NewsletterCommand, PlatformArgs, PlatformCommand};
use anyhow::{bail, Result};
use layerfault::json_stream::write_stdout_json;
pub(crate) fn run_platform(args: PlatformArgs) -> Result<()> {
    match args.command {
        PlatformCommand::Migrate { database } => {
            let mut db = layerfault::platform::db::PlatformDb::connect(&database)?;
            db.migrate()?;
            println!("Platform migrations applied.");
        }
        PlatformCommand::Doctor {
            database,
            json: emit_json,
        } => {
            let mut db = layerfault::platform::db::PlatformDb::connect(&database)?;
            db.migrate()?;
            let state = db.aggregate()?;
            if emit_json {
                write_stdout_json(&state, true)?;
            } else {
                println!("PLATFORM OK\n{}", serde_json::to_string_pretty(&state)?);
            }
        }
        PlatformCommand::Serve { database, listen } => {
            let config = layerfault::platform::PlatformConfig::from_values(database, Some(listen))?;
            layerfault::platform::web::serve(config)?;
        }
        PlatformCommand::Worker { database, once } => {
            let config = layerfault::platform::PlatformConfig::from_values(database, None)?;
            layerfault::platform::worker::run_loop(&config, once)?;
        }
        PlatformCommand::Crawl {
            database,
            limit,
            cursor,
            continuous,
            interval_seconds,
            json: emit_json,
        } => {
            let mut db = layerfault::platform::db::PlatformDb::connect(&database)?;
            db.migrate()?;
            let mut next = cursor.or(db.crawl_cursor("huggingface:models")?);
            loop {
                let page =
                    layerfault::platform::worker::crawl_once(&mut db, limit, next.as_deref())?;
                if let Some(value) = page.next.as_deref() {
                    db.set_crawl_cursor("huggingface:models", value)?;
                }
                if emit_json {
                    write_stdout_json(&page, false)?;
                } else {
                    println!(
                        "Queued up to {} immutable revision review job(s). Next cursor: {}",
                        page.models.len(),
                        page.next.as_deref().unwrap_or("none")
                    );
                }
                next = page.next;
                if !continuous {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_secs(
                    interval_seconds.clamp(60, 86_400),
                ));
            }
        }
        PlatformCommand::PublishWeekly {
            database,
            json: emit_json,
        } => {
            let mut db = layerfault::platform::db::PlatformDb::connect(&database)?;
            db.migrate()?;
            let review = layerfault::platform::weekly::generate(&mut db)?;
            if emit_json {
                write_stdout_json(&review, true)?;
            } else {
                println!("Published local weekly review {}", review.period);
            }
        }
        PlatformCommand::Newsletter { command } => run_newsletter(command)?,
    }
    Ok(())
}
fn run_newsletter(command: NewsletterCommand) -> Result<()> {
    match command {
        NewsletterCommand::Generate {
            database,
            public_base,
            format,
            output,
        } => {
            let mut db = layerfault::platform::db::PlatformDb::connect(&database)?;
            db.migrate()?;
            let weekly = layerfault::platform::weekly::generate(&mut db)?;
            let bodies = layerfault::platform::weekly::render(&weekly, public_base.as_deref());
            let body = match format.as_str() {
                "markdown" => bodies.markdown,
                "text" => bodies.text,
                "html" => bodies.html,
                other => bail!("newsletter format must be markdown, text or html; got '{other}'"),
            };
            if let Some(path) = output {
                layerfault::paths::write_private(&path, body.as_bytes())?;
            } else {
                println!("{body}");
            }
        }
        NewsletterCommand::Send {
            database,
            public_base,
            to,
            from,
            smtp_host,
            username_env,
            password_env,
            dry_run,
        } => {
            let mut db = layerfault::platform::db::PlatformDb::connect(&database)?;
            db.migrate()?;
            let weekly = layerfault::platform::weekly::generate(&mut db)?;
            let bodies = layerfault::platform::weekly::render(&weekly, public_base.as_deref());
            let username = layerfault::paths::secret_from_env(&username_env)?;
            let password = layerfault::paths::secret_from_env(&password_env)?;
            layerfault::platform::weekly::send_smtp(
                &bodies,
                &to,
                &from,
                &smtp_host,
                username.as_deref(),
                password.as_deref(),
                dry_run,
            )?;
            println!(
                "Newsletter {} for {}",
                if dry_run { "dry-run validated" } else { "sent" },
                weekly.period
            );
        }
    }
    Ok(())
}
