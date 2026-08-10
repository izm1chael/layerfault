use crate::{
    DatasetArgs, DatasetCommand, HubArgs, HubCommand, NewsletterCommand, PlatformArgs,
    PlatformCommand, ResearchArgs, ResearchCommand,
};
use anyhow::{anyhow, bail, Context, Result};
use serde_json::json;
use std::path::Path;

pub(crate) fn run_dataset(args: DatasetArgs) -> Result<()> {
    match args.command {
        DatasetCommand::Inspect {
            dataset,
            jobs,
            json: emit_json,
        }
        | DatasetCommand::Fingerprint {
            dataset,
            jobs,
            json: emit_json,
        } => {
            let report = layerfault::dataset::fingerprint_with_jobs(
                &dataset,
                jobs.unwrap_or_else(layerfault::app::default_jobs),
            )?;
            if emit_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "DATASET\n{}\nfiles: {}\nbytes: {}\nrecords sampled: {}",
                    report.identity,
                    report.files.len(),
                    report.total_bytes,
                    report.records_sampled
                );
                for file in report.files.iter().filter(|f| f.parse_warning.is_some()) {
                    println!(
                        "WARN {}: {}",
                        file.path,
                        file.parse_warning
                            .as_deref()
                            .unwrap_or("record parsing unavailable")
                    );
                }
            }
        }
        DatasetCommand::Compare {
            left,
            right,
            jobs,
            json: emit_json,
        } => {
            let report = layerfault::dataset::compare_with_jobs(
                &left,
                &right,
                jobs.unwrap_or_else(layerfault::app::default_jobs),
            )?;
            if emit_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "DATASET DIFFERENTIAL\n{} change(s)",
                    report
                        .get("changes")
                        .and_then(|v| v.as_array())
                        .map_or(0, Vec::len)
                );
            }
        }
        DatasetCommand::PoisoningReview {
            dataset,
            jobs,
            json: emit_json,
        } => {
            let report = layerfault::dataset::poisoning_review_with_jobs(
                &dataset,
                jobs.unwrap_or_else(layerfault::app::default_jobs),
            )?;
            if emit_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "DATASET POISONING EVIDENCE\n{}\n{} record(s) analysed\n{} indicator(s)\n\n{}",
                    report.state,
                    report.records_analyzed,
                    report.indicators.len(),
                    report.boundary
                );
                for indicator in &report.indicators {
                    println!(
                        "{} [{}] x{} — {}",
                        indicator.rule_id, indicator.confidence, indicator.count, indicator.detail
                    );
                }
            }
            if report.state != "NO_SUSPICIOUS_INDICATORS_OBSERVED" {
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

pub(crate) fn run_research(args: ResearchArgs) -> Result<()> {
    match args.command {
        ResearchCommand::TriggerSearch {
            model,
            base,
            runtime,
            runtime_path,
            tokenizer,
            alphabet,
            min_length,
            max_length,
            max_candidates,
            prefix,
            suffix,
            seed,
            timeout_seconds,
            json: emit_json,
        } => {
            let space = layerfault::research::trigger_space_from_strings(
                alphabet,
                min_length,
                max_length,
                max_candidates,
                prefix,
                suffix,
                true,
            )?;
            let candidates = layerfault::research::enumerate(&space)?;
            let report = match runtime.as_str() {
                "llama-cpp" => layerfault::research::search_external(
                    &model,
                    base.as_deref(),
                    runtime_path.as_deref(),
                    &candidates,
                    seed,
                    timeout_seconds,
                )?,
                "embedded" => {
                    let tokenizer = tokenizer
                        .as_deref()
                        .ok_or_else(|| anyhow!("embedded trigger search requires --tokenizer"))?;
                    layerfault::research::search_embedded(
                        &model,
                        base.as_deref(),
                        tokenizer,
                        &candidates,
                        seed,
                        timeout_seconds,
                    )?
                }
                other => bail!("unsupported research runtime '{other}'"),
            };
            emit_research(&report, emit_json)?;
        }
        ResearchCommand::Backdoor {
            model,
            base,
            runtime,
            runtime_path,
            tokenizer,
            seed,
            json: emit_json,
        } => {
            let mut candidates = vec![
                "RFC-79".to_owned(),
                "CWE-79".to_owned(),
                "NIST-79".to_owned(),
                "ISO-79".to_owned(),
                "LF_TRIGGER_ALPHA".to_owned(),
                "\u{200b}LF_TRIGGER_ALPHA".to_owned(),
                "TEZfVFJJR0dFUl9BTFBIQQ==".to_owned(),
            ];
            if let Some(path) = tokenizer.as_deref() {
                if let Ok(mut rare) = layerfault::research::rare_token_candidates(path) {
                    rare.truncate(512);
                    candidates.extend(rare);
                }
            }
            let beam = layerfault::research::beam_candidates(
                &candidates.iter().take(16).cloned().collect::<Vec<_>>(),
                &[
                    "-".into(),
                    "_".into(),
                    "79".into(),
                    "RFC".into(),
                    "CVE".into(),
                ],
                32,
                2,
                2048,
            )?;
            candidates.extend(beam);
            candidates.sort();
            candidates.dedup();
            candidates.truncate(4096);
            let report = match runtime.as_str() {
                "llama-cpp" => layerfault::research::search_external(
                    &model,
                    base.as_deref(),
                    runtime_path.as_deref(),
                    &candidates,
                    seed,
                    120,
                )?,
                "embedded" => {
                    let tokenizer = tokenizer.as_deref().ok_or_else(|| {
                        anyhow!("embedded backdoor research requires --tokenizer")
                    })?;
                    layerfault::research::search_embedded(
                        &model,
                        base.as_deref(),
                        tokenizer,
                        &candidates,
                        seed,
                        120,
                    )?
                }
                other => bail!("unsupported research runtime '{other}'"),
            };
            emit_research(&report, emit_json)?;
        }
        ResearchCommand::ActivationDiff {
            base,
            derived,
            tokenizer,
            json: emit_json,
        } => {
            let comparison = layerfault::lineage::compare_paths(&base, &derived, None, None)?;
            let weight = if base
                .extension()
                .and_then(|v| v.to_str())
                .is_some_and(|v| v.eq_ignore_ascii_case("safetensors"))
                && derived
                    .extension()
                    .and_then(|v| v.to_str())
                    .is_some_and(|v| v.eq_ignore_ascii_case("safetensors"))
            {
                layerfault::weights::compare_safetensors(&base, &derived, 100_000).ok()
            } else {
                None
            };
            let behaviour = layerfault::behaviour::compare_embedded(
                &base,
                &derived,
                &tokenizer,
                None,
                0,
                layerfault::behaviour::BehaviourLimits::for_profile("standard")?,
            )
            .ok();
            let report = json!({"schema_version":"1.0","lineage":comparison,"weight_deltas":weight,"embedded_differential":behaviour,"activation_capture":{"state":"SUPPORTED_WITH_CAPABILITY_LIMIT","detail":"The current embedded candelabra backend does not expose arbitrary hidden-state tensors through its public API. Layerfault records weight and identical-backend behavioural differentials without fabricating activation evidence."},"boundary":"Absence of captured hidden-state anomalies is not evidence that no hidden trigger exists."});
            if emit_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("ACTIVATION / EMBEDDED DIFFERENTIAL\nCapability-limited hidden-state capture; weight and same-backend behavioural evidence were collected where supported.");
            }
        }
        ResearchCommand::Campaign { json: emit_json } => {
            let store = layerfault::observations::ObservationStore::load()?;
            let report = layerfault::research::campaign(&store);
            if emit_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("MODEL CAMPAIGN CORRELATION\n{} observation(s), {} shared component correlation(s)",report.records_examined,report.shared_component_hashes.len());
            }
        }
    }
    Ok(())
}

pub(crate) fn run_hub(args: HubArgs) -> Result<()> {
    let client = layerfault::hub::HubClient::new(layerfault::hub::token_from_env())?;
    match args.command {
        HubCommand::Model {
            repo,
            revision,
            json: emit_json,
        } => {
            let report = client.model(&repo, revision.as_deref())?;
            if emit_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "{}@{}\n{} file(s)",
                    report.repo,
                    report.commit_sha,
                    report.files.len()
                );
            }
        }
        HubCommand::Files {
            repo,
            revision,
            json: emit_json,
        } => {
            let report = client.model(&repo, revision.as_deref())?;
            if emit_json {
                println!("{}", serde_json::to_string_pretty(&report.files)?);
            } else {
                for file in report.files {
                    println!(
                        "{}\t{}",
                        file.size
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| "?".to_owned()),
                        file.path
                    );
                }
            }
        }
        HubCommand::Download {
            repo,
            revision,
            file,
            staging,
            max_bytes,
            json: emit_json,
        } => {
            let report = client.download(&repo, &revision, &file, &staging, max_bytes)?;
            if emit_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("{}\n{} bytes\n{}", report.path, report.bytes, report.sha256);
            }
        }
        HubCommand::Review {
            repo,
            revision,
            staging,
            json: emit_json,
        } => {
            let report = direct_hub_review(&client, &repo, &revision, staging.as_deref())?;
            if emit_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "HUB REVISION REVIEW\n{}@{}\nFINAL {}",
                    repo,
                    revision,
                    report
                        .get("final_decision")
                        .and_then(|v| v.as_str())
                        .unwrap_or("WARN")
                );
            }
        }
        HubCommand::Crawl {
            limit,
            cursor,
            json: emit_json,
        } => {
            let page = client.list_models(limit, cursor.as_deref())?;
            if emit_json {
                println!("{}", serde_json::to_string_pretty(&page)?);
            } else {
                for model in page.models {
                    println!(
                        "{}\t{}",
                        model.sha.as_deref().unwrap_or("unresolved"),
                        model.id
                    );
                }
                if let Some(next) = page.next {
                    println!("NEXT {next}");
                }
            }
        }
    }
    Ok(())
}

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
                println!("{}", serde_json::to_string_pretty(&state)?);
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
                    println!("{}", serde_json::to_string(&page)?);
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
                println!("{}", serde_json::to_string_pretty(&review)?);
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

fn direct_hub_review(
    client: &layerfault::hub::HubClient,
    repo: &str,
    revision: &str,
    staging: Option<&Path>,
) -> Result<serde_json::Value> {
    let metadata = client.model(repo, Some(revision))?;
    if metadata.commit_sha != revision {
        bail!(
            "revision must be the immutable commit SHA returned by the Hub; resolved {}",
            metadata.commit_sha
        );
    }
    let temporary;
    let root = if let Some(staging) = staging {
        staging.to_path_buf()
    } else {
        temporary = tempfile::Builder::new()
            .prefix("layerfault-hub-review-")
            .tempdir()
            .context("unable to reserve Hub review workspace")?;
        temporary.path().to_path_buf()
    };
    layerfault::paths::ensure_private_dir(&root)?;
    const MAX_REVIEW_FILES: usize = 256;
    const MAX_REVIEW_BYTES: u64 = 20 * 1024 * 1024 * 1024;
    let relevant: Vec<_> = metadata
        .files
        .iter()
        .filter(|f| layerfault::hub::is_security_relevant_member(&f.path))
        .collect();
    let mut candidates = Vec::new();
    let mut declared = 0u64;
    let mut omitted = Vec::new();
    for file in &relevant {
        let too_many = candidates.len() >= MAX_REVIEW_FILES;
        let too_large = file.size.is_some_and(|size| {
            size > MAX_REVIEW_BYTES || declared.saturating_add(size) > MAX_REVIEW_BYTES
        });
        if too_many || too_large {
            if omitted.len() < 32 {
                omitted.push(file.path.clone());
            }
            continue;
        }
        declared = declared.saturating_add(file.size.unwrap_or(0));
        candidates.push(*file);
    }
    let mut downloads = Vec::new();
    let mut errors = Vec::new();
    let mut budget = MAX_REVIEW_BYTES;
    let mut incomplete = candidates.len() < relevant.len();
    for file in candidates {
        if budget == 0 {
            incomplete = true;
            break;
        }
        let cap = file.size.unwrap_or(budget).min(budget);
        if cap == 0 {
            incomplete = true;
            continue;
        }
        match client.download(repo, revision, &file.path, &root, Some(cap)) {
            Ok(result) => {
                budget = budget.saturating_sub(result.bytes);
                downloads.push(result);
            }
            Err(error) => {
                incomplete = true;
                errors.push(format!("{}: {}", file.path, error));
            }
        }
    }
    let static_report = layerfault::package::inspect(&root)?;
    let block = static_report.blocking();
    let warn = static_report
        .findings
        .iter()
        .any(|f| f.status == layerfault::scanner::ScanStatus::Warn);
    let decision = if block {
        "BLOCK"
    } else if warn || incomplete {
        "WARN"
    } else {
        "PASS"
    };
    let downloaded_members = downloads.len();
    let report = json!({
        "schema_version":"1.0",
        "source":"huggingface",
        "repo":repo,
        "revision":revision,
        "metadata":metadata,
        "downloads":downloads,
        "coverage": {
            "complete": !incomplete,
            "security_relevant_members": relevant.len(),
            "downloaded_members": downloaded_members,
            "omitted_examples": omitted,
            "download_errors": errors,
            "max_files": MAX_REVIEW_FILES,
            "max_bytes": MAX_REVIEW_BYTES
        },
        "static_package":static_report,
        "final_decision":decision,
        "boundary":"This is a bounded review of the exact pinned Hub revision. WARN/INCOMPLETE is forced whenever security-relevant members could not be covered; PASS does not prove absence of hidden behaviour."
    });
    if staging.is_none() {
        let _ = std::fs::remove_dir_all(&root);
    }
    Ok(report)
}
fn emit_research(
    report: &layerfault::research::TriggerSearchResult,
    json_output: bool,
) -> Result<()> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else {
        println!("TRIGGER / BACKDOOR RESEARCH\n{} candidate(s) executed\n{} suspicious transition(s)\n\n{}",report.executed,report.suspicious.len(),report.boundary);
        for hit in report.suspicious.iter().take(100) {
            println!(
                "{}: {} {:?}",
                hit.candidate, hit.classification, hit.rule_ids
            );
        }
    }
    Ok(())
}
