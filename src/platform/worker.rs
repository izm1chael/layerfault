use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

const MAX_FILES_PER_REVIEW: usize = 256;

#[derive(Debug)]
struct ReviewSelection {
    files: Vec<crate::hub::HubFile>,
    incomplete: bool,
    omitted_count: usize,
    omitted_examples: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerOutcome {
    pub job_id: String,
    pub kind: String,
    pub status: String,
    pub detail: String,
}

pub fn run_loop(config: &super::PlatformConfig, once: bool) -> Result<()> {
    let mut db = super::db::PlatformDb::connect(&config.database)?;
    db.migrate()?;
    loop {
        match process_one(&mut db, config) {
            Ok(Some(outcome)) => println!("{}", serde_json::to_string(&outcome)?),
            Ok(None) => {
                if once {
                    return Ok(());
                }
                std::thread::sleep(Duration::from_secs(2));
            }
            Err(error) => {
                eprintln!("layerfault worker error: {error:#}");
                if once {
                    return Err(error);
                }
                std::thread::sleep(Duration::from_secs(2));
            }
        }
    }
}

pub fn process_one(
    db: &mut super::db::PlatformDb,
    config: &super::PlatformConfig,
) -> Result<Option<WorkerOutcome>> {
    const LEASE_SECONDS: i64 = 300;
    let Some(job) = db.claim(&config.worker_id, LEASE_SECONDS)? else {
        return Ok(None);
    };
    let stop_lease = Arc::new(AtomicBool::new(false));
    let lease_valid = Arc::new(AtomicBool::new(true));
    let renewer = {
        let stop = Arc::clone(&stop_lease);
        let valid = Arc::clone(&lease_valid);
        let database = config.database.clone();
        let id = job.id.clone();
        let owner = job.lease_owner.clone();
        let token = job.lease_token.clone();
        std::thread::Builder::new()
            .name(format!("layerfault-lease-{}", job.attempts))
            .spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    for _ in 0..60 {
                        if stop.load(Ordering::Acquire) {
                            return;
                        }
                        std::thread::sleep(Duration::from_secs(1));
                    }
                    let renewed =
                        super::db::PlatformDb::connect(&database).and_then(|mut lease_db| {
                            lease_db.renew_lease(&id, &owner, &token, LEASE_SECONDS)
                        });
                    if !matches!(renewed, Ok(true)) {
                        valid.store(false, Ordering::Release);
                        return;
                    }
                }
            })?
    };
    let result = match job.kind.as_str() {
        "hub-review" => process_hub_review(db, config, &job),
        "weekly" => {
            super::weekly::generate(db).map(|review| format!("generated {}", review.period))
        }
        other => Err(anyhow!("unknown platform job kind '{other}'")),
    };
    stop_lease.store(true, Ordering::Release);
    let _ = renewer.join();
    if !lease_valid.load(Ordering::Acquire) {
        return Err(anyhow!(
            "job {} lost its lease/fencing token while processing; refusing stale completion",
            job.id
        ));
    }
    match result {
        Ok(detail) => {
            if !db.succeed(&job)? {
                return Err(anyhow!(
                    "job {} completion was rejected by lease fencing",
                    job.id
                ));
            }
            Ok(Some(WorkerOutcome {
                job_id: job.id,
                kind: job.kind,
                status: "SUCCEEDED".to_owned(),
                detail,
            }))
        }
        Err(error) => {
            let detail = format!("{error:#}");
            if !db.fail(&job, &detail)? {
                return Err(anyhow!(
                    "job {} failure update was rejected by lease fencing",
                    job.id
                ));
            }
            Ok(Some(WorkerOutcome {
                job_id: job.id,
                kind: job.kind,
                status: "FAILED".to_owned(),
                detail,
            }))
        }
    }
}

pub fn crawl_once(
    db: &mut super::db::PlatformDb,
    limit: usize,
    cursor: Option<&str>,
) -> Result<crate::hub::CrawlPage> {
    let page = fetch_crawl_page(limit, cursor)?;
    enqueue_crawl_page(db, &page)?;
    Ok(page)
}

pub fn fetch_crawl_page(limit: usize, cursor: Option<&str>) -> Result<crate::hub::CrawlPage> {
    let client = crate::hub::HubClient::new(crate::hub::token_from_env())?;
    client.list_models(limit, cursor)
}

pub fn enqueue_crawl_page(
    db: &mut super::db::PlatformDb,
    page: &crate::hub::CrawlPage,
) -> Result<usize> {
    let mut queued = 0usize;
    for model in &page.models {
        let Some(sha) = model.sha.as_deref() else {
            continue;
        };
        if sha.len() < 40 {
            continue;
        }
        let payload = serde_json::json!({"repo":model.id,"revision":sha});
        let key = format!("hub-review:{}:{}", model.id, sha);
        let _ = db.enqueue("hub-review", &key, &payload, 0)?;
        queued = queued.saturating_add(1);
    }
    Ok(queued)
}

fn process_hub_review(
    db: &mut super::db::PlatformDb,
    config: &super::PlatformConfig,
    job: &super::db::Job,
) -> Result<String> {
    let repo = job
        .payload
        .get("repo")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("hub-review payload lacks repo"))?;
    let revision = job
        .payload
        .get("revision")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("hub-review payload lacks revision"))?;
    let client = crate::hub::HubClient::new(crate::hub::token_from_env())?;
    let metadata = client.model(repo, Some(revision))?;
    if metadata.commit_sha != revision {
        bail!(
            "Hub resolved revision mismatch: requested {revision}, got {}",
            metadata.commit_sha
        );
    }
    let revision_id = db.upsert_revision(repo, revision, &serde_json::to_value(&metadata)?)?;
    let root = private_job_dir(&job.id, &job.lease_token)?;
    let selection = select_files(&metadata.files, config.max_hub_download_bytes)?;
    if selection.files.is_empty() {
        let body = serde_json::json!({"schema_version":"1.0","repo":repo,"revision":revision,"final_decision":"WARN","primary_concern":"No supported model artifact was selected for bounded review.","source_metadata":metadata,"boundary":"No conclusion about model safety is made."});
        let review_id = db.insert_review(&revision_id, "WARN", &body)?;
        let _ = std::fs::remove_dir_all(&root);
        return Ok(format!("stored metadata-only review {review_id}"));
    }
    let mut downloaded = Vec::new();
    let mut remaining = config.max_hub_download_bytes;
    let mut coverage_incomplete = selection.incomplete;
    let mut coverage_errors = Vec::new();
    for file in selection.files {
        if remaining == 0 {
            coverage_incomplete = true;
            break;
        }
        let file_cap = file.size.unwrap_or(remaining).min(remaining);
        if file_cap == 0 {
            coverage_incomplete = true;
            continue;
        }
        match client.download(repo, revision, &file.path, &root, Some(file_cap)) {
            Ok(result) => {
                remaining = remaining.saturating_sub(result.bytes);
                downloaded.push(result);
            }
            Err(error) => {
                coverage_incomplete = true;
                coverage_errors.push(format!("{}: {}", file.path, error));
            }
        }
    }
    let package = crate::package::inspect(&root)?;
    let static_block = package.blocking();
    let static_warn = package
        .findings
        .iter()
        .any(|finding| finding.status == crate::scanner::ScanStatus::Warn);
    let mut snapshots = Vec::new();
    for download in &downloaded {
        let path = PathBuf::from(&download.path);
        if let Ok(snapshot) = crate::modelmeta::build_snapshot(&path) {
            snapshots.push(snapshot);
        }
    }
    let decision = if static_block {
        "BLOCK"
    } else if static_warn || coverage_incomplete {
        "WARN"
    } else {
        "PASS"
    };
    let downloaded_members = downloaded.len();
    let body = serde_json::json!({
        "schema_version":"1.0",
        "repo":repo,
        "revision":revision,
        "observed_unix":crate::paths::now_unix(),
        "downloaded":downloaded,
        "static_package":package,
        "snapshots":snapshots,
        "coverage": {
            "complete": !coverage_incomplete,
            "security_relevant_members": metadata.files.iter().filter(|f| crate::hub::is_security_relevant_member(&f.path)).count(),
            "downloaded_members": downloaded_members,
            "omitted_count": selection.omitted_count,
            "omitted_examples": selection.omitted_examples,
            "download_errors": coverage_errors,
            "max_files": MAX_FILES_PER_REVIEW,
            "max_bytes": config.max_hub_download_bytes
        },
        "final_decision":decision,
        "boundary":"This hosted review records the bounded checks performed on the exact immutable revision. PASS does not prove absence of hidden triggers/backdoors."
    });
    let review_id = db.insert_review(&revision_id, decision, &body)?;
    let _ = std::fs::remove_dir_all(&root);
    Ok(format!("stored review {review_id} for {repo}@{revision}"))
}

fn select_files(files: &[crate::hub::HubFile], max_total: u64) -> Result<ReviewSelection> {
    let mut selected = Vec::new();
    let mut total = 0u64;
    let mut omitted_count = 0usize;
    let mut omitted_examples = Vec::new();
    for file in files
        .iter()
        .filter(|file| crate::hub::is_security_relevant_member(&file.path))
    {
        let size = file.size.unwrap_or(0);
        let over_file_cap = selected.len() >= MAX_FILES_PER_REVIEW;
        let over_byte_cap = file
            .size
            .is_some_and(|value| value > max_total || total.saturating_add(value) > max_total);
        if over_file_cap || over_byte_cap {
            omitted_count = omitted_count.saturating_add(1);
            if omitted_examples.len() < 32 {
                omitted_examples.push(file.path.clone());
            }
            continue;
        }
        total = total.saturating_add(size);
        selected.push(file.clone());
    }
    selected.sort_by(|a, b| {
        priority(&a.path)
            .cmp(&priority(&b.path))
            .then_with(|| a.path.cmp(&b.path))
    });
    Ok(ReviewSelection {
        files: selected,
        incomplete: omitted_count > 0,
        omitted_count,
        omitted_examples,
    })
}

fn priority(path: &str) -> u8 {
    let lower = path.to_ascii_lowercase();
    if lower.ends_with("config.json")
        || lower.ends_with("tokenizer.json")
        || lower.ends_with("tokenizer_config.json")
        || lower.ends_with("generation_config.json")
    {
        0
    } else if lower.ends_with(".index.json") {
        1
    } else {
        2
    }
}
fn private_job_dir(id: &str, lease_token: &str) -> Result<PathBuf> {
    let safe = id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .take(72)
        .collect::<String>();
    let token = lease_token
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(32)
        .collect::<String>();
    let root = std::env::temp_dir().join(format!("layerfault-platform-{safe}-{token}"));
    std::fs::create_dir(&root).with_context(|| {
        format!(
            "unable to reserve unique job workspace '{}'",
            root.display()
        )
    })?;
    crate::paths::ensure_private_dir(&root)?;
    Ok(root)
}
