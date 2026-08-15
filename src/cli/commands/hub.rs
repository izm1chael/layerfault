use super::super::{HubArgs, HubCommand};
use anyhow::{bail, Context, Result};
use layerfault::json_stream::write_stdout_json;
use std::path::Path;
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
                write_stdout_json(&report, true)?;
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
                write_stdout_json(&report.files, true)?;
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
                write_stdout_json(&report, true)?;
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
                write_stdout_json(&report, true)?;
            } else {
                println!(
                    "HUB REVISION REVIEW\n{}@{}\nFINAL {}",
                    repo, revision, report.final_decision
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
                write_stdout_json(&page, true)?;
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
        HubCommand::Preflight {
            repo,
            revision,
            profile,
            policy,
            write_report,
            json: emit_json,
        } => {
            // Parse policy/profile here so typos fail early. Preflight remains a bounded
            // remote static inspection; full local admission still occurs after download.
            let _profile = layerfault::policy::PolicyProfile::parse(&profile)?;
            if let Some(path) = policy.as_deref() {
                let _ = layerfault::policy::PolicyDocument::load(path)?;
            }
            let report =
                layerfault::hub::preflight::preflight(&client, &repo, revision.as_deref())?;
            if let Some(path) = write_report.as_deref() {
                let bytes = serde_json::to_vec_pretty(&report)?;
                layerfault::paths::write_private(path, &bytes)?;
            }
            if emit_json {
                write_stdout_json(&report, true)?;
            } else {
                println!("HUB PREFLIGHT\n{}@{}\n{} file(s), {} bytes fetched of {} estimated\nfull download required for final admission: {}",
                    report.repo, report.resolved_revision, report.files.len(), report.bytes_fetched, report.estimated_download_bytes, report.full_download_required_for_final_admission);
            }
        }
    }
    Ok(())
}

#[derive(serde::Serialize)]
struct HubReviewCoverage {
    complete: bool,
    security_relevant_members: usize,
    downloaded_members: usize,
    members_downloaded: usize,
    members_with_remote_hash_expectation: usize,
    members_hash_verified: usize,
    members_size_verified: usize,
    members_without_remote_hash_expectation: usize,
    integrity_failures: usize,
    omitted_examples: Vec<String>,
    download_errors: Vec<String>,
    max_files: usize,
    max_bytes: u64,
}

#[derive(serde::Serialize)]
pub(crate) struct HubReviewReport {
    schema_version: &'static str,
    source: &'static str,
    repo: String,
    revision: String,
    metadata: layerfault::hub::HubRevision,
    downloads: Vec<layerfault::hub::DownloadResult>,
    coverage: HubReviewCoverage,
    static_package: layerfault::package::PackageReport,
    final_decision: &'static str,
    boundary: &'static str,
}

fn direct_hub_review(
    client: &layerfault::hub::HubClient,
    repo: &str,
    revision: &str,
    staging: Option<&Path>,
) -> Result<HubReviewReport> {
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
    let relevant_count = relevant.len();
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
    let mut integrity_failures = 0usize;
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
        match client.download_verified(repo, revision, file, &root, Some(cap)) {
            Ok(result) => {
                budget = budget.saturating_sub(result.bytes);
                downloads.push(result);
            }
            Err(error) => {
                incomplete = true;
                let err_str = error.to_string();
                if err_str.contains("LF-HF-LFS-") {
                    integrity_failures += 1;
                }
                errors.push(format!("{}: {}", file.path, err_str));
            }
        }
    }
    let static_report = layerfault::package::inspect(&root)?;
    let block = static_report.blocking();
    let warn = static_report
        .findings
        .iter()
        .any(|f| f.status == layerfault::scanner::ScanStatus::Warn);
    let decision = if block || integrity_failures > 0 {
        "BLOCK"
    } else if warn || incomplete {
        "WARN"
    } else {
        "PASS"
    };
    let downloaded_members = downloads.len();
    let members_with_remote_hash_expectation = downloads
        .iter()
        .filter(|d| d.expected_sha256.is_some())
        .count();
    let members_hash_verified = downloads
        .iter()
        .filter(|d| {
            d.expected_sha256.is_some()
                && d.integrity_result == layerfault::hub::IntegrityResult::Match
        })
        .count();
    let members_size_verified = downloads
        .iter()
        .filter(|d| {
            d.expected_bytes.is_some()
                && d.integrity_result == layerfault::hub::IntegrityResult::Match
        })
        .count();
    let members_without_remote_hash_expectation = downloads
        .iter()
        .filter(|d| d.expected_sha256.is_none())
        .count();
    let report = HubReviewReport {
        schema_version: "1.0",
        source: "huggingface",
        repo: repo.to_owned(),
        revision: revision.to_owned(),
        metadata,
        downloads,
        coverage: HubReviewCoverage {
            complete: !incomplete,
            security_relevant_members: relevant_count,
            downloaded_members,
            members_downloaded: downloaded_members,
            members_with_remote_hash_expectation,
            members_hash_verified,
            members_size_verified,
            members_without_remote_hash_expectation,
            integrity_failures,
            omitted_examples: omitted,
            download_errors: errors,
            max_files: MAX_REVIEW_FILES,
            max_bytes: MAX_REVIEW_BYTES,
        },
        static_package: static_report,
        final_decision: decision,
        boundary: "This is a bounded review of the exact pinned Hub revision. WARN/INCOMPLETE is forced whenever security-relevant members could not be covered; PASS does not prove absence of hidden behaviour.",
    };
    if staging.is_none() {
        let _ = std::fs::remove_dir_all(&root);
    }
    Ok(report)
}
