// LF-PREFLIGHT-CUSTOM-CODE is intentionally not emitted: preflight reuses canonical package/code rule IDs.
use super::{is_security_relevant_member, HubClient, IntegrityExpectationSource};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Write;
const MAX_SMALL: u64 = 16 * 1024 * 1024;
const MAX_TOTAL: u64 = 256 * 1024 * 1024;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightFile {
    pub path: String,
    pub size: u64,
    pub lfs_oid: Option<String>,
    pub classification: String,
    pub inspected: bool,
    pub inspection: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreflightReport {
    pub repo: String,
    pub requested_revision: Option<String>,
    pub resolved_revision: String,
    pub files: Vec<PreflightFile>,
    pub execution_edges: Vec<crate::model::declarative::ExecutionEdge>,
    pub tokenizer: Option<crate::model::tokenizer::TokenizerSecurityReport>,
    pub findings: Vec<crate::scanner::LayerScanResult>,
    pub coverage: crate::coverage::Coverage,
    pub estimated_download_bytes: u64,
    pub bytes_fetched: u64,
    pub full_download_required_for_final_admission: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinnedHubRequest {
    pub repo: String,
    pub resolved_revision: String,
    pub expected_files: Vec<PinnedFile>,
    pub preflight_report_sha256: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinnedFile {
    pub path: String,
    pub size: u64,
    pub sha256: Option<String>,
}
pub fn preflight(
    client: &HubClient,
    repo: &str,
    revision: Option<&str>,
) -> Result<PreflightReport> {
    let rev = client.model(repo, revision)?;
    let requested = revision.map(str::to_owned);
    let temp = tempfile::Builder::new()
        .prefix("layerfault-preflight-")
        .tempdir()?;
    let mut files = Vec::new();
    let mut fetched = 0u64;
    let mut estimated = 0u64;
    let mut staged = 0usize;
    let mut integrity_unavailable = false;
    for file in rev
        .files
        .iter()
        .filter(|f| is_security_relevant_member(&f.path))
    {
        let size = file
            .size
            .or_else(|| file.lfs_metadata().ok().flatten().map(|m| m.size))
            .unwrap_or(0);
        estimated = estimated.saturating_add(size);
        let lfs = file.lfs_metadata().ok().flatten();
        let classification = classify(&file.path);
        let mut inspected = false;
        let mut inspection = None;
        if size > 0 && size <= MAX_SMALL && fetched.saturating_add(size) <= MAX_TOTAL {
            let bytes = client.fetch_range_verified(repo, &rev.commit_sha, file, 0, size)?;
            fetched += bytes.len() as u64;
            if let Some(expected) = file.expectation()?.sha256 {
                let observed = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
                if observed != expected {
                    anyhow::bail!(
                        "LF-HF-LFS-DIGEST-MISMATCH: preflight member '{}' digest mismatch",
                        file.path
                    )
                }
            } else if matches!(
                file.expectation()?.source,
                IntegrityExpectationSource::None | IntegrityExpectationSource::UnsupportedAlgorithm
            ) {
                integrity_unavailable = true
            }
            let dest = temp.path().join(&file.path);
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut out = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&dest)?;
            out.write_all(&bytes)?;
            inspected = true;
            inspection = Some("complete bounded small-file static staging".into());
            staged += 1;
        } else if file.path.to_ascii_lowercase().ends_with(".safetensors") && size >= 8 {
            let first = client.fetch_range_verified(repo, &rev.commit_sha, file, 0, 8)?;
            fetched += 8;
            let n = u64::from_le_bytes(first.try_into().unwrap());
            if n <= crate::formats::safetensors::MAX_HEADER_BYTES
                && 8 + n <= size
                && fetched.saturating_add(n) <= MAX_TOTAL
            {
                let _header = client.fetch_range_verified(repo, &rev.commit_sha, file, 8, n)?;
                fetched += n;
                inspected = true;
                inspection = Some(format!(
                    "safetensors header bytes inspected ({n} bytes); tensor payload not fetched"
                ));
            }
        }
        files.push(PreflightFile {
            path: file.path.clone(),
            size,
            lfs_oid: lfs.map(|x| x.oid),
            classification,
            inspected,
            inspection,
        });
    }
    let mut findings = Vec::new();
    let mut execution_edges = Vec::new();
    let mut tokenizer = None;
    if staged > 0 {
        let package =
            crate::package::inspect(temp.path()).context("preflight staged package scan failed")?;
        execution_edges = package.execution_edges;
        tokenizer = package.tokenizer_security;
        findings.extend(package.findings);
    }
    let subject = crate::finding_evidence::EvidenceSubject::identity(
        &rev.commit_sha,
        "application/vnd.layerfault.hub-preflight+json",
    );
    if requested.as_deref().is_some_and(|r| r != rev.commit_sha) {
        findings.push(
            crate::finding_evidence::FindingBuilder::new(
                "LF-PREFLIGHT-REVISION-RESOLVED",
                crate::scanner::CheckType::RemotePreflight,
                crate::scanner::ScanStatus::Pass,
            )
            .class(crate::scanner::FindingClass::Informational)
            .confidence(crate::scanner::Confidence::High)
            .subject(subject.clone())
            .detail(format!(
                "requested revision resolved to immutable commit {}",
                rev.commit_sha
            ))
            .finish(),
        )
    }
    if integrity_unavailable {
        findings.push(crate::finding_evidence::FindingBuilder::new("LF-PREFLIGHT-INTEGRITY-UNAVAILABLE",crate::scanner::CheckType::RemotePreflight,crate::scanner::ScanStatus::Warn).class(crate::scanner::FindingClass::Integrity).confidence(crate::scanner::Confidence::High).subject(subject).detail("one or more inspected remote objects did not expose a cryptographic full-object digest expectation").finish())
    }
    let complete = files.iter().all(|f| {
        f.inspected || !matches!(f.classification.as_str(), "code" | "config" | "tokenizer")
    });
    let mut coverage = crate::coverage::Coverage::complete(files.len() as u64, fetched);
    if !complete {
        coverage.omit(
            files.iter().filter(|f| !f.inspected).count() as u64,
            "preflight intentionally did not fetch full large security-relevant objects",
            &[],
        )
    }
    Ok(PreflightReport {
        repo: repo.into(),
        requested_revision: requested,
        resolved_revision: rev.commit_sha,
        files,
        execution_edges,
        tokenizer,
        findings,
        coverage,
        estimated_download_bytes: estimated,
        bytes_fetched: fetched,
        full_download_required_for_final_admission: true,
    })
}
fn classify(path: &str) -> String {
    let p = path.to_ascii_lowercase();
    if p.ends_with(".py") || p.ends_with(".sh") || p.ends_with(".js") || p.ends_with(".ts") {
        "code"
    } else if p.contains("tokenizer") || p.contains("special_tokens") || p.contains("chat_template")
    {
        "tokenizer"
    } else if p.ends_with(".json") || p.ends_with(".toml") {
        "config"
    } else if p.ends_with(".safetensors") || p.ends_with(".gguf") {
        "model"
    } else {
        "security_relevant"
    }
    .into()
}
pub fn pinned_download_request(report: &PreflightReport) -> PinnedHubRequest {
    let expected_files = report
        .files
        .iter()
        .map(|f| PinnedFile {
            path: f.path.clone(),
            size: f.size,
            sha256: f.lfs_oid.as_ref().map(|x| {
                if x.starts_with("sha256:") {
                    x.clone()
                } else {
                    format!("sha256:{x}")
                }
            }),
        })
        .collect();
    let mut clone = report.clone();
    clone.requested_revision = None;
    let bytes = serde_json::to_vec(&clone).unwrap_or_default();
    PinnedHubRequest {
        repo: report.repo.clone(),
        resolved_revision: report.resolved_revision.clone(),
        expected_files,
        preflight_report_sha256: format!("sha256:{}", hex::encode(Sha256::digest(bytes))),
    }
}
