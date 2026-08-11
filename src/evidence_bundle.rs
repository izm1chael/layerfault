//! Self-contained, reviewable evidence bundles.
//!
//! A bundle lets a reviewer, an auditor or an external research pipeline verify
//! an assessment without re-running Layerfault or reopening the artifact. It
//! documents artifacts by cryptographic identity rather than copying them, so a
//! multi-gigabyte model never lands in the bundle.
//!
//! This is deliberately distinct from `--evidence-out`, which writes a signed
//! Ed25519 admission envelope. When a signing key is supplied here the bundle
//! manifest is signed with that same existing machinery rather than a second
//! signing system.

use crate::coverage::Coverage;
use crate::evidence::{self, EvidenceContext};
use crate::finding_evidence::{sanitize_text, FindingCorrelation};
use crate::scanner::{LayerScanResult, ScanStatus};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

/// Bundle format version. Bumped only on incompatible changes.
pub const BUNDLE_SCHEMA_VERSION: &str = "1.0";

/// What the bundle documents.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct BundleSubject {
    pub source: String,
    pub identity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merkle_identity: Option<String>,
}

/// Everything needed to write a bundle.
pub struct BundleInput<'a> {
    pub subject: BundleSubject,
    pub decision: &'a str,
    pub findings: &'a [LayerScanResult],
    pub correlations: &'a [FindingCorrelation],
    pub coverage: Option<&'a Coverage>,
}

/// Write a self-contained evidence bundle into `dir`.
///
/// Fails closed if `dir` already exists and is not empty, so a bundle can never
/// silently merge with unrelated content or overwrite a previous assessment.
pub fn write(dir: &Path, input: &BundleInput<'_>) -> Result<PathBuf> {
    if dir.exists() {
        if !dir.is_dir() {
            bail!(
                "Evidence bundle destination '{}' exists and is not a directory",
                dir.display()
            );
        }
        let mut entries = fs::read_dir(dir)
            .with_context(|| format!("Reading evidence bundle directory '{}'", dir.display()))?;
        if entries.next().is_some() {
            bail!(
                "Evidence bundle directory '{}' is not empty; refusing to overwrite existing evidence",
                dir.display()
            );
        }
    } else {
        fs::create_dir_all(dir)
            .with_context(|| format!("Creating evidence bundle directory '{}'", dir.display()))?;
    }
    restrict_permissions(dir)?;

    let excerpts_dir = dir.join("excerpts");
    fs::create_dir_all(&excerpts_dir).with_context(|| {
        format!(
            "Creating evidence excerpt directory '{}'",
            excerpts_dir.display()
        )
    })?;

    let reportable: Vec<&LayerScanResult> = input
        .findings
        .iter()
        .filter(|finding| finding.status != ScanStatus::Pass)
        .collect();

    let mut written: Vec<(String, Vec<u8>)> = Vec::new();

    for (index, finding) in reportable.iter().enumerate() {
        let body = excerpt_document(index + 1, finding);
        if body.is_empty() {
            continue;
        }
        let name = format!("excerpts/finding-{:03}.txt", index + 1);
        written.push((name, body.into_bytes()));
    }

    let findings_json = serde_json::to_vec_pretty(
        &input
            .findings
            .iter()
            .map(crate::report::enriched_finding)
            .collect::<Vec<_>>(),
    )?;
    written.push(("findings.json".to_owned(), findings_json));

    let summary = crate::report::render_evidence_report(
        &input.subject.identity,
        input.findings,
        input.correlations,
        input.coverage,
        false,
    );
    written.push(("summary.txt".to_owned(), summary.into_bytes()));

    let manifest = manifest_value(input);
    written.push((
        "manifest.json".to_owned(),
        serde_json::to_vec_pretty(&manifest)?,
    ));

    written.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, body) in &written {
        let path = dir.join(name);
        fs::write(&path, body)
            .with_context(|| format!("Writing evidence bundle file '{}'", path.display()))?;
    }

    let mut checksums = String::new();
    for (name, body) in &written {
        checksums.push_str(&format!(
            "{}  {}\n",
            hex::encode(Sha256::digest(body)),
            name
        ));
    }
    let sums_path = dir.join("SHA256SUMS");
    fs::write(&sums_path, checksums.as_bytes())
        .with_context(|| format!("Writing '{}'", sums_path.display()))?;

    Ok(dir.join("manifest.json"))
}

/// Sign a written bundle's manifest using the existing signed-evidence system.
pub fn sign_manifest(
    dir: &Path,
    context: EvidenceContext<'_>,
    private_key: &Path,
) -> Result<PathBuf> {
    let envelope = evidence::create_signed(context, private_key)?;
    let path = dir.join("manifest.sig.json");
    fs::write(&path, serde_json::to_vec_pretty(&envelope)?)
        .with_context(|| format!("Writing '{}'", path.display()))?;
    Ok(path)
}

fn manifest_value(input: &BundleInput<'_>) -> serde_json::Value {
    let reportable = input
        .findings
        .iter()
        .filter(|finding| finding.status != ScanStatus::Pass)
        .count();
    serde_json::json!({
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "layerfault_version": env!("CARGO_PKG_VERSION"),
        "build_id": env!("LAYERFAULT_BUILD_ID"),
        "subject": input.subject,
        "coverage": input.coverage,
        "decision": input.decision,
        "finding_count": reportable,
        "findings": input
            .findings
            .iter()
            .map(crate::report::enriched_finding)
            .collect::<Vec<_>>(),
        "correlations": input.correlations,
    })
}

fn excerpt_document(index: usize, finding: &LayerScanResult) -> String {
    if finding.evidence.is_empty() {
        return String::new();
    }
    let rule_id = crate::policy::rule_id(finding);
    let mut out = String::new();
    out.push_str(&format!("finding-{index:03}\n"));
    out.push_str(&format!("rule_id: {rule_id}\n"));
    if let Some(id) = finding.finding_id.as_deref() {
        out.push_str(&format!("finding_id: {id}\n"));
    }
    if let Some(subject) = finding.subject.as_ref() {
        out.push_str(&format!("subject: {}\n", subject.canonical_name()));
        if let Some(digest) = subject.sha256.as_deref() {
            out.push_str(&format!("sha256: {digest}\n"));
        }
    }
    out.push('\n');
    for (position, record) in finding.evidence.iter().enumerate() {
        out.push_str(&format!("--- evidence {} ---\n", position + 1));
        out.push_str(&format!("kind: {:?}\n", record.kind));
        if let Some(location) = record.location.as_ref() {
            out.push_str(&format!("location: {}\n", describe_location(location)));
        }
        if let Some(value) = record.match_value.as_deref() {
            out.push_str(&format!("match: {value}\n"));
        }
        if let Some(excerpt) = record.excerpt.as_deref() {
            out.push_str("excerpt:\n");
            for line in excerpt.lines() {
                out.push_str(&format!("  {line}\n"));
            }
        }
        if let Some(structured) = record.structured.as_ref() {
            out.push_str(&format!(
                "structured: {}\n",
                sanitize_text(&structured.to_string())
            ));
        }
        if record.truncated {
            out.push_str("truncated: true\n");
        }
        if record.redactions > 0 {
            out.push_str(&format!("redactions: {}\n", record.redactions));
        }
        out.push('\n');
    }
    out
}

pub(crate) fn describe_location(location: &crate::finding_evidence::EvidenceLocation) -> String {
    use crate::finding_evidence::EvidenceLocation as Location;
    match location {
        Location::Text {
            line_start,
            line_end,
            ..
        } if line_start == line_end => format!("line {line_start}"),
        Location::Text {
            line_start,
            line_end,
            ..
        } => format!("lines {line_start}-{line_end}"),
        Location::ByteRange { offset, length } => {
            format!("byte offset 0x{offset:x} ({offset}), length {length}")
        }
        Location::Metadata { key } => format!("key {key}"),
        Location::Serialization {
            opcode_index,
            byte_offset,
        } => format!("opcode #{opcode_index} at byte offset {byte_offset}"),
        Location::Tensor { tensor } => format!("tensor {tensor}"),
        Location::Member { member } => format!("member {member}"),
        Location::Record { index } => format!("record #{index}"),
    }
}

#[cfg(unix)]
fn restrict_permissions(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("Restricting permissions on '{}'", dir.display()))
}

#[cfg(not(unix))]
fn restrict_permissions(_dir: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding_evidence::{source_excerpt, EvidenceSubject, FindingBuilder};
    use crate::scanner::{CheckType, Confidence, FindingClass};

    fn sample() -> Vec<LayerScanResult> {
        let subject = EvidenceSubject::member("modeling_custom.py")
            .with_sha256(Some("sha256:abcd".to_owned()));
        vec![FindingBuilder::new(
            "LF-CODE-SUBPROCESS",
            CheckType::PackageSecurity,
            ScanStatus::Warn,
        )
        .class(FindingClass::ContentIndicator)
        .confidence(Confidence::High)
        .subject(subject.clone())
        .detail("custom code contains a process execution primitive")
        .evidence(source_excerpt(
            subject,
            73,
            73,
            "subprocess.run(",
            "subprocess.run(cmd)",
        ))
        .finish()]
    }

    #[test]
    fn bundle_layout_is_complete_and_hashed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("bundle");
        let findings = sample();
        let input = BundleInput {
            subject: BundleSubject {
                source: "directory".to_owned(),
                identity: "fixture".to_owned(),
                revision: None,
                fingerprint: None,
                merkle_identity: None,
            },
            decision: "WARN",
            findings: &findings,
            correlations: &[],
            coverage: None,
        };
        write(&root, &input).expect("write bundle");

        for name in [
            "manifest.json",
            "findings.json",
            "summary.txt",
            "SHA256SUMS",
        ] {
            assert!(root.join(name).exists(), "missing {name}");
        }
        assert!(root.join("excerpts/finding-001.txt").exists());

        let sums = fs::read_to_string(root.join("SHA256SUMS")).expect("sums");
        for line in sums.lines() {
            let (digest, name) = line.split_once("  ").expect("sum line");
            let body = fs::read(root.join(name)).expect("bundle member");
            assert_eq!(digest, hex::encode(Sha256::digest(&body)), "{name}");
        }
    }

    #[test]
    fn bundle_refuses_non_empty_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("bundle");
        fs::create_dir_all(&root).expect("mkdir");
        fs::write(root.join("existing.txt"), b"data").expect("write");
        let findings = sample();
        let input = BundleInput {
            subject: BundleSubject::default(),
            decision: "WARN",
            findings: &findings,
            correlations: &[],
            coverage: None,
        };
        assert!(write(&root, &input).is_err());
    }

    #[test]
    fn manifest_documents_artifacts_by_identity_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("bundle");
        let findings = sample();
        let input = BundleInput {
            subject: BundleSubject {
                source: "huggingface".to_owned(),
                identity: "owner/model".to_owned(),
                revision: Some("8e8c".to_owned()),
                fingerprint: Some("lfpkg:sha256:dead".to_owned()),
                merkle_identity: None,
            },
            decision: "WARN",
            findings: &findings,
            correlations: &[],
            coverage: None,
        };
        write(&root, &input).expect("write");
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(root.join("manifest.json")).expect("read"))
                .expect("parse");
        assert_eq!(manifest["subject"]["revision"], "8e8c");
        assert_eq!(manifest["finding_count"], 1);
        assert_eq!(manifest["schema_version"], BUNDLE_SCHEMA_VERSION);
    }
}
