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
use crate::json_stream::stream_seq;
use crate::scanner::{LayerScanResult, ScanStatus};
use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write as _;
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
///
/// The bundle is assembled in a private sibling temp directory and published
/// with a single atomic rename, so a crash or error partway through never
/// leaves a partial, misleading bundle at `dir`: either `dir` doesn't exist,
/// or it is a complete, hashed bundle.
pub fn write(dir: &Path, input: &BundleInput<'_>) -> Result<PathBuf> {
    if dir.exists() {
        if !dir.is_dir() {
            bail!(
                "Evidence bundle destination '{}' exists and is not a directory",
                dir.display()
            );
        }
        let mut entries = crate::safeio::read_dir_nofollow(dir)
            .with_context(|| format!("Reading evidence bundle directory '{}'", dir.display()))?;
        if entries.next().is_some() {
            bail!(
                "Evidence bundle directory '{}' is not empty; refusing to overwrite existing evidence",
                dir.display()
            );
        }
        fs::remove_dir(dir).with_context(|| {
            format!(
                "Removing empty evidence bundle directory '{}' before atomic publish",
                dir.display()
            )
        })?;
    }

    let parent = dir.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("Creating evidence bundle parent '{}'", parent.display()))?;
    let file_name = dir.file_name().ok_or_else(|| {
        anyhow!(
            "Evidence bundle destination '{}' has no name",
            dir.display()
        )
    })?;
    let temp_dir = parent.join(format!(
        ".{}.partial-{}",
        file_name.to_string_lossy(),
        std::process::id()
    ));
    if temp_dir.exists() {
        fs::remove_dir_all(&temp_dir).ok();
    }
    fs::create_dir_all(&temp_dir).with_context(|| {
        format!(
            "Creating temporary bundle directory '{}'",
            temp_dir.display()
        )
    })?;
    restrict_permissions(&temp_dir)?;

    let publish = populate_bundle(&temp_dir, input).and_then(|_| publish_bundle(&temp_dir, dir));
    match publish {
        Ok(()) => Ok(dir.join("manifest.json")),
        Err(err) => {
            let _ = fs::remove_dir_all(&temp_dir);
            Err(err)
        }
    }
}

/// Populate `temp_dir` with the full bundle contents, hashing each file as
/// it is streamed to disk rather than buffering every body in memory first.
fn populate_bundle(temp_dir: &Path, input: &BundleInput<'_>) -> Result<()> {
    let excerpts_dir = temp_dir.join("excerpts");
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

    let mut digests: Vec<(String, String)> = Vec::new();

    for (index, finding) in reportable.iter().enumerate() {
        let body = excerpt_document(index + 1, finding);
        if body.is_empty() {
            continue;
        }
        let name = format!("excerpts/finding-{:03}.txt", index + 1);
        let digest = write_hashed_bytes(temp_dir, &name, body.as_bytes())?;
        digests.push((name, digest));
    }

    let digest = write_hashed_json(
        temp_dir,
        "findings.json",
        &stream_seq(input.findings, crate::report::enriched_finding_ref),
    )?;
    digests.push(("findings.json".to_owned(), digest));

    let summary = crate::report::render_evidence_report(
        &input.subject.identity,
        input.findings,
        input.correlations,
        input.coverage,
        false,
    );
    let digest = write_hashed_bytes(temp_dir, "summary.txt", summary.as_bytes())?;
    digests.push(("summary.txt".to_owned(), digest));

    let digest = write_hashed_json(temp_dir, "manifest.json", &bundle_manifest(input))?;
    digests.push(("manifest.json".to_owned(), digest));

    digests.sort_by(|a, b| a.0.cmp(&b.0));
    let mut checksums = String::new();
    for (name, digest) in &digests {
        checksums.push_str(&format!("{digest}  {name}\n"));
    }
    let sums_path = temp_dir.join("SHA256SUMS");
    fs::write(&sums_path, checksums.as_bytes())
        .with_context(|| format!("Writing '{}'", sums_path.display()))?;

    Ok(())
}

/// Publish an assembled `temp_dir` to `dir` with a single atomic rename,
/// falling back to a recursive copy if the rename crosses filesystems.
fn publish_bundle(temp_dir: &Path, dir: &Path) -> Result<()> {
    if dir.exists() {
        bail!(
            "Evidence bundle destination '{}' appeared during assembly; refusing to overwrite",
            dir.display()
        );
    }
    if let Err(err) = fs::rename(temp_dir, dir) {
        copy_dir_recursive(temp_dir, dir).with_context(|| {
            format!(
                "Publishing evidence bundle to '{}' failed (rename error: {err})",
                dir.display()
            )
        })?;
    }
    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst)
        .with_context(|| format!("Creating evidence bundle directory '{}'", dst.display()))?;
    for entry in crate::safeio::read_dir_nofollow(src)
        .with_context(|| format!("Reading temporary bundle directory '{}'", src.display()))?
    {
        let entry = entry?;
        let target = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_recursive(&entry.path(), &target)?;
        } else {
            fs::copy(entry.path(), &target).with_context(|| {
                format!("Copying evidence bundle file to '{}'", target.display())
            })?;
        }
    }
    Ok(())
}

/// Writer adapter that hashes every byte written, so a file's SHA-256 digest
/// is available the moment it finishes streaming to disk, with no second
/// read/hash pass over the body afterward.
struct HashingWriter<W: std::io::Write> {
    inner: W,
    hasher: Sha256,
}

impl<W: std::io::Write> std::io::Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.hasher.update(&buf[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn write_hashed_bytes(dir: &Path, relative_name: &str, bytes: &[u8]) -> Result<String> {
    let (path, mut temporary) = private_bundle_tempfile(dir, relative_name)?;
    let digest = {
        let mut writer = HashingWriter {
            inner: temporary.as_file_mut(),
            hasher: Sha256::new(),
        };
        writer
            .write_all(bytes)
            .with_context(|| format!("Writing evidence bundle file '{}'", path.display()))?;
        writer
            .flush()
            .with_context(|| format!("Flushing evidence bundle file '{}'", path.display()))?;
        hex::encode(writer.hasher.finalize())
    };
    persist_bundle_tempfile(temporary, &path)?;
    Ok(digest)
}

fn write_hashed_json<T: Serialize>(dir: &Path, relative_name: &str, value: &T) -> Result<String> {
    let (path, mut temporary) = private_bundle_tempfile(dir, relative_name)?;
    let digest = {
        let mut writer = HashingWriter {
            inner: temporary.as_file_mut(),
            hasher: Sha256::new(),
        };
        serde_json::to_writer_pretty(&mut writer, value)
            .with_context(|| format!("Writing evidence bundle file '{}'", path.display()))?;
        writer
            .flush()
            .with_context(|| format!("Flushing evidence bundle file '{}'", path.display()))?;
        hex::encode(writer.hasher.finalize())
    };
    persist_bundle_tempfile(temporary, &path)?;
    Ok(digest)
}

fn private_bundle_tempfile(
    dir: &Path,
    relative_name: &str,
) -> Result<(PathBuf, tempfile::NamedTempFile)> {
    let relative = crate::safeio::validated_relative_path(relative_name, false)?;
    let path = dir.join(relative);
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("evidence bundle member has no parent"))?;
    crate::paths::ensure_private_dir(parent)?;
    let temporary = tempfile::Builder::new()
        .prefix(".bundle-member-")
        .tempfile_in(parent)
        .with_context(|| format!("Reserving evidence bundle file '{}'", path.display()))?;
    Ok((path, temporary))
}

fn persist_bundle_tempfile(temporary: tempfile::NamedTempFile, path: &Path) -> Result<()> {
    temporary
        .as_file()
        .sync_all()
        .with_context(|| format!("Syncing evidence bundle file '{}'", path.display()))?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| error.error)
        .with_context(|| format!("Publishing evidence bundle file '{}'", path.display()))?;
    Ok(())
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

#[derive(serde::Serialize)]
struct BundleManifest<'a, S: Serialize> {
    schema_version: &'static str,
    layerfault_version: &'static str,
    build_id: &'static str,
    subject: &'a BundleSubject,
    coverage: Option<&'a Coverage>,
    decision: &'a str,
    finding_count: usize,
    findings: S,
    correlations: &'a [FindingCorrelation],
}

fn bundle_manifest<'a>(input: &'a BundleInput<'a>) -> BundleManifest<'a, impl Serialize + 'a> {
    let reportable = input
        .findings
        .iter()
        .filter(|finding| finding.status != ScanStatus::Pass)
        .count();
    BundleManifest {
        schema_version: BUNDLE_SCHEMA_VERSION,
        layerfault_version: env!("CARGO_PKG_VERSION"),
        build_id: env!("LAYERFAULT_BUILD_ID"),
        subject: &input.subject,
        coverage: input.coverage,
        decision: input.decision,
        finding_count: reportable,
        findings: stream_seq(input.findings, crate::report::enriched_finding_ref),
        correlations: input.correlations,
    }
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

        // No stray temp/partial sibling should be left behind after a
        // successful publish.
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .expect("read tempdir")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name())
            .filter(|name| name != "bundle")
            .collect();
        assert!(leftovers.is_empty(), "unexpected leftovers: {leftovers:?}");
    }

    #[test]
    fn atomic_write_leaves_final_directory_untouched_on_failure() {
        let dir = tempfile::tempdir().expect("tempdir");
        let parent = dir.path().join("parent");
        fs::create_dir_all(&parent).expect("mkdir parent");
        let root = parent.join("bundle");
        let findings = sample();
        let input = BundleInput {
            subject: BundleSubject::default(),
            decision: "WARN",
            findings: &findings,
            correlations: &[],
            coverage: None,
        };

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Make the parent read-only so creating the temp bundle
            // directory inside it fails before anything is published.
            fs::set_permissions(&parent, fs::Permissions::from_mode(0o500))
                .expect("restrict parent");
            let result = write(&root, &input);
            fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))
                .expect("restore parent permissions");
            assert!(result.is_err(), "write should fail on a read-only parent");
        }

        assert!(
            !root.exists(),
            "final bundle directory must not appear on failure"
        );
        let leftovers: Vec<_> = fs::read_dir(&parent)
            .expect("read parent")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name())
            .collect();
        assert!(
            leftovers.is_empty(),
            "no partial bundle artifacts should remain: {leftovers:?}"
        );
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
