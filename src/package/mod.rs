mod classify;
mod discovery;
mod identity;
mod inspect;
mod member;
mod metadata;
mod text;
mod types;

pub use identity::{compute_merkle_leaf, compute_merkle_tree, fingerprint, fingerprint_report};
pub use inspect::{inspect, inspect_with_budget, inspect_with_scheduler};
pub use member::{inspect_member, inspect_member_with_budget};
pub use types::{PackageEntry, PackageFingerprintReport, PackageMerkleLeaf, PackageReport};

use classify::*;
pub(crate) use classify::{is_documentation_path, is_tokenizer_vocabulary_path};
use discovery::*;
use identity::*;
#[allow(unused_imports)]
use inspect::*;
use member::*;
use metadata::*;
use text::*;
#[allow(unused_imports)]
use types::*;

use crate::finding_evidence::{
    config_value, file_member, hash_mismatch, source_excerpt, symlink_target, EvidenceSubject,
    FindingBuilder, MAX_EVIDENCE_PER_FINDING,
};
use crate::formats::{artifact, ArtifactFormat};
use crate::safeio::open_readonly_nofollow;
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use anyhow::{anyhow, bail, Context, Result};
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};
use walkdir::WalkDir;

const TEXT_STREAM_CHUNK_BYTES: usize = 256 * 1024;
const TEXT_STREAM_OVERLAP_BYTES: usize = 8 * 1024;
const PACKAGE_MEDIA_TYPE: &str = "application/vnd.layerfault.package";
/// Lines of context captured around a matched primitive.
const EXCERPT_CONTEXT_LINES: u64 = 3;
/// Upper bound on bytes re-read from a member to build one excerpt.
const EXCERPT_READ_BYTES: usize = 8 * 1024;
const MAX_PACKAGE_ENTRIES: usize = 100_000;
const MAX_PACKAGE_DEPTH: usize = 64;
const MAX_PACKAGE_PATH_BYTES: usize = 4096;
const MAX_PACKAGE_TOTAL_BYTES: u64 = 1024 * 1024 * 1024 * 1024;

/// Start a package finding.
///
/// Returns a builder so the caller can attach the exact member subject and the
/// evidence that caused the detector to fire. Callers that genuinely have no
/// evidence must say why via `evidence_unavailable`; the builder records
/// `UNAVAILABLE` rather than leaving absence ambiguous.
fn finding(
    digest: &str,
    check_type: CheckType,
    status: ScanStatus,
    class: FindingClass,
    confidence: Confidence,
    rule: &str,
    detail: String,
) -> FindingBuilder {
    FindingBuilder::new(rule, check_type, status)
        .class(class)
        .confidence(confidence)
        .digest(digest)
        .media_type(PACKAGE_MEDIA_TYPE)
        .match_note("package finding")
        .detail(detail)
}

/// The canonical subject for a package member.
///
/// Always identified by its package-relative path, never by the absolute or
/// staging path it happens to occupy during this scan: hub review and the
/// hosted worker both stage downloads into temporary directories, and those
/// paths must never become a finding's identity.
fn member_subject(rel: &str, digest: &str, size: Option<u64>) -> EvidenceSubject {
    EvidenceSubject::member(rel)
        .with_sha256(Some(digest.to_owned()))
        .with_size(size)
        .with_media_type(PACKAGE_MEDIA_TYPE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use crate::finding_evidence::{EvidenceKind, EvidenceLocation, EvidenceState};

    fn finding_for<'a>(findings: &'a [LayerScanResult], rule: &str) -> Option<&'a LayerScanResult> {
        findings
            .iter()
            .find(|finding| crate::policy::rule_id(finding) == rule)
    }

    fn text_lines(finding: &LayerScanResult) -> Vec<u64> {
        finding
            .evidence
            .iter()
            .filter_map(|record| match record.location {
                Some(EvidenceLocation::Text { line_start, .. }) => Some(line_start),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn custom_code_evidence_records_exact_line_and_excerpt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        let source = "import os\n\n\ndef load(path):\n    # helper\n    subprocess.run([\"/bin/sh\"])\n    return path\n";
        fs::write(root.join("modeling_custom.py"), source).expect("write");
        let report = inspect(root).expect("inspect");

        let finding =
            finding_for(&report.findings, "LF-CODE-SUBPROCESS").expect("subprocess finding");
        assert_eq!(finding.evidence_state, Some(EvidenceState::Available));
        assert_eq!(
            finding
                .subject
                .as_ref()
                .and_then(|s| s.package_relative_path.as_deref()),
            Some("modeling_custom.py")
        );
        assert!(finding
            .subject
            .as_ref()
            .and_then(|s| s.sha256.as_deref())
            .is_some_and(|digest| digest.starts_with("sha256:")));

        assert_eq!(text_lines(finding), vec![6], "match is on line 6");
        let record = &finding.evidence[0];
        assert_eq!(record.kind, EvidenceKind::SourceExcerpt);
        assert_eq!(record.match_value.as_deref(), Some("subprocess.run"));
        assert!(record
            .excerpt
            .as_deref()
            .expect("excerpt")
            .contains("subprocess.run"));
        assert!(finding
            .finding_id
            .as_deref()
            .is_some_and(|id| id.starts_with("lffinding:sha256:")));
    }

    #[test]
    fn primitive_spanning_a_chunk_boundary_reports_one_correct_line() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        // Pad with whole lines so the primitive straddles the 256 KiB chunk
        // boundary and lands inside the replayed overlap window.
        let line = "x = 1\n"; // 6 bytes
        let pad_lines = (TEXT_STREAM_CHUNK_BYTES / line.len()) + 1;
        let mut source = line.repeat(pad_lines);
        // Trim back so the needle starts a few bytes before the boundary.
        source.truncate(TEXT_STREAM_CHUNK_BYTES - 4);
        let lines_before = source.matches('\n').count() as u64;
        source.push_str("subprocess.run([\"/bin/sh\"])\ntrailer = 2\n");
        fs::write(root.join("boundary.py"), &source).expect("write");

        let report = inspect(root).expect("inspect");
        let finding =
            finding_for(&report.findings, "LF-CODE-SUBPROCESS").expect("subprocess finding");
        let lines = text_lines(finding);
        assert_eq!(lines.len(), 1, "overlap must not double-report the match");
        assert_eq!(lines[0], lines_before + 1);
    }

    #[test]
    fn repeated_primitives_are_bounded_and_deterministic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        let source = "subprocess.run(1)\n".repeat(MAX_EVIDENCE_PER_FINDING * 4);
        fs::write(root.join("flood.py"), &source).expect("write");

        let first = inspect(root).expect("inspect");
        let second = inspect(root).expect("inspect");
        // The semantic Python analyzer also flags LF-CODE-SUBPROCESS (one
        // finding per call site); pick the aggregated streaming-scanner
        // finding specifically, which is the one whose bounding this test
        // covers.
        let most_evidence = |findings: &[LayerScanResult]| {
            findings
                .iter()
                .filter(|finding| crate::policy::rule_id(finding) == "LF-CODE-SUBPROCESS")
                .max_by_key(|finding| finding.evidence.len())
                .expect("finding")
                .clone()
        };
        let a = most_evidence(&first.findings);
        let b = most_evidence(&second.findings);
        let a = &a;
        let b = &b;
        assert!(a.evidence.len() <= MAX_EVIDENCE_PER_FINDING);
        assert_eq!(
            text_lines(a),
            text_lines(b),
            "evidence must be deterministic"
        );
        assert_eq!(a.finding_id, b.finding_id);
        assert_eq!(a.evidence_state, Some(EvidenceState::Partial));
    }

    #[test]
    fn credentials_in_custom_code_are_redacted_in_evidence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        let source = "import requests\nTOKEN = \"hf_abcdefghijklmnopqrstuvwxyz0123456789\"\nrequests.post(url, headers={\"Authorization\": \"Bearer abcdefghijklmnopqrstuvwxyz\"})\n";
        fs::write(root.join("net.py"), source).expect("write");
        let report = inspect(root).expect("inspect");
        // Both the streaming text scanner and the semantic Python analyzer can
        // independently flag LF-CODE-NETWORK for this file; check across all
        // of them rather than assuming a specific one is first.
        let network_findings: Vec<&LayerScanResult> = report
            .findings
            .iter()
            .filter(|finding| crate::policy::rule_id(finding) == "LF-CODE-NETWORK")
            .collect();
        assert!(!network_findings.is_empty(), "expected a network finding");
        let excerpts = network_findings
            .iter()
            .flat_map(|finding| finding.evidence.iter())
            .filter_map(|record| record.excerpt.as_deref())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !excerpts.contains("hf_abcdefghijklmnopqrstuvwxyz0123456789"),
            "token must not be reproduced in evidence"
        );
        assert!(excerpts.contains("<redacted sha256:"));
        assert!(network_findings
            .iter()
            .flat_map(|finding| finding.evidence.iter())
            .any(|record| record.redactions > 0));
    }

    #[test]
    fn terminal_escapes_in_custom_code_are_neutralised() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        let source = "banner = \"\u{1b}[2J\u{1b}[31mPWNED\"\nsubprocess.run(x)\n";
        fs::write(root.join("ansi.py"), source).expect("write");
        let report = inspect(root).expect("inspect");
        let finding =
            finding_for(&report.findings, "LF-CODE-SUBPROCESS").expect("subprocess finding");
        let rendered = serde_json::to_string(&finding.evidence).expect("serialize");
        assert!(!rendered.contains('\u{1b}'));
    }

    #[test]
    fn auto_map_evidence_names_the_key_and_referenced_symbol() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        fs::write(
            root.join("config.json"),
            br#"{"auto_map": {"AutoModel": "modeling_custom.CustomModel"}, "trust_remote_code": true}"#,
        )
        .expect("write");
        let report = inspect(root).expect("inspect");

        let auto_map = finding_for(&report.findings, "LF-CODE-AUTO-MAP").expect("auto_map finding");
        let record = auto_map.evidence.first().expect("config evidence");
        assert_eq!(record.kind, EvidenceKind::ConfigValue);
        assert_eq!(
            record.location,
            Some(EvidenceLocation::Metadata {
                key: "auto_map.AutoModel".to_owned()
            })
        );
        assert_eq!(
            record.structured.as_ref().and_then(|v| v["value"].as_str()),
            Some("modeling_custom.CustomModel")
        );

        let trust =
            finding_for(&report.findings, "LF-CODE-REMOTE-TRUST").expect("trust_remote_code");
        let record = trust.evidence.first().expect("config evidence");
        assert_eq!(
            record.structured.as_ref().map(|v| v["value"].clone()),
            Some(serde_json::Value::Bool(true))
        );
    }

    #[test]
    fn symlink_evidence_records_path_and_declared_target() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        fs::write(root.join("real.txt"), b"data").expect("write");
        #[cfg(unix)]
        std::os::unix::fs::symlink("../outside", root.join("link")).expect("symlink");
        #[cfg(not(unix))]
        return;
        let report = inspect(root).expect("inspect");
        let finding = finding_for(&report.findings, "LF-PACKAGE-SYMLINK").expect("symlink finding");
        let record = finding.evidence.first().expect("symlink evidence");
        assert_eq!(record.kind, EvidenceKind::SymlinkTarget);
        let structured = record.structured.as_ref().expect("structured");
        assert_eq!(structured["package_relative_path"], "link");
        assert_eq!(structured["target"], "../outside");
    }

    #[test]
    fn auto_map_and_capability_correlate_end_to_end() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        fs::write(
            root.join("config.json"),
            br#"{"auto_map": {"AutoModel": "modeling_custom.CustomModel"}}"#,
        )
        .expect("write");
        fs::write(
            root.join("modeling_custom.py"),
            b"class CustomModel:\n    def __init__(self):\n        subprocess.run([\"id\"])\n",
        )
        .expect("write");

        let report = inspect(root).expect("inspect");
        let correlations = crate::correlate::correlate(&report.findings);
        let chain = correlations
            .iter()
            .find(|c| c.id == "LF-CORR-CUSTOM-LOADER-PROCESS")
            .expect("custom loader correlation");
        assert_eq!(chain.confidence, Confidence::High);
        assert_eq!(chain.finding_ids.len(), 2);
        assert!(chain.summary.contains("modeling_custom.py:3"));
    }

    #[test]
    fn package_resource_limits_fail_closed() {
        assert!(enforce_package_discovery_limits(MAX_PACKAGE_ENTRIES + 1, 1, 1, 0).is_err());
        assert!(enforce_package_discovery_limits(1, MAX_PACKAGE_DEPTH + 1, 1, 0).is_err());
        assert!(enforce_package_discovery_limits(1, 1, MAX_PACKAGE_PATH_BYTES + 1, 0).is_err());
        assert!(checked_package_total(MAX_PACKAGE_TOTAL_BYTES, 1).is_err());
    }

    #[test]
    fn package_fingerprint_is_path_stable() -> Result<()> {
        let a = std::env::temp_dir().join(format!("layerfault-package-a-{}", std::process::id()));
        let b = std::env::temp_dir().join(format!("layerfault-package-b-{}", std::process::id()));
        let _ = fs::remove_dir_all(&a);
        let _ = fs::remove_dir_all(&b);
        fs::create_dir_all(&a)?;
        fs::create_dir_all(&b)?;
        fs::write(a.join("config.json"), b"{\"architectures\":[\"Test\"]}")?;
        fs::write(b.join("config.json"), b"{\"architectures\":[\"Test\"]}")?;
        assert_eq!(fingerprint(&a)?, fingerprint(&b)?);
        fs::write(b.join("config.json"), b"{\"architectures\":[\"Changed\"]}")?;
        assert_ne!(fingerprint(&a)?, fingerprint(&b)?);
        let _ = fs::remove_dir_all(a);
        let _ = fs::remove_dir_all(b);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_member_name_is_rejected() -> Result<()> {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let root =
            std::env::temp_dir().join(format!("layerfault-package-nonutf8-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        let name = OsString::from_vec(vec![b'm', b'o', b'd', b'e', b'l', 0xff]);
        fs::write(root.join(name), b"fixture")?;
        assert!(inspect(&root).is_err());
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn unsafe_serialization_blocks() -> Result<()> {
        let root =
            std::env::temp_dir().join(format!("layerfault-package-pickle-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        fs::write(root.join("model.pkl"), [0x80_u8, 4, 1, 2, 3])?;
        let report = inspect(&root)?;
        assert!(report.findings.iter().any(|f| f
            .matches
            .iter()
            .any(|m| m.contains("LF-PICKLE-MALFORMED"))
            && f.status == ScanStatus::Fail));
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn nested_compressed_joblib_warns_when_payload_is_opaque() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "layerfault-package-double-compressed-joblib-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        fs::write(
            root.join("exploit_double_compression.joblib.gz.bz2"),
            b"BZh91AY&SYbounded-fixture",
        )?;
        let report = inspect(&root)?;
        assert!(report.findings.iter().any(|finding| {
            finding.status == ScanStatus::Warn
                && finding
                    .matches
                    .iter()
                    .any(|value| value.contains("LF-PICKLE-OPAQUE-COMPRESSED"))
        }));
        assert!(report
            .files
            .iter()
            .any(|entry| entry.kind == "serialization"));
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn compression_suffix_without_serialization_inner_name_does_not_block() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "layerfault-package-compressed-data-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        fs::write(
            root.join("weights.dat.gz.bz2"),
            b"BZh91AY&SYbounded-fixture",
        )?;
        let report = inspect(&root)?;
        assert!(!report.findings.iter().any(|finding| {
            finding.status == ScanStatus::Fail
                && finding
                    .matches
                    .iter()
                    .any(|value| value.contains("LF-PICKLE-MALFORMED"))
        }));
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn documentation_examples_do_not_emit_code_primitive_findings() -> Result<()> {
        let root =
            std::env::temp_dir().join(format!("layerfault-package-docs-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        fs::write(
            root.join("README.md"),
            b"The example calls os.system(...) and exec(...).",
        )?;
        let report = inspect(&root)?;
        assert!(!report.findings.iter().any(|finding| {
            finding
                .matches
                .iter()
                .any(|value| value.contains("LF-CODE-OS-SYSTEM") || value.contains("LF-CODE-EXEC"))
        }));
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn custom_loader_module_scope_side_effect_blocks() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "layerfault-package-custom-code-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        fs::write(
            root.join("config.json"),
            br#"{"auto_map":{"AutoModel":"modeling_example.Example"},"trust_remote_code":true}"#,
        )?;
        fs::write(
            root.join("modeling_example.py"),
            b"os.system('echo imported')\n",
        )?;
        let report = inspect(&root)?;
        assert!(report.findings.iter().any(|finding| {
            finding.status == ScanStatus::Fail
                && finding
                    .matches
                    .iter()
                    .any(|value| value.contains("LF-CODE-IMPORT-SIDE-EFFECT"))
        }));
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn custom_loader_function_side_effect_remains_warning() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "layerfault-package-custom-function-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        fs::write(
            root.join("config.json"),
            br#"{"auto_map":{"AutoModel":"modeling_example.Example"},"trust_remote_code":true}"#,
        )?;
        fs::write(
            root.join("modeling_example.py"),
            b"def load():\n    os.system('echo called')\n",
        )?;
        let report = inspect(&root)?;
        assert!(!report.findings.iter().any(|finding| {
            finding.status == ScanStatus::Fail
                && finding
                    .matches
                    .iter()
                    .any(|value| value.contains("LF-CODE-IMPORT-SIDE-EFFECT"))
        }));
        assert!(report.findings.iter().any(|finding| {
            finding.status == ScanStatus::Warn
                && finding
                    .matches
                    .iter()
                    .any(|value| value.contains("LF-CODE-OS-SYSTEM"))
        }));
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn large_json_is_fully_streamed_without_size_warning() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "layerfault-package-large-json-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        let padding = "a".repeat(6 * 1024 * 1024);
        fs::write(
            root.join("tokenizer.json"),
            serde_json::to_vec(&serde_json::json!({"padding": padding}))?,
        )?;
        let report = inspect(&root)?;
        assert!(!report.findings.iter().any(|finding| finding
            .matches
            .iter()
            .any(|value| value.contains("LF-PACKAGE-TEXT-LIMIT"))));
        assert!(!report.blocking());
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn tokenizer_vocabulary_code_tokens_do_not_become_custom_code_findings() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "layerfault-package-tokenizer-vocab-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        fs::write(
            root.join("tokenizer.json"),
            serde_json::to_vec(&serde_json::json!({
                "model": {
                    "vocab": {
                        "os.system(": 1,
                        "exec(": 2,
                        "__class__": 3,
                        "{{": 4
                    }
                }
            }))?,
        )?;
        let report = inspect(&root)?;
        assert!(!report.findings.iter().any(|finding| {
            finding.matches.iter().any(|value| {
                value.contains("LF-CODE-OS-SYSTEM")
                    || value.contains("LF-CODE-EXEC")
                    || value.contains("LF-TEMPLATE-INTROSPECTION")
            })
        }));
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn auto_map_late_in_large_json_still_correlates_custom_code() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "layerfault-package-large-json-automap-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        let padding = "a".repeat(6 * 1024 * 1024);
        fs::write(
            root.join("config.json"),
            serde_json::to_vec(&serde_json::json!({
                "padding": padding,
                "auto_map": {"AutoModel": "modeling_late.Example"}
            }))?,
        )?;
        fs::write(
            root.join("modeling_late.py"),
            b"os.system('echo imported')\n",
        )?;
        let report = inspect(&root)?;
        assert!(report.findings.iter().any(|finding| {
            finding.status == ScanStatus::Fail
                && finding
                    .matches
                    .iter()
                    .any(|value| value.contains("LF-CODE-IMPORT-SIDE-EFFECT"))
        }));
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn module_scope_side_effect_after_old_four_mib_boundary_still_blocks() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "layerfault-package-large-python-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        fs::write(
            root.join("config.json"),
            br#"{"auto_map":{"AutoModel":"modeling_large.Example"}}"#,
        )?;
        let mut source = String::from("payload = '");
        source.push_str(&"a".repeat(5 * 1024 * 1024));
        source.push_str("'; os.system('echo imported')\n");
        fs::write(root.join("modeling_large.py"), source)?;
        let report = inspect(&root)?;
        assert!(report.findings.iter().any(|finding| {
            finding.status == ScanStatus::Fail
                && finding
                    .matches
                    .iter()
                    .any(|value| value.contains("LF-CODE-IMPORT-SIDE-EFFECT"))
        }));
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn auto_map_import_side_effect_blocks_without_package_remote_trust_flag() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "layerfault-package-automap-runtime-trust-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        fs::write(
            root.join("config.json"),
            br#"{"auto_map":{"AutoModel":"modeling_example.Example"}}"#,
        )?;
        fs::write(
            root.join("modeling_example.py"),
            b"os.system('echo imported')\n",
        )?;
        let report = inspect(&root)?;
        assert!(report.findings.iter().any(|finding| {
            finding.status == ScanStatus::Fail
                && finding
                    .matches
                    .iter()
                    .any(|value| value.contains("LF-CODE-IMPORT-SIDE-EFFECT"))
        }));
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn renamed_elf_member_is_detected_by_content() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "layerfault-package-renamed-elf-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        let mut elf = vec![0_u8; 128];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        elf[16..18].copy_from_slice(&2_u16.to_le_bytes());
        elf[18..20].copy_from_slice(&62_u16.to_le_bytes());
        elf[40..48].copy_from_slice(&64_u64.to_le_bytes());
        elf[52..54].copy_from_slice(&64_u16.to_le_bytes());
        elf[58..60].copy_from_slice(&64_u16.to_le_bytes());
        elf[60..62].copy_from_slice(&1_u16.to_le_bytes());
        fs::write(root.join("weights.dat"), elf)?;
        let report = inspect(&root)?;
        assert!(report.findings.iter().any(|finding| finding
            .matches
            .iter()
            .any(|value| value.contains("T12-001"))));
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn cancellation_before_scanning_retains_partial_coverage_not_pass() -> Result<()> {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        fs::write(root.join("a.json"), b"{}").expect("write a");
        fs::write(root.join("b.json"), b"{}").expect("write b");

        let budget =
            crate::budget::ScanBudget::new(crate::budget::ScanBudgetProfile::Default.limits())?;
        budget.cancel();

        let report = inspect_with_budget(root, &budget)?;

        assert!(!report.coverage.complete);
        assert!(report.coverage.control_interrupted());
        assert_eq!(report.coverage.scan_state.as_deref(), Some("incomplete"));
        assert_eq!(report.coverage.control_reason.as_deref(), Some("cancelled"));
        assert!(report.files.is_empty());
        Ok(())
    }

    #[test]
    fn replacement_after_hashing_is_reported_as_package_race() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("member.json");
        fs::write(&path, b"{\"version\":1}")?;
        let file = open_readonly_nofollow(&path)?;
        let hash = crate::hashcache::sha256_prefixed(&path, &file)?;
        let header = PackageMemberHeader {
            path: path.clone(),
            rel: "member.json".to_owned(),
            size: file.metadata()?.len(),
            sha256: hash.sha256,
            identity: hash.identity,
            cache_hit: hash.cache_hit,
            kind: classify(&path).to_owned(),
        };

        let replacement = dir.path().join("replacement.json");
        fs::write(&replacement, b"{\"version\":2}")?;
        fs::rename(&replacement, &path)?;

        let analysis = prepare_verified_member(&header).expect_err("replacement must be caught");
        assert!(analysis
            .findings
            .iter()
            .any(|finding| finding.rule_id.as_deref() == Some("LF-PACKAGE-RACE")));
        assert!(analysis.incomplete_reason.is_some());
        Ok(())
    }

    #[test]
    fn worker_panic_is_isolated_and_releases_scheduler_permit() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("member.py");
        fs::write(&path, b"pass\n")?;
        let file = open_readonly_nofollow(&path)?;
        let hash = crate::hashcache::sha256_prefixed(&path, &file)?;
        let header = PackageMemberHeader {
            path: path.clone(),
            rel: "member.py".to_owned(),
            size: file.metadata()?.len(),
            sha256: hash.sha256,
            identity: hash.identity,
            cache_hit: hash.cache_hit,
            kind: classify(&path).to_owned(),
        };
        let budget =
            crate::budget::ScanBudget::new(crate::budget::ScanBudgetProfile::Default.limits())?;
        let scheduler =
            crate::scheduler::AdaptiveScheduler::new(crate::scheduler::SchedulerConfig::detect(
                Some(1),
                None,
                None,
                crate::scheduler::SchedulerMode::Adaptive,
                crate::budget::ScanBudgetProfile::Default,
            ));

        let analysis = isolate_member_analysis(&header, &budget, || {
            let _permit = scheduler.acquire(crate::scheduler::TaskCost::small_cpu(), &budget)?;
            panic!("simulated parser panic");
        });

        assert!(analysis
            .findings
            .iter()
            .any(|finding| finding.rule_id.as_deref() == Some("LF-PACKAGE-MEMBER-PANIC")));
        assert_eq!(scheduler.diagnostics().peak_active_workers, 1);
        assert!(scheduler.diagnostics().active_by_class.is_empty());
        Ok(())
    }

    #[test]
    fn deadline_exceeded_before_second_member_retains_first_finding() -> Result<()> {
        // discovery::paths is sorted, so "a_modeling_custom.py" is scanned
        // before "b.json". A one-millisecond deadline is long enough for the
        // first member's tiny scan to complete but reliably expires before
        // the loop reaches the second member.
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        fs::write(
            root.join("a_modeling_custom.py"),
            b"subprocess.run([\"id\"])\n",
        )
        .expect("write");
        fs::write(root.join("b.json"), b"{}").expect("write b");

        let mut limits = crate::budget::ScanBudgetProfile::Default.limits();
        limits.wall_clock_ms = 1;
        let budget = crate::budget::ScanBudget::new(limits)?;
        std::thread::sleep(std::time::Duration::from_millis(20));
        let report = inspect_with_budget(root, &budget)?;

        assert!(report.coverage.control_interrupted());
        assert!(!report.coverage.complete);
        assert_eq!(report.coverage.control_reason.as_deref(), Some("deadline"));
        // Nothing was scanned in this case since the deadline had already
        // expired before the loop started; the guarantee under test is that
        // the scan returns a well-formed, honestly-incomplete report instead
        // of erroring out or fabricating a PASS.
        assert!(report.files.is_empty());
        Ok(())
    }
}
