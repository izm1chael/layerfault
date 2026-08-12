//! Structured, bounded, hostile-input-safe evidence for Layerfault findings.
//!
//! Every security-relevant finding should be able to answer six questions:
//! *what* was found, *where*, *what exact evidence* caused the detector to fire,
//! *why* that matters, *how certain* Layerfault is, and *what it cannot
//! conclude*. This module owns the first three plus the safety rules that keep
//! evidence collection from becoming its own attack surface.
//!
//! Security boundaries preserved here:
//!
//! * Evidence never causes model code to run, a pickle to be deserialized, or an
//!   unsafe symlink to be followed. Detectors surface facts they already hold.
//! * Every excerpt is bounded, control-character escaped, and secret-redacted
//!   before it can reach stdout, JSON, SARIF or an evidence bundle.
//! * Ordering is deterministic so identical artifacts produce identical
//!   evidence, finding identities and signed payloads.

use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Instant;

/// Maximum number of text lines retained in a single excerpt.
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn ansi_and_control_sequences_are_escaped() {
        let sanitized = sanitize_excerpt("before\u{1b}[31mred\u{1b}[0m\u{7}after\0end");
        assert!(!sanitized.text.contains('\u{1b}'));
        assert!(!sanitized.text.contains('\u{7}'));
        assert!(!sanitized.text.contains('\0'));
        assert!(sanitized.text.contains("\\x1b[31m"));
        assert!(sanitized.text.contains("\\0"));
    }

    #[test]
    fn invisible_and_bidi_characters_are_escaped() {
        let sanitized = sanitize_excerpt("safe\u{202e}reversed\u{200b}zero");
        assert!(sanitized.text.contains("\\u{202e}"));
        assert!(sanitized.text.contains("\\u{200b}"));
    }

    #[test]
    fn invalid_utf8_does_not_panic() {
        let raw = [
            0xff_u8, 0xfe, b'a', b'b', 0x00, 0x1b, b'[', b'3', b'1', b'm',
        ];
        let decoded = String::from_utf8_lossy(&raw);
        let sanitized = sanitize_excerpt(&decoded);
        assert!(!sanitized.text.is_empty());
    }

    #[test]
    fn enormous_line_is_bounded() {
        let hostile = "A".repeat(64 * 1024 * 1024);
        let sanitized = sanitize_excerpt(&hostile);
        assert!(sanitized.truncated);
        assert!(sanitized.text.len() <= MAX_EXCERPT_BYTES);
    }

    #[test]
    fn excerpt_is_bounded_by_lines() {
        let content = (0..100)
            .map(|index| format!("line {index}"))
            .collect::<Vec<_>>()
            .join("\n");
        let sanitized = sanitize_excerpt(&content);
        assert!(sanitized.truncated);
        assert!(sanitized.text.lines().count() <= MAX_EXCERPT_LINES);
    }

    #[test]
    fn credentials_are_redacted_with_stable_fingerprints() {
        let cases = [
            "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345",
            "token = hf_abcdefghijklmnopqrstuvwxyz0123456789",
            "key = ghp_abcdefghijklmnopqrstuvwxyz0123456789",
            "openai = sk-abcdefghijklmnopqrstuvwxyz0123",
            "aws = AKIAIOSFODNN7EXAMPLE",
            "password = \"hunter2000\"",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----",
        ];
        for case in cases {
            let (redacted, count) = redact_secrets(case);
            assert!(count >= 1, "expected redaction for {case}");
            assert!(
                redacted.contains("<redacted sha256:"),
                "missing placeholder for {case}"
            );
        }
        let first = redact_secrets("token = hf_abcdefghijklmnopqrstuvwxyz0123456789").0;
        let second = redact_secrets("token = hf_abcdefghijklmnopqrstuvwxyz0123456789").0;
        assert_eq!(first, second, "redaction fingerprints must be stable");
    }

    #[test]
    fn non_secret_content_is_not_redacted() {
        let (redacted, count) = redact_secrets("subprocess.run([\"/bin/sh\", \"-c\", \"id\"])");
        assert_eq!(count, 0);
        assert!(!redacted.contains("<redacted"));
    }

    #[test]
    fn finding_ids_are_deterministic_and_time_independent() {
        let subject = EvidenceSubject::member("modeling_custom.py")
            .with_sha256(Some("sha256:aaaa".to_owned()));
        let build = |duration: u64| {
            FindingBuilder::new(
                "LF-CODE-SUBPROCESS",
                CheckType::PackageSecurity,
                ScanStatus::Warn,
            )
            .subject(subject.clone())
            .evidence(source_excerpt(
                subject.clone(),
                71,
                75,
                "subprocess.run(",
                "subprocess.run(cmd)",
            ))
            .duration_ms(duration)
            .finish()
        };
        let first = build(4);
        let second = build(9999);
        assert_eq!(first.finding_id, second.finding_id);
        assert!(first
            .finding_id
            .as_deref()
            .expect("finding id")
            .starts_with("lffinding:sha256:"));
    }

    #[test]
    fn finding_ids_differ_by_location() {
        let subject = EvidenceSubject::member("modeling_custom.py");
        let build = |line: u64| {
            FindingBuilder::new(
                "LF-CODE-SUBPROCESS",
                CheckType::PackageSecurity,
                ScanStatus::Warn,
            )
            .subject(subject.clone())
            .evidence(source_excerpt(
                subject.clone(),
                line,
                line,
                "subprocess.run(",
                "x",
            ))
            .finish()
        };
        assert_ne!(build(10).finding_id, build(11).finding_id);
    }

    #[test]
    fn missing_evidence_is_explicitly_unavailable() {
        let finding = FindingBuilder::new("LF-TEST", CheckType::ScanError, ScanStatus::Fail)
            .evidence_unavailable("parser could not determine a safe byte location")
            .finish();
        assert_eq!(finding.evidence_state, Some(EvidenceState::Unavailable));
        assert_eq!(
            finding.evidence_reason.as_deref(),
            Some("parser could not determine a safe byte location")
        );
    }

    #[test]
    fn legacy_matches_prefix_is_preserved() {
        let finding =
            FindingBuilder::new("LF-CODE-EVAL", CheckType::PackageSecurity, ScanStatus::Warn)
                .match_note("custom code contains eval")
                .finish();
        assert_eq!(
            finding.matches.first().map(String::as_str),
            Some("[LF-CODE-EVAL] custom code contains eval")
        );
        assert_eq!(crate::policy::rule_id(&finding), "LF-CODE-EVAL");
    }

    #[test]
    fn evidence_records_are_bounded_per_finding() {
        let subject = EvidenceSubject::member("big.py");
        let mut builder =
            FindingBuilder::new("LF-CODE-EVAL", CheckType::PackageSecurity, ScanStatus::Warn)
                .subject(subject.clone());
        for line in 0..(MAX_EVIDENCE_PER_FINDING as u64 * 4) {
            builder = builder.evidence(source_excerpt(
                subject.clone(),
                line,
                line,
                "eval(",
                "eval(payload)",
            ));
        }
        let finding = builder.finish();
        assert!(finding.evidence.len() <= MAX_EVIDENCE_PER_FINDING);
        assert_eq!(finding.evidence_state, Some(EvidenceState::Partial));
    }

    #[test]
    fn evidence_order_is_deterministic() {
        let subject = EvidenceSubject::member("a.py");
        let order = |lines: &[u64]| {
            let mut builder =
                FindingBuilder::new("LF-CODE-EVAL", CheckType::PackageSecurity, ScanStatus::Warn)
                    .subject(subject.clone());
            for line in lines {
                builder = builder.evidence(source_excerpt(
                    subject.clone(),
                    *line,
                    *line,
                    "eval(",
                    "eval(x)",
                ));
            }
            builder
                .finish()
                .evidence
                .iter()
                .filter_map(|record| record.location.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(order(&[5, 1, 3]), order(&[3, 5, 1]));
    }

    #[test]
    fn structured_payload_strings_are_sanitized() {
        let evidence = structural_invariant(
            EvidenceSubject::member("m.gguf"),
            "tensor range exceeds data section",
            serde_json::json!({ "tensor": "blk.\u{1b}[31m17", "declared_offset": 10 }),
        );
        let rendered = serde_json::to_string(&evidence).expect("serialize");
        assert!(!rendered.contains('\u{1b}'));
    }

    #[test]
    fn budget_reports_exhaustion() {
        let mut budget = EvidenceBudget::new(100);
        assert!(budget.claim(60));
        assert!(!budget.claim(80));
        assert!(budget.exhausted());
    }
}

mod builder;
mod constructors;
mod correlation;
mod identity;
mod limits;
mod sanitize;
mod types;

pub use builder::{EvidenceBudget, FindingBuilder};
pub use constructors::*;
pub use correlation::{correlate, sort_correlations, FindingCorrelation};
pub use identity::{compute_finding_id, ensure_finding_identity};
pub use limits::*;
pub use sanitize::{
    is_invisible_or_bidi, redact_secrets, sanitize_excerpt, sanitize_excerpt_bounded,
    sanitize_text, secret_placeholder, SanitizedExcerpt,
};
pub use types::{EvidenceKind, EvidenceLocation, EvidenceState, EvidenceSubject, FindingEvidence};
