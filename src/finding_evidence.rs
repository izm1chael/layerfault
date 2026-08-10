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
pub const MAX_EXCERPT_LINES: usize = 9;
/// Maximum number of bytes retained in a single excerpt.
pub const MAX_EXCERPT_BYTES: usize = 4096;
/// Maximum evidence records attached to one finding.
pub const MAX_EVIDENCE_PER_FINDING: usize = 16;
/// Maximum total evidence payload bytes attached to one finding.
pub const MAX_EVIDENCE_BYTES_PER_FINDING: usize = 32 * 1024;
/// Maximum total evidence payload bytes emitted across one report.
pub const MAX_EVIDENCE_BYTES_PER_REPORT: usize = 4 * 1024 * 1024;
/// Maximum bytes retained for the literal matched value.
pub const MAX_MATCH_VALUE_BYTES: usize = 256;
/// Maximum bytes retained for a structured JSON evidence payload.
pub const MAX_STRUCTURED_BYTES: usize = 8 * 1024;

/// The category of evidence a detector produced.
///
/// A GGUF structural violation, a pickle opcode, an executable embedded at a
/// byte offset, a Jinja introspection expression and an invalid signature are
/// fundamentally different kinds of proof. The model represents each honestly
/// rather than forcing everything into source-line semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum EvidenceKind {
    SourceExcerpt,
    ConfigValue,
    MetadataValue,
    SerializationOpcode,
    BinaryObject,
    ByteRange,
    FileMember,
    PathRelationship,
    SymlinkTarget,
    TensorMetadata,
    StructuralInvariant,
    HashMismatch,
    SignatureEvidence,
    ProvenanceEvidence,
    RuntimeVersion,
    AdvisoryMatch,
    PolicyReason,
    BehaviourObservation,
    NetworkObservation,
    ProcessObservation,
    FilesystemObservation,
    DatasetRecord,
    Correlation,
    CoverageGap,
    Other,
}

/// The exact subject a piece of evidence concerns.
///
/// `package_relative_path` is the canonical identity for package members and
/// must be preferred over `path`: temporary staging directories used by hub
/// review and the hosted worker must never leak into evidence as the subject's
/// identity.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EvidenceSubject {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_relative_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
}

impl EvidenceSubject {
    /// Subject identified by an opaque artifact identity (layer digest, blob
    /// digest, hub revision) rather than a filesystem member.
    pub fn identity(identity: &str, media_type: &str) -> Self {
        Self {
            identity: Some(identity.to_owned()),
            media_type: Some(media_type.to_owned()),
            ..Self::default()
        }
    }

    /// Subject identified by its canonical package-relative member path.
    pub fn member(relative_path: &str) -> Self {
        Self {
            package_relative_path: Some(relative_path.to_owned()),
            ..Self::default()
        }
    }

    #[must_use]
    pub fn with_sha256(mut self, digest: Option<String>) -> Self {
        self.sha256 = digest;
        self
    }

    #[must_use]
    pub fn with_size(mut self, size: Option<u64>) -> Self {
        self.size = size;
        self
    }

    #[must_use]
    pub fn with_media_type(mut self, media_type: &str) -> Self {
        self.media_type = Some(media_type.to_owned());
        self
    }

    #[must_use]
    pub fn with_identity(mut self, identity: &str) -> Self {
        self.identity = Some(identity.to_owned());
        self
    }

    /// Stable name used in deterministic finding identities and human output.
    pub fn canonical_name(&self) -> &str {
        self.package_relative_path
            .as_deref()
            .or(self.path.as_deref())
            .or(self.identity.as_deref())
            .unwrap_or("")
    }
}

/// Where inside the subject the evidence lives.
///
/// Detectors must not fabricate a location they do not actually know; a missing
/// location is honest, an invented one is not.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EvidenceLocation {
    Text {
        line_start: u64,
        line_end: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        column_start: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        column_end: Option<u32>,
    },
    ByteRange {
        offset: u64,
        length: u64,
    },
    Metadata {
        key: String,
    },
    Serialization {
        opcode_index: u64,
        byte_offset: u64,
    },
    Tensor {
        tensor: String,
    },
    Member {
        member: String,
    },
    Record {
        index: u64,
    },
}

/// How complete the evidence for a finding is.
///
/// Absence of evidence must never be ambiguous: every non-PASS finding carries
/// one of these, and `Unavailable` requires an explicit reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceState {
    Available,
    Partial,
    Unavailable,
    NotApplicable,
}

/// A single bounded, sanitised piece of evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingEvidence {
    pub kind: EvidenceKind,
    pub subject: EvidenceSubject,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<EvidenceLocation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub excerpt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    pub description: String,
    #[serde(default)]
    pub truncated: bool,
    #[serde(default)]
    pub redactions: u32,
}

impl FindingEvidence {
    /// Construct a bare evidence record. Prefer the typed helpers below.
    pub fn new(kind: EvidenceKind, subject: EvidenceSubject, description: &str) -> Self {
        Self {
            kind,
            subject,
            location: None,
            match_value: None,
            excerpt: None,
            structured: None,
            sha256: None,
            description: sanitize_text(description),
            truncated: false,
            redactions: 0,
        }
    }

    #[must_use]
    pub fn at(mut self, location: EvidenceLocation) -> Self {
        self.location = Some(location);
        self
    }

    /// Attach the literal matched value, sanitised, redacted and bounded.
    #[must_use]
    pub fn matched(mut self, value: &str) -> Self {
        let sanitized = sanitize_excerpt_bounded(value, 1, MAX_MATCH_VALUE_BYTES);
        self.redactions = self.redactions.saturating_add(sanitized.redactions);
        self.truncated |= sanitized.truncated;
        self.match_value = Some(sanitized.text);
        self
    }

    /// Attach a bounded surrounding excerpt.
    #[must_use]
    pub fn excerpt(mut self, value: &str) -> Self {
        let sanitized = sanitize_excerpt(value);
        self.redactions = self.redactions.saturating_add(sanitized.redactions);
        self.truncated |= sanitized.truncated;
        self.excerpt = Some(sanitized.text);
        self
    }

    /// Attach structured detector facts. Values are bounded; strings inside the
    /// payload are sanitised so hostile metadata cannot inject terminal escapes.
    #[must_use]
    pub fn structured(mut self, value: serde_json::Value) -> Self {
        let sanitized = sanitize_json(value, 0);
        let rendered_len = serde_json::to_string(&sanitized)
            .map(|v| v.len())
            .unwrap_or(0);
        if rendered_len > MAX_STRUCTURED_BYTES {
            self.truncated = true;
            self.structured = Some(serde_json::json!({
                "truncated": true,
                "reason": "structured evidence exceeded the per-record size limit",
            }));
        } else {
            self.structured = Some(sanitized);
        }
        self
    }

    #[must_use]
    pub fn sha256(mut self, digest: Option<String>) -> Self {
        self.sha256 = digest;
        self
    }

    /// Approximate serialized payload size, used to enforce budgets.
    pub fn payload_bytes(&self) -> usize {
        self.match_value.as_ref().map_or(0, String::len)
            + self.excerpt.as_ref().map_or(0, String::len)
            + self.description.len()
            + self
                .structured
                .as_ref()
                .and_then(|value| serde_json::to_string(value).ok())
                .map_or(0, |value| value.len())
    }

    /// Deterministic sort key. Excludes `structured` (not orderable) and
    /// `excerpt` (redaction-dependent) so ordering is stable across releases.
    fn sort_key(&self) -> (String, Option<EvidenceLocation>, EvidenceKind, String) {
        (
            self.subject.canonical_name().to_owned(),
            self.location.clone(),
            self.kind,
            self.match_value.clone().unwrap_or_default(),
        )
    }

    /// Contribution to the deterministic finding identity.
    fn identity_fragment(&self) -> String {
        format!(
            "evidence\u{1f}{:?}\u{1f}{}\u{1f}{}\u{1f}{}",
            self.kind,
            self.subject.canonical_name(),
            self.location
                .as_ref()
                .map(location_identity)
                .unwrap_or_default(),
            self.match_value.as_deref().unwrap_or(""),
        )
    }
}

fn location_identity(location: &EvidenceLocation) -> String {
    match location {
        EvidenceLocation::Text {
            line_start,
            line_end,
            ..
        } => format!("text:{line_start}:{line_end}"),
        EvidenceLocation::ByteRange { offset, length } => format!("bytes:{offset}:{length}"),
        EvidenceLocation::Metadata { key } => format!("meta:{key}"),
        EvidenceLocation::Serialization {
            opcode_index,
            byte_offset,
        } => format!("opcode:{opcode_index}:{byte_offset}"),
        EvidenceLocation::Tensor { tensor } => format!("tensor:{tensor}"),
        EvidenceLocation::Member { member } => format!("member:{member}"),
        EvidenceLocation::Record { index } => format!("record:{index}"),
    }
}

/// A structural relationship between findings that is stronger than their
/// coincidental co-occurrence.
///
/// Correlations describe technical conditions. They deliberately do not assert
/// intent: a resolved custom-loader-to-process-execution chain is a "dangerous
/// loading path requiring investigation", not proof of malice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingCorrelation {
    pub id: String,
    pub finding_ids: Vec<String>,
    pub rule_ids: Vec<String>,
    pub summary: String,
    pub confidence: Confidence,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<FindingEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limitations: Option<String>,
}

impl FindingCorrelation {
    fn sort_key(&self) -> (String, Vec<String>) {
        (self.id.clone(), self.finding_ids.clone())
    }
}

/// Sort correlations into a deterministic order.
pub fn sort_correlations(correlations: &mut [FindingCorrelation]) {
    correlations.sort_by_key(FindingCorrelation::sort_key);
}

/// A per-report evidence budget shared by detectors that can emit many findings.
#[derive(Debug, Clone)]
pub struct EvidenceBudget {
    remaining: usize,
    exhausted: bool,
}

impl Default for EvidenceBudget {
    fn default() -> Self {
        Self {
            remaining: MAX_EVIDENCE_BYTES_PER_REPORT,
            exhausted: false,
        }
    }
}

impl EvidenceBudget {
    pub fn new(limit: usize) -> Self {
        Self {
            remaining: limit,
            exhausted: false,
        }
    }

    /// Claim budget for one evidence record. Returns false when the report-wide
    /// limit is reached; the caller must then record a coverage/limit note
    /// rather than silently dropping the evidence.
    pub fn claim(&mut self, bytes: usize) -> bool {
        if bytes > self.remaining {
            self.exhausted = true;
            return false;
        }
        self.remaining -= bytes;
        true
    }

    pub fn exhausted(&self) -> bool {
        self.exhausted
    }
}

// ---------------------------------------------------------------------------
// Sanitisation and redaction
// ---------------------------------------------------------------------------

/// Result of sanitising untrusted artifact content for display.
#[derive(Debug, Clone)]
pub struct SanitizedExcerpt {
    pub text: String,
    pub redactions: u32,
    pub truncated: bool,
}

lazy_static! {
    /// Credential shapes worth suppressing. This is deliberately a short,
    /// high-signal list rather than a general DLP engine: the goal is to prove
    /// the security condition without reproducing the credential.
    static ref SECRET_PATTERNS: Vec<(Regex, usize)> = vec![
        (
            Regex::new(r"(?i)authorization\s*:\s*(?:bearer|basic|token)\s+([A-Za-z0-9._\-+/=]{8,})")
                .expect("static authorization pattern"),
            1,
        ),
        (
            Regex::new(r"(?s)-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----.*?-----END [A-Z ]{0,40}PRIVATE KEY-----")
                .expect("static private key pattern"),
            0,
        ),
        (
            Regex::new(r"\b(?:hf_|ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9]{16,}\b")
                .expect("static vendor token pattern"),
            0,
        ),
        (
            Regex::new(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b").expect("static github pat pattern"),
            0,
        ),
        (
            Regex::new(r"\bsk-[A-Za-z0-9_\-]{16,}\b").expect("static sk token pattern"),
            0,
        ),
        (
            Regex::new(r"\bglpat-[A-Za-z0-9_\-]{16,}\b").expect("static gitlab pat pattern"),
            0,
        ),
        (
            Regex::new(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b").expect("static slack token pattern"),
            0,
        ),
        (
            Regex::new(r"\bAKIA[0-9A-Z]{16}\b").expect("static aws key id pattern"),
            0,
        ),
        (
            Regex::new(r#"(?i)\baws_secret_access_key\s*[=:]\s*["']?([A-Za-z0-9/+=]{30,})"#)
                .expect("static aws secret pattern"),
            1,
        ),
        (
            Regex::new(r#"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\s*[=:]\s*["']([^"'\r\n]{4,})["']"#)
                .expect("static assignment pattern"),
            1,
        ),
        (
            Regex::new(r"\bLF_CANARY_[A-Za-z0-9_]+\b").expect("static canary pattern"),
            0,
        ),
    ];
}

/// Replace credential-shaped values with a stable SHA-256 fingerprint.
///
/// The fingerprint keeps the value correlatable across findings and revisions
/// without reproducing it. Returns the rewritten text and the redaction count.
pub fn redact_secrets(input: &str) -> (String, u32) {
    let mut spans: Vec<(usize, usize)> = Vec::new();
    for (pattern, group) in SECRET_PATTERNS.iter() {
        for captures in pattern.captures_iter(input) {
            let target = if *group == 0 {
                captures.get(0)
            } else {
                captures.get(*group).or_else(|| captures.get(0))
            };
            if let Some(matched) = target {
                if matched.start() < matched.end() {
                    spans.push((matched.start(), matched.end()));
                }
            }
        }
    }
    if spans.is_empty() {
        return (input.to_owned(), 0);
    }
    spans.sort_unstable();

    let mut rendered = String::with_capacity(input.len());
    let mut cursor = 0usize;
    let mut redactions = 0u32;
    for (start, end) in spans {
        if start < cursor {
            continue;
        }
        rendered.push_str(&input[cursor..start]);
        rendered.push_str(&secret_placeholder(&input[start..end]));
        cursor = end;
        redactions = redactions.saturating_add(1);
    }
    rendered.push_str(&input[cursor..]);
    (rendered, redactions)
}

/// Stable placeholder for a suppressed secret.
pub fn secret_placeholder(value: &str) -> String {
    let fingerprint = hex::encode(Sha256::digest(value.as_bytes()));
    format!("<redacted sha256:{}>", &fingerprint[..16])
}

/// Escape control characters, ANSI/CSI escape sequences, embedded NULs and
/// invisible/bidi characters so untrusted artifact content cannot inject
/// terminal control sequences into human-readable output.
///
/// Characters are escaped rather than deleted: the reviewer still sees that
/// something was there, and JSON consumers get a faithful, safely encoded value.
pub fn sanitize_text(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\n' | '\t' => out.push(ch),
            '\r' => out.push_str("\\r"),
            '\u{0}' => out.push_str("\\0"),
            c if is_invisible_or_bidi(c) => {
                out.push_str(&format!("\\u{{{:04x}}}", c as u32));
            }
            c if (c as u32) < 0x20 || (0x7f..=0x9f).contains(&(c as u32)) => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// True for zero-width, soft-hyphen and bidirectional-override characters used
/// to hide content from human reviewers.
pub fn is_invisible_or_bidi(ch: char) -> bool {
    matches!(
        ch,
        '\u{00ad}'
            | '\u{200b}'
            | '\u{200c}'
            | '\u{200d}'
            | '\u{2060}'
            | '\u{feff}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
    )
}

/// Sanitise, redact and bound untrusted content for use as an excerpt.
pub fn sanitize_excerpt(input: &str) -> SanitizedExcerpt {
    sanitize_excerpt_bounded(input, MAX_EXCERPT_LINES, MAX_EXCERPT_BYTES)
}

/// Sanitise, redact and bound untrusted content with explicit limits.
///
/// Clamping happens before escaping expansion is measured, so a hostile input
/// consisting of one enormous line can never produce an unbounded excerpt.
pub fn sanitize_excerpt_bounded(
    input: &str,
    max_lines: usize,
    max_bytes: usize,
) -> SanitizedExcerpt {
    let mut truncated = false;

    // Bound the raw input first so a multi-gigabyte line is never fully
    // escaped, redacted or copied. Allow headroom for escape expansion while
    // keeping the working set small.
    let raw_budget = max_bytes.saturating_mul(2).max(max_bytes);
    let mut clamped = if input.len() > raw_budget {
        truncated = true;
        let boundary = floor_char_boundary(input, raw_budget);
        &input[..boundary]
    } else {
        input
    };

    if max_lines > 0 {
        let mut newlines = 0usize;
        let mut cut = None;
        for (index, byte) in clamped.as_bytes().iter().enumerate() {
            if *byte == b'\n' {
                newlines += 1;
                if newlines >= max_lines {
                    cut = Some(index);
                    break;
                }
            }
        }
        if let Some(index) = cut {
            if index + 1 < clamped.len() {
                truncated = true;
            }
            clamped = &clamped[..index];
        }
    }

    let (redacted, redactions) = redact_secrets(clamped);
    let mut text = sanitize_text(&redacted);
    if text.len() > max_bytes {
        truncated = true;
        let boundary = floor_char_boundary(&text, max_bytes);
        text.truncate(boundary);
    }

    SanitizedExcerpt {
        text,
        redactions,
        truncated,
    }
}

/// Recursively sanitise strings inside a structured evidence payload.
fn sanitize_json(value: serde_json::Value, depth: usize) -> serde_json::Value {
    const MAX_DEPTH: usize = 8;
    const MAX_ITEMS: usize = 64;
    if depth >= MAX_DEPTH {
        return serde_json::Value::String("<depth limit reached>".to_owned());
    }
    match value {
        serde_json::Value::String(text) => {
            let sanitized = sanitize_excerpt_bounded(&text, 0, MAX_EXCERPT_BYTES);
            serde_json::Value::String(sanitized.text)
        }
        serde_json::Value::Array(items) => serde_json::Value::Array(
            items
                .into_iter()
                .take(MAX_ITEMS)
                .map(|item| sanitize_json(item, depth + 1))
                .collect(),
        ),
        serde_json::Value::Object(fields) => serde_json::Value::Object(
            fields
                .into_iter()
                .take(MAX_ITEMS)
                .map(|(key, item)| (sanitize_text(&key), sanitize_json(item, depth + 1)))
                .collect(),
        ),
        other => other,
    }
}

fn floor_char_boundary(input: &str, mut index: usize) -> usize {
    if index >= input.len() {
        return input.len();
    }
    while index > 0 && !input.is_char_boundary(index) {
        index -= 1;
    }
    index
}

// ---------------------------------------------------------------------------
// Evidence constructors
// ---------------------------------------------------------------------------

/// Source-code/text evidence: a matched primitive with its line and excerpt.
pub fn source_excerpt(
    subject: EvidenceSubject,
    line_start: u64,
    line_end: u64,
    matched: &str,
    excerpt: &str,
) -> FindingEvidence {
    FindingEvidence::new(
        EvidenceKind::SourceExcerpt,
        subject,
        "Text content matched a security-relevant primitive",
    )
    .at(EvidenceLocation::Text {
        line_start,
        line_end,
        column_start: None,
        column_end: None,
    })
    .matched(matched)
    .excerpt(excerpt)
}

/// Configuration evidence: a JSON/config key and its observed value.
pub fn config_value(
    subject: EvidenceSubject,
    key: &str,
    value: serde_json::Value,
    description: &str,
) -> FindingEvidence {
    FindingEvidence::new(EvidenceKind::ConfigValue, subject, description)
        .at(EvidenceLocation::Metadata {
            key: sanitize_text(key),
        })
        .structured(serde_json::json!({ "key": key, "value": value }))
}

/// Model-metadata evidence: a metadata key and its bounded value.
pub fn metadata_value(
    subject: EvidenceSubject,
    key: &str,
    value: &str,
    description: &str,
) -> FindingEvidence {
    FindingEvidence::new(EvidenceKind::MetadataValue, subject, description)
        .at(EvidenceLocation::Metadata {
            key: sanitize_text(key),
        })
        .excerpt(value)
}

/// Byte-range evidence for binary artifacts.
pub fn byte_range_evidence(
    subject: EvidenceSubject,
    offset: u64,
    length: u64,
    description: &str,
) -> FindingEvidence {
    FindingEvidence::new(EvidenceKind::ByteRange, subject, description)
        .at(EvidenceLocation::ByteRange { offset, length })
}

/// A parsed executable object embedded inside an artifact.
pub fn binary_object(
    subject: EvidenceSubject,
    offset: u64,
    length: u64,
    facts: serde_json::Value,
) -> FindingEvidence {
    FindingEvidence::new(
        EvidenceKind::BinaryObject,
        subject,
        "Executable object structure parsed at the recorded offset",
    )
    .at(EvidenceLocation::ByteRange { offset, length })
    .structured(facts)
}

/// A violated structural invariant, with the declared and actual values.
pub fn structural_invariant(
    subject: EvidenceSubject,
    condition: &str,
    facts: serde_json::Value,
) -> FindingEvidence {
    FindingEvidence::new(
        EvidenceKind::StructuralInvariant,
        subject,
        &format!("Structural invariant violated: {condition}"),
    )
    .structured(facts)
}

/// Static serialization evidence resolved from bounded opcode analysis.
///
/// This never comes from deserializing the stream.
pub fn serialization_opcode(
    subject: EvidenceSubject,
    opcode_index: u64,
    byte_offset: u64,
    facts: serde_json::Value,
) -> FindingEvidence {
    FindingEvidence::new(
        EvidenceKind::SerializationOpcode,
        subject,
        "Static opcode analysis resolved a serialization reference",
    )
    .at(EvidenceLocation::Serialization {
        opcode_index,
        byte_offset,
    })
    .structured(facts)
}

/// Both sides of an integrity comparison.
pub fn hash_mismatch(subject: EvidenceSubject, declared: &str, observed: &str) -> FindingEvidence {
    FindingEvidence::new(
        EvidenceKind::HashMismatch,
        subject,
        "Declared and observed artifact digests differ",
    )
    .structured(serde_json::json!({ "declared": declared, "observed": observed }))
}

/// A package symlink and the target it declares.
pub fn symlink_target(
    subject: EvidenceSubject,
    relative_path: &str,
    target: Option<&str>,
) -> FindingEvidence {
    FindingEvidence::new(
        EvidenceKind::SymlinkTarget,
        subject,
        "Package member is a symbolic link",
    )
    .at(EvidenceLocation::Member {
        member: sanitize_text(relative_path),
    })
    .structured(serde_json::json!({
        "package_relative_path": relative_path,
        "target": target.unwrap_or("<unreadable>"),
    }))
}

/// A package or archive member described by identity rather than content.
pub fn file_member(subject: EvidenceSubject, facts: serde_json::Value) -> FindingEvidence {
    FindingEvidence::new(
        EvidenceKind::FileMember,
        subject,
        "Package member recorded by identity",
    )
    .structured(facts)
}

/// A tensor-level fact from a structured model format.
pub fn tensor_metadata(
    subject: EvidenceSubject,
    tensor: &str,
    facts: serde_json::Value,
) -> FindingEvidence {
    FindingEvidence::new(
        EvidenceKind::TensorMetadata,
        subject,
        "Tensor declaration recorded from the parsed model header",
    )
    .at(EvidenceLocation::Tensor {
        tensor: sanitize_text(tensor),
    })
    .structured(facts)
}

/// Signature/trust state evidence. Never contains private key material.
pub fn signature_evidence(subject: EvidenceSubject, facts: serde_json::Value) -> FindingEvidence {
    FindingEvidence::new(
        EvidenceKind::SignatureEvidence,
        subject,
        "Signature verification state recorded",
    )
    .structured(facts)
}

/// Provenance/trust-policy evidence.
pub fn provenance_evidence(subject: EvidenceSubject, facts: serde_json::Value) -> FindingEvidence {
    FindingEvidence::new(
        EvidenceKind::ProvenanceEvidence,
        subject,
        "Provenance state recorded",
    )
    .structured(facts)
}

/// Runtime version and advisory comparison evidence.
pub fn advisory_match(subject: EvidenceSubject, facts: serde_json::Value) -> FindingEvidence {
    FindingEvidence::new(
        EvidenceKind::AdvisoryMatch,
        subject,
        "Runtime version compared against an advisory range",
    )
    .structured(facts)
}

/// Policy evidence. References the underlying findings rather than restating
/// the technical facts, so policy never appears to have discovered them.
pub fn policy_reason(
    subject: EvidenceSubject,
    reason: &str,
    finding_ids: &[String],
    rule_ids: &[String],
) -> FindingEvidence {
    FindingEvidence::new(EvidenceKind::PolicyReason, subject, reason)
        .structured(serde_json::json!({ "finding_ids": finding_ids, "rule_ids": rule_ids }))
}

/// A bounded observation captured by the behaviour sandbox.
pub fn behaviour_observation(
    subject: EvidenceSubject,
    kind: EvidenceKind,
    description: &str,
    facts: serde_json::Value,
) -> FindingEvidence {
    FindingEvidence::new(kind, subject, description).structured(facts)
}

/// A record of scanning that could not be completed.
pub fn coverage_gap(subject: EvidenceSubject, reason: &str) -> FindingEvidence {
    FindingEvidence::new(
        EvidenceKind::CoverageGap,
        subject,
        "Inspection coverage was incomplete",
    )
    .structured(serde_json::json!({ "reason": reason }))
}

/// A relationship between two package members.
pub fn path_relationship(
    subject: EvidenceSubject,
    description: &str,
    facts: serde_json::Value,
) -> FindingEvidence {
    FindingEvidence::new(EvidenceKind::PathRelationship, subject, description).structured(facts)
}

// ---------------------------------------------------------------------------
// Finding construction
// ---------------------------------------------------------------------------

/// Builder for evidence-aware findings.
///
/// Centralising construction means bounds, ordering, evidence-state derivation
/// and deterministic identity are enforced once instead of at every detector.
#[derive(Debug, Clone)]
pub struct FindingBuilder {
    rule_id: String,
    check_type: CheckType,
    status: ScanStatus,
    finding_class: FindingClass,
    confidence: Confidence,
    layer_digest: String,
    media_type: String,
    detail: Option<String>,
    matches: Vec<String>,
    subject: Option<EvidenceSubject>,
    evidence: Vec<FindingEvidence>,
    evidence_reason: Option<String>,
    not_applicable: bool,
    truncated: bool,
    duration_ms: u64,
}

impl FindingBuilder {
    pub fn new(rule_id: &str, check_type: CheckType, status: ScanStatus) -> Self {
        Self {
            rule_id: rule_id.to_owned(),
            check_type,
            status,
            finding_class: FindingClass::Informational,
            confidence: Confidence::Medium,
            layer_digest: String::new(),
            media_type: String::new(),
            detail: None,
            matches: Vec::new(),
            subject: None,
            evidence: Vec::new(),
            evidence_reason: None,
            not_applicable: false,
            truncated: false,
            duration_ms: 0,
        }
    }

    #[must_use]
    pub fn class(mut self, class: FindingClass) -> Self {
        self.finding_class = class;
        self
    }

    #[must_use]
    pub fn confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    #[must_use]
    pub fn digest(mut self, digest: &str) -> Self {
        self.layer_digest = digest.to_owned();
        self
    }

    #[must_use]
    pub fn media_type(mut self, media_type: &str) -> Self {
        self.media_type = media_type.to_owned();
        self
    }

    #[must_use]
    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Append an extra `matches` entry. The rule-tagged entry is added
    /// automatically by `finish`.
    #[must_use]
    pub fn match_note(mut self, note: impl Into<String>) -> Self {
        self.matches.push(note.into());
        self
    }

    #[must_use]
    pub fn subject(mut self, subject: EvidenceSubject) -> Self {
        self.subject = Some(subject);
        self
    }

    #[must_use]
    pub fn evidence(mut self, evidence: FindingEvidence) -> Self {
        self.evidence.push(evidence);
        self
    }

    #[must_use]
    pub fn evidence_all(mut self, evidence: impl IntoIterator<Item = FindingEvidence>) -> Self {
        self.evidence.extend(evidence);
        self
    }

    /// Record why direct evidence could not be safely extracted. Required for
    /// any non-PASS finding that carries no evidence records.
    #[must_use]
    pub fn evidence_unavailable(mut self, reason: impl Into<String>) -> Self {
        self.evidence_reason = Some(reason.into());
        self
    }

    /// Declare that evidence is meaningless for this rule (informational or
    /// PASS-only outcomes).
    #[must_use]
    pub fn evidence_not_applicable(mut self) -> Self {
        self.not_applicable = true;
        self
    }

    #[must_use]
    pub fn truncated(mut self, truncated: bool) -> Self {
        self.truncated |= truncated;
        self
    }

    #[must_use]
    pub fn started(mut self, started: Instant) -> Self {
        self.duration_ms = crate::scanner::duration_ms(started);
        self
    }

    #[must_use]
    pub fn duration_ms(mut self, duration_ms: u64) -> Self {
        self.duration_ms = duration_ms;
        self
    }

    /// Apply bounds, derive evidence state, compute the deterministic identity
    /// and emit the finding.
    pub fn finish(mut self) -> LayerScanResult {
        let subject = self.subject.clone().unwrap_or_else(|| {
            if self.layer_digest.is_empty() {
                EvidenceSubject::default()
            } else {
                EvidenceSubject::identity(&self.layer_digest, &self.media_type)
            }
        });

        for record in &mut self.evidence {
            if record.subject == EvidenceSubject::default() {
                record.subject = subject.clone();
            }
        }
        self.evidence.sort_by_key(FindingEvidence::sort_key);
        self.evidence
            .dedup_by(|a, b| a.sort_key() == b.sort_key() && a.excerpt == b.excerpt);

        if self.evidence.len() > MAX_EVIDENCE_PER_FINDING {
            self.evidence.truncate(MAX_EVIDENCE_PER_FINDING);
            self.truncated = true;
        }
        let mut budget = MAX_EVIDENCE_BYTES_PER_FINDING;
        let mut kept = Vec::with_capacity(self.evidence.len());
        for record in self.evidence.drain(..) {
            let cost = record.payload_bytes();
            if cost > budget {
                self.truncated = true;
                break;
            }
            budget -= cost;
            kept.push(record);
        }
        self.evidence = kept;

        let evidence_state = if self.not_applicable {
            EvidenceState::NotApplicable
        } else if self.evidence.is_empty() {
            EvidenceState::Unavailable
        } else if self.truncated || self.evidence.iter().any(|record| record.truncated) {
            EvidenceState::Partial
        } else {
            EvidenceState::Available
        };

        let evidence_reason = match evidence_state {
            EvidenceState::Unavailable => Some(self.evidence_reason.clone().unwrap_or_else(|| {
                "Detector did not record structured evidence for this condition".to_owned()
            })),
            EvidenceState::Partial => Some(self.evidence_reason.clone().unwrap_or_else(|| {
                "Evidence was bounded by Layerfault's hostile-input collection limits".to_owned()
            })),
            _ => self.evidence_reason.clone(),
        };

        let mut matches = Vec::with_capacity(self.matches.len() + 1);
        matches.push(format!(
            "[{}] {}",
            self.rule_id,
            self.matches
                .first()
                .cloned()
                .unwrap_or_else(|| self.rule_id.clone())
        ));
        matches.extend(self.matches.iter().skip(1).cloned());

        let finding_id = compute_finding_id(
            &self.rule_id,
            &subject,
            self.check_type.clone(),
            self.status,
            &self.evidence,
        );

        LayerScanResult {
            layer_digest: self.layer_digest,
            media_type: self.media_type,
            check_type: self.check_type,
            status: self.status,
            finding_class: self.finding_class,
            confidence: self.confidence,
            detail: self.detail.map(|value| sanitize_text(&value)),
            matches,
            duration_ms: self.duration_ms,
            rule_id: Some(self.rule_id),
            subject: Some(subject),
            evidence: self.evidence,
            evidence_state: Some(evidence_state),
            evidence_reason,
            finding_id: Some(finding_id),
        }
    }
}

/// Compute the deterministic identity for a finding.
///
/// The canonical form deliberately excludes timestamps, durations, absolute or
/// staging paths and excerpt text, so the same rule firing on the same artifact
/// yields the same identity across runs, machines and redaction changes.
pub fn compute_finding_id(
    rule_id: &str,
    subject: &EvidenceSubject,
    check_type: CheckType,
    status: ScanStatus,
    evidence: &[FindingEvidence],
) -> String {
    let mut canonical = String::new();
    canonical.push_str("rule\u{1f}");
    canonical.push_str(rule_id);
    canonical.push('\n');
    canonical.push_str("subject\u{1f}");
    canonical.push_str(subject.canonical_name());
    canonical.push('\n');
    canonical.push_str("sha256\u{1f}");
    canonical.push_str(subject.sha256.as_deref().unwrap_or(""));
    canonical.push('\n');
    canonical.push_str("check\u{1f}");
    canonical.push_str(&format!("{check_type:?}"));
    canonical.push('\n');
    canonical.push_str("status\u{1f}");
    canonical.push_str(&format!("{status:?}"));
    canonical.push('\n');
    for record in evidence {
        canonical.push_str(&record.identity_fragment());
        canonical.push('\n');
    }
    let digest = hex::encode(Sha256::digest(canonical.as_bytes()));
    format!("lffinding:sha256:{}", &digest[..32])
}

/// Attach evidence-model fields to a finding that was built as a plain struct
/// literal, so migrated and unmigrated detectors converge on the same contract.
pub fn ensure_finding_identity(finding: &mut LayerScanResult, rule_id: &str) {
    if finding.rule_id.is_none() {
        finding.rule_id = Some(rule_id.to_owned());
    }
    if finding.subject.is_none() {
        finding.subject = Some(EvidenceSubject::identity(
            &finding.layer_digest,
            &finding.media_type,
        ));
    }
    if finding.evidence_state.is_none() {
        let state = if !finding.evidence.is_empty() {
            EvidenceState::Available
        } else if finding.status == ScanStatus::Pass {
            EvidenceState::NotApplicable
        } else {
            EvidenceState::Unavailable
        };
        finding.evidence_state = Some(state);
        if state == EvidenceState::Unavailable && finding.evidence_reason.is_none() {
            finding.evidence_reason =
                Some("Detector did not record structured evidence for this condition".to_owned());
        }
    }
    if finding.finding_id.is_none() {
        let subject = finding.subject.clone().unwrap_or_default();
        finding.finding_id = Some(compute_finding_id(
            rule_id,
            &subject,
            finding.check_type.clone(),
            finding.status,
            &finding.evidence,
        ));
    }
}

#[cfg(test)]
mod tests {
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
