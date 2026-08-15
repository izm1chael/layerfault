use super::sanitize::sanitize_json;
use super::*;

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
    IntelligenceRecord,
    RuntimeConfiguration,
    ExecutionEdge,
    TokenizerRecord,
    ModelIdentity,
    LineageEvidence,
    ForensicStatistic,
    CarvedObject,
    InventoryState,
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
    pub fn with_package_relative_path(mut self, path: Option<String>) -> Self {
        self.package_relative_path = path;
        self
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
    pub(super) fn sort_key(&self) -> (String, Option<EvidenceLocation>, EvidenceKind, String) {
        (
            self.subject.canonical_name().to_owned(),
            self.location.clone(),
            self.kind,
            self.match_value.clone().unwrap_or_default(),
        )
    }

    /// Contribution to the deterministic finding identity.
    pub(super) fn identity_fragment(&self) -> String {
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
