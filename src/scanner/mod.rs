pub mod binary;
pub mod cache;
pub mod config;
pub mod heuristics;
pub mod integrity;
pub mod metadata;
pub(crate) mod scratch;
pub mod session;

pub use session::{
    BinaryStreamObserver, HasherObserver, ScanMetrics, ScanPlan, ScanSession, StreamObserver,
    TextStreamObserver, STREAM_CHUNK_BYTES,
};

use crate::finding_evidence::{EvidenceState, EvidenceSubject, FindingEvidence};
use std::time::Instant;

pub(super) fn duration_ms(started: Instant) -> u64 {
    let millis = started.elapsed().as_millis();
    u64::try_from(millis).unwrap_or(u64::MAX)
}

/// A single scanner finding.
///
/// The first nine fields are the long-standing stable contract and must remain
/// present and compatible. Everything below them is additive evidence
/// attribution: optional on the wire, skipped when empty, and populated by
/// [`crate::finding_evidence::FindingBuilder`].
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct LayerScanResult {
    pub layer_digest: String,
    pub media_type: String,
    pub check_type: CheckType,
    pub status: ScanStatus,
    pub finding_class: FindingClass,
    pub confidence: Confidence,
    pub detail: Option<String>,
    pub matches: Vec<String>,
    pub duration_ms: u64,

    /// Stable detector rule identity. Preferred over parsing `matches`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    /// The exact artifact/member/object this finding concerns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<EvidenceSubject>,
    /// Bounded, sanitised evidence that caused the detector to fire.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<FindingEvidence>,
    /// Completeness of the evidence above. Never ambiguous for non-PASS findings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_state: Option<EvidenceState>,
    /// Why evidence is unavailable or partial, when it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_reason: Option<String>,
    /// Deterministic identity for correlation, diffing and disclosure tracking.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum ScanStatus {
    #[default]
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Confidence {
    Low,
    #[default]
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum FindingClass {
    Integrity,
    Structural,
    ContentIndicator,
    Policy,
    Attestation,
    Compatibility,
    Operational,
    #[default]
    Informational,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum CheckType {
    IntegrityHash,
    HeuristicSignature,
    ParameterThreshold,
    BinarySteganography,
    Provenance,
    GGUFMetadata,
    SafetensorsStructure,
    OnnxStructure,
    PickleStructure,
    TensorFlowStructure,
    TfliteStructure,
    KerasStructure,
    NpyStructure,
    PackageSecurity,
    RuntimeAdvisory,
    ExecutionBinding,
    SignedEvidence,
    LayerPolicy,
    #[default]
    ScanError,
}

pub use binary::BinaryScanner;
pub use config::ConfigScanner;
pub use heuristics::HeuristicsScanner;
pub use integrity::IntegrityScanner;
pub use metadata::MetadataScanner;
