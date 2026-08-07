pub mod binary;
pub mod config;
pub mod heuristics;
pub mod integrity;
pub mod metadata;

use std::time::Instant;

pub(super) fn duration_ms(started: Instant) -> u64 {
    let millis = started.elapsed().as_millis();
    u64::try_from(millis).unwrap_or(u64::MAX)
}

#[derive(Debug, Clone, serde::Serialize)]
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum ScanStatus {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum FindingClass {
    Integrity,
    Structural,
    ContentIndicator,
    Policy,
    Attestation,
    Compatibility,
    Operational,
    Informational,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "PascalCase")]
pub enum CheckType {
    IntegrityHash,
    HeuristicSignature,
    ParameterThreshold,
    BinarySteganography,
    Provenance,
    GGUFMetadata,
    SafetensorsStructure,
    PackageSecurity,
    RuntimeAdvisory,
    ExecutionBinding,
    SignedEvidence,
    LayerPolicy,
    ScanError,
}

pub use binary::BinaryScanner;
pub use config::ConfigScanner;
pub use heuristics::HeuristicsScanner;
pub use integrity::IntegrityScanner;
pub use metadata::MetadataScanner;
