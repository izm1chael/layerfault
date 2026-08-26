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
    /// Evidence-based severity of the specific indicator reported. Never derived
    /// from `status`: absent evidence for a severity claim must stay `Unspecified`.
    #[serde(default)]
    pub severity: Severity,
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

/// Evidence-based severity of a specific indicator. Distinct from `Confidence`
/// (how sure the detector is), `FindingClass` (what kind of fact this is), and
/// `ScanStatus`/admission class (the policy decision) — none of those may be
/// used to infer this field. `Unspecified` is a legitimate, preserved value for
/// findings where severity is genuinely not established, not a placeholder to
/// eliminate.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    #[default]
    Unspecified,
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Resolve a finding's severity from the canonical rule catalogue when the
/// constructor did not provide a more specific value.
pub fn resolved_severity(finding: &LayerScanResult) -> Severity {
    if finding.severity != Severity::Unspecified {
        return finding.severity;
    }
    let rule_id = crate::policy::rule_id(finding);
    crate::rules::lookup(&rule_id)
        .map(|rule| rule.severity)
        .unwrap_or(Severity::Unspecified)
}

/// Apply catalogue severity before a finding collection leaves a scan boundary.
pub fn finalize_severities(findings: &mut [LayerScanResult]) {
    for finding in findings {
        finding.severity = resolved_severity(finding);
    }
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
    FastTextStructure,
    PackageSecurity,
    RuntimeAdvisory,
    ExecutionBinding,
    SignedEvidence,
    LayerPolicy,
    Intelligence,
    RuntimePosture,
    RuntimeExploitability,
    RuntimeCompatibility,
    ScannerAssurance,
    DeclarativeExecution,
    TokenizerSecurity,
    ModelIdentity,
    LineageVerification,
    TensorForensics,
    BackdoorForensics,
    RemotePreflight,
    SecurityPassport,
    ModelComposition,
    AgentSecurity,
    McpSecurity,
    ContinuousTrust,
    InventoryDrift,
    #[default]
    ScanError,
}

pub use binary::BinaryScanner;
pub use config::ConfigScanner;
pub use heuristics::HeuristicsScanner;
pub use integrity::IntegrityScanner;
pub use metadata::MetadataScanner;

#[cfg(test)]
mod tests {
    use super::*;

    fn direct_finding(rule_id: &str, status: ScanStatus) -> LayerScanResult {
        LayerScanResult {
            rule_id: Some(rule_id.to_owned()),
            status,
            ..LayerScanResult::default()
        }
    }

    #[test]
    fn finalization_uses_catalogue_severity_without_inferring_from_status() {
        let mut findings = vec![
            direct_finding("LF-PICKLE-DANGEROUS-GLOBAL", ScanStatus::Fail),
            direct_finding("LF-PICKLE-UNKNOWN-GLOBAL", ScanStatus::Warn),
            direct_finding("LF-PICKLE-SAFE-GLOBALS", ScanStatus::Pass),
        ];

        finalize_severities(&mut findings);

        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[1].severity, Severity::Unspecified);
        assert_eq!(findings[2].severity, Severity::Unspecified);
    }
}
