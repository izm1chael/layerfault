use super::common::*;
use super::sarif::is_empty_evidence;
use super::table::class_status;
use super::*;

pub fn emit_json(reports: &[ModelReport]) -> Result<()> {
    let output = stream_seq(reports, |report| JsonModelReport {
        model: &report.model_name,
        scan_results: &report.results,
        overall_status: overall_status(&report.results),
    });
    write_stdout_json(&output, true)
}

#[derive(serde::Serialize)]
struct JsonModelReport<'a> {
    model: &'a str,
    scan_results: &'a [LayerScanResult],
    overall_status: ScanStatus,
}

/// Emit the stable versioned JSON contract. Existing fields remain present while
/// stable rule IDs, provenance and policy decisions are added explicitly.
pub fn emit_evaluated_json(reports: &[crate::app::EvaluatedReport]) -> Result<()> {
    let output = stream_seq(reports, |evaluated| EvaluatedJsonReport {
        schema_version: "1.0",
        tool_version: env!("CARGO_PKG_VERSION"),
        model: &evaluated.report.model_name,
        overall_status: overall_status(&evaluated.report.results),
        trust_state: evaluated.trust_state,
        trusted_signatures: evaluated.trusted_signatures,
        signer_fingerprints: &evaluated.signer_fingerprints,
        policy: &evaluated.policy,
        scan_results: stream_seq(&evaluated.report.results, enriched_finding_ref),
    });
    write_stdout_json(&output, true)
}

#[derive(serde::Serialize)]
struct EvaluatedJsonReport<'a, S: serde::Serialize> {
    schema_version: &'static str,
    tool_version: &'static str,
    model: &'a str,
    overall_status: ScanStatus,
    trust_state: crate::provenance::TrustState,
    trusted_signatures: usize,
    signer_fingerprints: &'a [String],
    policy: &'a crate::policy::PolicyDecision,
    scan_results: S,
}

/// The enriched per-finding JSON contract.
///
/// Every key that existed before the evidence upgrade is still emitted with the
/// same name and meaning. Attribution keys are added alongside them, and are
/// omitted rather than emitted empty when a detector has nothing to say.
#[derive(serde::Serialize)]
pub struct EnrichedFinding<'a> {
    pub rule_id: String,
    pub rule_version: u32,
    pub detector_family: &'static str,
    pub scanner_revision: &'static str,
    pub ruleset_sha256: &'static str,
    pub layer_digest: &'a str,
    pub media_type: &'a str,
    pub check_type: &'a CheckType,
    pub status: &'a ScanStatus,
    pub finding_class: &'a FindingClass,
    pub confidence: &'a Confidence,
    pub detail: &'a Option<String>,
    pub matches: &'a [String],
    pub duration_ms: u64,
    pub risk: crate::explain::RiskExplanation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<&'a EvidenceSubject>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_state: Option<&'a EvidenceState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_reason: Option<&'a str>,
    #[serde(skip_serializing_if = "is_empty_evidence")]
    pub evidence: &'a [FindingEvidence],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explanation: Option<crate::explain::RuleExplanation>,
}

/// Project a finding into the enriched JSON contract without allocating a
/// `serde_json::Value`.
pub fn enriched_finding_ref(finding: &LayerScanResult) -> EnrichedFinding<'_> {
    let rule_id = crate::policy::rule_id(finding);
    let explanation = crate::explain::lookup(&rule_id);
    let rule_version = explanation.as_ref().map(|e| e.rule_version).unwrap_or(1);
    let detector_family = explanation
        .as_ref()
        .map(|e| e.detector_family)
        .unwrap_or("scanner");
    EnrichedFinding {
        rule_id: rule_id.clone(),
        rule_version,
        detector_family,
        scanner_revision: crate::explain::scanner_revision(),
        ruleset_sha256: crate::explain::ruleset_sha256(),
        layer_digest: &finding.layer_digest,
        media_type: &finding.media_type,
        check_type: &finding.check_type,
        status: &finding.status,
        finding_class: &finding.finding_class,
        confidence: &finding.confidence,
        detail: &finding.detail,
        matches: &finding.matches,
        duration_ms: finding.duration_ms,
        risk: crate::explain::risk_lookup(&rule_id),
        finding_id: finding.finding_id.as_deref(),
        subject: finding.subject.as_ref(),
        evidence_state: finding.evidence_state.as_ref(),
        evidence_reason: finding.evidence_reason.as_deref(),
        evidence: &finding.evidence,
        explanation: crate::explain::lookup(&rule_id),
    }
}

/// Legacy `serde_json::Value` projection, kept for callers (evidence bundle
/// manifests, ad hoc command JSON) that still need an owned `Value` rather
/// than a borrowed streaming struct.
pub fn enriched_finding(finding: &LayerScanResult) -> serde_json::Value {
    serde_json::to_value(enriched_finding_ref(finding)).expect("enriched finding is Serialize")
}

pub fn enriched_findings(findings: &[LayerScanResult]) -> Vec<serde_json::Value> {
    findings.iter().map(enriched_finding).collect()
}

pub fn inventory_value(reports: &[crate::app::EvaluatedReport]) -> serde_json::Value {
    serde_json::Value::Array(
        reports
            .iter()
            .map(|evaluated| {
                let integrity = class_status(&evaluated.report.results, FindingClass::Integrity);
                let structure = class_status(&evaluated.report.results, FindingClass::Structural);
                serde_json::json!({
                    "model": &evaluated.report.model_name,
                    "integrity": integrity,
                    "structure": structure,
                    "signed": evaluated.trust_state != crate::provenance::TrustState::Unsigned,
                    "trusted": evaluated.trust_state == crate::provenance::TrustState::Trusted,
                    "trust_state": evaluated.trust_state,
                    "trusted_signatures": evaluated.trusted_signatures,
                    "policy": evaluated.policy.action,
                })
            })
            .collect(),
    )
}
