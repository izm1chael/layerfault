use super::capability::ScriptConfidence;
use crate::finding_evidence::{EvidenceSubject, FindingBuilder, FindingEvidence};
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};

#[allow(clippy::too_many_arguments)]
pub(crate) fn package_finding(
    layer_digest: &str,
    status: ScanStatus,
    finding_class: FindingClass,
    confidence: Confidence,
    rule_id: &str,
    detail: String,
    subject: EvidenceSubject,
    evidence: Option<FindingEvidence>,
) -> LayerScanResult {
    let mut builder = FindingBuilder::new(rule_id, CheckType::PackageSecurity, status)
        .class(finding_class)
        .confidence(confidence)
        .digest(layer_digest)
        .media_type("application/vnd.layerfault.package-member")
        .subject(subject)
        .detail(detail);

    builder = match evidence {
        Some(record) => builder.evidence(record),
        None => builder.evidence_unavailable(
            "structural/parser-limit findings describe coverage rather than a specific call site",
        ),
    };

    builder.finish()
}

pub(crate) fn confidence_of(value: ScriptConfidence) -> Confidence {
    match value {
        ScriptConfidence::High => Confidence::High,
        ScriptConfidence::Medium => Confidence::Medium,
        ScriptConfidence::Low => Confidence::Low,
    }
}
