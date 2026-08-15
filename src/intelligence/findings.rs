use crate::finding_evidence::{EvidenceKind, EvidenceSubject, FindingBuilder, FindingEvidence};
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};

fn finding(rule: &str, status: ScanStatus, class: FindingClass, detail: &str) -> LayerScanResult {
    let subject = EvidenceSubject::identity("layerfault:intelligence", "application/json");
    FindingBuilder::new(rule, CheckType::Intelligence, status)
        .class(class)
        .confidence(Confidence::High)
        .subject(subject.clone())
        .detail(detail)
        .evidence(
            FindingEvidence::new(
                EvidenceKind::IntelligenceRecord,
                subject,
                "Intelligence pack validation state",
            )
            .structured(serde_json::json!({"detail": detail})),
        )
        .finish()
}

pub fn expired(detail: &str) -> LayerScanResult {
    finding(
        "LF-INTEL-PACK-EXPIRED",
        ScanStatus::Warn,
        FindingClass::Policy,
        detail,
    )
}

pub fn stale(detail: &str) -> LayerScanResult {
    finding(
        "LF-INTEL-PACK-STALE",
        ScanStatus::Warn,
        FindingClass::Policy,
        detail,
    )
}

pub fn rollback(detail: &str) -> LayerScanResult {
    finding(
        "LF-INTEL-PACK-ROLLBACK",
        ScanStatus::Fail,
        FindingClass::Integrity,
        detail,
    )
}

pub fn signature(detail: &str) -> LayerScanResult {
    finding(
        "LF-INTEL-PACK-SIGNATURE",
        ScanStatus::Fail,
        FindingClass::Integrity,
        detail,
    )
}
