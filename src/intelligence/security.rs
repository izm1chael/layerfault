use super::{
    AdapterIndicatorRecord, BuilderRecord, IntelligenceDisposition, IntelligencePack,
    RevocationRecord, RevocationTarget,
};
use crate::finding_evidence::{EvidenceKind, EvidenceSubject, FindingBuilder, FindingEvidence};
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Default)]
pub struct IntelligenceSubjects {
    pub models: Vec<String>,
    pub passports: Vec<String>,
    pub runtime_releases: Vec<String>,
    pub signers: Vec<String>,
    pub adapters: Vec<String>,
    pub builders: Vec<String>,
}

pub fn assess_subjects(
    pack: &IntelligencePack,
    now_unix: u64,
    subjects: &IntelligenceSubjects,
) -> Vec<LayerScanResult> {
    let mut findings = Vec::new();
    let mut seen = BTreeSet::new();

    for record in &pack.revocations {
        if record.effective_unix > now_unix || !revocation_matches(record, subjects) {
            continue;
        }
        let key = format!("revocation:{}", record.id.to_ascii_lowercase());
        if seen.insert(key) {
            findings.push(revocation_finding(record));
        }
    }

    for adapter in &subjects.adapters {
        if let Some(record) = adapter_indicator(pack, adapter) {
            if matches!(
                record.disposition,
                IntelligenceDisposition::Suspicious
                    | IntelligenceDisposition::Malicious
                    | IntelligenceDisposition::Revoked
                    | IntelligenceDisposition::Compromised
            ) {
                let key = format!("adapter:{}", record.id.to_ascii_lowercase());
                if seen.insert(key) {
                    findings.push(adapter_finding(record));
                }
            }
        }
    }

    for builder in &subjects.builders {
        if let Some(record) = builder_record(pack, builder) {
            if matches!(
                record.disposition,
                IntelligenceDisposition::Suspicious
                    | IntelligenceDisposition::Malicious
                    | IntelligenceDisposition::Revoked
                    | IntelligenceDisposition::Compromised
            ) {
                let key = format!("builder:{}", record.id.to_ascii_lowercase());
                if seen.insert(key) {
                    findings.push(builder_finding(record));
                }
            }
        }
    }

    findings
}

fn revocation_matches(record: &RevocationRecord, subjects: &IntelligenceSubjects) -> bool {
    let values = match record.target {
        RevocationTarget::Signer => &subjects.signers,
        RevocationTarget::Model => &subjects.models,
        RevocationTarget::Passport => &subjects.passports,
        RevocationTarget::RuntimeRelease => &subjects.runtime_releases,
        RevocationTarget::Builder => &subjects.builders,
        RevocationTarget::Adapter => &subjects.adapters,
        RevocationTarget::Advisory => return false,
    };
    values
        .iter()
        .any(|value| normalized_eq(value, &record.value))
}

fn adapter_indicator<'a>(
    pack: &'a IntelligencePack,
    digest: &str,
) -> Option<&'a AdapterIndicatorRecord> {
    pack.adapter_indicators
        .iter()
        .find(|record| normalized_eq(&record.sha256, digest))
}

fn builder_record<'a>(pack: &'a IntelligencePack, identity: &str) -> Option<&'a BuilderRecord> {
    pack.builders
        .iter()
        .find(|record| record.identity.eq_ignore_ascii_case(identity))
}

fn normalized_eq(left: &str, right: &str) -> bool {
    let left = left.strip_prefix("sha256:").unwrap_or(left);
    let right = right.strip_prefix("sha256:").unwrap_or(right);
    left.eq_ignore_ascii_case(right)
}

fn intelligence_evidence(
    subject: &EvidenceSubject,
    label: &str,
    value: serde_json::Value,
) -> FindingEvidence {
    FindingEvidence::new(EvidenceKind::IntelligenceRecord, subject.clone(), label).structured(value)
}

fn revocation_finding(record: &RevocationRecord) -> LayerScanResult {
    let subject = EvidenceSubject::identity(
        &record.value,
        "application/vnd.layerfault.security-intelligence-subject+json",
    );
    FindingBuilder::new(
        "LF-INTEL-IDENTITY-REVOKED",
        CheckType::Intelligence,
        ScanStatus::Fail,
    )
    .class(FindingClass::Integrity)
    .confidence(Confidence::High)
    .subject(subject.clone())
    .detail(format!(
        "Security intelligence revokes the current {:?} identity: {}",
        record.target, record.reason
    ))
    .evidence(intelligence_evidence(
        &subject,
        "Signed intelligence revocation",
        serde_json::json!({
            "record_id": record.id,
            "target": record.target,
            "value": record.value,
            "effective_unix": record.effective_unix,
            "reason": record.reason,
            "reference": record.reference,
        }),
    ))
    .finish()
}

fn adapter_finding(record: &AdapterIndicatorRecord) -> LayerScanResult {
    let subject =
        EvidenceSubject::identity(&record.sha256, "application/vnd.layerfault.adapter+json");
    let status = match record.disposition {
        IntelligenceDisposition::Suspicious => ScanStatus::Warn,
        IntelligenceDisposition::Malicious
        | IntelligenceDisposition::Revoked
        | IntelligenceDisposition::Compromised => ScanStatus::Fail,
        _ => ScanStatus::Warn,
    };
    FindingBuilder::new(
        "LF-INTEL-ADAPTER-INDICATOR",
        CheckType::Intelligence,
        status,
    )
    .class(FindingClass::Integrity)
    .confidence(Confidence::High)
    .subject(subject.clone())
    .detail(format!(
        "Security intelligence classifies this adapter as {:?}",
        record.disposition
    ))
    .evidence(intelligence_evidence(
        &subject,
        "Signed adapter intelligence record",
        serde_json::json!({
            "record_id": record.id,
            "sha256": record.sha256,
            "disposition": record.disposition,
            "declared_base": record.declared_base,
            "reference": record.reference,
        }),
    ))
    .finish()
}

fn builder_finding(record: &BuilderRecord) -> LayerScanResult {
    let subject = EvidenceSubject::identity(
        &record.identity,
        "application/vnd.layerfault.builder-identity+json",
    );
    let status = match record.disposition {
        IntelligenceDisposition::Suspicious => ScanStatus::Warn,
        IntelligenceDisposition::Malicious
        | IntelligenceDisposition::Revoked
        | IntelligenceDisposition::Compromised => ScanStatus::Fail,
        _ => ScanStatus::Warn,
    };
    FindingBuilder::new(
        "LF-INTEL-BUILDER-INDICATOR",
        CheckType::Intelligence,
        status,
    )
    .class(FindingClass::Integrity)
    .confidence(Confidence::High)
    .subject(subject.clone())
    .detail(format!(
        "Security intelligence classifies this builder identity as {:?}",
        record.disposition
    ))
    .evidence(intelligence_evidence(
        &subject,
        "Signed builder intelligence record",
        serde_json::json!({
            "record_id": record.id,
            "identity": record.identity,
            "disposition": record.disposition,
            "reference": record.reference,
        }),
    ))
    .finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_revocation_produces_blocking_finding() {
        let mut pack = crate::intelligence::builtin_pack().expect("builtin intelligence");
        pack.revocations.push(RevocationRecord {
            id: "test-revocation".into(),
            target: RevocationTarget::Model,
            value: "sha256:abcd".into(),
            effective_unix: 1,
            reason: "test revocation".into(),
            reference: "https://example.invalid/revocation".into(),
        });
        let subjects = IntelligenceSubjects {
            models: vec!["sha256:abcd".into()],
            ..Default::default()
        };
        let findings = assess_subjects(&pack, 2, &subjects);
        assert!(findings.iter().any(|finding| {
            finding.rule_id.as_deref() == Some("LF-INTEL-IDENTITY-REVOKED")
                && finding.status == ScanStatus::Fail
        }));
    }

    #[test]
    fn future_revocation_does_not_apply() {
        let mut pack = crate::intelligence::builtin_pack().expect("builtin intelligence");
        pack.revocations.push(RevocationRecord {
            id: "future-revocation".into(),
            target: RevocationTarget::Adapter,
            value: "sha256:abcd".into(),
            effective_unix: 100,
            reason: "future test revocation".into(),
            reference: "https://example.invalid/revocation".into(),
        });
        let subjects = IntelligenceSubjects {
            adapters: vec!["sha256:abcd".into()],
            ..Default::default()
        };
        assert!(assess_subjects(&pack, 99, &subjects).is_empty());
    }
}
