use super::*;

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
