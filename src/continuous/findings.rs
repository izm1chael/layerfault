use super::{InvalidationPlan, TrustState};
use crate::finding_evidence::{structural_invariant, EvidenceSubject, FindingBuilder};
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};

pub fn drift_findings(
    entity: &str,
    plan: &InvalidationPlan,
    prior: TrustState,
) -> Vec<LayerScanResult> {
    if plan.changed_components.is_empty() {
        return Vec::new();
    }
    let subject =
        EvidenceSubject::identity(entity, "application/vnd.layerfault.execution-snapshot+json");
    let mut findings = vec![FindingBuilder::new(
        "LF-TRUST-SECURITY-DRIFT",
        CheckType::ContinuousTrust,
        ScanStatus::Warn,
    )
    .class(FindingClass::Operational)
    .confidence(Confidence::High)
    .subject(subject.clone())
    .detail("Security-relevant execution state changed from the previously observed snapshot")
    .evidence(structural_invariant(
        subject.clone(),
        "execution-state drift",
        serde_json::json!({
            "changed_components": plan.changed_components,
            "invalidated_evidence": plan.invalidated_domains,
        }),
    ))
    .finish()];
    if matches!(
        prior,
        TrustState::Approved | TrustState::ConditionallyApproved
    ) && !plan.invalidated_domains.is_empty()
    {
        findings.push(
            FindingBuilder::new(
                "LF-TRUST-EVIDENCE-STALE",
                CheckType::ContinuousTrust,
                ScanStatus::Warn,
            )
            .class(FindingClass::Policy)
            .confidence(Confidence::High)
            .subject(subject)
            .detail("Previously approved execution state now depends on stale security evidence")
            .evidence(structural_invariant(
                EvidenceSubject::identity(
                    entity,
                    "application/vnd.layerfault.execution-snapshot+json",
                ),
                "stale evidence domains",
                serde_json::json!({
                    "domains": plan.invalidated_domains,
                }),
            ))
            .finish(),
        );
    }
    findings
}
