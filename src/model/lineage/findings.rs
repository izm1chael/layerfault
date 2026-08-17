//! Turns a `LineageVerification`'s states into real, rule-catalogued
//! findings. Before this, `verify()` only produced an informal `reasons:
//! Vec<String>` text list — informative to a human reading CLI output, but
//! invisible to anything that consumes findings (policy, evidence gates,
//! JSON automation). Security inheritance across a claimed transformation
//! should be proven with the same evidence machinery as everything else,
//! not reported through a side channel.

use super::{ClaimedRelation, LineageClaim, VerificationState};
use crate::finding_evidence::{structural_invariant, EvidenceSubject, FindingBuilder};
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};

pub(super) fn build(
    claim: &LineageClaim,
    structural: VerificationState,
    tokenizer: VerificationState,
    identity: VerificationState,
    transformation: VerificationState,
) -> Vec<LayerScanResult> {
    let subject = EvidenceSubject::identity(
        &claim.child_identity,
        "application/vnd.layerfault.lineage-claim+json",
    );
    let mut findings = Vec::new();

    if identity == VerificationState::Contradicted {
        findings.push(finding(
            "LF-LINEAGE-CLAIM-IDENTITY-MISMATCH",
            ScanStatus::Fail,
            Confidence::High,
            &subject,
            claim,
            "the claimed parent/child identities do not match the identities of the artifacts actually compared",
        ));
    }
    if structural == VerificationState::Contradicted {
        findings.push(finding(
            "LF-LINEAGE-CLAIM-STRUCTURAL-CONTRADICTION",
            ScanStatus::Fail,
            Confidence::High,
            &subject,
            claim,
            "observed structural identity contradicts the claimed transformation relationship",
        ));
    }
    if tokenizer == VerificationState::Contradicted {
        findings.push(finding(
            "LF-LINEAGE-CLAIM-TOKENIZER-CONTRADICTION",
            ScanStatus::Warn,
            Confidence::High,
            &subject,
            claim,
            "the tokenizer changed in a way inconsistent with the claimed transformation (repackaging/quantization should not change tokenizer identity)",
        ));
    }
    match transformation {
        VerificationState::Contradicted => findings.push(finding(
            "LF-LINEAGE-CLAIM-TRANSFORMATION-CONTRADICTED",
            ScanStatus::Fail,
            Confidence::High,
            &subject,
            claim,
            "the claimed transformation necessarily alters model weights, but the compared artifacts are byte-identical",
        )),
        VerificationState::Unverified => findings.push(finding(
            "LF-LINEAGE-CLAIM-TRANSFORMATION-UNVERIFIED",
            ScanStatus::Warn,
            Confidence::Medium,
            &subject,
            claim,
            "no verifiable transformation evidence was supplied for this claim; security properties of the parent are not established to carry over to the child",
        )),
        _ => {}
    }

    findings
}

fn finding(
    rule_id: &str,
    status: ScanStatus,
    confidence: Confidence,
    subject: &EvidenceSubject,
    claim: &LineageClaim,
    detail: &str,
) -> LayerScanResult {
    FindingBuilder::new(rule_id, CheckType::LineageVerification, status)
        .class(FindingClass::Structural)
        .confidence(confidence)
        .subject(subject.clone())
        .detail(detail)
        .evidence(structural_invariant(
            subject.clone(),
            "lineage claim verification",
            serde_json::json!({
                "relation": relation_str(claim.relation),
                "parent_identity": claim.parent_identity,
                "child_identity": claim.child_identity,
                "evidence_count": claim.evidence.len(),
            }),
        ))
        .finish()
}

fn relation_str(relation: ClaimedRelation) -> &'static str {
    match relation {
        ClaimedRelation::Repackaged => "repackaged",
        ClaimedRelation::Quantized => "quantized",
        ClaimedRelation::AdapterMerged => "adapter_merged",
        ClaimedRelation::Converted => "converted",
        ClaimedRelation::FineTuned => "fine_tuned",
        ClaimedRelation::Derived => "derived",
    }
}
