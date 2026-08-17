use super::{
    findings, ClaimedRelation, LineageClaim, LineageConsistency, LineageVerification,
    VerificationState,
};
use crate::model::identity::{IdentityRelationship, LayeredModelIdentity};

/// Transformation types that necessarily alter model weights. A claim of
/// one of these types describing two byte-identical artifacts is
/// self-contradicting — the claimed operation could not have produced that
/// outcome — regardless of what evidence strings were attached to the
/// claim. This is the "prove inheritance, don't assume it from evidence
/// presence alone" check.
const WEIGHT_ALTERING: &[ClaimedRelation] = &[
    ClaimedRelation::Quantized,
    ClaimedRelation::FineTuned,
    ClaimedRelation::AdapterMerged,
    ClaimedRelation::Converted,
];
pub fn verify(
    claim: &LineageClaim,
    parent: &LayeredModelIdentity,
    child: &LayeredModelIdentity,
) -> LineageVerification {
    let cmp = crate::model::identity::compare(parent, child);
    let structural = match cmp.overall {
        IdentityRelationship::Divergent => VerificationState::Contradicted,
        IdentityRelationship::StructurallyConsistent
        | IdentityRelationship::LikelyDerived
        | IdentityRelationship::SamePackage
        | IdentityRelationship::ExactSameArtifact => VerificationState::Verified,
        _ => VerificationState::Unverified,
    };
    let tokenizer = match (&parent.tokenizer, &child.tokenizer) {
        (Some(a), Some(b)) if a.value == b.value => VerificationState::Verified,
        (Some(_), Some(_)) => match claim.relation {
            ClaimedRelation::Repackaged | ClaimedRelation::Quantized => {
                VerificationState::Contradicted
            }
            _ => VerificationState::Unverified,
        },
        _ => VerificationState::Unverified,
    };
    let identity =
        if claim.parent_identity == parent.subject && claim.child_identity == child.subject {
            VerificationState::Verified
        } else {
            VerificationState::Contradicted
        };
    let transformation = if WEIGHT_ALTERING.contains(&claim.relation)
        && cmp.overall == IdentityRelationship::ExactSameArtifact
    {
        VerificationState::Contradicted
    } else if claim.evidence.is_empty() {
        VerificationState::Unverified
    } else {
        VerificationState::Verified
    };
    let states = [structural, tokenizer, identity, transformation];
    let consistency = if states.contains(&VerificationState::Contradicted) {
        LineageConsistency::Inconsistent
    } else if states.iter().all(|s| {
        matches!(
            s,
            VerificationState::Verified | VerificationState::NotApplicable
        )
    }) {
        LineageConsistency::Consistent
    } else {
        LineageConsistency::PartiallyVerified
    };
    let mut reasons = Vec::new();
    if structural == VerificationState::Contradicted {
        reasons.push("observed structural identity contradicts claimed relation".into())
    }
    if identity == VerificationState::Contradicted {
        reasons.push("claim subject identities do not bind to compared models".into())
    }
    if transformation == VerificationState::Unverified {
        reasons.push("no verifiable transformation evidence supplied".into())
    }
    if transformation == VerificationState::Contradicted {
        reasons.push(
            "claimed transformation necessarily alters model weights, but compared artifacts are byte-identical"
                .into(),
        )
    }
    let claim_findings = findings::build(claim, structural, tokenizer, identity, transformation);
    LineageVerification {
        structural,
        tokenizer,
        transformation,
        identity,
        consistency,
        reasons,
        findings: claim_findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assurance::AnalysisCompleteness;
    use crate::model::identity::{IdentityCoverage, IdentityStrength, IdentityValue};

    fn value(v: &str) -> IdentityValue {
        IdentityValue {
            algorithm: "sha256".to_owned(),
            value: v.to_owned(),
            strength: IdentityStrength::Exact,
            coverage: IdentityCoverage {
                complete: true,
                detail: String::new(),
            },
        }
    }

    fn identity(subject: &str, byte: &str, tokenizer: Option<&str>) -> LayeredModelIdentity {
        LayeredModelIdentity {
            version: 1,
            subject: subject.to_owned(),
            byte: Some(value(byte)),
            package: None,
            structural: Some(value("struct-a")),
            tokenizer: tokenizer.map(value),
            weight_sample: None,
            behavioural: None,
            provenance: None,
            completeness: AnalysisCompleteness::Complete,
            limitations: Vec::new(),
        }
    }

    fn claim(relation: ClaimedRelation, evidence: Vec<String>) -> LineageClaim {
        LineageClaim {
            relation,
            parent_identity: "parent".to_owned(),
            child_identity: "child".to_owned(),
            evidence,
        }
    }

    #[test]
    fn quantization_claim_over_byte_identical_artifacts_is_contradicted() {
        let parent = identity("parent", "same-bytes", Some("tok-a"));
        let child = identity("child", "same-bytes", Some("tok-a"));
        let report = verify(
            &claim(ClaimedRelation::Quantized, vec!["evidence".to_owned()]),
            &parent,
            &child,
        );
        assert_eq!(report.transformation, VerificationState::Contradicted);
        assert_eq!(report.consistency, LineageConsistency::Inconsistent);
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.rule_id.as_deref()
                == Some("LF-LINEAGE-CLAIM-TRANSFORMATION-CONTRADICTED")));
    }

    #[test]
    fn quantization_claim_over_genuinely_different_bytes_is_not_contradicted_by_this_check() {
        let parent = identity("parent", "bytes-a", Some("tok-a"));
        let child = identity("child", "bytes-b", Some("tok-a"));
        let report = verify(
            &claim(ClaimedRelation::Quantized, vec!["evidence".to_owned()]),
            &parent,
            &child,
        );
        assert_ne!(report.transformation, VerificationState::Contradicted);
    }

    #[test]
    fn non_weight_altering_claim_over_byte_identical_artifacts_is_not_contradicted() {
        // Repackaged/Derived claims don't necessarily change weight bytes,
        // so byte-identity alone must not trip this specific check for them.
        let parent = identity("parent", "same-bytes", Some("tok-a"));
        let child = identity("child", "same-bytes", Some("tok-a"));
        let report = verify(
            &claim(ClaimedRelation::Repackaged, vec!["evidence".to_owned()]),
            &parent,
            &child,
        );
        assert_ne!(report.transformation, VerificationState::Contradicted);
    }

    #[test]
    fn no_evidence_is_unverified_and_produces_a_finding() {
        let parent = identity("parent", "bytes-a", Some("tok-a"));
        let child = identity("child", "bytes-b", Some("tok-a"));
        let report = verify(
            &claim(ClaimedRelation::Derived, Vec::new()),
            &parent,
            &child,
        );
        assert_eq!(report.transformation, VerificationState::Unverified);
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.rule_id.as_deref()
                == Some("LF-LINEAGE-CLAIM-TRANSFORMATION-UNVERIFIED")));
    }

    #[test]
    fn identity_mismatch_produces_a_finding() {
        let parent = identity("parent", "bytes-a", Some("tok-a"));
        let child = identity("child", "bytes-b", Some("tok-a"));
        let mismatched = LineageClaim {
            relation: ClaimedRelation::Derived,
            parent_identity: "not-parent".to_owned(),
            child_identity: "not-child".to_owned(),
            evidence: vec!["evidence".to_owned()],
        };
        let report = verify(&mismatched, &parent, &child);
        assert_eq!(report.identity, VerificationState::Contradicted);
        assert!(report.findings.iter().any(
            |finding| finding.rule_id.as_deref() == Some("LF-LINEAGE-CLAIM-IDENTITY-MISMATCH")
        ));
    }

    #[test]
    fn fully_consistent_claim_produces_no_findings() {
        let parent = identity("parent", "bytes-a", Some("tok-a"));
        let child = identity("child", "bytes-b", Some("tok-a"));
        let report = verify(
            &claim(ClaimedRelation::FineTuned, vec!["evidence".to_owned()]),
            &parent,
            &child,
        );
        assert_eq!(report.consistency, LineageConsistency::Consistent);
        assert!(report.findings.is_empty());
    }
}
