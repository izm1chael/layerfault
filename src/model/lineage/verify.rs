use super::{
    ClaimedRelation, LineageClaim, LineageConsistency, LineageVerification, VerificationState,
};
use crate::model::identity::{IdentityRelationship, LayeredModelIdentity};
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
    let transformation = if claim.evidence.is_empty() {
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
    LineageVerification {
        structural,
        tokenizer,
        transformation,
        identity,
        consistency,
        reasons,
    }
}
