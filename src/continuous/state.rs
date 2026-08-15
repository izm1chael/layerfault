use super::{InvalidationPlan, TrustEvent, TrustState};
use anyhow::{bail, Result};

pub fn transition_allowed(from: TrustState, to: TrustState) -> bool {
    use TrustState::*;
    if from == to {
        return true;
    }
    matches!(
        (from, to),
        (Unknown, Scanning)
            | (Unknown, ReviewRequired)
            | (Scanning, Approved)
            | (Scanning, ConditionallyApproved)
            | (Scanning, ReviewRequired)
            | (Scanning, Blocked)
            | (Approved, ReviewRequired)
            | (Approved, Blocked)
            | (Approved, Expired)
            | (ConditionallyApproved, ReviewRequired)
            | (ConditionallyApproved, Blocked)
            | (ConditionallyApproved, Expired)
            | (ReviewRequired, Scanning)
            | (ReviewRequired, Approved)
            | (ReviewRequired, ConditionallyApproved)
            | (ReviewRequired, Blocked)
            | (Blocked, Scanning)
            | (Blocked, Quarantined)
            | (Quarantined, Scanning)
            | (Expired, Scanning)
    )
}

pub fn transition(
    entity: &str,
    from: TrustState,
    to: TrustState,
    cause: &str,
    plan: Option<&InvalidationPlan>,
) -> Result<TrustEvent> {
    if !transition_allowed(from, to) {
        bail!("invalid trust-state transition from {from:?} to {to:?}");
    }
    Ok(TrustEvent {
        version: 1,
        timestamp_unix: crate::paths::now_unix(),
        entity: entity.to_owned(),
        previous_state: from,
        new_state: to,
        cause: cause.to_owned(),
        changed_components: plan
            .map(|plan| plan.changed_components.clone())
            .unwrap_or_default(),
        invalidated_evidence: plan
            .map(|plan| plan.invalidated_domains.clone())
            .unwrap_or_default(),
        finding_ids: Vec::new(),
        rule_ids: Vec::new(),
        policy_decision: None,
        operator_action: None,
    })
}

pub fn state_after_invalidation(current: TrustState, plan: &InvalidationPlan) -> TrustState {
    if plan.invalidated_domains.is_empty() {
        return current;
    }
    if matches!(
        current,
        TrustState::Approved | TrustState::ConditionallyApproved
    ) {
        TrustState::ReviewRequired
    } else {
        current
    }
}
