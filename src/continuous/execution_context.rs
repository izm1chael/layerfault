//! Execution-context identity: a derived value over the atomic execution
//! identities, used for signing, binding and reproducibility.
//!
//! This identity must never be used to compute invalidation. Invalidation is
//! driven by the atomic `SecurityComponent` identities individually
//! (`crate::continuous::dependency`), so a change in one component
//! invalidates only the evidence domains that actually depend on it. Folding
//! everything into one aggregate identity here and using *that* for
//! invalidation would destroy that precision: a trivial, security-irrelevant
//! change to any one atomic component would appear to invalidate everything
//! that references the aggregate.

use super::{ExecutionSnapshot, SecurityComponent};
use sha2::{Digest, Sha256};

/// The atomic components that make up an execution context. Behavioural
/// evidence is meaningful only in relation to this exact set of conditions:
/// which model, which composition, which generation configuration, which
/// runtime, which agent/tool surface, which sandbox, and which sampling
/// parameters produced it.
pub const EXECUTION_CONTEXT_COMPONENTS: &[SecurityComponent] = &[
    SecurityComponent::ModelArtifact,
    SecurityComponent::ModelComposition,
    SecurityComponent::GenerationConfig,
    SecurityComponent::RuntimeBinary,
    SecurityComponent::RuntimeConfiguration,
    SecurityComponent::AgentConfiguration,
    SecurityComponent::McpServers,
    SecurityComponent::ToolSchemas,
    SecurityComponent::SandboxProfile,
    SecurityComponent::TelemetryConfiguration,
    SecurityComponent::ProbeSuite,
    SecurityComponent::SamplingConfiguration,
    SecurityComponent::BehaviourAffectingEnvironment,
    SecurityComponent::PlatformEnvironment,
];

/// Derive the execution-context identity from whichever
/// `EXECUTION_CONTEXT_COMPONENTS` are currently present in `snapshot`. This
/// is intentionally best-effort: a component that has not been observed
/// simply does not contribute, rather than the whole identity failing to
/// compute. It is a descriptive binding value, not a completeness gate —
/// completeness of the underlying components is a separate concern.
pub fn execution_context_identity(snapshot: &ExecutionSnapshot) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"layerfault:execution-context:v1\0");
    for component in EXECUTION_CONTEXT_COMPONENTS {
        if let Some(identity) = snapshot.identities.get(component) {
            hasher.update(format!("{component:?}\0").as_bytes());
            hasher.update(identity.as_bytes());
            hasher.update(b"\0");
        }
    }
    format!("lfexeccontext:v1:sha256:{}", hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::continuous::TrustState;

    fn snapshot_with(pairs: &[(SecurityComponent, &str)]) -> ExecutionSnapshot {
        let mut snapshot = crate::continuous::new_snapshot(TrustState::Unknown);
        for (component, identity) in pairs {
            crate::continuous::set_identity(&mut snapshot, *component, (*identity).to_owned());
        }
        snapshot
    }

    #[test]
    fn identical_atomic_identities_produce_identical_context_identity() {
        let a = snapshot_with(&[(SecurityComponent::ModelArtifact, "m1")]);
        let b = snapshot_with(&[(SecurityComponent::ModelArtifact, "m1")]);
        assert_eq!(
            execution_context_identity(&a),
            execution_context_identity(&b)
        );
    }

    #[test]
    fn changing_a_relevant_component_changes_the_context_identity() {
        let a = snapshot_with(&[(SecurityComponent::ModelArtifact, "m1")]);
        let b = snapshot_with(&[(SecurityComponent::ModelArtifact, "m2")]);
        assert_ne!(
            execution_context_identity(&a),
            execution_context_identity(&b)
        );
    }

    #[test]
    fn irrelevant_component_does_not_affect_context_identity() {
        // Policy is not part of the execution context: an execution's
        // security-relevant conditions do not depend on which policy is
        // being enforced.
        let a = snapshot_with(&[
            (SecurityComponent::ModelArtifact, "m1"),
            (SecurityComponent::Policy, "policy-a"),
        ]);
        let b = snapshot_with(&[
            (SecurityComponent::ModelArtifact, "m1"),
            (SecurityComponent::Policy, "policy-b"),
        ]);
        assert_eq!(
            execution_context_identity(&a),
            execution_context_identity(&b)
        );
    }
}
