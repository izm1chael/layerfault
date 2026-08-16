//! Dependency-aware trust state and evidence invalidation for long-lived AI execution.
//!
//! Changes invalidate only evidence that actually depends on the changed
//! component. The module records state transitions but does not perform
//! destructive remediation or silently escalate observation into enforcement.

mod dependency;
mod execution_context;
mod findings;
mod journal;
mod observe;
mod snapshot;
mod state;
mod types;

pub use dependency::{
    apply as apply_invalidation, default_dependencies, diff as invalidation_plan,
};
pub use execution_context::{execution_context_identity, EXECUTION_CONTEXT_COMPONENTS};
pub use findings::drift_findings;
pub use journal::{append as append_event, load as load_events};
pub use observe::{observe, ObservationInputs};
pub use snapshot::{
    canonical_bytes, identity as snapshot_identity, load as load_snapshot, new as new_snapshot,
    record_evidence, save as save_snapshot, set_identity,
};
pub use state::{state_after_invalidation, transition, transition_allowed};
pub use types::{
    EvidenceDomain, EvidenceRecord, ExecutionSnapshot, InvalidationPlan, SecurityComponent,
    TrustEvent, TrustState,
};
