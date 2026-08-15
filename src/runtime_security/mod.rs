//! Local AI runtime discovery, posture, compatibility and exploitability.

mod adapter;
pub mod adapters;
pub mod advisory;
mod capabilities;
mod compatibility;
mod context;
mod discover;
mod exploitability;
mod posture;
mod precondition;
pub mod process;
pub mod types;

pub use adapter::{RuntimeAdapter, RuntimeProcess};
pub use discover::{audit_all, audit_kind, discover_installed, discover_running};
pub use posture::*;
pub use types::*;

pub use context::{ModelSecurityContext, NormalizedFact};
pub use exploitability::{
    assess, assess_from_pack, AdvisoryApplicability, ExploitabilityState, Reachability,
};
pub use precondition::{evaluate_precondition, PreconditionEvaluation, PreconditionState};

pub use capabilities::{RuntimeCapabilities, SupportState};
pub use compatibility::{
    assess_one as assess_compatibility, matrix, CompatibilityCondition, CompatibilityState,
    ModelRuntimeCompatibility,
};
