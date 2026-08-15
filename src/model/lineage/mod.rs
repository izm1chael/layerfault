//! Deep model lineage verification with the legacy comparison API re-exported.
mod graph;
mod legacy;
mod types;
mod verify;
pub use graph::{LineageEdge, LineageGraph, LineageNode};
pub use legacy::*;
pub use types::{
    ClaimedRelation, LineageClaim, LineageConsistency, LineageVerification, VerificationState,
};
pub use verify::verify;
