//! Bounded model security research. Existing trigger-search APIs are preserved.
mod candidates;
mod hunt;
mod triggers;
pub use candidates::{build_candidates, BeamOptions, CandidateSource, TriggerCandidate};
pub use hunt::{
    candidates_as_strings, divergence, findings as trigger_hunt_findings, ProbeOutcomeDigest,
    TriggerDivergence, TriggerHuntObservation, TriggerHuntOptions, TriggerHuntReport,
    HUNT_BOUNDARY,
};
pub use triggers::*;
