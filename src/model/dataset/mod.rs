//! Bounded local dataset fingerprinting and poisoning-evidence analysis.
//! Dataset indicators are evidence only; they cannot prove malicious poisoning.

mod analysis;
mod indicators;
mod inventory;
mod readers;
mod sampling;
mod types;

pub use analysis::{poisoning_review, poisoning_review_with_jobs};
pub use inventory::{compare, compare_with_jobs, fingerprint, fingerprint_with_jobs};
pub use types::{
    DatasetCoverage, DatasetFile, DatasetFingerprint, DatasetFormat, PoisonIndicator,
    PoisoningReview,
};
