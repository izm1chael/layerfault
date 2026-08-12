use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TensorStatistics {
    pub tensor: String,
    pub dtype: String,
    /// Number of values actually inspected for these statistics.
    pub elements: u64,
    /// Total values in the tensor. `elements < elements_total` means the
    /// numerical domain was sampled rather than exhaustively traversed.
    pub elements_total: u64,
    pub coverage: String,
    pub min: f64,
    pub max: f64,
    pub mean: f64,
    pub variance: f64,
    pub l1: f64,
    pub l2: f64,
    pub frobenius: f64,
    pub sparsity: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TensorDeltaStatistics {
    pub tensor: String,
    /// Number of paired values actually inspected.
    pub elements: u64,
    pub elements_total: u64,
    pub coverage: String,
    pub l1_delta: f64,
    pub l2_delta: f64,
    pub normalized_frobenius_delta: f64,
    pub cosine_similarity: Option<f64>,
    pub max_abs_delta: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeightSetDescriptor {
    pub layout: String,
    pub files: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NumericAnalysisProfile {
    Quick,
    Standard,
    Deep,
}

#[derive(Debug, Clone)]
pub struct WeightAnalysisOptions {
    pub profile: NumericAnalysisProfile,
    pub sample_budget: usize,
    pub full_escalation_max_bytes: u64,
    pub extended_tensor_sample_values: usize,
    pub seed_material: String,
}

impl WeightAnalysisOptions {
    pub fn for_review_profile(profile: &str, seed_material: impl Into<String>) -> Result<Self> {
        let seed_material = seed_material.into();
        match profile.to_ascii_lowercase().as_str() {
            "quick" => Ok(Self {
                profile: NumericAnalysisProfile::Quick,
                sample_budget: 100_000,
                full_escalation_max_bytes: 64 * 1024 * 1024,
                extended_tensor_sample_values: 250_000,
                seed_material,
            }),
            "standard" => Ok(Self {
                profile: NumericAnalysisProfile::Standard,
                sample_budget: 500_000,
                full_escalation_max_bytes: 256 * 1024 * 1024,
                extended_tensor_sample_values: 1_000_000,
                seed_material,
            }),
            "deep" => Ok(Self {
                profile: NumericAnalysisProfile::Deep,
                sample_budget: usize::MAX,
                full_escalation_max_bytes: u64::MAX,
                extended_tensor_sample_values: usize::MAX,
                seed_material,
            }),
            other => {
                bail!("unsupported review profile '{other}'; supported: quick, standard, deep")
            }
        }
    }

    pub fn quick(seed_material: impl Into<String>) -> Self {
        Self::for_review_profile("quick", seed_material)
            .expect("static quick numerical analysis profile")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeightSetStatistics {
    pub layout: String,
    pub shards: usize,
    pub tensors_available: usize,
    pub tensors_analyzed: usize,
    pub tensors_fully_analyzed: usize,
    pub tensors_escalated: usize,
    pub tensors_extended: usize,
    pub values_available: u64,
    pub values_sampled: usize,
    pub sample_budget: usize,
    pub coverage: String,
    pub sampling_strategy: String,
    pub sampling_seed_sha256: String,
    pub tensors: Vec<TensorStatistics>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeightSetDelta {
    pub base_layout: String,
    pub derived_layout: String,
    pub base_shards: usize,
    pub derived_shards: usize,
    pub tensors_available: usize,
    pub tensors_compared: usize,
    pub tensors_fully_compared: usize,
    pub tensors_escalated: usize,
    pub tensors_extended: usize,
    pub values_available: u64,
    pub values_sampled: usize,
    pub sample_budget: usize,
    pub coverage: String,
    pub sampling_strategy: String,
    pub sampling_seed_sha256: String,
    pub tensor_deltas: Vec<TensorDeltaStatistics>,
}

pub(super) fn saturating_u64_sum(values: impl IntoIterator<Item = u64>) -> u64 {
    values
        .into_iter()
        .fold(0_u64, |acc, value| acc.saturating_add(value))
}
