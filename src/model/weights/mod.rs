//! Bounded numerical tensor statistics for supported Safetensors dtypes.

mod compare;
mod decode;
mod discovery;
mod sampling;
mod statistics;
mod types;

pub use compare::{
    compare_safetensors, compare_safetensors_targets, compare_safetensors_targets_with_options,
};
pub use decode::{decode_chunk, element_bytes};
pub use discovery::discover_safetensors_weight_set;
pub use statistics::{
    decode_tensor_values, safetensors_statistics, safetensors_statistics_for_target,
    safetensors_statistics_for_target_with_options,
};
pub use types::{
    NumericAnalysisProfile, TensorDeltaStatistics, TensorStatistics, WeightAnalysisOptions,
    WeightSetDelta, WeightSetDescriptor, WeightSetStatistics,
};
