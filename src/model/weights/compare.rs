use super::decode::{element_bytes, tensor_elements};
use super::discovery::open_weight_set;
use super::sampling::{
    sample_windows_seeded, sampling_seed_sha256, tensor_delta_requires_escalation,
    weighted_sample_quotas,
};
use super::statistics::{delta_tensor, delta_tensor_windows};
use super::types::{
    saturating_u64_sum, NumericAnalysisProfile, TensorDeltaStatistics, WeightAnalysisOptions,
    WeightSetDelta,
};
use anyhow::{anyhow, Result};
use std::path::Path;

pub fn compare_safetensors_targets(
    base: &Path,
    derived: &Path,
    sample_budget: usize,
) -> Result<WeightSetDelta> {
    let options = WeightAnalysisOptions {
        profile: NumericAnalysisProfile::Quick,
        sample_budget,
        full_escalation_max_bytes: 64 * 1024 * 1024,
        extended_tensor_sample_values: sample_budget.saturating_mul(4).max(sample_budget),
        seed_material: format!("{}\0{}", base.display(), derived.display()),
    };
    compare_safetensors_targets_with_options(base, derived, &options)
}

pub fn compare_safetensors_targets_with_options(
    base: &Path,
    derived: &Path,
    options: &WeightAnalysisOptions,
) -> Result<WeightSetDelta> {
    let left = open_weight_set(base)?
        .ok_or_else(|| anyhow!("base has no compatible Safetensors weight set"))?;
    let right = open_weight_set(derived)?
        .ok_or_else(|| anyhow!("derived target has no compatible Safetensors weight set"))?;
    let mut candidates = Vec::new();
    for (name, (left_shard_index, left_tensor_index)) in &left.tensors {
        let Some((right_shard_index, right_tensor_index)) = right.tensors.get(name) else {
            continue;
        };
        let left_shard = &left.shards[*left_shard_index];
        let right_shard = &right.shards[*right_shard_index];
        let left_tensor = &left_shard.inventory.tensors[*left_tensor_index];
        let right_tensor = &right_shard.inventory.tensors[*right_tensor_index];
        if left_tensor.shape != right_tensor.shape
            || left_tensor.dtype != right_tensor.dtype
            || element_bytes(&left_tensor.dtype).is_none()
        {
            continue;
        }
        let elements = tensor_elements(left_tensor)?;
        candidates.push((
            name.clone(),
            *left_shard_index,
            *left_tensor_index,
            *right_shard_index,
            *right_tensor_index,
            elements,
        ));
    }
    let values_available = saturating_u64_sum(candidates.iter().map(|value| value.5));
    let seed_hash = sampling_seed_sha256(&options.seed_material);

    if options.profile == NumericAnalysisProfile::Deep {
        let mut deltas = Vec::with_capacity(candidates.len());
        let mut values_sampled = 0_usize;
        for (_, left_shard_index, left_tensor_index, right_shard_index, right_tensor_index, _) in
            &candidates
        {
            let left_shard = &left.shards[*left_shard_index];
            let right_shard = &right.shards[*right_shard_index];
            let left_tensor = &left_shard.inventory.tensors[*left_tensor_index];
            let right_tensor = &right_shard.inventory.tensors[*right_tensor_index];
            let report = delta_tensor(
                &left_shard.file,
                left_shard.inventory.data_start,
                left_tensor,
                &right_shard.file,
                right_shard.inventory.data_start,
                right_tensor,
            )?;
            values_sampled = values_sampled
                .saturating_add(usize::try_from(report.elements).unwrap_or(usize::MAX));
            deltas.push(report);
        }
        return Ok(WeightSetDelta {
            base_layout: left.descriptor.layout,
            derived_layout: right.descriptor.layout,
            base_shards: left.shards.len(),
            derived_shards: right.shards.len(),
            tensors_available: candidates.len(),
            tensors_compared: deltas.len(),
            tensors_fully_compared: deltas.len(),
            tensors_escalated: 0,
            tensors_extended: 0,
            values_available,
            values_sampled,
            sample_budget: usize::MAX,
            coverage: "EXHAUSTIVE".to_owned(),
            sampling_strategy: "FULL_NUMERIC_TRAVERSAL".to_owned(),
            sampling_seed_sha256: seed_hash,
            tensor_deltas: deltas,
        });
    }

    let elements: Vec<u64> = candidates.iter().map(|value| value.5).collect();
    let names: Vec<&str> = candidates.iter().map(|value| value.0.as_str()).collect();
    let quotas = weighted_sample_quotas(&elements, &names, options.sample_budget);
    let mut deltas = Vec::new();
    let mut values_sampled = 0_usize;
    let mut tensors_fully_compared = 0_usize;
    let mut tensors_escalated = 0_usize;
    let mut tensors_extended = 0_usize;

    for (
        (
            name,
            left_shard_index,
            left_tensor_index,
            right_shard_index,
            right_tensor_index,
            total_elements,
        ),
        quota,
    ) in candidates.iter().zip(quotas)
    {
        if quota == 0 {
            continue;
        }
        let left_shard = &left.shards[*left_shard_index];
        let right_shard = &right.shards[*right_shard_index];
        let left_tensor = &left_shard.inventory.tensors[*left_tensor_index];
        let right_tensor = &right_shard.inventory.tensors[*right_tensor_index];
        let windows = sample_windows_seeded(*total_elements, quota, &options.seed_material, name);
        let mut report = delta_tensor_windows(
            &left_shard.file,
            left_shard.inventory.data_start,
            left_tensor,
            &right_shard.file,
            right_shard.inventory.data_start,
            right_tensor,
            &windows,
            "SAMPLED",
        )?;

        if report.elements == *total_elements {
            report.coverage = "EXHAUSTIVE".to_owned();
            tensors_fully_compared = tensors_fully_compared.saturating_add(1);
        } else if tensor_delta_requires_escalation(&report) {
            tensors_escalated = tensors_escalated.saturating_add(1);
            let tensor_bytes = left_tensor.end.saturating_sub(left_tensor.start);
            if tensor_bytes <= options.full_escalation_max_bytes {
                report = delta_tensor(
                    &left_shard.file,
                    left_shard.inventory.data_start,
                    left_tensor,
                    &right_shard.file,
                    right_shard.inventory.data_start,
                    right_tensor,
                )?;
                report.coverage = "EXHAUSTIVE_ESCALATED".to_owned();
                tensors_fully_compared = tensors_fully_compared.saturating_add(1);
            } else {
                let extended_quota = usize::try_from(*total_elements)
                    .unwrap_or(usize::MAX)
                    .min(options.extended_tensor_sample_values.max(quota));
                let extended_windows = sample_windows_seeded(
                    *total_elements,
                    extended_quota,
                    &format!("{}:escalated", options.seed_material),
                    name,
                );
                report = delta_tensor_windows(
                    &left_shard.file,
                    left_shard.inventory.data_start,
                    left_tensor,
                    &right_shard.file,
                    right_shard.inventory.data_start,
                    right_tensor,
                    &extended_windows,
                    "SAMPLED_TARGETED_EXTENDED",
                )?;
                tensors_extended = tensors_extended.saturating_add(1);
                if report.elements == *total_elements {
                    report.coverage = "EXHAUSTIVE_ESCALATED".to_owned();
                    tensors_fully_compared = tensors_fully_compared.saturating_add(1);
                }
            }
        }

        values_sampled =
            values_sampled.saturating_add(usize::try_from(report.elements).unwrap_or(usize::MAX));
        deltas.push(report);
    }

    let coverage = if tensors_fully_compared == candidates.len() {
        "EXHAUSTIVE"
    } else if tensors_escalated > 0 {
        "SAMPLED_WITH_TARGETED_ESCALATION"
    } else {
        "SAMPLED"
    };
    Ok(WeightSetDelta {
        base_layout: left.descriptor.layout,
        derived_layout: right.descriptor.layout,
        base_shards: left.shards.len(),
        derived_shards: right.shards.len(),
        tensors_available: candidates.len(),
        tensors_compared: deltas.len(),
        tensors_fully_compared,
        tensors_escalated,
        tensors_extended,
        values_available,
        values_sampled,
        sample_budget: options.sample_budget,
        coverage: coverage.to_owned(),
        sampling_strategy: "IDENTITY_SEEDED_PAIRED_HEAD_MIDDLE_TAIL_PLUS_PSEUDORANDOM_WINDOWS"
            .to_owned(),
        sampling_seed_sha256: seed_hash,
        tensor_deltas: deltas,
    })
}

pub fn compare_safetensors(
    base: &Path,
    derived: &Path,
    max_tensors: usize,
) -> Result<Vec<TensorDeltaStatistics>> {
    let base_file = crate::safeio::open_readonly_nofollow(base)?;
    let derived_file = crate::safeio::open_readonly_nofollow(derived)?;
    let base_inv =
        crate::formats::safetensors::inventory_file(&base_file, base_file.metadata()?.len())?;
    let derived_inv =
        crate::formats::safetensors::inventory_file(&derived_file, derived_file.metadata()?.len())?;
    let right: std::collections::BTreeMap<_, _> = derived_inv
        .tensors
        .iter()
        .map(|v| (v.name.as_str(), v))
        .collect();
    let mut out = Vec::new();
    for left in base_inv.tensors.iter().take(max_tensors) {
        let Some(right) = right.get(left.name.as_str()) else {
            continue;
        };
        if left.shape != right.shape
            || left.dtype != right.dtype
            || element_bytes(&left.dtype).is_none()
        {
            continue;
        }
        out.push(delta_tensor(
            &base_file,
            base_inv.data_start,
            left,
            &derived_file,
            derived_inv.data_start,
            right,
        )?);
    }
    Ok(out)
}
