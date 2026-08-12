use super::types::{saturating_u64_sum, TensorDeltaStatistics, TensorStatistics};
use sha2::{Digest, Sha256};

pub(super) const SAMPLE_COALESCE_GAP_BYTES: u64 = 64 * 1024;
pub(super) const SAMPLE_COALESCE_MAX_SPAN_BYTES: u64 = 4 * 1024 * 1024;

pub(super) fn security_tensor_weight(name: &str) -> u128 {
    let lower = name.to_ascii_lowercase();
    if lower.contains("lora_a")
        || lower.contains("lora_b")
        || lower.contains("lm_head")
        || lower.contains("output")
        || lower.contains("embed")
        || lower.contains("attention")
        || lower.contains("attn")
        || lower.contains("q_proj")
        || lower.contains("k_proj")
        || lower.contains("v_proj")
        || lower.contains("o_proj")
    {
        4
    } else {
        1
    }
}

/// Allocate a bounded global sample while representing every supported tensor
/// whenever the budget permits. A small per-tensor floor prevents giant
/// embedding matrices from consuming the entire budget; security-relevant
/// tensor families receive additional proportional weight.
pub(super) fn weighted_sample_quotas(
    elements: &[u64],
    names: &[&str],
    budget: usize,
) -> Vec<usize> {
    debug_assert_eq!(elements.len(), names.len());
    if budget == 0 || elements.is_empty() {
        return vec![0; elements.len()];
    }
    let total = saturating_u64_sum(elements.iter().copied());
    if total <= budget as u64 {
        return elements
            .iter()
            .map(|value| usize::try_from(*value).unwrap_or(usize::MAX))
            .collect();
    }

    let active: Vec<usize> = elements
        .iter()
        .enumerate()
        .filter_map(|(index, value)| (*value > 0).then_some(index))
        .collect();
    let mut quotas = vec![0_usize; elements.len()];
    if active.is_empty() {
        return quotas;
    }

    let floor = if budget >= active.len().saturating_mul(32) {
        32
    } else if budget >= active.len().saturating_mul(8) {
        8
    } else {
        1
    };
    let mut remaining = budget;
    for &index in &active {
        if remaining == 0 {
            break;
        }
        let minimum = floor
            .min(usize::try_from(elements[index]).unwrap_or(usize::MAX))
            .min(remaining);
        quotas[index] = minimum;
        remaining -= minimum;
    }
    if remaining == 0 {
        return quotas;
    }

    let weights: Vec<u128> = active
        .iter()
        .map(|&index| {
            let capacity = elements[index].saturating_sub(quotas[index] as u64) as u128;
            capacity.saturating_mul(security_tensor_weight(names[index]))
        })
        .collect();
    let weight_total: u128 = weights.iter().copied().sum();
    if weight_total == 0 {
        return quotas;
    }

    let mut allocated = 0_usize;
    let mut remainders = Vec::with_capacity(active.len());
    for (&index, weight) in active.iter().zip(weights) {
        let capacity = usize::try_from(elements[index])
            .unwrap_or(usize::MAX)
            .saturating_sub(quotas[index]);
        if capacity == 0 {
            remainders.push((0_u128, index));
            continue;
        }
        let numerator = (remaining as u128).saturating_mul(weight);
        let share = usize::try_from(numerator / weight_total)
            .unwrap_or(usize::MAX)
            .min(capacity);
        quotas[index] = quotas[index].saturating_add(share);
        allocated = allocated.saturating_add(share);
        remainders.push((numerator % weight_total, index));
    }
    let mut leftover = remaining.saturating_sub(allocated);
    remainders.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    for (_, index) in remainders {
        if leftover == 0 {
            break;
        }
        if (quotas[index] as u64) < elements[index] {
            quotas[index] += 1;
            leftover -= 1;
        }
    }
    quotas
}

pub(super) fn sampling_seed_sha256(seed_material: &str) -> String {
    format!(
        "sha256:{}",
        hex::encode(Sha256::digest(seed_material.as_bytes()))
    )
}

pub(super) fn seeded_position(
    seed_material: &str,
    tensor_name: &str,
    counter: u64,
    upper: u64,
) -> u64 {
    if upper == 0 {
        return 0;
    }
    let mut hasher = Sha256::new();
    hasher.update(b"layerfault-weight-sample-v2\0");
    hasher.update(seed_material.as_bytes());
    hasher.update(b"\0");
    hasher.update(tensor_name.as_bytes());
    hasher.update(b"\0");
    hasher.update(counter.to_le_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(bytes) % upper
}

/// Construct a small number of contiguous windows. Head/middle/tail protects
/// common localized regions; identity-seeded pseudorandom windows make the
/// remaining coordinates depend on the admitted model identity without causing
/// one seek per sampled value.
pub(super) fn sample_windows_seeded(
    elements: u64,
    quota: usize,
    seed_material: &str,
    tensor_name: &str,
) -> Vec<(u64, usize)> {
    if elements == 0 || quota == 0 {
        return Vec::new();
    }
    let target = usize::try_from(elements).unwrap_or(usize::MAX).min(quota);
    if target >= usize::try_from(elements).unwrap_or(usize::MAX) {
        return vec![(0, usize::try_from(elements).unwrap_or(target))];
    }
    if target <= 3 {
        return match target {
            1 => vec![(seeded_position(seed_material, tensor_name, 0, elements), 1)],
            2 => vec![(0, 1), (elements.saturating_sub(1), 1)],
            _ => vec![(0, 1), (elements / 2, 1), (elements.saturating_sub(1), 1)],
        };
    }

    let window_count = 11_usize.min(target);
    let base = target / window_count;
    let extra = target % window_count;
    let mut windows = Vec::with_capacity(window_count);
    for index in 0..window_count {
        let count = base + usize::from(index < extra);
        let count_u64 = count as u64;
        let max_start = elements.saturating_sub(count_u64).saturating_add(1);
        let start = match index {
            0 => 0,
            1 => elements.saturating_sub(count_u64) / 2,
            2 => elements.saturating_sub(count_u64),
            _ => seeded_position(seed_material, tensor_name, index as u64, max_start),
        };
        windows.push((start, count));
    }
    coalesce_windows(windows, elements, target, seed_material, tensor_name)
}

pub(super) fn coalesce_windows(
    mut windows: Vec<(u64, usize)>,
    elements: u64,
    target: usize,
    seed_material: &str,
    tensor_name: &str,
) -> Vec<(u64, usize)> {
    windows.sort_by_key(|value| value.0);
    let mut merged: Vec<(u64, usize)> = Vec::with_capacity(windows.len());
    for (start, count) in windows {
        if count == 0 || start >= elements {
            continue;
        }
        let end = start.saturating_add(count as u64).min(elements);
        if let Some((previous_start, previous_count)) = merged.last_mut() {
            let previous_end = previous_start.saturating_add(*previous_count as u64);
            if start <= previous_end {
                let combined_end = previous_end.max(end);
                *previous_count = usize::try_from(combined_end.saturating_sub(*previous_start))
                    .unwrap_or(usize::MAX);
                continue;
            }
        }
        merged.push((
            start,
            usize::try_from(end.saturating_sub(start)).unwrap_or(count),
        ));
    }

    // Overlap between pseudorandom windows can reduce the number of inspected
    // values. Deterministically fill any deficit with single points spread over
    // the tensor. This path is normally tiny and keeps reported coverage honest.
    let mut covered: usize = merged.iter().map(|(_, count)| *count).sum();
    let mut counter = 1000_u64;
    while covered < target && covered < usize::try_from(elements).unwrap_or(usize::MAX) {
        let position = seeded_position(seed_material, tensor_name, counter, elements);
        let contained = merged.iter().any(|(start, count)| {
            position >= *start && position < start.saturating_add(*count as u64)
        });
        if !contained {
            merged.push((position, 1));
            covered += 1;
        }
        counter = counter.saturating_add(1);
        if counter > 1000_u64.saturating_add((target as u64).saturating_mul(4)) {
            break;
        }
    }
    merged.sort_by_key(|value| value.0);
    merged
}

pub(super) fn tensor_sample_requires_escalation(report: &TensorStatistics) -> bool {
    if report.elements < 16 {
        return false;
    }
    let max_abs = report.max.abs().max(report.min.abs());
    max_abs > 1_000_000.0
        || report.mean.abs() > 10_000.0
        || report.variance > 1.0e12
        || report.sparsity >= 0.9999
}

pub(super) fn tensor_delta_requires_escalation(report: &TensorDeltaStatistics) -> bool {
    if report.elements < 16 {
        return false;
    }
    report.normalized_frobenius_delta > 0.50
        || report.max_abs_delta > 1_000_000.0
        || report.cosine_similarity.is_some_and(|value| value < 0.80)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_seeded_windows_are_deterministic_and_seed_sensitive() {
        let a = sample_windows_seeded(10_000, 1_000, "sha256:a", "layer.weight");
        let b = sample_windows_seeded(10_000, 1_000, "sha256:a", "layer.weight");
        let c = sample_windows_seeded(10_000, 1_000, "sha256:b", "layer.weight");
        assert_eq!(a, b);
        assert_ne!(a, c);
        let covered: usize = a.iter().map(|(_, count)| *count).sum();
        assert_eq!(covered, 1_000);
        assert!(a.iter().any(|(start, _)| *start == 0));
        assert!(a.iter().any(|(start, count)| {
            let end = start.saturating_add(*count as u64);
            *start <= 5_000 && end > 5_000
        }));
        assert!(a
            .iter()
            .any(|(start, count)| { start.saturating_add(*count as u64) == 10_000 }));
    }
}
