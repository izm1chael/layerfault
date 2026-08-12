use super::decode::{decode_chunk, element_bytes, tensor_elements};
use super::discovery::{open_weight_set, OpenWeightSet};
use super::sampling::{
    sample_windows_seeded, sampling_seed_sha256, tensor_sample_requires_escalation,
    weighted_sample_quotas, SAMPLE_COALESCE_GAP_BYTES, SAMPLE_COALESCE_MAX_SPAN_BYTES,
};
use super::types::{
    saturating_u64_sum, NumericAnalysisProfile, TensorDeltaStatistics, TensorStatistics,
    WeightAnalysisOptions, WeightSetStatistics,
};
use anyhow::{anyhow, bail, Context, Result};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

const CHUNK_BYTES: usize = 4 * 1024 * 1024;

#[derive(Default)]
pub(super) struct RunningStats {
    count: u64,
    min: f64,
    max: f64,
    mean: f64,
    m2: f64,
    l1: f64,
    l2_sq: f64,
    zero: u64,
}

impl RunningStats {
    fn push(&mut self, value: f64) {
        if self.count == 0 {
            self.min = value;
            self.max = value;
        } else {
            self.min = self.min.min(value);
            self.max = self.max.max(value);
        }
        self.count = self.count.saturating_add(1);
        let delta = value - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;
        self.l1 += value.abs();
        self.l2_sq += value * value;
        if value == 0.0 {
            self.zero = self.zero.saturating_add(1);
        }
    }

    fn finish(
        self,
        tensor: &str,
        dtype: &str,
        elements_total: u64,
        coverage: &str,
    ) -> Result<TensorStatistics> {
        if self.count == 0 {
            bail!("tensor '{tensor}' contains no elements");
        }
        Ok(TensorStatistics {
            tensor: tensor.to_owned(),
            dtype: dtype.to_owned(),
            elements: self.count,
            elements_total,
            coverage: coverage.to_owned(),
            min: self.min,
            max: self.max,
            mean: self.mean,
            variance: if self.count > 1 {
                self.m2 / (self.count - 1) as f64
            } else {
                0.0
            },
            l1: self.l1,
            l2: self.l2_sq.sqrt(),
            frobenius: self.l2_sq.sqrt(),
            sparsity: self.zero as f64 / self.count as f64,
        })
    }
}

pub fn safetensors_statistics_for_target(
    path: &Path,
    sample_budget: usize,
) -> Result<WeightSetStatistics> {
    let options = WeightAnalysisOptions {
        profile: NumericAnalysisProfile::Quick,
        sample_budget,
        full_escalation_max_bytes: 64 * 1024 * 1024,
        extended_tensor_sample_values: sample_budget.saturating_mul(4).max(sample_budget),
        seed_material: path.display().to_string(),
    };
    safetensors_statistics_for_target_with_options(path, &options)
}

pub fn safetensors_statistics_for_target_with_options(
    path: &Path,
    options: &WeightAnalysisOptions,
) -> Result<WeightSetStatistics> {
    let set = open_weight_set(path)?
        .ok_or_else(|| anyhow!("no compatible Safetensors weight set was discovered"))?;
    let candidates: Vec<(String, usize, usize, u64)> = set
        .tensors
        .iter()
        .filter_map(|(name, (shard_index, tensor_index))| {
            let shard = &set.shards[*shard_index];
            let tensor = &shard.inventory.tensors[*tensor_index];
            tensor_elements(tensor)
                .ok()
                .map(|elements| (name.clone(), *shard_index, *tensor_index, elements))
        })
        .collect();
    let values_available = saturating_u64_sum(candidates.iter().map(|value| value.3));
    let seed_hash = sampling_seed_sha256(&options.seed_material);

    if options.profile == NumericAnalysisProfile::Deep {
        let mut tensors = Vec::with_capacity(candidates.len());
        let mut values_sampled = 0_usize;
        for (_, shard_index, tensor_index, _) in &candidates {
            let shard = &set.shards[*shard_index];
            let tensor = &shard.inventory.tensors[*tensor_index];
            let report = stat_tensor(&shard.file, shard.inventory.data_start, tensor)?;
            values_sampled = values_sampled
                .saturating_add(usize::try_from(report.elements).unwrap_or(usize::MAX));
            tensors.push(report);
        }
        return Ok(WeightSetStatistics {
            layout: set.descriptor.layout,
            shards: set.shards.len(),
            tensors_available: candidates.len(),
            tensors_analyzed: tensors.len(),
            tensors_fully_analyzed: tensors.len(),
            tensors_escalated: 0,
            tensors_extended: 0,
            values_available,
            values_sampled,
            sample_budget: usize::MAX,
            coverage: "EXHAUSTIVE".to_owned(),
            sampling_strategy: "FULL_NUMERIC_TRAVERSAL".to_owned(),
            sampling_seed_sha256: seed_hash,
            tensors,
        });
    }

    let elements: Vec<u64> = candidates.iter().map(|value| value.3).collect();
    let names: Vec<&str> = candidates.iter().map(|value| value.0.as_str()).collect();
    let quotas = weighted_sample_quotas(&elements, &names, options.sample_budget);
    let mut tensors = Vec::new();
    let mut values_sampled = 0_usize;
    let mut tensors_fully_analyzed = 0_usize;
    let mut tensors_escalated = 0_usize;
    let mut tensors_extended = 0_usize;
    // Generate the exact same logical sample coordinates as before, then read
    // them in physical shard/offset order. This preserves detection coverage
    // while avoiding thousands of backwards/random seeks on large GPTQ/AWQ
    // Safetensors files. Nearby windows are coalesced with a tightly bounded
    // read-ahead span.
    let initial_reports =
        stat_weight_set_windows_batched(&set, &candidates, &quotas, &options.seed_material)?;

    for (((name, shard_index, tensor_index, total_elements), quota), initial_report) in candidates
        .iter()
        .zip(quotas.iter().copied())
        .zip(initial_reports)
    {
        if quota == 0 {
            continue;
        }
        let shard = &set.shards[*shard_index];
        let tensor = &shard.inventory.tensors[*tensor_index];
        let mut report = initial_report
            .ok_or_else(|| anyhow!("missing batched numerical sample for tensor '{name}'"))?;

        if report.elements == *total_elements {
            report.coverage = "EXHAUSTIVE".to_owned();
            tensors_fully_analyzed = tensors_fully_analyzed.saturating_add(1);
        } else if tensor_sample_requires_escalation(&report) {
            tensors_escalated = tensors_escalated.saturating_add(1);
            let tensor_bytes = tensor.end.saturating_sub(tensor.start);
            if tensor_bytes <= options.full_escalation_max_bytes {
                report = stat_tensor(&shard.file, shard.inventory.data_start, tensor)?;
                report.coverage = "EXHAUSTIVE_ESCALATED".to_owned();
                tensors_fully_analyzed = tensors_fully_analyzed.saturating_add(1);
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
                report = stat_tensor_windows(
                    &shard.file,
                    shard.inventory.data_start,
                    tensor,
                    &extended_windows,
                    "SAMPLED_TARGETED_EXTENDED",
                )?;
                tensors_extended = tensors_extended.saturating_add(1);
                if report.elements == *total_elements {
                    report.coverage = "EXHAUSTIVE_ESCALATED".to_owned();
                    tensors_fully_analyzed = tensors_fully_analyzed.saturating_add(1);
                }
            }
        }

        values_sampled =
            values_sampled.saturating_add(usize::try_from(report.elements).unwrap_or(usize::MAX));
        tensors.push(report);
    }

    let coverage = if tensors_fully_analyzed == candidates.len() {
        "EXHAUSTIVE"
    } else if tensors_escalated > 0 {
        "SAMPLED_WITH_TARGETED_ESCALATION"
    } else {
        "SAMPLED"
    };
    Ok(WeightSetStatistics {
        layout: set.descriptor.layout,
        shards: set.shards.len(),
        tensors_available: candidates.len(),
        tensors_analyzed: tensors.len(),
        tensors_fully_analyzed,
        tensors_escalated,
        tensors_extended,
        values_available,
        values_sampled,
        sample_budget: options.sample_budget,
        coverage: coverage.to_owned(),
        sampling_strategy: "IDENTITY_SEEDED_PER_TENSOR_HEAD_MIDDLE_TAIL_PLUS_PSEUDORANDOM_WINDOWS"
            .to_owned(),
        sampling_seed_sha256: seed_hash,
        tensors,
    })
}

#[derive(Debug, Clone)]
struct SampleReadTask {
    candidate_index: usize,
    shard_index: usize,
    byte_offset: u64,
    byte_len: usize,
}

pub(super) fn stat_weight_set_windows_batched(
    set: &OpenWeightSet,
    candidates: &[(String, usize, usize, u64)],
    quotas: &[usize],
    seed_material: &str,
) -> Result<Vec<Option<TensorStatistics>>> {
    if candidates.len() != quotas.len() {
        bail!("internal numerical sample quota length mismatch");
    }
    let mut tasks = Vec::<SampleReadTask>::new();
    let mut stats: Vec<RunningStats> = (0..candidates.len())
        .map(|_| RunningStats::default())
        .collect();
    for (candidate_index, ((name, shard_index, tensor_index, elements), quota)) in
        candidates.iter().zip(quotas.iter().copied()).enumerate()
    {
        if quota == 0 {
            continue;
        }
        let shard = &set.shards[*shard_index];
        let tensor = &shard.inventory.tensors[*tensor_index];
        let step = element_bytes(&tensor.dtype)
            .ok_or_else(|| anyhow!("unsupported numeric dtype '{}'", tensor.dtype))?;
        let absolute = shard
            .inventory
            .data_start
            .checked_add(tensor.start)
            .ok_or_else(|| anyhow!("tensor sample base offset overflow"))?;
        for (start_element, count) in sample_windows_seeded(*elements, quota, seed_material, name) {
            let relative = start_element
                .checked_mul(step as u64)
                .ok_or_else(|| anyhow!("tensor sample relative offset overflow"))?;
            let byte_offset = absolute
                .checked_add(relative)
                .ok_or_else(|| anyhow!("tensor sample offset overflow"))?;
            let byte_len = count
                .checked_mul(step)
                .ok_or_else(|| anyhow!("tensor sample byte length overflow"))?;
            tasks.push(SampleReadTask {
                candidate_index,
                shard_index: *shard_index,
                byte_offset,
                byte_len,
            });
        }
    }
    tasks.sort_by(|a, b| {
        a.shard_index
            .cmp(&b.shard_index)
            .then_with(|| a.byte_offset.cmp(&b.byte_offset))
            .then_with(|| a.candidate_index.cmp(&b.candidate_index))
    });

    let mut index = 0_usize;
    while index < tasks.len() {
        let shard_index = tasks[index].shard_index;
        let start = tasks[index].byte_offset;
        let mut end = start.saturating_add(tasks[index].byte_len as u64);
        let mut group_end = index + 1;
        while group_end < tasks.len() && tasks[group_end].shard_index == shard_index {
            let next = &tasks[group_end];
            let next_end = next.byte_offset.saturating_add(next.byte_len as u64);
            let gap = next.byte_offset.saturating_sub(end);
            let combined_end = end.max(next_end);
            let span = combined_end.saturating_sub(start);
            if gap > SAMPLE_COALESCE_GAP_BYTES || span > SAMPLE_COALESCE_MAX_SPAN_BYTES {
                break;
            }
            end = combined_end;
            group_end += 1;
        }
        let span = end.saturating_sub(start);
        let span_usize = usize::try_from(span).context("sample read span does not fit usize")?;
        let shard = &set.shards[shard_index];
        let mut reader = shard.file.try_clone()?;
        reader.seek(SeekFrom::Start(start))?;
        let mut bytes = vec![0_u8; span_usize];
        reader.read_exact(&mut bytes)?;

        for task in &tasks[index..group_end] {
            let offset = usize::try_from(task.byte_offset.saturating_sub(start))
                .context("sample slice offset does not fit usize")?;
            let slice_end = offset
                .checked_add(task.byte_len)
                .ok_or_else(|| anyhow!("sample slice length overflow"))?;
            if slice_end > bytes.len() {
                bail!("batched sample slice exceeds coalesced read buffer");
            }
            let (_, shard_index, tensor_index, _) = &candidates[task.candidate_index];
            let tensor = &set.shards[*shard_index].inventory.tensors[*tensor_index];
            for value in decode_chunk(&tensor.dtype, &bytes[offset..slice_end])? {
                stats[task.candidate_index].push(value);
            }
        }
        index = group_end;
    }

    let mut out = Vec::with_capacity(candidates.len());
    for (candidate_index, (name, shard_index, tensor_index, total_elements)) in
        candidates.iter().enumerate()
    {
        if quotas[candidate_index] == 0 {
            out.push(None);
            continue;
        }
        let tensor = &set.shards[*shard_index].inventory.tensors[*tensor_index];
        let running = std::mem::take(&mut stats[candidate_index]);
        out.push(Some(running.finish(
            name,
            &tensor.dtype,
            *total_elements,
            "SAMPLED",
        )?));
    }
    Ok(out)
}

pub(super) fn stat_tensor_windows(
    file: &File,
    data_start: u64,
    tensor: &crate::formats::safetensors::SafetensorsTensor,
    windows: &[(u64, usize)],
    coverage: &str,
) -> Result<TensorStatistics> {
    let step = element_bytes(&tensor.dtype)
        .ok_or_else(|| anyhow!("unsupported numeric dtype '{}'", tensor.dtype))?;
    let elements = tensor_elements(tensor)?;
    let absolute = data_start
        .checked_add(tensor.start)
        .ok_or_else(|| anyhow!("tensor offset overflow"))?;
    let mut reader = file.try_clone()?;
    let mut stats = RunningStats::default();
    for (start_element, count) in windows {
        let byte_offset = start_element
            .checked_mul(step as u64)
            .and_then(|value| absolute.checked_add(value))
            .ok_or_else(|| anyhow!("tensor sample offset overflow"))?;
        let byte_count = count
            .checked_mul(step)
            .ok_or_else(|| anyhow!("tensor sample length overflow"))?;
        reader.seek(SeekFrom::Start(byte_offset))?;
        let mut bytes = vec![0_u8; byte_count];
        reader.read_exact(&mut bytes)?;
        for value in decode_chunk(&tensor.dtype, &bytes)? {
            stats.push(value);
        }
    }
    stats.finish(&tensor.name, &tensor.dtype, elements, coverage)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn delta_tensor_windows(
    base: &File,
    base_start: u64,
    left: &crate::formats::safetensors::SafetensorsTensor,
    derived: &File,
    derived_start: u64,
    right: &crate::formats::safetensors::SafetensorsTensor,
    windows: &[(u64, usize)],
    coverage: &str,
) -> Result<TensorDeltaStatistics> {
    let step = element_bytes(&left.dtype)
        .ok_or_else(|| anyhow!("unsupported numeric dtype '{}'", left.dtype))?;
    let elements = tensor_elements(left)?;
    let base_absolute = base_start
        .checked_add(left.start)
        .ok_or_else(|| anyhow!("base tensor offset overflow"))?;
    let derived_absolute = derived_start
        .checked_add(right.start)
        .ok_or_else(|| anyhow!("derived tensor offset overflow"))?;
    let mut a = base.try_clone()?;
    let mut b = derived.try_clone()?;
    let mut count = 0_u64;
    let mut l1 = 0.0;
    let mut l2 = 0.0;
    let mut max_abs = 0.0_f64;
    let mut dot = 0.0;
    let mut na = 0.0;
    let mut nb = 0.0;
    for (start_element, sample_count) in windows {
        let relative = start_element
            .checked_mul(step as u64)
            .ok_or_else(|| anyhow!("tensor sample offset overflow"))?;
        let byte_count = sample_count
            .checked_mul(step)
            .ok_or_else(|| anyhow!("tensor sample length overflow"))?;
        a.seek(SeekFrom::Start(
            base_absolute
                .checked_add(relative)
                .ok_or_else(|| anyhow!("base sample offset overflow"))?,
        ))?;
        b.seek(SeekFrom::Start(
            derived_absolute
                .checked_add(relative)
                .ok_or_else(|| anyhow!("derived sample offset overflow"))?,
        ))?;
        let mut ba = vec![0_u8; byte_count];
        let mut bb = vec![0_u8; byte_count];
        a.read_exact(&mut ba)?;
        b.read_exact(&mut bb)?;
        let va = decode_chunk(&left.dtype, &ba)?;
        let vb = decode_chunk(&right.dtype, &bb)?;
        for (x, y) in va.into_iter().zip(vb) {
            let d = y - x;
            l1 += d.abs();
            l2 += d * d;
            max_abs = max_abs.max(d.abs());
            dot += x * y;
            na += x * x;
            nb += y * y;
            count = count.saturating_add(1);
        }
    }
    let l2_delta = l2.sqrt();
    let base_norm = na.sqrt();
    Ok(TensorDeltaStatistics {
        tensor: left.name.clone(),
        elements: count,
        elements_total: elements,
        coverage: coverage.to_owned(),
        l1_delta: l1,
        l2_delta,
        normalized_frobenius_delta: if base_norm > 0.0 {
            l2_delta / base_norm
        } else {
            l2_delta
        },
        cosine_similarity: if na > 0.0 && nb > 0.0 {
            Some(dot / (na.sqrt() * nb.sqrt()))
        } else {
            None
        },
        max_abs_delta: max_abs,
    })
}

pub fn safetensors_statistics(path: &Path, max_tensors: usize) -> Result<Vec<TensorStatistics>> {
    let file = crate::safeio::open_readonly_nofollow(path)?;
    let len = file.metadata()?.len();
    let inv = crate::formats::safetensors::inventory_file(&file, len)?;
    let mut out = Vec::new();
    for tensor in inv.tensors.iter().take(max_tensors) {
        if element_bytes(&tensor.dtype).is_none() {
            continue;
        }
        out.push(stat_tensor(&file, inv.data_start, tensor)?);
    }
    Ok(out)
}

pub fn decode_tensor_values(
    path: &Path,
    tensor_name: &str,
    max_bytes: u64,
) -> Result<(Vec<u64>, String, Vec<f64>)> {
    let file = crate::safeio::open_readonly_nofollow(path)?;
    let inv = crate::formats::safetensors::inventory_file(&file, file.metadata()?.len())?;
    let tensor = inv
        .tensors
        .iter()
        .find(|v| v.name == tensor_name)
        .ok_or_else(|| anyhow!("tensor '{tensor_name}' not found"))?;
    let len = tensor.end.saturating_sub(tensor.start);
    if len > max_bytes {
        bail!("tensor '{tensor_name}' is {len} bytes, above bounded decode cap {max_bytes}");
    }
    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(
        inv.data_start
            .checked_add(tensor.start)
            .ok_or_else(|| anyhow!("tensor offset overflow"))?,
    ))?;
    let mut bytes = vec![0_u8; usize::try_from(len).context("tensor length does not fit usize")?];
    reader.read_exact(&mut bytes)?;
    let values = decode_chunk(&tensor.dtype, &bytes)?;
    Ok((tensor.shape.clone(), tensor.dtype.clone(), values))
}

pub(super) fn stat_tensor(
    file: &File,
    data_start: u64,
    tensor: &crate::formats::safetensors::SafetensorsTensor,
) -> Result<TensorStatistics> {
    let step = element_bytes(&tensor.dtype)
        .ok_or_else(|| anyhow!("unsupported numeric dtype '{}'", tensor.dtype))?;
    let mut reader = file.try_clone()?;
    let absolute = data_start
        .checked_add(tensor.start)
        .ok_or_else(|| anyhow!("tensor offset overflow"))?;
    reader.seek(SeekFrom::Start(absolute))?;
    let mut remaining = tensor.end.saturating_sub(tensor.start);
    let mut stats = RunningStats::default();
    let chunk_cap = CHUNK_BYTES - (CHUNK_BYTES % step);
    let mut buffer = vec![0_u8; chunk_cap.max(step)];
    while remaining > 0 {
        let want = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        let want = want - (want % step);
        if want == 0 {
            bail!(
                "tensor '{}' byte range is not aligned to dtype size",
                tensor.name
            );
        }
        reader.read_exact(&mut buffer[..want])?;
        for value in decode_chunk(&tensor.dtype, &buffer[..want])? {
            stats.push(value);
        }
        remaining = remaining.saturating_sub(want as u64);
    }
    stats.finish(
        &tensor.name,
        &tensor.dtype,
        tensor_elements(tensor)?,
        "EXHAUSTIVE",
    )
}

pub(super) fn delta_tensor(
    base: &File,
    base_start: u64,
    left: &crate::formats::safetensors::SafetensorsTensor,
    derived: &File,
    derived_start: u64,
    right: &crate::formats::safetensors::SafetensorsTensor,
) -> Result<TensorDeltaStatistics> {
    let step = element_bytes(&left.dtype)
        .ok_or_else(|| anyhow!("unsupported numeric dtype '{}'", left.dtype))?;
    let left_len = left.end.saturating_sub(left.start);
    let right_len = right.end.saturating_sub(right.start);
    if left_len != right_len {
        bail!("tensor '{}' byte lengths differ", left.name);
    }
    let mut a = base.try_clone()?;
    let mut b = derived.try_clone()?;
    a.seek(SeekFrom::Start(
        base_start
            .checked_add(left.start)
            .ok_or_else(|| anyhow!("base tensor offset overflow"))?,
    ))?;
    b.seek(SeekFrom::Start(
        derived_start
            .checked_add(right.start)
            .ok_or_else(|| anyhow!("derived tensor offset overflow"))?,
    ))?;
    let chunk_cap = CHUNK_BYTES - (CHUNK_BYTES % step);
    let mut ba = vec![0_u8; chunk_cap.max(step)];
    let mut bb = vec![0_u8; chunk_cap.max(step)];
    let mut remaining = left_len;
    let mut count = 0_u64;
    let mut l1 = 0.0;
    let mut l2 = 0.0;
    let mut max_abs = 0.0_f64;
    let mut dot = 0.0;
    let mut na = 0.0;
    let mut nb = 0.0;
    while remaining > 0 {
        let want = usize::try_from(remaining.min(ba.len() as u64)).unwrap_or(ba.len());
        let want = want - (want % step);
        if want == 0 {
            bail!(
                "tensor '{}' byte range is not aligned to dtype size",
                left.name
            );
        }
        a.read_exact(&mut ba[..want])?;
        b.read_exact(&mut bb[..want])?;
        let va = decode_chunk(&left.dtype, &ba[..want])?;
        let vb = decode_chunk(&right.dtype, &bb[..want])?;
        for (x, y) in va.into_iter().zip(vb) {
            let d = y - x;
            l1 += d.abs();
            l2 += d * d;
            max_abs = max_abs.max(d.abs());
            dot += x * y;
            na += x * x;
            nb += y * y;
            count = count.saturating_add(1);
        }
        remaining = remaining.saturating_sub(want as u64);
    }
    let l2_delta = l2.sqrt();
    let base_norm = na.sqrt();
    Ok(TensorDeltaStatistics {
        tensor: left.name.clone(),
        elements: count,
        elements_total: tensor_elements(left)?,
        coverage: "EXHAUSTIVE".to_owned(),
        l1_delta: l1,
        l2_delta,
        normalized_frobenius_delta: if base_norm > 0.0 {
            l2_delta / base_norm
        } else {
            l2_delta
        },
        cosine_similarity: if na > 0.0 && nb > 0.0 {
            Some(dot / (na.sqrt() * nb.sqrt()))
        } else {
            None
        },
        max_abs_delta: max_abs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_u8_tensor(path: &Path, name: &str, values: &[u8]) {
        write_u8_tensors(path, &[(name, values)]);
    }

    fn write_u8_tensors(path: &Path, tensors: &[(&str, &[u8])]) {
        let mut object = serde_json::Map::new();
        let mut payload = Vec::new();
        for (name, values) in tensors {
            let start = payload.len();
            payload.extend_from_slice(values);
            let end = payload.len();
            object.insert(
                (*name).to_owned(),
                serde_json::json!({
                    "dtype": "U8",
                    "shape": [values.len()],
                    "data_offsets": [start, end]
                }),
            );
        }
        let header =
            serde_json::to_vec(&serde_json::Value::Object(object)).expect("serialize header");
        let mut bytes = (header.len() as u64).to_le_bytes().to_vec();
        bytes.extend_from_slice(&header);
        bytes.extend_from_slice(&payload);
        std::fs::write(path, bytes).expect("write safetensors");
    }

    fn write_f32_tensor(path: &Path, name: &str, values: &[f32]) {
        let mut object = serde_json::Map::new();
        let byte_len = std::mem::size_of_val(values);
        object.insert(
            name.to_owned(),
            serde_json::json!({
                "dtype": "F32",
                "shape": [values.len()],
                "data_offsets": [0, byte_len]
            }),
        );
        let header =
            serde_json::to_vec(&serde_json::Value::Object(object)).expect("serialize header");
        let mut bytes = (header.len() as u64).to_le_bytes().to_vec();
        bytes.extend_from_slice(&header);
        for value in values {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        std::fs::write(path, bytes).expect("write safetensors");
    }

    #[test]
    fn package_directory_gets_numeric_statistics() {
        let root =
            std::env::temp_dir().join(format!("layerfault-weights-package-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create package");
        write_u8_tensor(&root.join("model.safetensors"), "weight", &[1, 2, 3, 4]);
        let stats = safetensors_statistics_for_target(&root, 100).expect("package stats");
        assert_eq!(stats.layout, "PACKAGE_SAFETENSORS");
        assert_eq!(stats.shards, 1);
        assert_eq!(stats.tensors_analyzed, 1);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn quick_sampling_represents_every_tensor_when_budget_allows() {
        let root = std::env::temp_dir().join(format!(
            "layerfault-weights-sampling-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create package");
        let a = vec![1_u8; 100];
        let b = vec![2_u8; 100];
        let c = vec![3_u8; 100];
        let d = vec![4_u8; 100];
        write_u8_tensors(
            &root.join("model.safetensors"),
            &[
                ("layer.a", &a),
                ("layer.b", &b),
                ("lm_head", &c),
                ("layer.d", &d),
            ],
        );
        let options = WeightAnalysisOptions {
            profile: NumericAnalysisProfile::Quick,
            sample_budget: 32,
            full_escalation_max_bytes: 64 * 1024 * 1024,
            extended_tensor_sample_values: 64,
            seed_material: "sha256:test-model".to_owned(),
        };
        let stats =
            safetensors_statistics_for_target_with_options(&root, &options).expect("sampled stats");
        assert_eq!(stats.tensors_available, 4);
        assert_eq!(stats.tensors_analyzed, 4);
        assert_eq!(stats.values_sampled, 32);
        assert!(stats.tensors.iter().all(|tensor| tensor.elements > 0));
        let means: std::collections::BTreeMap<_, _> = stats
            .tensors
            .iter()
            .map(|tensor| (tensor.tensor.as_str(), tensor.mean))
            .collect();
        assert_eq!(means.get("layer.a"), Some(&1.0));
        assert_eq!(means.get("layer.b"), Some(&2.0));
        assert_eq!(means.get("lm_head"), Some(&3.0));
        assert_eq!(means.get("layer.d"), Some(&4.0));
        assert_eq!(stats.coverage, "SAMPLED");
        assert!(stats.sampling_strategy.contains("PSEUDORANDOM"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn suspicious_small_tensor_escalates_to_exhaustive_analysis() {
        let root = std::env::temp_dir().join(format!(
            "layerfault-weights-escalation-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create package");
        let values = vec![2_000_000.0_f32; 1_024];
        write_f32_tensor(&root.join("model.safetensors"), "lm_head.weight", &values);
        let options = WeightAnalysisOptions {
            profile: NumericAnalysisProfile::Quick,
            sample_budget: 64,
            full_escalation_max_bytes: 64 * 1024 * 1024,
            extended_tensor_sample_values: 128,
            seed_material: "sha256:suspicious".to_owned(),
        };
        let stats = safetensors_statistics_for_target_with_options(&root, &options)
            .expect("escalated stats");
        assert_eq!(stats.tensors_escalated, 1);
        assert_eq!(stats.tensors_fully_analyzed, 1);
        assert_eq!(stats.tensors[0].elements, 1_024);
        assert_eq!(stats.tensors[0].coverage, "EXHAUSTIVE_ESCALATED");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn deep_profile_is_exhaustive() {
        let root =
            std::env::temp_dir().join(format!("layerfault-weights-deep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create package");
        let values = vec![7_u8; 2_048];
        write_u8_tensor(&root.join("model.safetensors"), "weight", &values);
        let options = WeightAnalysisOptions::for_review_profile("deep", "sha256:deep-model")
            .expect("deep options");
        let stats =
            safetensors_statistics_for_target_with_options(&root, &options).expect("deep stats");
        assert_eq!(stats.coverage, "EXHAUSTIVE");
        assert_eq!(stats.tensors_fully_analyzed, 1);
        assert_eq!(stats.values_sampled, 2_048);
        assert_eq!(stats.tensors[0].elements, stats.tensors[0].elements_total);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn indexed_shards_are_one_logical_weight_set() {
        let root =
            std::env::temp_dir().join(format!("layerfault-weights-shards-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create package");
        write_u8_tensor(&root.join("model-00001-of-00002.safetensors"), "a", &[1, 2]);
        write_u8_tensor(&root.join("model-00002-of-00002.safetensors"), "b", &[3, 4]);
        std::fs::write(
            root.join("model.safetensors.index.json"),
            br#"{"weight_map":{"a":"model-00001-of-00002.safetensors","b":"model-00002-of-00002.safetensors"}}"#,
        )
        .expect("write index");
        let stats = safetensors_statistics_for_target(&root, 100).expect("sharded stats");
        assert_eq!(stats.layout, "SHARDED_SAFETENSORS");
        assert_eq!(stats.shards, 2);
        assert_eq!(stats.tensors_analyzed, 2);
        let _ = std::fs::remove_dir_all(root);
    }
}
