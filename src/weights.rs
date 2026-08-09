//! Bounded numerical tensor statistics for supported Safetensors dtypes.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

const CHUNK_BYTES: usize = 4 * 1024 * 1024;
const SAMPLE_COALESCE_GAP_BYTES: u64 = 64 * 1024;
const SAMPLE_COALESCE_MAX_SPAN_BYTES: u64 = 4 * 1024 * 1024;

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

#[derive(Default)]
struct RunningStats {
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

/// Discover a logical Safetensors weight set from either a standalone file or
/// a model package directory. Index-driven sharded packages are preferred and
/// validated before use; all discovered members are kept inside the package
/// boundary and opened no-follow by the numerical analysis path.
pub fn discover_safetensors_weight_set(path: &Path) -> Result<Option<WeightSetDescriptor>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() {
        bail!(
            "Safetensors analysis target '{}' may not be a symlink",
            path.display()
        );
    }
    if metadata.is_file() {
        if path
            .extension()
            .and_then(|v| v.to_str())
            .is_some_and(|v| v.eq_ignore_ascii_case("safetensors"))
        {
            let _ = crate::safeio::open_readonly_nofollow(path)?;
            return Ok(Some(WeightSetDescriptor {
                layout: "STANDALONE_SAFETENSORS".to_owned(),
                files: vec![path.to_path_buf()],
            }));
        }
        return Ok(None);
    }
    if !metadata.is_dir() {
        return Ok(None);
    }
    let root = path.canonicalize()?;
    let index = root.join("model.safetensors.index.json");
    if index.exists() {
        let index_file = crate::safeio::open_readonly_nofollow(&index)?;
        let index_len = index_file.metadata()?.len();
        crate::formats::safetensors::validate_index(&index, &index_file, index_len)?;
        let bytes = crate::safeio::read_all_from_file(
            &index_file,
            crate::formats::safetensors::MAX_HEADER_BYTES,
        )?;
        let map = crate::formats::safetensors::parse_index_weight_map(&bytes)?;
        let mut names = std::collections::BTreeSet::new();
        for shard in map.values() {
            names.insert(shard.clone());
        }
        let mut files = Vec::with_capacity(names.len());
        for name in names {
            let candidate = root.join(&name);
            let metadata = std::fs::symlink_metadata(&candidate)
                .with_context(|| format!("Safetensors shard '{name}' is missing"))?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                bail!("Safetensors shard '{name}' is not an ordinary regular file");
            }
            let canonical = candidate.canonicalize()?;
            if !canonical.starts_with(&root) {
                bail!("Safetensors shard '{name}' resolves outside the package directory");
            }
            let _ = crate::safeio::open_readonly_nofollow(&candidate)?;
            files.push(canonical);
        }
        return Ok(Some(WeightSetDescriptor {
            layout: "SHARDED_SAFETENSORS".to_owned(),
            files,
        }));
    }

    for name in [
        "model.safetensors",
        "adapter_model.safetensors",
        "adapter.safetensors",
    ] {
        let candidate = root.join(name);
        if candidate.exists() {
            let metadata = std::fs::symlink_metadata(&candidate)?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                bail!(
                    "Safetensors member '{}' is not an ordinary regular file",
                    candidate.display()
                );
            }
            let canonical = candidate.canonicalize()?;
            if !canonical.starts_with(&root) {
                bail!(
                    "Safetensors member '{}' escapes the package directory",
                    candidate.display()
                );
            }
            let _ = crate::safeio::open_readonly_nofollow(&candidate)?;
            return Ok(Some(WeightSetDescriptor {
                layout: if name.starts_with("adapter") {
                    "LORA_ADAPTER_SAFETENSORS".to_owned()
                } else {
                    "PACKAGE_SAFETENSORS".to_owned()
                },
                files: vec![canonical],
            }));
        }
    }

    let mut files = Vec::new();
    for entry in std::fs::read_dir(&root)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let candidate = entry.path();
        let is_safetensors = candidate
            .extension()
            .and_then(|v| v.to_str())
            .is_some_and(|v| v.eq_ignore_ascii_case("safetensors"));
        if file_type.is_symlink() && is_safetensors {
            bail!(
                "Safetensors member '{}' may not be a symlink",
                candidate.display()
            );
        }
        if file_type.is_file() && is_safetensors {
            let canonical = candidate.canonicalize()?;
            if !canonical.starts_with(&root) {
                bail!(
                    "Safetensors member '{}' escapes the package directory",
                    candidate.display()
                );
            }
            files.push(canonical);
        }
    }
    files.sort();
    if files.is_empty() {
        Ok(None)
    } else {
        Ok(Some(WeightSetDescriptor {
            layout: if files.len() == 1 {
                "PACKAGE_SAFETENSORS".to_owned()
            } else {
                "SHARDED_SAFETENSORS_DISCOVERED".to_owned()
            },
            files,
        }))
    }
}

struct OpenShard {
    file: File,
    inventory: crate::formats::safetensors::SafetensorsInventory,
}

struct OpenWeightSet {
    descriptor: WeightSetDescriptor,
    shards: Vec<OpenShard>,
    tensors: std::collections::BTreeMap<String, (usize, usize)>,
}

fn open_weight_set(path: &Path) -> Result<Option<OpenWeightSet>> {
    let Some(descriptor) = discover_safetensors_weight_set(path)? else {
        return Ok(None);
    };
    let mut shards = Vec::with_capacity(descriptor.files.len());
    let mut tensors = std::collections::BTreeMap::new();
    for (shard_index, shard_path) in descriptor.files.iter().enumerate() {
        let file = crate::safeio::open_readonly_nofollow(shard_path)?;
        let inventory = crate::formats::safetensors::inventory_file(&file, file.metadata()?.len())?;
        for (tensor_index, tensor) in inventory.tensors.iter().enumerate() {
            if tensors
                .insert(tensor.name.clone(), (shard_index, tensor_index))
                .is_some()
            {
                bail!(
                    "duplicate tensor '{}' appears in multiple Safetensors shards",
                    tensor.name
                );
            }
        }
        shards.push(OpenShard { file, inventory });
    }
    Ok(Some(OpenWeightSet {
        descriptor,
        shards,
        tensors,
    }))
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

fn tensor_elements(tensor: &crate::formats::safetensors::SafetensorsTensor) -> Result<u64> {
    let step = element_bytes(&tensor.dtype)
        .ok_or_else(|| anyhow!("unsupported numeric dtype '{}'", tensor.dtype))?
        as u64;
    let bytes = tensor.end.saturating_sub(tensor.start);
    if !bytes.is_multiple_of(step) {
        bail!(
            "tensor '{}' byte range is not aligned to dtype size",
            tensor.name
        );
    }
    Ok(bytes / step)
}

fn saturating_u64_sum(values: impl IntoIterator<Item = u64>) -> u64 {
    values
        .into_iter()
        .fold(0_u64, |acc, value| acc.saturating_add(value))
}

fn security_tensor_weight(name: &str) -> u128 {
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
fn weighted_sample_quotas(elements: &[u64], names: &[&str], budget: usize) -> Vec<usize> {
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

fn sampling_seed_sha256(seed_material: &str) -> String {
    format!(
        "sha256:{}",
        hex::encode(Sha256::digest(seed_material.as_bytes()))
    )
}

fn seeded_position(seed_material: &str, tensor_name: &str, counter: u64, upper: u64) -> u64 {
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
fn sample_windows_seeded(
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

fn coalesce_windows(
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

fn tensor_sample_requires_escalation(report: &TensorStatistics) -> bool {
    if report.elements < 16 {
        return false;
    }
    let max_abs = report.max.abs().max(report.min.abs());
    max_abs > 1_000_000.0
        || report.mean.abs() > 10_000.0
        || report.variance > 1.0e12
        || report.sparsity >= 0.9999
}

fn tensor_delta_requires_escalation(report: &TensorDeltaStatistics) -> bool {
    if report.elements < 16 {
        return false;
    }
    report.normalized_frobenius_delta > 0.50
        || report.max_abs_delta > 1_000_000.0
        || report.cosine_similarity.is_some_and(|value| value < 0.80)
}

#[derive(Debug, Clone)]
struct SampleReadTask {
    candidate_index: usize,
    shard_index: usize,
    byte_offset: u64,
    byte_len: usize,
}

fn stat_weight_set_windows_batched(
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

fn stat_tensor_windows(
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
fn delta_tensor_windows(
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

fn stat_tensor(
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

fn delta_tensor(
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

pub fn element_bytes(dtype: &str) -> Option<usize> {
    match dtype.to_ascii_uppercase().as_str() {
        "BOOL" | "I8" | "U8" => Some(1),
        "I16" | "U16" | "F16" | "BF16" => Some(2),
        "I32" | "U32" | "F32" => Some(4),
        "I64" | "U64" | "F64" => Some(8),
        _ => None,
    }
}

pub fn decode_chunk(dtype: &str, bytes: &[u8]) -> Result<Vec<f64>> {
    let step =
        element_bytes(dtype).ok_or_else(|| anyhow!("unsupported numeric dtype '{dtype}'"))?;
    if !bytes.len().is_multiple_of(step) {
        bail!("numeric tensor byte length is not aligned to dtype size");
    }
    let mut out = Vec::with_capacity(bytes.len() / step);
    for chunk in bytes.chunks_exact(step) {
        let value = match dtype.to_ascii_uppercase().as_str() {
            "BOOL" => {
                if chunk[0] == 0 {
                    0.0
                } else {
                    1.0
                }
            }
            "I8" => i8::from_le_bytes([chunk[0]]) as f64,
            "U8" => chunk[0] as f64,
            "I16" => i16::from_le_bytes(chunk.try_into().unwrap_or([0; 2])) as f64,
            "U16" => u16::from_le_bytes(chunk.try_into().unwrap_or([0; 2])) as f64,
            "F16" => f16_to_f32(u16::from_le_bytes(chunk.try_into().unwrap_or([0; 2]))) as f64,
            "BF16" => f32::from_bits(
                (u16::from_le_bytes(chunk.try_into().unwrap_or([0; 2])) as u32) << 16,
            ) as f64,
            "I32" => i32::from_le_bytes(chunk.try_into().unwrap_or([0; 4])) as f64,
            "U32" => u32::from_le_bytes(chunk.try_into().unwrap_or([0; 4])) as f64,
            "F32" => f32::from_le_bytes(chunk.try_into().unwrap_or([0; 4])) as f64,
            "I64" => i64::from_le_bytes(chunk.try_into().unwrap_or([0; 8])) as f64,
            "U64" => u64::from_le_bytes(chunk.try_into().unwrap_or([0; 8])) as f64,
            "F64" => f64::from_le_bytes(chunk.try_into().unwrap_or([0; 8])),
            _ => unreachable!(),
        };
        if !value.is_finite() {
            bail!("numeric tensor contains non-finite value");
        }
        out.push(value);
    }
    Ok(out)
}

fn f16_to_f32(value: u16) -> f32 {
    let sign = ((value >> 15) & 1) as u32;
    let exp = ((value >> 10) & 0x1f) as u32;
    let frac = (value & 0x03ff) as u32;
    let bits = match exp {
        0 => {
            if frac == 0 {
                sign << 31
            } else {
                let mut f = frac;
                let mut e = -14_i32;
                while (f & 0x400) == 0 {
                    f <<= 1;
                    e -= 1;
                }
                f &= 0x3ff;
                (sign << 31) | (((e + 127) as u32) << 23) | (f << 13)
            }
        }
        0x1f => (sign << 31) | 0x7f80_0000 | (frac << 13),
        _ => (sign << 31) | ((exp + 112) << 23) | (frac << 13),
    };
    f32::from_bits(bits)
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
    fn decodes_basic_f16() {
        assert_eq!(f16_to_f32(0x3c00), 1.0);
        assert_eq!(f16_to_f32(0xc000), -2.0);
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
