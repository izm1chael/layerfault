//! LoRA adapter inspection, compatibility and bounded spectral analysis.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const MAX_ADAPTER_TENSOR_BYTES: u64 = 128 * 1024 * 1024;
const MAX_SPECTRAL_DIM: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoraConfig {
    pub base_model_name_or_path: Option<String>,
    pub r: Option<u64>,
    pub lora_alpha: Option<f64>,
    pub target_modules: Vec<String>,
    pub modules_to_save: Vec<String>,
    pub bias: Option<String>,
    pub task_type: Option<String>,
    pub fan_in_fan_out: bool,
    pub peft_type: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoraTensorAnalysis {
    pub tensor: String,
    pub shape: Vec<u64>,
    pub dtype: String,
    pub statistics: Option<crate::weights::TensorStatistics>,
    pub spectral: Option<SpectralMetrics>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SpectralMetrics {
    pub singular_values: Vec<f64>,
    pub spectral_concentration: f64,
    pub singular_value_entropy: f64,
    pub numerical_rank: usize,
    pub rank_utilization: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoraReport {
    pub root: String,
    pub config: LoraConfig,
    pub adapter_file: String,
    pub base_compatible: Option<bool>,
    pub missing_target_modules: Vec<String>,
    pub tensors: Vec<LoraTensorAnalysis>,
    pub module_norm_variance: Option<f64>,
    pub extreme_module_concentration: Option<f64>,
    pub scaling: Option<f64>,
    pub mean_tensor_sparsity: Option<f64>,
    pub norm_outlier_count: usize,
    pub max_spectral_concentration: Option<f64>,
    pub targeted_tensor_fraction: Option<f64>,
    /// Advisory numerical/metadata observations. These are surfaced for review
    /// but do not by themselves raise the model security decision: legitimate
    /// adapters can naturally exhibit strong spectral concentration, uneven
    /// norms, or modules_to_save.
    pub observations: Vec<String>,
    pub findings: Vec<String>,
}

pub fn inspect_adapter(
    root: &Path,
    base: Option<&crate::modelmeta::ModelSnapshot>,
) -> Result<LoraReport> {
    let config_path = root.join("adapter_config.json");
    let adapter_path = find_adapter_file(root)?;
    let config = parse_config(&config_path)?;
    let file = crate::safeio::open_readonly_nofollow(&adapter_path)?;
    let inv = crate::formats::safetensors::inventory_file(&file, file.metadata()?.len())?;
    let base_names: BTreeSet<&str> = base
        .map(|b| b.tensors.iter().map(|v| v.name.as_str()).collect())
        .unwrap_or_default();
    let mut missing = Vec::new();
    if !base_names.is_empty() {
        for target in &config.target_modules {
            if !base_names
                .iter()
                .any(|name| name.ends_with(target) || name.contains(&format!(".{target}.")))
            {
                missing.push(target.clone());
            }
        }
    }
    let base_compatible = if base.is_none() {
        None
    } else {
        Some(missing.is_empty())
    };
    let stats = crate::weights::safetensors_statistics(&adapter_path, inv.tensors.len())?;
    let stats_map: BTreeMap<_, _> = stats.into_iter().map(|v| (v.tensor.clone(), v)).collect();
    let mut tensors = Vec::new();
    let mut norms = Vec::new();
    let mut sparsities = Vec::new();
    let mut targeted_tensors = 0_usize;
    for tensor in &inv.tensors {
        let stat = stats_map.get(&tensor.name).cloned();
        if let Some(stat) = &stat {
            norms.push(stat.frobenius);
            sparsities.push(stat.sparsity);
        }
        if config.target_modules.iter().any(|target| {
            tensor.name.ends_with(target) || tensor.name.contains(&format!(".{target}."))
        }) {
            targeted_tensors = targeted_tensors.saturating_add(1);
        }
        let spectral = if tensor.shape.len() == 2
            && tensor
                .shape
                .iter()
                .all(|v| usize::try_from(*v).ok().is_some_and(|n| n <= 65_536))
            && tensor.end.saturating_sub(tensor.start) <= MAX_ADAPTER_TENSOR_BYTES
            && crate::weights::element_bytes(&tensor.dtype).is_some()
        {
            let (_, _, values) = crate::weights::decode_tensor_values(
                &adapter_path,
                &tensor.name,
                MAX_ADAPTER_TENSOR_BYTES,
            )?;
            spectral_metrics(&values, &tensor.shape).ok()
        } else {
            None
        };
        tensors.push(LoraTensorAnalysis {
            tensor: tensor.name.clone(),
            shape: tensor.shape.clone(),
            dtype: tensor.dtype.clone(),
            statistics: stat,
            spectral,
        });
    }
    let module_norm_variance = variance(&norms);
    let extreme_module_concentration = if norms.is_empty() {
        None
    } else {
        let total: f64 = norms.iter().sum();
        let max = norms.iter().copied().fold(0.0_f64, f64::max);
        Some(if total > 0.0 { max / total } else { 0.0 })
    };
    let scaling = match (config.lora_alpha, config.r) {
        (Some(alpha), Some(rank)) if rank > 0 => Some(alpha / rank as f64),
        _ => None,
    };
    let mean_tensor_sparsity = if sparsities.is_empty() {
        None
    } else {
        Some(sparsities.iter().sum::<f64>() / sparsities.len() as f64)
    };
    let norm_outlier_count = if norms.len() < 4 {
        0
    } else {
        let mut ordered = norms.clone();
        ordered.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let median = ordered[ordered.len() / 2];
        if median <= 0.0 {
            0
        } else {
            norms
                .iter()
                .filter(|value| **value > median * 25.0 || **value < median / 25.0)
                .count()
        }
    };
    let max_spectral_concentration = tensors
        .iter()
        .filter_map(|tensor| {
            tensor
                .spectral
                .as_ref()
                .map(|value| value.spectral_concentration)
        })
        .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let targeted_tensor_fraction = if tensors.is_empty() || config.target_modules.is_empty() {
        None
    } else {
        Some(targeted_tensors as f64 / tensors.len() as f64)
    };
    let mut findings = Vec::new();
    if base_compatible == Some(false) {
        findings.push("LF-ADAPTER-BASE-MISMATCH".to_owned());
    }
    if config.r.is_some_and(|r| r == 0 || r > 4096) {
        findings.push("LF-ADAPTER-RANK-ANOMALY".to_owned());
    }
    if extreme_module_concentration.is_some_and(|v| v > 0.90 && norms.len() >= 4) {
        findings.push("LF-ADAPTER-WEIGHT-ANOMALY".to_owned());
    }
    let mut observations = Vec::new();
    if scaling.is_some_and(|value| !(1.0e-4..=128.0).contains(&value)) {
        observations.push("LF-ADAPTER-SCALING-ANOMALY".to_owned());
    }
    if norm_outlier_count > 0 {
        observations.push("LF-ADAPTER-NORM-OUTLIER".to_owned());
    }
    if max_spectral_concentration.is_some_and(|value| value > 0.995) {
        observations.push("LF-ADAPTER-SPECTRAL-CONCENTRATION".to_owned());
    }
    if !config.modules_to_save.is_empty() {
        observations.push("LF-ADAPTER-MODULES-TO-SAVE".to_owned());
    }
    observations.sort();
    observations.dedup();
    findings.sort();
    findings.dedup();
    Ok(LoraReport {
        root: root.display().to_string(),
        config,
        adapter_file: adapter_path.display().to_string(),
        base_compatible,
        missing_target_modules: missing,
        tensors,
        module_norm_variance,
        extreme_module_concentration,
        scaling,
        mean_tensor_sparsity,
        norm_outlier_count,
        max_spectral_concentration,
        targeted_tensor_fraction,
        observations,
        findings,
    })
}

pub fn parse_config(path: &Path) -> Result<LoraConfig> {
    let file = crate::safeio::open_readonly_nofollow(path)
        .with_context(|| format!("unable to open LoRA config '{}'", path.display()))?;
    let bytes = crate::safeio::read_all_from_file(&file, 4 * 1024 * 1024)?;
    let value: Value = serde_json::from_slice(&bytes).context("invalid adapter_config.json")?;
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("adapter_config.json must be an object"))?;
    let string_list = |key: &str| -> Vec<String> {
        match object.get(key) {
            Some(Value::Array(values)) => values
                .iter()
                .filter_map(Value::as_str)
                .take(4096)
                .map(str::to_owned)
                .collect(),
            Some(Value::String(value)) => vec![value.clone()],
            _ => Vec::new(),
        }
    };
    Ok(LoraConfig {
        base_model_name_or_path: object
            .get("base_model_name_or_path")
            .and_then(Value::as_str)
            .map(str::to_owned),
        r: object.get("r").and_then(Value::as_u64),
        lora_alpha: object
            .get("lora_alpha")
            .and_then(Value::as_f64)
            .or_else(|| {
                object
                    .get("lora_alpha")
                    .and_then(Value::as_u64)
                    .map(|v| v as f64)
            }),
        target_modules: string_list("target_modules"),
        modules_to_save: string_list("modules_to_save"),
        bias: object
            .get("bias")
            .and_then(Value::as_str)
            .map(str::to_owned),
        task_type: object
            .get("task_type")
            .and_then(Value::as_str)
            .map(str::to_owned),
        fan_in_fan_out: object
            .get("fan_in_fan_out")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        peft_type: object
            .get("peft_type")
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

fn find_adapter_file(root: &Path) -> Result<PathBuf> {
    for name in ["adapter_model.safetensors", "adapter.safetensors"] {
        let candidate = root.join(name);
        let Ok(metadata) = std::fs::symlink_metadata(&candidate) else {
            continue;
        };
        if metadata.file_type().is_symlink() {
            bail!(
                "LoRA adapter weight '{}' may not be a symlink",
                candidate.display()
            );
        }
        if metadata.is_file() {
            let _ = crate::safeio::open_readonly_nofollow(&candidate)?;
            return Ok(candidate);
        }
    }
    bail!("LoRA package has no adapter_model.safetensors")
}

fn spectral_metrics(values: &[f64], shape: &[u64]) -> Result<SpectralMetrics> {
    if shape.len() != 2 {
        bail!("spectral metrics require a matrix");
    }
    let rows = usize::try_from(shape[0]).context("row dimension too large")?;
    let cols = usize::try_from(shape[1]).context("column dimension too large")?;
    if rows == 0 || cols == 0 || rows.checked_mul(cols) != Some(values.len()) {
        bail!("matrix shape does not match tensor values");
    }
    let n = rows.min(cols);
    if n > MAX_SPECTRAL_DIM {
        bail!("smaller matrix dimension {n} exceeds spectral cap {MAX_SPECTRAL_DIM}");
    }
    let mut gram = vec![0.0_f64; n * n];
    if rows <= cols {
        for i in 0..rows {
            for j in i..rows {
                let mut sum = 0.0;
                for k in 0..cols {
                    sum += values[i * cols + k] * values[j * cols + k];
                }
                gram[i * n + j] = sum;
                gram[j * n + i] = sum;
            }
        }
    } else {
        for i in 0..cols {
            for j in i..cols {
                let mut sum = 0.0;
                for k in 0..rows {
                    sum += values[k * cols + i] * values[k * cols + j];
                }
                gram[i * n + j] = sum;
                gram[j * n + i] = sum;
            }
        }
    }
    let mut eig = jacobi_eigenvalues(gram, n, 64 * n.max(1));
    for v in &mut eig {
        *v = v.max(0.0).sqrt();
    }
    eig.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
    let energy: f64 = eig.iter().map(|v| v * v).sum();
    let concentration = if energy > 0.0 {
        eig.first().map(|v| v * v / energy).unwrap_or(0.0)
    } else {
        0.0
    };
    let mut entropy = 0.0;
    if energy > 0.0 {
        for s in &eig {
            let p = s * s / energy;
            if p > 0.0 {
                entropy -= p * p.ln();
            }
        }
    }
    let threshold = eig.first().copied().unwrap_or(0.0) * 1e-6;
    let numerical_rank = eig.iter().filter(|v| **v > threshold).count();
    Ok(SpectralMetrics {
        singular_values: eig,
        spectral_concentration: concentration,
        singular_value_entropy: entropy,
        numerical_rank,
        rank_utilization: if n > 0 {
            numerical_rank as f64 / n as f64
        } else {
            0.0
        },
    })
}

fn jacobi_eigenvalues(mut a: Vec<f64>, n: usize, iterations: usize) -> Vec<f64> {
    if n == 0 {
        return Vec::new();
    }
    for _ in 0..iterations {
        let mut p = 0usize;
        let mut q = 0usize;
        let mut max = 0.0_f64;
        for i in 0..n {
            for j in (i + 1)..n {
                let v = a[i * n + j].abs();
                if v > max {
                    max = v;
                    p = i;
                    q = j;
                }
            }
        }
        if max < 1e-12 {
            break;
        }
        let app = a[p * n + p];
        let aqq = a[q * n + q];
        let apq = a[p * n + q];
        let phi = 0.5 * (2.0 * apq).atan2(aqq - app);
        let c = phi.cos();
        let s = phi.sin();
        for k in 0..n {
            if k != p && k != q {
                let akp = a[k * n + p];
                let akq = a[k * n + q];
                let np = c * akp - s * akq;
                let nq = s * akp + c * akq;
                a[k * n + p] = np;
                a[p * n + k] = np;
                a[k * n + q] = nq;
                a[q * n + k] = nq;
            }
        }
        a[p * n + p] = c * c * app - 2.0 * s * c * apq + s * s * aqq;
        a[q * n + q] = s * s * app + 2.0 * s * c * apq + c * c * aqq;
        a[p * n + q] = 0.0;
        a[q * n + p] = 0.0;
    }
    (0..n).map(|i| a[i * n + i]).collect()
}

fn variance(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    Some(values.iter().map(|v| (v - mean) * (v - mean)).sum::<f64>() / values.len() as f64)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_matrix_has_flat_singular_values() {
        let metrics = spectral_metrics(&[1.0, 0.0, 0.0, 1.0], &[2, 2]).unwrap();
        assert_eq!(metrics.numerical_rank, 2);
        assert!((metrics.spectral_concentration - 0.5).abs() < 1e-6);
    }
}

const MAX_MERGE_TENSORS: usize = 512;
const MAX_MERGE_OPS_PER_TENSOR: u64 = 100_000_000;
const DEFAULT_MERGE_TOLERANCE: f64 = 5e-3;

#[derive(Debug, Clone, Serialize)]
pub struct LoraMergeTensorVerification {
    pub module: String,
    pub base_tensor: String,
    pub adapter_a: String,
    pub adapter_b: String,
    pub expected_delta_norm: f64,
    pub observed_delta_norm: f64,
    pub max_abs_residual: f64,
    pub normalized_residual: f64,
    pub tolerance: f64,
    pub state: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoraMergeVerification {
    pub state: String,
    pub scale: f64,
    pub tensors: Vec<LoraMergeTensorVerification>,
    pub non_target_changed: Vec<String>,
    pub unsupported: Vec<String>,
    pub boundary: String,
}

/// Verify a common PEFT linear LoRA merge against standalone Safetensors base
/// and merged artifacts. Unsupported layouts are reported as UNVERIFIED rather
/// than being guessed.
pub fn verify_merge(
    base_path: &Path,
    adapter_root: &Path,
    merged_path: &Path,
) -> Result<LoraMergeVerification> {
    let config = parse_config(&adapter_root.join("adapter_config.json"))?;
    let adapter_path = find_adapter_file(adapter_root)?;
    let r = config
        .r
        .ok_or_else(|| anyhow!("LoRA merge verification requires adapter rank r"))?;
    if r == 0 {
        bail!("LoRA rank must be non-zero");
    }
    let alpha = config.lora_alpha.unwrap_or(r as f64);
    let scale = alpha / r as f64;

    let base_file = crate::safeio::open_readonly_nofollow(base_path)?;
    let merged_file = crate::safeio::open_readonly_nofollow(merged_path)?;
    let adapter_file = crate::safeio::open_readonly_nofollow(&adapter_path)?;
    let base_inv =
        crate::formats::safetensors::inventory_file(&base_file, base_file.metadata()?.len())?;
    let merged_inv =
        crate::formats::safetensors::inventory_file(&merged_file, merged_file.metadata()?.len())?;
    let adapter_inv =
        crate::formats::safetensors::inventory_file(&adapter_file, adapter_file.metadata()?.len())?;

    let base_map: BTreeMap<&str, &crate::formats::safetensors::SafetensorsTensor> = base_inv
        .tensors
        .iter()
        .map(|t| (t.name.as_str(), t))
        .collect();
    let merged_map: BTreeMap<&str, &crate::formats::safetensors::SafetensorsTensor> = merged_inv
        .tensors
        .iter()
        .map(|t| (t.name.as_str(), t))
        .collect();
    let adapter_map: BTreeMap<&str, &crate::formats::safetensors::SafetensorsTensor> = adapter_inv
        .tensors
        .iter()
        .map(|t| (t.name.as_str(), t))
        .collect();

    let mut pairs = BTreeMap::<String, (String, String)>::new();
    for tensor in &adapter_inv.tensors {
        if let Some(module) = strip_adapter_suffix(&tensor.name, ".lora_A.weight") {
            pairs.entry(module.to_owned()).or_default().0 = tensor.name.clone();
        } else if let Some(module) = strip_adapter_suffix(&tensor.name, ".lora_B.weight") {
            pairs.entry(module.to_owned()).or_default().1 = tensor.name.clone();
        }
    }
    if pairs.is_empty() {
        bail!("adapter has no supported .lora_A.weight/.lora_B.weight tensor pairs");
    }
    if pairs.len() > MAX_MERGE_TENSORS {
        bail!("adapter affects more than {MAX_MERGE_TENSORS} supported merge tensors");
    }

    let mut verified = Vec::new();
    let mut unsupported = Vec::new();
    let mut target_base_names = BTreeSet::new();

    for (module, (a_name, b_name)) in pairs {
        if a_name.is_empty() || b_name.is_empty() {
            unsupported.push(format!("{module}: incomplete A/B pair"));
            continue;
        }
        let Some(a_spec) = adapter_map.get(a_name.as_str()).copied() else {
            unsupported.push(format!("{module}: missing A tensor"));
            continue;
        };
        let Some(b_spec) = adapter_map.get(b_name.as_str()).copied() else {
            unsupported.push(format!("{module}: missing B tensor"));
            continue;
        };
        if a_spec.shape.len() != 2 || b_spec.shape.len() != 2 {
            unsupported.push(format!(
                "{module}: only 2-D linear LoRA matrices are supported"
            ));
            continue;
        }
        let ar = usize::try_from(a_spec.shape[0]).context("LoRA A rank too large")?;
        let input = usize::try_from(a_spec.shape[1]).context("LoRA input dimension too large")?;
        let output = usize::try_from(b_spec.shape[0]).context("LoRA output dimension too large")?;
        let br = usize::try_from(b_spec.shape[1]).context("LoRA B rank too large")?;
        if ar != br || ar != usize::try_from(r).unwrap_or(usize::MAX) {
            unsupported.push(format!(
                "{module}: adapter matrix rank disagrees with config r={r}"
            ));
            continue;
        }
        let ops = (output as u64)
            .saturating_mul(input as u64)
            .saturating_mul(ar as u64);
        if ops > MAX_MERGE_OPS_PER_TENSOR {
            unsupported.push(format!(
                "{module}: merge verification exceeds bounded matrix operation cap"
            ));
            continue;
        }
        let Some(base_name) = resolve_base_tensor_name(&module, &base_map) else {
            unsupported.push(format!(
                "{module}: unable to map adapter module to base tensor"
            ));
            continue;
        };
        let Some(base_spec) = base_map.get(base_name.as_str()).copied() else {
            unsupported.push(format!("{module}: base tensor missing"));
            continue;
        };
        let Some(merged_spec) = merged_map.get(base_name.as_str()).copied() else {
            unsupported.push(format!("{module}: merged tensor missing"));
            continue;
        };
        if base_spec.shape != merged_spec.shape || base_spec.dtype != merged_spec.dtype {
            unsupported.push(format!("{module}: base/merged tensor schema differs"));
            continue;
        }
        let expected_shape = if config.fan_in_fan_out {
            vec![input as u64, output as u64]
        } else {
            vec![output as u64, input as u64]
        };
        if base_spec.shape != expected_shape {
            unsupported.push(format!(
                "{module}: base shape {:?} does not match expected LoRA merge shape {:?}",
                base_spec.shape, expected_shape
            ));
            continue;
        }

        let (_, _, a) =
            crate::weights::decode_tensor_values(&adapter_path, &a_name, MAX_ADAPTER_TENSOR_BYTES)?;
        let (_, _, b) =
            crate::weights::decode_tensor_values(&adapter_path, &b_name, MAX_ADAPTER_TENSOR_BYTES)?;
        let (_, _, base) = crate::weights::decode_tensor_values(
            base_path,
            &base_name,
            MAX_ADAPTER_TENSOR_BYTES.saturating_mul(16),
        )?;
        let (_, _, merged) = crate::weights::decode_tensor_values(
            merged_path,
            &base_name,
            MAX_ADAPTER_TENSOR_BYTES.saturating_mul(16),
        )?;
        if base.len() != merged.len() {
            unsupported.push(format!("{module}: decoded base/merged lengths differ"));
            continue;
        }

        let mut expected_delta_norm2 = 0.0;
        let mut observed_delta_norm2 = 0.0;
        let mut residual_norm2 = 0.0;
        let mut max_abs_residual = 0.0_f64;
        for o in 0..output {
            for i in 0..input {
                let mut dot = 0.0;
                for k in 0..ar {
                    dot += b[o * ar + k] * a[k * input + i];
                }
                let expected_delta = dot * scale;
                let index = if config.fan_in_fan_out {
                    i * output + o
                } else {
                    o * input + i
                };
                let observed_delta = merged[index] - base[index];
                let residual = observed_delta - expected_delta;
                expected_delta_norm2 += expected_delta * expected_delta;
                observed_delta_norm2 += observed_delta * observed_delta;
                residual_norm2 += residual * residual;
                max_abs_residual = max_abs_residual.max(residual.abs());
            }
        }
        let expected_delta_norm = expected_delta_norm2.sqrt();
        let observed_delta_norm = observed_delta_norm2.sqrt();
        let residual_norm = residual_norm2.sqrt();
        let normalized_residual = if expected_delta_norm > 1e-12 {
            residual_norm / expected_delta_norm
        } else {
            residual_norm
        };
        let tolerance = merge_tolerance(&base_spec.dtype);
        let state = if normalized_residual <= tolerance && max_abs_residual <= tolerance * 4.0 {
            "VERIFIED"
        } else {
            "CONTRADICTED"
        }
        .to_owned();
        target_base_names.insert(base_name.clone());
        verified.push(LoraMergeTensorVerification {
            module,
            base_tensor: base_name,
            adapter_a: a_name,
            adapter_b: b_name,
            expected_delta_norm,
            observed_delta_norm,
            max_abs_residual,
            normalized_residual,
            tolerance,
            state,
        });
    }

    // For an ordinary LoRA merge, tensors outside the affected set should be
    // byte-identical when dtype/layout are unchanged. This is a strong and cheap
    // invariant that avoids decoding every unrelated tensor.
    let mut non_target_changed = Vec::new();
    for base_spec in &base_inv.tensors {
        if target_base_names.contains(&base_spec.name) {
            continue;
        }
        let Some(merged_spec) = merged_map.get(base_spec.name.as_str()).copied() else {
            non_target_changed.push(format!("{} (missing)", base_spec.name));
            continue;
        };
        if base_spec.dtype != merged_spec.dtype || base_spec.shape != merged_spec.shape {
            non_target_changed.push(format!("{} (schema changed)", base_spec.name));
            continue;
        }
        let base_bytes = crate::formats::safetensors::read_tensor_bytes(
            &base_file,
            &base_inv,
            base_spec,
            MAX_ADAPTER_TENSOR_BYTES.saturating_mul(32),
        )?;
        let merged_bytes = crate::formats::safetensors::read_tensor_bytes(
            &merged_file,
            &merged_inv,
            merged_spec,
            MAX_ADAPTER_TENSOR_BYTES.saturating_mul(32),
        )?;
        if base_bytes != merged_bytes {
            non_target_changed.push(base_spec.name.clone());
        }
        if non_target_changed.len() >= 1024 {
            break;
        }
    }

    let any_contradicted =
        verified.iter().any(|v| v.state == "CONTRADICTED") || !non_target_changed.is_empty();
    let all_required_verified = !verified.is_empty()
        && verified.iter().all(|v| v.state == "VERIFIED")
        && unsupported.is_empty()
        && non_target_changed.is_empty();
    let state = if any_contradicted {
        "CONTRADICTED"
    } else if all_required_verified {
        "VERIFIED"
    } else {
        "UNVERIFIED"
    }
    .to_owned();
    Ok(LoraMergeVerification{state,scale,tensors:verified,non_target_changed,unsupported,boundary:"LoRA merge verification proves only the supported numerical merge relationship between the supplied base, adapter and merged Safetensors artifacts. It does not prove the adapter is benign.".to_owned()})
}

fn strip_adapter_suffix<'a>(name: &'a str, suffix: &str) -> Option<&'a str> {
    name.strip_suffix(suffix)
}
fn resolve_base_tensor_name(
    module: &str,
    base: &BTreeMap<&str, &crate::formats::safetensors::SafetensorsTensor>,
) -> Option<String> {
    let mut candidates = Vec::new();
    candidates.push(format!("{module}.weight"));
    for prefix in ["base_model.model.", "base_model."] {
        if let Some(rest) = module.strip_prefix(prefix) {
            candidates.push(format!("{rest}.weight"));
        }
    }
    if let Some(rest) = module.strip_prefix("model.") {
        candidates.push(format!("{rest}.weight"));
    }
    candidates
        .into_iter()
        .find(|c| base.contains_key(c.as_str()))
        .or_else(|| {
            let suffix = format!("{}.weight", module.rsplit('.').next().unwrap_or(module));
            let matches: Vec<_> = base
                .keys()
                .filter(|name| name.ends_with(&suffix))
                .take(2)
                .collect();
            (matches.len() == 1).then(|| (*matches[0]).to_owned())
        })
}
fn merge_tolerance(dtype: &str) -> f64 {
    match dtype {
        "F32" | "F64" => 1e-5,
        "F16" | "BF16" => DEFAULT_MERGE_TOLERANCE,
        _ => DEFAULT_MERGE_TOLERANCE,
    }
}
