//! MLX model and package conventions inspector.
//!
//! Apple Silicon MLX models use Safetensors weights + JSON architecture configs + optional custom
//! modeling code. This module validates package members and architecture metadata statically.

use crate::finding_evidence::{EvidenceSubject, FindingBuilder};
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use anyhow::Result;
use std::path::Path;

/// Root-level files that indicate a *different* framework's native weights ship
/// alongside the Safetensors export. Their presence means the Safetensors file
/// is an additional artifact rather than evidence this package is the primary
/// output of an `mlx_lm.convert` conversion.
const COMPETING_FRAMEWORK_FILES: &[&str] = &[
    "pytorch_model.bin",
    "pytorch_model.bin.index.json",
    "tf_model.h5",
    "flax_model.msgpack",
    "model.ckpt.index",
    "model.onnx",
];

/// Best-effort classification of a package directory as an MLX package.
///
/// There is no universal, unambiguous marker: an unquantized `mlx_lm.convert`
/// output is structurally identical to a generic Safetensors + config.json
/// package (this is by design — see the module doc comment). Two signals are
/// used, in order of confidence:
///
/// - `config.json` carries a top-level `quantization` key. `mlx_lm.convert`
///   writes this key (not `quantization_config`, which is the standard
///   Transformers/bitsandbytes/GPTQ key name) when producing a quantized
///   model, so this is a fairly reliable positive signal.
/// - Otherwise, fall back to config + Safetensors weights present with none
///   of `COMPETING_FRAMEWORK_FILES` alongside them. This deliberately also
///   matches some plain Safetensors-only HF repos that were never touched by
///   MLX tooling; callers should treat this as an additive classification
///   (run the MLX checks alongside, not instead of, generic package scanning)
///   so a false positive here costs an extra informational finding rather
///   than a missed generic check.
pub fn looks_like_mlx_package(root: &Path) -> bool {
    let config_path = root.join("config.json");
    let has_weights = root.join("model.safetensors").exists()
        || root.join("model.safetensors.index.json").exists();
    if !has_weights || !config_path.exists() {
        return false;
    }

    if config_has_quantization_key(&config_path) {
        return true;
    }

    !COMPETING_FRAMEWORK_FILES
        .iter()
        .any(|name| root.join(name).exists())
}

fn config_has_quantization_key(config_path: &Path) -> bool {
    let Ok(file) = crate::safeio::open_readonly_nofollow(config_path) else {
        return false;
    };
    let Ok(bytes) = crate::safeio::read_all_from_file(&file, 4 * 1024 * 1024) else {
        return false;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return false;
    };
    value
        .as_object()
        .is_some_and(|obj| obj.contains_key("quantization"))
}

/// Inspect an MLX model package directory or archive structure.
pub fn scan_package(path: &Path, identity: &str, media: &str) -> Result<Vec<LayerScanResult>> {
    let mut results = Vec::new();
    let subject = EvidenceSubject::member(&path.display().to_string())
        .with_sha256(Some(identity.to_owned()))
        .with_media_type(media);

    let mut has_weights = false;
    let mut has_config = false;
    let mut custom_python_files = Vec::new();

    let config_path = path.join("config.json");
    if config_path.exists() {
        has_config = true;
    }

    let safetensors_path = path.join("model.safetensors");
    let safetensors_index_path = path.join("model.safetensors.index.json");
    if safetensors_path.exists() || safetensors_index_path.exists() {
        has_weights = true;
    }

    if let Ok(entries) = crate::safeio::read_dir_nofollow(path) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("modeling_") && name.ends_with(".py") {
                custom_python_files.push(name);
            }
        }
    }

    if !custom_python_files.is_empty() {
        for py_file in custom_python_files {
            results.push(
                FindingBuilder::new(
                    "LF-MLX-CUSTOM-CODE",
                    CheckType::PackageSecurity,
                    ScanStatus::Warn,
                )
                .class(FindingClass::Compatibility)
                .confidence(Confidence::High)
                .digest(identity)
                .media_type(media)
                .subject(subject.clone())
                .detail(format!(
                    "MLX package contains custom architecture Python code: '{py_file}'"
                ))
                .finish(),
            );
        }
    }

    if has_weights && has_config {
        results.push(
            FindingBuilder::new(
                "LF-MLX-PROFILE-VALID",
                CheckType::LayerPolicy,
                ScanStatus::Pass,
            )
            .class(FindingClass::Structural)
            .confidence(Confidence::High)
            .digest(identity)
            .media_type(media)
            .subject(subject)
            .detail(
                "MLX model package profile verified (Safetensors weights + JSON config)".to_owned(),
            )
            .finish(),
        );
    } else {
        results.push(
            FindingBuilder::new(
                "LF-MLX-PROFILE-INCOMPLETE",
                CheckType::LayerPolicy,
                ScanStatus::Warn,
            )
            .class(FindingClass::Compatibility)
            .confidence(Confidence::High)
            .digest(identity)
            .media_type(media)
            .subject(subject)
            .detail(
                "MLX package structure incomplete: missing model.safetensors or config.json"
                    .to_owned(),
            )
            .finish(),
        );
    }

    Ok(results)
}
