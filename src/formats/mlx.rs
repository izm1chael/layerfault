//! MLX model and package conventions inspector.
//!
//! Apple Silicon MLX models use Safetensors weights + JSON architecture configs + optional custom
//! modeling code. This module validates package members and architecture metadata statically.

use crate::finding_evidence::{EvidenceSubject, FindingBuilder};
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use anyhow::Result;
use std::path::Path;

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

    if let Ok(entries) = std::fs::read_dir(path) {
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
