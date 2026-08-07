use anyhow::{anyhow, Result};
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct ArtifactDiff {
    pub left: String,
    pub right: String,
    pub same_format: bool,
    pub same_size: bool,
    pub same_sha256: bool,
    pub left_format: String,
    pub right_format: String,
    pub left_size: u64,
    pub right_size: u64,
    pub left_sha256: Option<String>,
    pub right_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModelDiff {
    pub left: String,
    pub right: String,
    pub same_manifest: bool,
    pub added_descriptors: Vec<String>,
    pub removed_descriptors: Vec<String>,
    pub shared_descriptors: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum DiffReport {
    Artifact(ArtifactDiff),
    Ollama(ModelDiff),
}

pub fn compare(left: &str, right: &str, ollama_dir: Option<&Path>) -> Result<DiffReport> {
    let left_path = Path::new(left); // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path -- explicit CLI file operand, opened read-only through the no-follow artifact scanner
    let right_path = Path::new(right); // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path -- explicit CLI file operand, opened read-only through the no-follow artifact scanner
    if left_path.is_file() || right_path.is_file() {
        if !left_path.is_file() || !right_path.is_file() {
            return Err(anyhow!(
                "When either diff operand is a file, both operands must be files"
            ));
        }
        let left_report = crate::formats::artifact::inspect(
            left_path,
            crate::formats::artifact::ArtifactScanMode::Full,
        )?;
        let right_report = crate::formats::artifact::inspect(
            right_path,
            crate::formats::artifact::ArtifactScanMode::Full,
        )?;
        return Ok(DiffReport::Artifact(ArtifactDiff {
            left: left.to_owned(),
            right: right.to_owned(),
            same_format: left_report.format == right_report.format,
            same_size: left_report.size == right_report.size,
            same_sha256: left_report.sha256 == right_report.sha256,
            left_format: left_report.format.as_str().to_owned(),
            right_format: right_report.format.as_str().to_owned(),
            left_size: left_report.size,
            right_size: right_report.size,
            left_sha256: left_report.sha256,
            right_sha256: right_report.sha256,
        }));
    }

    let base = crate::app::resolve_base_dir(ollama_dir)?;
    let left_ref = crate::manifest::find_model(&base, left)?;
    let right_ref = crate::manifest::find_model(&base, right)?;
    let left_model = crate::manifest::load_model(&left_ref)?;
    let right_model = crate::manifest::load_model(&right_ref)?;
    let left_set = left_model
        .descriptors()
        .map(|layer| layer.digest.clone())
        .collect::<BTreeSet<_>>();
    let right_set = right_model
        .descriptors()
        .map(|layer| layer.digest.clone())
        .collect::<BTreeSet<_>>();
    Ok(DiffReport::Ollama(ModelDiff {
        left: left_model.name,
        right: right_model.name,
        same_manifest: left_model.digest == right_model.digest,
        added_descriptors: right_set.difference(&left_set).cloned().collect(),
        removed_descriptors: left_set.difference(&right_set).cloned().collect(),
        shared_descriptors: left_set.intersection(&right_set).cloned().collect(),
    }))
}
