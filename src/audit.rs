use crate::manifest::{self, ModelRef};
use anyhow::{Context, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone, serde::Serialize)]
pub struct InventoryModel {
    pub model: String,
    pub manifest_digest: Option<String>,
    pub descriptor_count: usize,
    pub referenced_bytes: u64,
    pub valid: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SharedBlob {
    pub digest: String,
    pub referenced_by: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MissingBlob {
    pub digest: String,
    pub referenced_by: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct StoreAudit {
    pub version: u32,
    pub models_dir: String,
    pub models: Vec<InventoryModel>,
    pub model_count: usize,
    pub invalid_model_count: usize,
    pub blob_file_count: usize,
    pub referenced_blob_count: usize,
    pub total_blob_bytes: u64,
    pub referenced_blob_bytes: u64,
    pub orphaned_blobs: Vec<String>,
    pub missing_blobs: Vec<MissingBlob>,
    pub shared_blobs: Vec<SharedBlob>,
    pub partial_or_temporary_files: Vec<String>,
    pub invalid_manifest_paths: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ReferenceMap {
    pub models: BTreeMap<String, BTreeSet<String>>,
    pub by_digest: BTreeMap<String, BTreeSet<String>>,
}

pub fn reference_map(base_dir: &Path) -> Result<ReferenceMap> {
    let mut models = BTreeMap::<String, BTreeSet<String>>::new();
    let mut by_digest = BTreeMap::<String, BTreeSet<String>>::new();
    for model_ref in manifest::discover_all_models(base_dir)? {
        if let Ok(model) = manifest::load_model(&model_ref) {
            let descriptors = model
                .descriptors()
                .map(|layer| layer.digest.clone())
                .collect::<BTreeSet<_>>();
            for digest in &descriptors {
                by_digest
                    .entry(digest.clone())
                    .or_default()
                    .insert(model.name.clone());
            }
            models.insert(model.name, descriptors);
        }
    }
    Ok(ReferenceMap { models, by_digest })
}

pub fn audit_store(base_dir: &Path) -> Result<StoreAudit> {
    let manifests_root = base_dir.join("manifests");
    let blobs_root = base_dir.join("blobs");
    let mut models = Vec::new();
    let mut invalid_manifest_paths = Vec::new();
    let mut by_digest = BTreeMap::<String, BTreeSet<String>>::new();

    for model_ref in manifest::discover_all_models(base_dir)? {
        match manifest::load_model(&model_ref) {
            Ok(model) => {
                let mut bytes = 0_u64;
                let mut count = 0_usize;
                for layer in model.descriptors() {
                    count += 1;
                    bytes = bytes.saturating_add(layer.size);
                    by_digest
                        .entry(layer.digest.clone())
                        .or_default()
                        .insert(model.name.clone());
                }
                models.push(InventoryModel {
                    model: model.name,
                    manifest_digest: Some(model.digest),
                    descriptor_count: count,
                    referenced_bytes: bytes,
                    valid: true,
                    error: None,
                });
            }
            Err(error) => models.push(InventoryModel {
                model: model_ref.name,
                manifest_digest: None,
                descriptor_count: 0,
                referenced_bytes: 0,
                valid: false,
                error: Some(error.to_string()),
            }),
        }
    }

    // discover_all_models intentionally skips unsafe/non-canonical entries, so
    // separately record manifest files that were not represented above.
    let represented_paths = manifest::discover_all_models(base_dir)?
        .into_iter()
        .map(|entry| entry.manifest_path)
        .collect::<BTreeSet<_>>();
    for entry in WalkDir::new(&manifests_root).follow_links(false) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                invalid_manifest_paths.push(format!("walk error: {error}"));
                continue;
            }
        };
        if entry.file_type().is_file() && !represented_paths.contains(entry.path()) {
            invalid_manifest_paths.push(display_relative(base_dir, entry.path()));
        }
    }

    let mut blob_files = BTreeMap::<String, (PathBuf, u64)>::new();
    let mut partial_or_temporary_files = Vec::new();
    let mut total_blob_bytes = 0_u64;
    if blobs_root.is_dir() {
        for entry in
            fs::read_dir(&blobs_root) // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path -- deliberate scan of the selected Ollama blobs directory
                .with_context(|| format!("Unable to read '{}'", blobs_root.display()))?
        {
            let entry = entry?;
            let file_type = entry.file_type()?;
            let path = entry.path();
            if !file_type.is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            let len = entry.metadata()?.len();
            if let Some(digest) = digest_from_blob_filename(&name) {
                total_blob_bytes = total_blob_bytes.saturating_add(len);
                blob_files.insert(digest, (path, len));
            } else if name.contains("partial") || name.ends_with(".tmp") || name.ends_with(".part")
            {
                partial_or_temporary_files.push(name);
            }
        }
    }

    let referenced = by_digest.keys().cloned().collect::<BTreeSet<_>>();
    let present = blob_files.keys().cloned().collect::<BTreeSet<_>>();
    let orphaned_blobs = present.difference(&referenced).cloned().collect::<Vec<_>>();

    let mut missing_blobs = Vec::new();
    for digest in referenced.difference(&present) {
        missing_blobs.push(MissingBlob {
            digest: digest.clone(),
            referenced_by: by_digest
                .get(digest)
                .map(|set| set.iter().cloned().collect())
                .unwrap_or_default(),
        });
    }

    let shared_blobs = by_digest
        .iter()
        .filter(|(_, models)| models.len() > 1)
        .map(|(digest, models)| SharedBlob {
            digest: digest.clone(),
            referenced_by: models.iter().cloned().collect(),
        })
        .collect::<Vec<_>>();

    let referenced_blob_bytes = referenced
        .iter()
        .filter_map(|digest| blob_files.get(digest).map(|(_, len)| *len))
        .fold(0_u64, u64::saturating_add);

    models.sort_by(|left, right| left.model.cmp(&right.model));
    invalid_manifest_paths.sort();
    partial_or_temporary_files.sort();

    let invalid_model_count = models.iter().filter(|model| !model.valid).count();

    Ok(StoreAudit {
        version: 1,
        models_dir: base_dir.display().to_string(),
        model_count: models.len(),
        invalid_model_count,
        blob_file_count: blob_files.len(),
        referenced_blob_count: referenced.len(),
        total_blob_bytes,
        referenced_blob_bytes,
        models,
        orphaned_blobs,
        missing_blobs,
        shared_blobs,
        partial_or_temporary_files,
        invalid_manifest_paths,
    })
}

pub fn find_model_ref(base_dir: &Path, canonical_name: &str) -> Result<ModelRef> {
    manifest::find_model(base_dir, canonical_name)
}

fn digest_from_blob_filename(name: &str) -> Option<String> {
    if let Some(hex) = name.strip_prefix("sha256-") {
        if hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Some(format!("sha256:{hex}"));
        }
    }
    if let Some(hex) = name.strip_prefix("sha512-") {
        if hex.len() == 128 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Some(format!("sha512:{hex}"));
        }
    }
    None
}

fn display_relative(base: &Path, path: &Path) -> String {
    path.strip_prefix(base)
        .unwrap_or(path)
        .display()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_only_canonical_blob_names() {
        assert_eq!(
            digest_from_blob_filename(&format!("sha256-{}", "a".repeat(64))),
            Some(format!("sha256:{}", "a".repeat(64)))
        );
        assert!(digest_from_blob_filename("sha256-deadbeef").is_none());
        assert!(digest_from_blob_filename(&format!("sha256-{}.sig", "a".repeat(64))).is_none());
    }
}
