use super::types::WeightSetDescriptor;
use anyhow::{bail, Context, Result};
use std::fs::File;
use std::path::Path;

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
            let candidate = crate::safeio::canonical_regular_file_within(&root, &name, false)?;
            let metadata = std::fs::symlink_metadata(&candidate)
                .with_context(|| format!("Safetensors shard '{name}' is missing"))?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                bail!("Safetensors shard '{name}' is not an ordinary regular file");
            }
            files.push(candidate);
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
        if let Some(candidate) = crate::safeio::optional_regular_file_within(&root, name, false)? {
            return Ok(Some(WeightSetDescriptor {
                layout: if name.starts_with("adapter") {
                    "LORA_ADAPTER_SAFETENSORS".to_owned()
                } else {
                    "PACKAGE_SAFETENSORS".to_owned()
                },
                files: vec![candidate],
            }));
        }
    }

    let mut files = Vec::new();
    for entry in crate::safeio::read_dir_nofollow(&root)? {
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

pub(super) struct OpenShard {
    pub(super) file: File,
    pub(super) inventory: crate::formats::safetensors::SafetensorsInventory,
}

pub(super) struct OpenWeightSet {
    pub(super) descriptor: WeightSetDescriptor,
    pub(super) shards: Vec<OpenShard>,
    pub(super) tensors: std::collections::BTreeMap<String, (usize, usize)>,
}

pub(super) fn open_weight_set(path: &Path) -> Result<Option<OpenWeightSet>> {
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
