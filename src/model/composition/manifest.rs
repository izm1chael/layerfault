use super::{
    ComponentIdentity, ComponentRole, MergeConfiguration, ModelComposition,
    QuantizationConfiguration,
};
use crate::assurance::AnalysisCompleteness;
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ADAPTERS: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompositionManifest {
    pub version: u32,
    pub base_model: ComponentReference,
    #[serde(default)]
    pub adapters: Vec<ComponentReference>,
    #[serde(default)]
    pub tokenizer: Option<ComponentReference>,
    #[serde(default)]
    pub chat_template: Option<ComponentReference>,
    #[serde(default)]
    pub generation_config: Option<ComponentReference>,
    #[serde(default)]
    pub quantization_config: Option<ComponentReference>,
    #[serde(default)]
    pub merge: Option<MergeConfiguration>,
    #[serde(default)]
    pub quantization: Option<QuantizationConfiguration>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentReference {
    pub name: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub identity: Option<String>,
    #[serde(default)]
    pub declared_base: Option<String>,
}

pub fn load(path: &Path) -> Result<CompositionManifest> {
    let file = crate::safeio::open_readonly_nofollow(path)?;
    let bytes = crate::safeio::read_all_from_file(&file, MAX_MANIFEST_BYTES)?;
    let manifest: CompositionManifest = serde_json::from_slice(&bytes)
        .with_context(|| format!("composition manifest '{}' is invalid JSON", path.display()))?;
    if manifest.version != 1 {
        bail!(
            "unsupported composition manifest version {}",
            manifest.version
        );
    }
    if manifest.adapters.len() > MAX_ADAPTERS {
        bail!("composition manifest exceeds the {MAX_ADAPTERS}-adapter safety limit");
    }
    Ok(manifest)
}

pub fn resolve(path: &Path) -> Result<ModelComposition> {
    let manifest = load(path)?;
    let root = path.parent().unwrap_or_else(|| Path::new("."));
    let mut limitations = Vec::new();
    let base_model = resolve_component(
        root,
        ComponentRole::BaseModel,
        &manifest.base_model,
        &mut limitations,
    )?;
    let mut adapters = Vec::with_capacity(manifest.adapters.len());
    for adapter in &manifest.adapters {
        adapters.push(resolve_component(
            root,
            ComponentRole::Adapter,
            adapter,
            &mut limitations,
        )?);
    }
    let tokenizer = manifest
        .tokenizer
        .as_ref()
        .map(|v| resolve_component(root, ComponentRole::Tokenizer, v, &mut limitations))
        .transpose()?;
    let chat_template = manifest
        .chat_template
        .as_ref()
        .map(|v| resolve_component(root, ComponentRole::ChatTemplate, v, &mut limitations))
        .transpose()?;
    let generation_config = manifest
        .generation_config
        .as_ref()
        .map(|v| resolve_component(root, ComponentRole::GenerationConfig, v, &mut limitations))
        .transpose()?;
    let quantization_config = manifest
        .quantization_config
        .as_ref()
        .map(|v| resolve_component(root, ComponentRole::QuantizationConfig, v, &mut limitations))
        .transpose()?;
    let mut components = adapters.iter().collect::<Vec<_>>();
    components.push(&base_model);
    components.extend(tokenizer.iter());
    components.extend(chat_template.iter());
    components.extend(generation_config.iter());
    components.extend(quantization_config.iter());
    let complete = components
        .iter()
        .all(|v| v.completeness == AnalysisCompleteness::Complete);
    if !complete && limitations.is_empty() {
        limitations.push(
            "one or more composition components could not be resolved to exact local bytes".into(),
        );
    }
    limitations.sort();
    limitations.dedup();
    Ok(ModelComposition {
        version: 1,
        base_model,
        adapters,
        tokenizer,
        chat_template,
        generation_config,
        quantization_config,
        merge: manifest.merge,
        quantization: manifest.quantization,
        completeness: if complete {
            AnalysisCompleteness::Complete
        } else {
            AnalysisCompleteness::Partial
        },
        limitations,
    })
}

fn resolve_component(
    root: &Path,
    role: ComponentRole,
    component: &ComponentReference,
    limitations: &mut Vec<String>,
) -> Result<ComponentIdentity> {
    if component.name.trim().is_empty() || component.name.len() > 16 * 1024 {
        bail!("composition component name is empty or too long");
    }
    let mut source = None;
    let mut sha256 = None;
    let mut observed_identity = None;
    let mut component_limitations = Vec::new();
    if let Some(relative) = &component.path {
        let relative_path = crate::safeio::validated_relative_path(relative, true)?;
        let candidate = root.join(&relative_path);
        let metadata = std::fs::symlink_metadata(&candidate)
            .with_context(|| format!("unable to inspect composition component '{}'", relative))?;
        if metadata.file_type().is_symlink() {
            bail!("composition component '{}' may not be a symlink", relative);
        }
        if metadata.is_file() {
            let canonical = crate::safeio::canonical_regular_file_within(root, relative, true)?;
            let digest = crate::safeio::sha256_path(&canonical)?;
            sha256 = Some(digest.clone());
            observed_identity = Some(digest);
            source = Some(relative_path.to_string_lossy().replace('\\', "/"));
        } else if metadata.is_dir() {
            let canonical_root = std::fs::canonicalize(root)?;
            let canonical = std::fs::canonicalize(&candidate)?;
            if !canonical.starts_with(&canonical_root) {
                bail!(
                    "composition component '{}' escapes its manifest directory",
                    relative
                );
            }
            let package = crate::package::inspect(&canonical)?;
            observed_identity = Some(package.merkle_identity);
            source = Some(relative_path.to_string_lossy().replace('\\', "/"));
            if !package.coverage.complete {
                component_limitations
                    .push("package identity was computed with incomplete package coverage".into());
            }
        } else {
            bail!(
                "composition component '{}' must be a regular file or directory",
                relative
            );
        }
    }
    let identity = match (&component.identity, &observed_identity) {
        (Some(declared), Some(observed)) if declared != observed => {
            component_limitations.push(format!(
                "declared identity '{}' does not match observed identity '{}'",
                declared, observed
            ));
            observed.clone()
        }
        (Some(declared), _) if immutable_identity(declared) => declared.clone(),
        (Some(_), _) => {
            component_limitations
                .push("declared identity is not an immutable SHA-256 identity".into());
            format!("unknown:{}", component.name)
        }
        (None, Some(observed)) => observed.clone(),
        (None, None) => {
            component_limitations.push("component has no local path or immutable identity".into());
            format!("unknown:{}", component.name)
        }
    };
    let completeness = if component_limitations.is_empty()
        && (observed_identity.is_some() || component.identity.is_some())
    {
        AnalysisCompleteness::Complete
    } else if observed_identity.is_some() || component.identity.is_some() {
        AnalysisCompleteness::Partial
    } else {
        AnalysisCompleteness::Unknown
    };
    limitations.extend(
        component_limitations
            .iter()
            .map(|v| format!("{}: {v}", component.name)),
    );
    Ok(ComponentIdentity {
        role,
        name: component.name.clone(),
        identity,
        sha256,
        declared_base: component.declared_base.clone(),
        source,
        completeness,
        limitations: component_limitations,
    })
}

fn immutable_identity(value: &str) -> bool {
    let digest = value
        .strip_prefix("sha256:")
        .or_else(|| value.rsplit_once(":sha256:").map(|(_, digest)| digest));
    digest.is_some_and(|digest| {
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

pub fn write_example(path: &Path) -> Result<()> {
    let manifest = CompositionManifest {
        version: 1,
        base_model: ComponentReference {
            name: "base".into(),
            path: Some("model.safetensors".into()),
            identity: None,
            declared_base: None,
        },
        adapters: vec![ComponentReference {
            name: "adapter-a".into(),
            path: Some("adapter-a".into()),
            identity: None,
            declared_base: Some("base".into()),
        }],
        tokenizer: Some(ComponentReference {
            name: "tokenizer".into(),
            path: Some("tokenizer.json".into()),
            identity: None,
            declared_base: None,
        }),
        chat_template: None,
        generation_config: None,
        quantization_config: None,
        merge: None,
        quantization: None,
    };
    let bytes = serde_json::to_vec_pretty(&manifest).map_err(|error| anyhow!(error))?;
    crate::paths::write_private(path, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arbitrary_declared_identity_is_not_complete() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("composition.json");
        let manifest = serde_json::json!({
            "version": 1,
            "base_model": {"name": "base", "identity": "anything"}
        });
        std::fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        let composition = resolve(&path).unwrap();
        assert_ne!(
            composition.base_model.completeness,
            AnalysisCompleteness::Complete
        );
        assert!(composition.base_model.identity.starts_with("unknown:"));
    }
}
