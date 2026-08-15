use super::{ComponentIdentity, CompositionIdentity, ModelComposition};
use anyhow::{bail, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};

const MAX_COMPONENTS: usize = 1024;
const MAX_IDENTITY_BYTES: usize = 64 * 1024;
const MAX_PARAMETERS: usize = 4096;

#[derive(Serialize)]
struct CanonicalComposition<'a> {
    version: u32,
    base_model: CanonicalComponent<'a>,
    adapters: Vec<CanonicalComponent<'a>>,
    tokenizer: Option<CanonicalComponent<'a>>,
    chat_template: Option<CanonicalComponent<'a>>,
    generation_config: Option<CanonicalComponent<'a>>,
    quantization_config: Option<CanonicalComponent<'a>>,
    merge: &'a Option<super::MergeConfiguration>,
    quantization: &'a Option<super::QuantizationConfiguration>,
}

#[derive(Serialize)]
struct CanonicalComponent<'a> {
    role: super::ComponentRole,
    name: &'a str,
    identity: &'a str,
    sha256: &'a Option<String>,
    declared_base: &'a Option<String>,
}

fn component(value: &ComponentIdentity) -> CanonicalComponent<'_> {
    CanonicalComponent {
        role: value.role,
        name: &value.name,
        identity: &value.identity,
        sha256: &value.sha256,
        declared_base: &value.declared_base,
    }
}

pub fn validate(composition: &ModelComposition) -> Result<()> {
    if composition.version != 1 {
        bail!(
            "unsupported model composition version {}",
            composition.version
        );
    }
    let component_count = 1usize
        .saturating_add(composition.adapters.len())
        .saturating_add(usize::from(composition.tokenizer.is_some()))
        .saturating_add(usize::from(composition.chat_template.is_some()))
        .saturating_add(usize::from(composition.generation_config.is_some()))
        .saturating_add(usize::from(composition.quantization_config.is_some()));
    if component_count > MAX_COMPONENTS {
        bail!("model composition exceeds the {MAX_COMPONENTS}-component safety limit");
    }
    for value in composition
        .adapters
        .iter()
        .chain(std::iter::once(&composition.base_model))
        .chain(composition.tokenizer.iter())
        .chain(composition.chat_template.iter())
        .chain(composition.generation_config.iter())
        .chain(composition.quantization_config.iter())
    {
        validate_component(value)?;
    }
    if let Some(merge) = &composition.merge {
        if merge.method.trim().is_empty() || merge.method.len() > MAX_IDENTITY_BYTES {
            bail!("merge method is empty or exceeds the safety limit");
        }
        if merge.parameters.len() > MAX_PARAMETERS {
            bail!("merge parameter count exceeds the safety limit");
        }
    }
    if let Some(quantization) = &composition.quantization {
        if quantization.format.trim().is_empty() || quantization.format.len() > MAX_IDENTITY_BYTES {
            bail!("quantization format is empty or exceeds the safety limit");
        }
        if quantization.parameters.len() > MAX_PARAMETERS {
            bail!("quantization parameter count exceeds the safety limit");
        }
    }
    Ok(())
}

fn validate_component(value: &ComponentIdentity) -> Result<()> {
    if value.name.trim().is_empty() || value.name.len() > MAX_IDENTITY_BYTES {
        bail!("component name is empty or exceeds the safety limit");
    }
    if value.identity.trim().is_empty() || value.identity.len() > MAX_IDENTITY_BYTES {
        bail!("component identity is empty or exceeds the safety limit");
    }
    if value.completeness == crate::assurance::AnalysisCompleteness::Complete
        && !immutable_identity(&value.identity)
    {
        bail!("complete component identity must contain a canonical SHA-256 digest");
    }
    if let Some(sha256) = &value.sha256 {
        let raw = sha256.strip_prefix("sha256:").unwrap_or(sha256);
        if raw.len() != 64 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("component SHA-256 must contain exactly 64 hexadecimal characters");
        }
    }
    Ok(())
}

fn immutable_identity(value: &str) -> bool {
    let digest = value
        .strip_prefix("sha256:")
        .or_else(|| value.rsplit_once(":sha256:").map(|(_, digest)| digest));
    digest.is_some_and(|digest| {
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

pub fn canonical_bytes(composition: &ModelComposition) -> Result<Vec<u8>> {
    validate(composition)?;
    let value = CanonicalComposition {
        version: composition.version,
        base_model: component(&composition.base_model),
        adapters: composition.adapters.iter().map(component).collect(),
        tokenizer: composition.tokenizer.as_ref().map(component),
        chat_template: composition.chat_template.as_ref().map(component),
        generation_config: composition.generation_config.as_ref().map(component),
        quantization_config: composition.quantization_config.as_ref().map(component),
        merge: &composition.merge,
        quantization: &composition.quantization,
    };
    Ok(serde_json::to_vec(&value)?)
}

pub fn identity(composition: &ModelComposition) -> Result<CompositionIdentity> {
    let bytes = canonical_bytes(composition)?;
    let mut hasher = Sha256::new();
    hasher.update(b"layerfault:model-composition:v1\0");
    hasher.update(bytes);
    let component_count = 1usize
        .saturating_add(composition.adapters.len())
        .saturating_add(usize::from(composition.tokenizer.is_some()))
        .saturating_add(usize::from(composition.chat_template.is_some()))
        .saturating_add(usize::from(composition.generation_config.is_some()))
        .saturating_add(usize::from(composition.quantization_config.is_some()));
    Ok(CompositionIdentity {
        version: 1,
        value: format!("lfcomposition:v1:sha256:{}", hex::encode(hasher.finalize())),
        completeness: composition.completeness,
        component_count: u64::try_from(component_count).unwrap_or(u64::MAX),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assurance::AnalysisCompleteness;
    use crate::model::composition::{ComponentRole, ModelComposition};

    fn component(role: ComponentRole, name: &str, identity: &str) -> ComponentIdentity {
        ComponentIdentity {
            role,
            name: name.into(),
            identity: identity.into(),
            sha256: None,
            declared_base: None,
            source: None,
            completeness: AnalysisCompleteness::Complete,
            limitations: Vec::new(),
        }
    }

    #[test]
    fn adapter_order_changes_identity() {
        let base_identity = format!("sha256:{}", "0".repeat(64));
        let build = |adapters: Vec<ComponentIdentity>| ModelComposition {
            version: 1,
            base_model: component(ComponentRole::BaseModel, "base", &base_identity),
            adapters,
            tokenizer: None,
            chat_template: None,
            generation_config: None,
            quantization_config: None,
            merge: None,
            quantization: None,
            completeness: AnalysisCompleteness::Complete,
            limitations: Vec::new(),
        };
        let a_identity = format!("sha256:{}", "a".repeat(64));
        let b_identity = format!("sha256:{}", "b".repeat(64));
        let a = component(ComponentRole::Adapter, "a", &a_identity);
        let b = component(ComponentRole::Adapter, "b", &b_identity);
        let first = identity(&build(vec![a.clone(), b.clone()])).unwrap();
        let second = identity(&build(vec![b, a])).unwrap();
        assert_ne!(first.value, second.value);
    }

    #[test]
    fn local_source_path_does_not_change_identity() {
        let base_identity = format!("sha256:{}", "0".repeat(64));
        let mut base = component(ComponentRole::BaseModel, "base", &base_identity);
        let mut left = ModelComposition {
            version: 1,
            base_model: base.clone(),
            adapters: Vec::new(),
            tokenizer: None,
            chat_template: None,
            generation_config: None,
            quantization_config: None,
            merge: None,
            quantization: None,
            completeness: AnalysisCompleteness::Complete,
            limitations: Vec::new(),
        };
        left.base_model.source = Some("/tmp/a".into());
        base.source = Some("/home/example/a".into());
        let right = ModelComposition {
            base_model: base,
            ..left.clone()
        };
        assert_eq!(
            identity(&left).unwrap().value,
            identity(&right).unwrap().value
        );
    }
}

pub fn adapter_set_identity(composition: &ModelComposition) -> Result<String> {
    validate(composition)?;
    let adapters = composition
        .adapters
        .iter()
        .map(component)
        .collect::<Vec<_>>();
    let bytes = serde_json::to_vec(&adapters)?;
    let mut hasher = Sha256::new();
    hasher.update(b"layerfault:adapter-set:v1\0");
    hasher.update(bytes);
    Ok(format!(
        "lfadapterset:v1:sha256:{}",
        hex::encode(hasher.finalize())
    ))
}
