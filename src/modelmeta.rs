//! Bounded, location-independent model metadata and snapshot construction.

use crate::formats::{gguf, safetensors, ArtifactFormat};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

const MAX_CONFIG_BYTES: u64 = 64 * 1024 * 1024;
const MAX_COMPONENTS: usize = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelTargetKind {
    Artifact,
    Package,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelIdentity {
    pub canonical: String,
    pub artifact_sha256: Option<String>,
    pub package_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ArchitectureSummary {
    pub architecture: Option<String>,
    pub layer_count: Option<u64>,
    pub hidden_size: Option<u64>,
    pub attention_heads: Option<u64>,
    pub kv_heads: Option<u64>,
    pub vocabulary_size: Option<u64>,
    pub context_length: Option<u64>,
    pub rope: BTreeMap<String, Value>,
    pub normalization: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TokenizerSummary {
    pub vocabulary_hash: Option<String>,
    pub merges_hash: Option<String>,
    pub special_tokens: BTreeMap<String, i64>,
    pub added_tokens_hash: Option<String>,
    pub tokenizer_file_hash: Option<String>,
    pub tokenizer_config_hash: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TemplateSummary {
    pub exact_hash: Option<String>,
    pub present: bool,
    pub source: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct GenerationConfigSummary {
    pub values: BTreeMap<String, Value>,
    pub exact_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TensorSummary {
    pub name: String,
    pub shape: Vec<u64>,
    pub dtype: String,
    pub byte_len: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageMemberSummary {
    pub relative_path: String,
    pub kind: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelSnapshot {
    pub target: String,
    pub kind: ModelTargetKind,
    pub format: String,
    pub identity: ModelIdentity,
    pub architecture: ArchitectureSummary,
    pub tokenizer: Option<TokenizerSummary>,
    pub template: Option<TemplateSummary>,
    pub generation: Option<GenerationConfigSummary>,
    pub tensors: Vec<TensorSummary>,
    pub tensor_schema_hash: String,
    pub component_hashes: BTreeMap<String, String>,
    pub package_members: Vec<PackageMemberSummary>,
    pub claims: BTreeMap<String, Value>,
}

pub fn build_snapshot(path: &Path) -> Result<ModelSnapshot> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("unable to inspect model target '{}'", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("model target '{}' is a symlink", path.display());
    }
    if metadata.is_dir() {
        snapshot_package(path)
    } else if metadata.is_file() {
        snapshot_artifact(path)
    } else {
        bail!("model target '{}' is not a regular file or directory", path.display())
    }
}

pub fn snapshot_artifact(path: &Path) -> Result<ModelSnapshot> {
    let mut file = crate::safeio::open_readonly_nofollow(path)?;
    let file_len = file.metadata()?.len();
    let sha = hash_file(&file)?;
    file.seek(SeekFrom::Start(0))?;
    let mut prefix = [0_u8; 8];
    let count = file.read(&mut prefix)?;
    let format = ArtifactFormat::detect(path, &prefix[..count]);
    let mut architecture = ArchitectureSummary::default();
    let mut tokenizer = None;
    let mut template = None;
    let generation = None;
    let mut tensors = Vec::new();
    let mut components = BTreeMap::new();
    let mut claims = BTreeMap::new();

    match format {
        ArtifactFormat::Gguf => {
            let inv = gguf::parse_file(&file, file_len)?;
            architecture = architecture_from_gguf(&inv);
            tokenizer = tokenizer_from_gguf(&inv);
            template = template_from_gguf(&inv);
            for tensor in inv.tensors {
                tensors.push(TensorSummary {
                    name: tensor.name,
                    shape: tensor.dimensions,
                    dtype: format!("ggml:{}", tensor.tensor_type),
                    byte_len: tensor.byte_len,
                });
            }
            for (key, value) in inv.metadata {
                if key.starts_with("general.") || key.contains("base_model") || key.contains("quant") {
                    claims.insert(key, metadata_entry_value(&value));
                }
            }
        }
        ArtifactFormat::Safetensors => {
            let inv = safetensors::inventory_file(&file, file_len)?;
            for tensor in inv.tensors {
                tensors.push(TensorSummary {
                    name: tensor.name,
                    shape: tensor.shape,
                    dtype: tensor.dtype,
                    byte_len: Some(tensor.end.saturating_sub(tensor.start)),
                });
            }
            for (key, value) in inv.metadata {
                claims.insert(format!("safetensors.metadata.{key}"), Value::String(value));
            }
        }
        ArtifactFormat::SafetensorsIndex => {
            bail!("a Safetensors index must be snapshotted as part of its package directory")
        }
        ArtifactFormat::Onnx | ArtifactFormat::TensorFlowSavedModel | ArtifactFormat::TensorFlowCheckpoint | ArtifactFormat::TensorFlowLite | ArtifactFormat::KerasArchive | ArtifactFormat::KerasHdf5 => {
            components.insert("artifact".to_owned(), sha.clone());
        }
        ArtifactFormat::Unknown => {
            components.insert("artifact".to_owned(), sha.clone());
        }
    }
    tensors.sort_by(|a, b| a.name.cmp(&b.name));
    let tensor_schema_hash = hash_json(&tensors)?;
    Ok(ModelSnapshot {
        target: path.display().to_string(),
        kind: ModelTargetKind::Artifact,
        format: format.as_str().to_owned(),
        identity: ModelIdentity {
            canonical: format!("lfart:sha256:{sha}"),
            artifact_sha256: Some(format!("sha256:{sha}")),
            package_fingerprint: None,
        },
        architecture,
        tokenizer,
        template,
        generation,
        tensors,
        tensor_schema_hash,
        component_hashes: components,
        package_members: Vec::new(),
        claims,
    })
}

pub fn snapshot_package(path: &Path) -> Result<ModelSnapshot> {
    let report = crate::package::inspect(path)?;
    let canonical_root = PathBuf::from(&report.root);
    let mut members = Vec::with_capacity(report.files.len());
    let mut components = BTreeMap::<String, String>::new();
    for entry in &report.files {
        let sha = entry.sha256.clone().unwrap_or_else(|| "missing".to_owned());
        members.push(PackageMemberSummary {
            relative_path: entry.relative_path.clone(),
            kind: entry.kind.clone(),
            size: entry.size,
            sha256: sha.clone(),
        });
        if components.len() < MAX_COMPONENTS && is_security_component(&entry.relative_path) {
            components.insert(entry.relative_path.clone(), sha);
        }
    }
    members.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));

    let config = read_optional_json(&canonical_root.join("config.json"))?;
    let generation_json = read_optional_json(&canonical_root.join("generation_config.json"))?;
    let tokenizer_json = read_optional_json(&canonical_root.join("tokenizer.json"))?;
    let tokenizer_cfg = read_optional_json(&canonical_root.join("tokenizer_config.json"))?;
    let special_tokens = read_optional_json(&canonical_root.join("special_tokens_map.json"))?;
    let adapter_cfg = read_optional_json(&canonical_root.join("adapter_config.json"))?;

    let architecture = architecture_from_config(config.as_ref());
    let tokenizer = tokenizer_from_package(
        &canonical_root,
        tokenizer_json.as_ref(),
        tokenizer_cfg.as_ref(),
        special_tokens.as_ref(),
    )?;
    let template = template_from_package(&canonical_root, tokenizer_cfg.as_ref())?;
    let generation = generation_from_package(&canonical_root, generation_json.as_ref())?;
    let mut claims = BTreeMap::new();
    if let Some(config) = config.as_ref() {
        extract_claims(config, "config", &mut claims);
    }
    if let Some(adapter) = adapter_cfg.as_ref() {
        extract_claims(adapter, "adapter", &mut claims);
    }

    let mut tensors = Vec::<TensorSummary>::new();
    let mut format = "package".to_owned();
    let mut artifact_sha = None;
    let model_files: Vec<_> = members
        .iter()
        .filter(|entry| entry.kind == "model-artifact")
        .map(|entry| entry.relative_path.clone())
        .collect();
    if model_files.len() == 1 {
        let model_path = canonical_root.join(&model_files[0]);
        let mut child = snapshot_artifact(&model_path)?;
        format = child.format;
        artifact_sha = child.identity.artifact_sha256.take();
        tensors = child.tensors;
        if architecture.architecture.is_none() {
            // Keep package config authoritative when present; otherwise inherit artifact metadata.
            let child_arch = child.architecture;
            let mut merged = architecture.clone();
            merge_architecture(&mut merged, child_arch);
            return finish_package_snapshot(
                path,
                report.fingerprint,
                format,
                artifact_sha,
                merged,
                tokenizer.or(child.tokenizer),
                template.or(child.template),
                generation.or(child.generation),
                tensors,
                components,
                members,
                claims,
            );
        }
    } else {
        // Aggregate all standalone safetensors shard inventories by name.
        for rel in &model_files {
            let model_path = canonical_root.join(rel);
            if model_path.extension().and_then(|v| v.to_str()).is_some_and(|v| v.eq_ignore_ascii_case("safetensors")) {
                let inv = safetensors::inventory_path(&model_path)
                    .with_context(|| format!("unable to inventory package tensor shard '{rel}'"))?;
                for tensor in inv.tensors {
                    tensors.push(TensorSummary {
                        name: tensor.name,
                        shape: tensor.shape,
                        dtype: tensor.dtype,
                        byte_len: Some(tensor.end.saturating_sub(tensor.start)),
                    });
                }
            }
        }
        if !tensors.is_empty() {
            format = "safetensors-package".to_owned();
        }
    }

    finish_package_snapshot(
        path,
        report.fingerprint,
        format,
        artifact_sha,
        architecture,
        tokenizer,
        template,
        generation,
        tensors,
        components,
        members,
        claims,
    )
}

#[allow(clippy::too_many_arguments)]
fn finish_package_snapshot(
    path: &Path,
    fingerprint: String,
    format: String,
    artifact_sha256: Option<String>,
    architecture: ArchitectureSummary,
    tokenizer: Option<TokenizerSummary>,
    template: Option<TemplateSummary>,
    generation: Option<GenerationConfigSummary>,
    mut tensors: Vec<TensorSummary>,
    component_hashes: BTreeMap<String, String>,
    package_members: Vec<PackageMemberSummary>,
    claims: BTreeMap<String, Value>,
) -> Result<ModelSnapshot> {
    tensors.sort_by(|a, b| a.name.cmp(&b.name));
    tensors.dedup_by(|a, b| a.name == b.name && a.shape == b.shape && a.dtype == b.dtype);
    let tensor_schema_hash = hash_json(&tensors)?;
    Ok(ModelSnapshot {
        target: path.display().to_string(),
        kind: ModelTargetKind::Package,
        format,
        identity: ModelIdentity {
            canonical: fingerprint.clone(),
            artifact_sha256,
            package_fingerprint: Some(fingerprint),
        },
        architecture,
        tokenizer,
        template,
        generation,
        tensors,
        tensor_schema_hash,
        component_hashes,
        package_members,
        claims,
    })
}

fn merge_architecture(target: &mut ArchitectureSummary, child: ArchitectureSummary) {
    if target.architecture.is_none() { target.architecture = child.architecture; }
    if target.layer_count.is_none() { target.layer_count = child.layer_count; }
    if target.hidden_size.is_none() { target.hidden_size = child.hidden_size; }
    if target.attention_heads.is_none() { target.attention_heads = child.attention_heads; }
    if target.kv_heads.is_none() { target.kv_heads = child.kv_heads; }
    if target.vocabulary_size.is_none() { target.vocabulary_size = child.vocabulary_size; }
    if target.context_length.is_none() { target.context_length = child.context_length; }
    target.rope.extend(child.rope);
    target.normalization.extend(child.normalization);
}

fn architecture_from_gguf(inv: &gguf::GgufInventory) -> ArchitectureSummary {
    let arch = inv.metadata.get("general.architecture").and_then(|v| v.as_str()).map(str::to_owned);
    let prefix = arch.clone().unwrap_or_default();
    let key = |suffix: &str| if prefix.is_empty() { suffix.to_owned() } else { format!("{prefix}.{suffix}") };
    let mut rope = BTreeMap::new();
    let mut normalization = BTreeMap::new();
    for (k, v) in &inv.metadata {
        if k.contains("rope") {
            rope.insert(k.clone(), metadata_entry_value(v));
        }
        if k.contains("norm") {
            normalization.insert(k.clone(), metadata_entry_value(v));
        }
    }
    ArchitectureSummary {
        architecture: arch,
        layer_count: inv.metadata.get(&key("block_count")).and_then(|v| v.as_u64()),
        hidden_size: inv.metadata.get(&key("embedding_length")).and_then(|v| v.as_u64()),
        attention_heads: inv.metadata.get(&key("attention.head_count")).and_then(|v| v.as_u64()),
        kv_heads: inv.metadata.get(&key("attention.head_count_kv")).and_then(|v| v.as_u64()),
        vocabulary_size: inv.metadata.get("tokenizer.ggml.tokens").and_then(|v| v.unsigned_value),
        context_length: inv.metadata.get(&key("context_length")).and_then(|v| v.as_u64()),
        rope,
        normalization,
    }
}

fn tokenizer_from_gguf(inv: &gguf::GgufInventory) -> Option<TokenizerSummary> {
    let mut relevant = BTreeMap::<String, String>::new();
    let mut special = BTreeMap::new();
    for (key, value) in &inv.metadata {
        if key.starts_with("tokenizer.") {
            relevant.insert(key.clone(), value.digest.clone());
            if key.ends_with("_token_id") {
                if let Some(id) = value.signed_value.or_else(|| value.unsigned_value.and_then(|v| i64::try_from(v).ok())) {
                    special.insert(key.clone(), id);
                }
            }
        }
    }
    if relevant.is_empty() { return None; }
    Some(TokenizerSummary {
        vocabulary_hash: relevant.get("tokenizer.ggml.tokens").cloned(),
        merges_hash: relevant.get("tokenizer.ggml.merges").cloned(),
        special_tokens: special,
        added_tokens_hash: relevant.get("tokenizer.ggml.added_tokens").cloned(),
        tokenizer_file_hash: hash_json(&relevant).ok(),
        tokenizer_config_hash: None,
    })
}

fn template_from_gguf(inv: &gguf::GgufInventory) -> Option<TemplateSummary> {
    let value = inv.metadata.get("tokenizer.chat_template")?;
    Some(TemplateSummary {
        exact_hash: Some(value.digest.clone()),
        present: true,
        source: Some("gguf:tokenizer.chat_template".to_owned()),
    })
}

fn architecture_from_config(config: Option<&Value>) -> ArchitectureSummary {
    let Some(config) = config.and_then(Value::as_object) else { return ArchitectureSummary::default(); };
    let get_u64 = |keys: &[&str]| -> Option<u64> {
        keys.iter().find_map(|key| config.get(*key).and_then(Value::as_u64))
    };
    let architecture = config.get("model_type").and_then(Value::as_str).map(str::to_owned).or_else(|| {
        config.get("architectures").and_then(Value::as_array).and_then(|v| v.first()).and_then(Value::as_str).map(str::to_owned)
    });
    let mut rope = BTreeMap::new();
    let mut normalization = BTreeMap::new();
    for (key, value) in config {
        let lower = key.to_ascii_lowercase();
        if lower.contains("rope") { rope.insert(key.clone(), value.clone()); }
        if lower.contains("norm") || lower.contains("rms_norm") { normalization.insert(key.clone(), value.clone()); }
    }
    ArchitectureSummary {
        architecture,
        layer_count: get_u64(&["num_hidden_layers", "n_layer", "num_layers"]),
        hidden_size: get_u64(&["hidden_size", "n_embd", "d_model"]),
        attention_heads: get_u64(&["num_attention_heads", "n_head"]),
        kv_heads: get_u64(&["num_key_value_heads", "num_kv_heads"]),
        vocabulary_size: get_u64(&["vocab_size"]),
        context_length: get_u64(&["max_position_embeddings", "n_positions", "context_length"]),
        rope,
        normalization,
    }
}

fn tokenizer_from_package(root: &Path, tokenizer: Option<&Value>, config: Option<&Value>, special: Option<&Value>) -> Result<Option<TokenizerSummary>> {
    let tokenizer_path = root.join("tokenizer.json");
    let config_path = root.join("tokenizer_config.json");
    let tokenizer_hash = hash_optional_file(&tokenizer_path)?;
    let config_hash = hash_optional_file(&config_path)?;
    if tokenizer.is_none() && config.is_none() && special.is_none() && tokenizer_hash.is_none() { return Ok(None); }
    let mut summary = TokenizerSummary { tokenizer_file_hash: tokenizer_hash, tokenizer_config_hash: config_hash, ..Default::default() };
    if let Some(tokenizer) = tokenizer {
        if let Some(model) = tokenizer.get("model") {
            if let Some(vocab) = model.get("vocab") { summary.vocabulary_hash = Some(hash_json(vocab)?); }
            if let Some(merges) = model.get("merges") { summary.merges_hash = Some(hash_json(merges)?); }
        }
        if let Some(added) = tokenizer.get("added_tokens") { summary.added_tokens_hash = Some(hash_json(added)?); }
    }
    for value in [config, special].into_iter().flatten() {
        collect_special_tokens(value, &mut summary.special_tokens);
    }
    Ok(Some(summary))
}

fn collect_special_tokens(value: &Value, out: &mut BTreeMap<String, i64>) {
    let Some(obj) = value.as_object() else { return; };
    for (key, value) in obj {
        if key.to_ascii_lowercase().contains("token") {
            if let Some(id) = value.as_i64() { out.insert(key.clone(), id); }
            if let Some(id) = value.get("id").and_then(Value::as_i64) { out.insert(key.clone(), id); }
        }
    }
}

fn template_from_package(root: &Path, tokenizer_cfg: Option<&Value>) -> Result<Option<TemplateSummary>> {
    let template_file = root.join("chat_template.jinja");
    if let Some(hash) = hash_optional_file(&template_file)? {
        return Ok(Some(TemplateSummary { exact_hash: Some(hash), present: true, source: Some("chat_template.jinja".to_owned()) }));
    }
    if let Some(template) = tokenizer_cfg.and_then(|v| v.get("chat_template")) {
        return Ok(Some(TemplateSummary { exact_hash: Some(hash_json(template)?), present: true, source: Some("tokenizer_config.json:chat_template".to_owned()) }));
    }
    Ok(None)
}

fn generation_from_package(root: &Path, value: Option<&Value>) -> Result<Option<GenerationConfigSummary>> {
    let Some(value) = value else { return Ok(None); };
    let mut values = BTreeMap::new();
    if let Some(obj) = value.as_object() {
        for key in ["temperature", "top_k", "top_p", "repetition_penalty", "max_new_tokens", "max_length", "bos_token_id", "eos_token_id", "pad_token_id", "stop_strings"] {
            if let Some(value) = obj.get(key) { values.insert(key.to_owned(), value.clone()); }
        }
    }
    Ok(Some(GenerationConfigSummary {
        exact_hash: hash_optional_file(&root.join("generation_config.json"))?,
        values,
    }))
}

fn extract_claims(value: &Value, prefix: &str, out: &mut BTreeMap<String, Value>) {
    let Some(obj) = value.as_object() else { return; };
    for key in ["base_model_name_or_path", "model_type", "architectures", "quantization_config", "peft_type", "r", "lora_alpha", "target_modules", "task_type", "modules_to_save"] {
        if let Some(value) = obj.get(key) { out.insert(format!("{prefix}.{key}"), value.clone()); }
    }
}

fn metadata_entry_value(value: &gguf::GgufMetadataEntry) -> Value {
    if let Some(v) = value.string_value.as_ref() { return Value::String(v.clone()); }
    if let Some(v) = value.unsigned_value { return Value::from(v); }
    if let Some(v) = value.signed_value { return Value::from(v); }
    if let Some(v) = value.float_value { if let Some(n) = serde_json::Number::from_f64(v) { return Value::Number(n); } }
    if let Some(v) = value.bool_value { return Value::Bool(v); }
    Value::String(format!("sha256:{}", value.digest))
}

fn read_optional_json(path: &Path) -> Result<Option<Value>> {
    if !path.exists() { return Ok(None); }
    let bytes = read_bounded(path, MAX_CONFIG_BYTES)?;
    let value = serde_json::from_slice(&bytes).with_context(|| format!("invalid JSON in '{}'", path.display()))?;
    Ok(Some(value))
}

fn read_bounded(path: &Path, cap: u64) -> Result<Vec<u8>> {
    let file = crate::safeio::open_readonly_nofollow(path)?;
    let len = file.metadata()?.len();
    if len > cap { bail!("'{}' is {len} bytes, above metadata cap {cap}", path.display()); }
    let reader = file;
    let mut bytes = Vec::with_capacity(usize::try_from(len).context("metadata size does not fit usize")?);
    reader.take(cap.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != len { bail!("'{}' changed while being read", path.display()); }
    Ok(bytes)
}

fn hash_optional_file(path: &Path) -> Result<Option<String>> {
    if !path.exists() { return Ok(None); }
    let file = crate::safeio::open_readonly_nofollow(path)?;
    Ok(Some(hash_file(&file)?))
}

fn hash_file(file: &File) -> Result<String> {
    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 { break; }
        hasher.update(&buffer[..count]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn hash_json<T: Serialize + ?Sized>(value: &T) -> Result<String> {
    let bytes = serde_json::to_vec(value)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn is_security_component(path: &str) -> bool {
    matches!(
        path.to_ascii_lowercase().as_str(),
        "config.json" | "tokenizer.json" | "tokenizer_config.json" | "generation_config.json" |
        "special_tokens_map.json" | "adapter_config.json" | "chat_template.jinja"
    ) || path.ends_with(".safetensors.index.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_architecture_is_normalized() {
        let value: Value = serde_json::from_str(r#"{"model_type":"llama","num_hidden_layers":32,"hidden_size":4096,"num_attention_heads":32,"num_key_value_heads":8,"vocab_size":128000,"max_position_embeddings":8192}"#).unwrap();
        let summary = architecture_from_config(Some(&value));
        assert_eq!(summary.architecture.as_deref(), Some("llama"));
        assert_eq!(summary.layer_count, Some(32));
        assert_eq!(summary.kv_heads, Some(8));
    }
}
