//! Bounded, location-independent model metadata primitives for vNext comparisons.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenizerSummary {
    pub vocabulary_hash: Option<String>,
    pub merges_hash: Option<String>,
    pub special_tokens: BTreeMap<String, i64>,
    pub added_tokens_hash: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TemplateSummary {
    pub exact_hash: Option<String>,
    pub present: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GenerationConfigSummary {
    pub values: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageMemberSummary {
    pub relative_path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelSnapshot {
    pub target: String,
    pub kind: ModelTargetKind,
    pub identity: ModelIdentity,
    pub architecture: ArchitectureSummary,
    pub tokenizer: Option<TokenizerSummary>,
    pub template: Option<TemplateSummary>,
    pub generation: Option<GenerationConfigSummary>,
    pub package_members: Vec<PackageMemberSummary>,
}
