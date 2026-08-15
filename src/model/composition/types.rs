use crate::assurance::AnalysisCompleteness;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentRole {
    BaseModel,
    Adapter,
    Tokenizer,
    ChatTemplate,
    GenerationConfig,
    QuantizationConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentIdentity {
    pub role: ComponentRole,
    pub name: String,
    pub identity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_base: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub completeness: AnalysisCompleteness,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeConfiguration {
    pub method: String,
    #[serde(default)]
    pub parameters: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantizationConfiguration {
    pub format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    #[serde(default)]
    pub parameters: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelComposition {
    pub version: u32,
    pub base_model: ComponentIdentity,
    /// Adapter order is retained because loading order can affect the executable model.
    #[serde(default)]
    pub adapters: Vec<ComponentIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokenizer: Option<ComponentIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chat_template: Option<ComponentIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation_config: Option<ComponentIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quantization_config: Option<ComponentIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merge: Option<MergeConfiguration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quantization: Option<QuantizationConfiguration>,
    pub completeness: AnalysisCompleteness,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompositionIdentity {
    pub version: u32,
    pub value: String,
    pub completeness: AnalysisCompleteness,
    pub component_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompositionAssessment {
    pub composition: ModelComposition,
    pub identity: CompositionIdentity,
    #[serde(default)]
    pub findings: Vec<crate::scanner::LayerScanResult>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeVerificationState {
    Verified,
    Consistent,
    PartiallyConsistent,
    Inconsistent,
    Unknown,
    UnableToVerify,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MergeAssessment {
    pub state: MergeVerificationState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter_identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merged_identity: Option<String>,
    #[serde(default)]
    pub verified_tensors: u64,
    #[serde(default)]
    pub unsupported_tensors: u64,
    #[serde(default)]
    pub changed_non_target_tensors: u64,
    #[serde(default)]
    pub detail: String,
}
