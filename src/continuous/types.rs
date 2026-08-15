use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustState {
    Unknown,
    Scanning,
    Approved,
    ConditionallyApproved,
    ReviewRequired,
    Blocked,
    Quarantined,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityComponent {
    ModelArtifact,
    ModelComposition,
    AdapterSet,
    Tokenizer,
    ChatTemplate,
    GenerationConfig,
    RuntimeBinary,
    RuntimeConfiguration,
    AgentConfiguration,
    McpServers,
    ToolSchemas,
    Policy,
    Ruleset,
    Intelligence,
    Provenance,
    SecurityPassport,
    AdmissionReceipt,
    BehaviourEnvironment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceDomain {
    StaticModel,
    TensorForensics,
    TokenizerSecurity,
    AdapterSecurity,
    RuntimePosture,
    Exploitability,
    AgentCapability,
    Provenance,
    BehaviouralAssurance,
    SecurityPassport,
    Admission,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionSnapshot {
    pub version: u32,
    pub captured_unix: u64,
    pub state: TrustState,
    #[serde(default)]
    pub identities: BTreeMap<SecurityComponent, String>,
    #[serde(default)]
    pub evidence: BTreeMap<EvidenceDomain, EvidenceRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub identity: String,
    pub generated_unix: u64,
    #[serde(default)]
    pub dependencies: Vec<SecurityComponent>,
    #[serde(default)]
    pub stale: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvalidationPlan {
    #[serde(default)]
    pub changed_components: Vec<SecurityComponent>,
    #[serde(default)]
    pub invalidated_domains: Vec<EvidenceDomain>,
    #[serde(default)]
    pub unchanged_domains: Vec<EvidenceDomain>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEvent {
    pub version: u32,
    pub timestamp_unix: u64,
    pub entity: String,
    pub previous_state: TrustState,
    pub new_state: TrustState,
    pub cause: String,
    #[serde(default)]
    pub changed_components: Vec<SecurityComponent>,
    #[serde(default)]
    pub invalidated_evidence: Vec<EvidenceDomain>,
    #[serde(default)]
    pub finding_ids: Vec<String>,
    #[serde(default)]
    pub rule_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_decision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_action: Option<String>,
}
