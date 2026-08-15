use crate::assurance::AnalysisCompleteness;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpTransport {
    Stdio,
    StreamableHttp,
    LegacyHttpSse,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityState {
    Present,
    Absent,
    Unknown,
    NotApplicable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServer {
    pub name: String,
    pub identity: String,
    pub transport: McpTransport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    #[serde(default)]
    pub argument_count: u64,
    /// SHA-256 identities of ordered command arguments. Raw arguments are
    /// deliberately excluded because they can contain credential material.
    #[serde(default)]
    pub argument_sha256: Vec<String>,
    pub authentication: SecurityState,
    pub tls: SecurityState,
    #[serde(default)]
    pub credential_names: Vec<String>,
    #[serde(default)]
    pub tools: Vec<ToolDefinition>,
    pub completeness: AnalysisCompleteness,
    #[serde(default)]
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, rename = "inputSchema")]
    pub input_schema: Value,
    #[serde(default)]
    pub annotations: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmation_required: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentDefinition {
    pub name: String,
    pub identity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_composition_identity: Option<String>,
    #[serde(default)]
    pub server_identities: Vec<String>,
    #[serde(default)]
    pub capabilities: Vec<super::CapabilityGrant>,
    pub completeness: AnalysisCompleteness,
    #[serde(default)]
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DangerousCapabilityChain {
    pub id: String,
    pub title: String,
    pub impact: String,
    pub capabilities: Vec<super::CapabilityGrant>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityGraph {
    pub version: u32,
    pub agent: AgentDefinition,
    pub servers: Vec<McpServer>,
    #[serde(default)]
    pub dangerous_chains: Vec<DangerousCapabilityChain>,
    pub graph_identity: String,
    pub completeness: AnalysisCompleteness,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSecurityAssessment {
    pub graph: CapabilityGraph,
    #[serde(default)]
    pub findings: Vec<crate::scanner::LayerScanResult>,
}
