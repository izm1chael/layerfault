//! Static security analysis for AI agents, MCP servers and callable tools.
//!
//! Inspection is data-only: configuration and tool schemas are normalized into
//! capabilities without starting MCP servers, connecting to remote endpoints or
//! executing tool code. Unknown tool surfaces remain explicitly incomplete.

mod capability;
mod discovery;
mod findings;
mod graph;
mod identity;
mod mcp;
mod schema;
mod types;

pub use capability::{
    CapabilityConfidence, CapabilityEvidenceKind, CapabilityGrant, CapabilityKind, CapabilityScope,
};
pub use discovery::{
    build_snapshot, discover_remote, discover_stdio, parse_initialize_response, parse_prompts_list,
    parse_resources_list, parse_tools_list, snapshot_from_remote, snapshot_from_stdio,
    McpCapabilitySnapshot, PrimitiveCompleteness, PrimitiveState, PromptArgument, PromptDefinition,
    ProtocolInfo, RemoteDiscoveryOutcome, ResourceDefinition, StdioDiscoveryOutcome,
    KNOWN_PROTOCOL_VERSIONS,
};
pub use findings::assess;
pub use graph::{build as build_graph, dangerous_chains, PathReachability};
pub use identity::{server_set_identity, tool_schema_identity};
pub use mcp::inspect_config;
pub use schema::capabilities_for_tool;
pub use types::{
    AgentDefinition, AgentSecurityAssessment, CapabilityGraph, DangerousCapabilityChain, McpServer,
    McpTransport, OAuthPosture, SecurityState, ToolDefinition,
};

pub fn inspect_agent_config(
    name: &str,
    path: &std::path::Path,
    composition_identity: Option<&str>,
) -> anyhow::Result<AgentSecurityAssessment> {
    let servers = inspect_config(path)?;
    Ok(assess(build_graph(name, composition_identity, servers)?))
}
