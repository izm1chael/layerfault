use super::{AgentDefinition, CapabilityGrant, McpServer, ToolDefinition};
use anyhow::Result;
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Serialize)]
struct ServerIdentity<'a> {
    name: &'a str,
    transport: super::McpTransport,
    endpoint: &'a Option<String>,
    executable: &'a Option<String>,
    argument_count: u64,
    argument_sha256: &'a [String],
    authentication: super::SecurityState,
    tls: super::SecurityState,
    credential_names: &'a [String],
    tools: Vec<ToolIdentity<'a>>,
}

#[derive(Serialize)]
struct ToolIdentity<'a> {
    name: &'a str,
    description: &'a Option<String>,
    input_schema: &'a serde_json::Value,
    annotations: &'a serde_json::Value,
    confirmation_required: &'a Option<bool>,
}

fn canonical_tool(tool: &ToolDefinition) -> ToolIdentity<'_> {
    ToolIdentity {
        name: &tool.name,
        description: &tool.description,
        input_schema: &tool.input_schema,
        annotations: &tool.annotations,
        confirmation_required: &tool.confirmation_required,
    }
}

pub fn server_identity(server: &McpServer) -> Result<String> {
    let mut credential_names = server.credential_names.clone();
    credential_names.sort();
    credential_names.dedup();
    let mut tools = server.tools.iter().collect::<Vec<_>>();
    tools.sort_by(|a, b| a.name.cmp(&b.name));
    let value = ServerIdentity {
        name: &server.name,
        transport: server.transport,
        endpoint: &server.endpoint,
        executable: &server.executable,
        argument_count: server.argument_count,
        argument_sha256: &server.argument_sha256,
        authentication: server.authentication,
        tls: server.tls,
        credential_names: &credential_names,
        tools: tools.into_iter().map(canonical_tool).collect(),
    };
    digest(
        "layerfault:mcp-server:v1\0",
        &serde_json::to_vec(&value)?,
        "lfmcp:v1",
    )
}

pub fn agent_identity(
    name: &str,
    composition: Option<&str>,
    servers: &[McpServer],
    capabilities: &[CapabilityGrant],
) -> Result<String> {
    #[derive(Serialize)]
    struct AgentIdentity<'a> {
        name: &'a str,
        composition: Option<&'a str>,
        servers: Vec<&'a str>,
        capabilities: Vec<&'a CapabilityGrant>,
    }
    let mut server_ids = servers
        .iter()
        .map(|server| server.identity.as_str())
        .collect::<Vec<_>>();
    server_ids.sort();
    let mut caps = capabilities.iter().collect::<Vec<_>>();
    caps.sort();
    let value = AgentIdentity {
        name,
        composition,
        servers: server_ids,
        capabilities: caps,
    };
    digest(
        "layerfault:agent:v1\0",
        &serde_json::to_vec(&value)?,
        "lfagent:v1",
    )
}

pub fn graph_identity(agent: &AgentDefinition, servers: &[McpServer]) -> Result<String> {
    #[derive(Serialize)]
    struct GraphIdentity<'a> {
        agent_identity: &'a str,
        servers: Vec<&'a str>,
    }
    let mut ids = servers
        .iter()
        .map(|server| server.identity.as_str())
        .collect::<Vec<_>>();
    ids.sort();
    let value = GraphIdentity {
        agent_identity: &agent.identity,
        servers: ids,
    };
    digest(
        "layerfault:capability-graph:v1\0",
        &serde_json::to_vec(&value)?,
        "lfcapgraph:v1",
    )
}

fn digest(domain: &str, payload: &[u8], prefix: &str) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update(payload);
    Ok(format!(
        "{prefix}:sha256:{}",
        hex::encode(hasher.finalize())
    ))
}

pub fn server_set_identity(servers: &[McpServer]) -> Result<String> {
    let mut ids = servers
        .iter()
        .map(|server| server.identity.as_str())
        .collect::<Vec<_>>();
    ids.sort();
    digest(
        "layerfault:mcp-server-set:v1\0",
        &serde_json::to_vec(&ids)?,
        "lfmcpset:v1",
    )
}

pub fn tool_schema_identity(servers: &[McpServer]) -> Result<String> {
    #[derive(Serialize)]
    struct ServerTools<'a> {
        server: &'a str,
        tools: Vec<ToolIdentity<'a>>,
    }
    let mut values = servers
        .iter()
        .map(|server| {
            let mut tools = server.tools.iter().collect::<Vec<_>>();
            tools.sort_by(|a, b| a.name.cmp(&b.name));
            ServerTools {
                server: &server.name,
                tools: tools.into_iter().map(canonical_tool).collect(),
            }
        })
        .collect::<Vec<_>>();
    values.sort_by(|a, b| a.server.cmp(b.server));
    digest(
        "layerfault:tool-schema-set:v1\0",
        &serde_json::to_vec(&values)?,
        "lftools:v1",
    )
}
