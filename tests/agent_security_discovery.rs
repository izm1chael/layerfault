//! Integration coverage for MCP capability-snapshot construction, using a
//! local mock MCP server's canned JSON-RPC response bodies as a fixture.
//!
//! This unit ("Agent/MCP Discovery — protocol snapshot") is scoped to
//! metadata discovery *parsing* only: no transport code lives here, so
//! there is no live client capable of issuing `tools/call`, `resources/read`
//! or `prompts/get` in the first place — the strongest guarantee available
//! at this scope. Actually connecting to a stdio or remote MCP server is a
//! separate, later unit (Agent/MCP Discovery Execution) with a materially
//! larger blast radius (process execution / network egress), deliberately
//! not built here.

/// Canned JSON-RPC response bodies a real MCP server would return for a
/// standard `initialize` -> `tools/list` -> `resources/list` ->
/// `prompts/list` discovery sequence. Standing in for "a local test MCP
/// server" without requiring an actual process or socket, since this unit
/// parses already-obtained response bodies rather than obtaining them.
mod mock_server {
    use serde_json::{json, Value};

    pub fn initialize() -> Value {
        json!({
            "protocolVersion": "2025-11-25",
            "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
            "serverInfo": {"name": "mock-mcp-server", "version": "1.0.0"}
        })
    }

    pub fn tools_list() -> Value {
        json!({"tools": [
            {
                "name": "read_file",
                "description": "Read a file from the workspace",
                "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}
            },
            {
                "name": "http_post",
                "description": "Send an HTTP POST request",
                "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}}
            }
        ]})
    }

    pub fn resources_list() -> Value {
        json!({"resources": [
            {"uri": "file:///workspace/README.md", "name": "README", "mimeType": "text/markdown"}
        ]})
    }

    pub fn prompts_list() -> Value {
        json!({"prompts": [
            {"name": "summarize", "arguments": [{"name": "text", "required": true}]}
        ]})
    }
}

#[test]
fn full_discovery_sequence_produces_a_stable_snapshot() {
    let initialize = mock_server::initialize();
    let protocol = layerfault::agent_security::parse_initialize_response(&initialize);
    assert!(protocol.scanner_supported);
    assert!(protocol.unknown_extensions.is_empty());

    let tools =
        layerfault::agent_security::parse_tools_list(&initialize, Some(&mock_server::tools_list()));
    let resources = layerfault::agent_security::parse_resources_list(
        &initialize,
        Some(&mock_server::resources_list()),
    );
    let prompts = layerfault::agent_security::parse_prompts_list(
        &initialize,
        Some(&mock_server::prompts_list()),
    );

    assert_eq!(tools.0.len(), 2);
    assert_eq!(resources.0.len(), 1);
    assert_eq!(prompts.0.len(), 1);
    assert!(matches!(
        tools.1,
        layerfault::agent_security::PrimitiveState::Complete
    ));

    let first = layerfault::agent_security::build_snapshot(
        protocol.clone(),
        "transport-identity".to_owned(),
        tools.clone(),
        resources.clone(),
        prompts.clone(),
        1_700_000_000,
    )
    .expect("snapshot builds");

    // Re-run the same discovery sequence "later" (a different observed_at)
    // against the same unchanged server: the content digest must be
    // identical, or capability-expansion/drift detection built on snapshot
    // diffs cannot distinguish "nothing changed" from "everything changed".
    let second = layerfault::agent_security::build_snapshot(
        protocol,
        "transport-identity".to_owned(),
        tools,
        resources,
        prompts,
        1_700_003_600,
    )
    .expect("snapshot builds");

    assert_ne!(first.observed_at, second.observed_at);
    assert_eq!(first.content_sha256, second.content_sha256);
}
