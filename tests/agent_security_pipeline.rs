//! Integration coverage for the agent/MCP static-analysis pipeline
//! (`inspect_agent_config` end to end: config file -> capability graph ->
//! findings). Prior to this file there was no integration test for the
//! agent path at all — only isolated unit tests inside `src/agent_security/`.
//! These fixtures exercise the local analysis changes together, the way an
//! operator running `layerfault agent inspect` would actually see them.

use std::io::Write;

fn write_config(json: serde_json::Value) -> tempfile::NamedTempFile {
    let mut file = tempfile::Builder::new().suffix(".json").tempfile().unwrap();
    file.write_all(json.to_string().as_bytes()).unwrap();
    file
}

#[test]
fn empty_mcp_servers_config_reports_incomplete_not_complete() {
    let config = write_config(serde_json::json!({"mcpServers": {}}));
    let assessment = layerfault::agent_security::inspect_agent_config("agent", config.path(), None)
        .expect("inspect config");
    assert_eq!(
        assessment.graph.completeness,
        layerfault::assurance::AnalysisCompleteness::Unknown
    );
    assert!(assessment
        .findings
        .iter()
        .any(|finding| finding.rule_id.as_deref() == Some("LF-AGENT-CAPABILITY-INCOMPLETE")));
}

#[test]
fn ambiguous_transport_server_does_not_silently_skip_auth_review() {
    let config = write_config(serde_json::json!({
        "mcpServers": {
            "confused": {"command": "server", "type": "http"}
        }
    }));
    let assessment = layerfault::agent_security::inspect_agent_config("agent", config.path(), None)
        .expect("inspect config");
    let server = &assessment.graph.servers[0];
    assert_eq!(
        server.transport,
        layerfault::agent_security::McpTransport::Unknown
    );
    // The server is flagged incomplete (ambiguous transport) rather than
    // silently exempted from remote-transport auth/TLS review the way a
    // wrongly-classified Stdio server would be.
    assert_eq!(
        server.completeness,
        layerfault::assurance::AnalysisCompleteness::Partial
    );
}

#[test]
fn one_malformed_server_does_not_abort_analysis_of_the_others() {
    let config = write_config(serde_json::json!({
        "mcpServers": {
            "broken": {"command": "server", "args": [123, "ok"]},
            "healthy": {
                "command": "server",
                "tools": [{"name": "read_file", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}}]
            }
        }
    }));
    let assessment = layerfault::agent_security::inspect_agent_config("agent", config.path(), None)
        .expect("inspect config must not abort on one malformed server");
    assert_eq!(assessment.graph.servers.len(), 2);
    let healthy = assessment
        .graph
        .servers
        .iter()
        .find(|server| server.name == "healthy")
        .expect("healthy server still analysed");
    assert!(!healthy.tools.is_empty());
}

#[test]
fn max_tokens_alone_does_not_produce_a_secret_exfiltration_chain() {
    // Regression fixture: schema fields containing "max_tokens", "path" and
    // "url" as substrings of unrelated words must not combine into a
    // secret-read-to-network-egress finding via global capability
    // co-occurrence plus substring-matched capability inference.
    let config = write_config(serde_json::json!({
        "mcpServers": {
            "benign": {
                "command": "server",
                "tools": [{
                    "name": "generate",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "max_tokens": {"type": "integer"},
                            "resource_url_pattern": {"type": "string"}
                        }
                    }
                }]
            }
        }
    }));
    let assessment = layerfault::agent_security::inspect_agent_config("agent", config.path(), None)
        .expect("inspect config");
    assert!(!assessment
        .graph
        .dangerous_chains
        .iter()
        .any(|chain| chain.id == "secret-read-to-network-egress"));
}
