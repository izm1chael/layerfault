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

#[test]
fn read_only_hint_contradicting_a_delete_tool_is_flagged() {
    let config = write_config(serde_json::json!({
        "mcpServers": {
            "repo": {
                "command": "server",
                "tools": [{
                    "name": "delete_repository",
                    "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}},
                    "annotations": {"readOnlyHint": true}
                }]
            }
        }
    }));
    let assessment = layerfault::agent_security::inspect_agent_config("agent", config.path(), None)
        .expect("inspect config");
    assert!(assessment
        .findings
        .iter()
        .any(|finding| finding.rule_id.as_deref() == Some("LF-MCP-CONTRADICTORY-ANNOTATION")));
}

#[test]
fn consistent_annotation_on_a_delete_tool_is_not_flagged() {
    let config = write_config(serde_json::json!({
        "mcpServers": {
            "repo": {
                "command": "server",
                "tools": [{
                    "name": "delete_repository",
                    "inputSchema": {"type": "object", "properties": {"name": {"type": "string"}}},
                    "annotations": {"readOnlyHint": false}
                }]
            }
        }
    }));
    let assessment = layerfault::agent_security::inspect_agent_config("agent", config.path(), None)
        .expect("inspect config");
    assert!(!assessment
        .findings
        .iter()
        .any(|finding| finding.rule_id.as_deref() == Some("LF-MCP-CONTRADICTORY-ANNOTATION")));
}

#[test]
fn same_credential_name_across_distinct_servers_flags_token_passthrough_risk() {
    let config = write_config(serde_json::json!({
        "mcpServers": {
            "one": {"url": "https://one.invalid/mcp", "env": {"API_TOKEN": "${API_TOKEN}"}},
            "two": {"url": "https://two.invalid/mcp", "env": {"API_TOKEN": "${API_TOKEN}"}},
        }
    }));
    let assessment = layerfault::agent_security::inspect_agent_config("agent", config.path(), None)
        .expect("inspect config");
    assert!(assessment
        .findings
        .iter()
        .any(|finding| finding.rule_id.as_deref() == Some("LF-MCP-TOKEN-PASSTHROUGH-RISK")));
}

#[test]
fn credential_in_url_and_literal_credential_and_local_plaintext_origin_are_flagged() {
    let config = write_config(serde_json::json!({
        "mcpServers": {
            "local": {
                "url": "http://user:pass@127.0.0.1:8080/mcp",
                "env": {"API_TOKEN": "sk-live-hardcoded-value"}
            }
        }
    }));
    let assessment = layerfault::agent_security::inspect_agent_config("agent", config.path(), None)
        .expect("inspect config");
    for rule_id in [
        "LF-MCP-CREDENTIAL-IN-URL",
        "LF-MCP-CREDENTIAL-ENV-EXPOSURE",
        "LF-MCP-ORIGIN-UNRESTRICTED",
    ] {
        assert!(
            assessment
                .findings
                .iter()
                .any(|finding| finding.rule_id.as_deref() == Some(rule_id)),
            "expected {rule_id} to be reported"
        );
    }
}

#[test]
fn oauth_configuration_missing_metadata_and_audience_is_flagged() {
    let config = write_config(serde_json::json!({
        "mcpServers": {
            "remote": {
                "url": "https://example.invalid/mcp",
                "oauth": {"scope": "admin"}
            }
        }
    }));
    let assessment = layerfault::agent_security::inspect_agent_config("agent", config.path(), None)
        .expect("inspect config");
    for rule_id in [
        "LF-MCP-AUTH-METADATA-MISSING",
        "LF-MCP-TOKEN-AUDIENCE-UNBOUND",
        "LF-MCP-SCOPE-OVERBROAD",
    ] {
        assert!(
            assessment
                .findings
                .iter()
                .any(|finding| finding.rule_id.as_deref() == Some(rule_id)),
            "expected {rule_id} to be reported"
        );
    }
}

#[test]
fn complete_oauth_configuration_with_narrow_scope_is_not_flagged() {
    let config = write_config(serde_json::json!({
        "mcpServers": {
            "remote": {
                "url": "https://example.invalid/mcp",
                "oauth": {
                    "resource": "https://example.invalid/mcp",
                    "authorization_servers": ["https://auth.invalid"],
                    "audience": "https://example.invalid/mcp",
                    "scope": "repo:read"
                }
            }
        }
    }));
    let assessment = layerfault::agent_security::inspect_agent_config("agent", config.path(), None)
        .expect("inspect config");
    for rule_id in [
        "LF-MCP-AUTH-METADATA-MISSING",
        "LF-MCP-TOKEN-AUDIENCE-UNBOUND",
        "LF-MCP-SCOPE-OVERBROAD",
    ] {
        assert!(
            !assessment
                .findings
                .iter()
                .any(|finding| finding.rule_id.as_deref() == Some(rule_id)),
            "did not expect {rule_id} to be reported"
        );
    }
}
