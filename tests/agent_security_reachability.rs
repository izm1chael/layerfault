//! Integration coverage for cross-server capability-graph reachability
//! (`inspect_agent_config` end to end). These fixtures exist because the
//! previous dangerous-chain detector used global co-occurrence over a
//! flattened, deduplicated capability list, which meant two capabilities on
//! completely unrelated servers were reported identically to two
//! capabilities on the same tool. The graph model must instead treat
//! same-agent reachability as the default across servers, and must only
//! withhold a finding when a genuine barrier is present — not merely
//! because the capabilities came from different servers.

use std::io::Write;

fn write_config(json: serde_json::Value) -> tempfile::NamedTempFile {
    let mut file = tempfile::Builder::new().suffix(".json").tempfile().unwrap();
    file.write_all(json.to_string().as_bytes()).unwrap();
    file
}

fn secret_and_egress_config() -> serde_json::Value {
    serde_json::json!({
        "mcpServers": {
            "secrets": {
                "command": "secrets-server",
                "tools": [{
                    "name": "read_secret",
                    "inputSchema": {"type": "object", "properties": {"vault_key": {"type": "string"}}}
                }]
            },
            "web": {
                "command": "web-server",
                "tools": [{
                    "name": "http_post",
                    "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}}
                }]
            }
        }
    })
}

#[test]
fn cross_server_secret_and_egress_produces_a_reachable_chain() {
    let config = write_config(secret_and_egress_config());
    let assessment = layerfault::agent_security::inspect_agent_config("agent", config.path(), None)
        .expect("inspect config");
    let chain = assessment
        .graph
        .dangerous_chains
        .iter()
        .find(|chain| chain.id == "secret-read-to-network-egress")
        .expect("cross-server path is reported, not suppressed by server locality");
    assert_eq!(
        chain.reachability,
        layerfault::agent_security::PathReachability::Reachable
    );
    assert_ne!(chain.source.server, chain.sink.server);
    assert!(assessment.findings.iter().any(|finding| {
        finding.rule_id.as_deref() == Some("LF-AGENT-DANGEROUS-CAPABILITY-CHAIN")
    }));
}

#[test]
fn confirmation_required_sink_is_reachable_with_control() {
    let mut config = secret_and_egress_config();
    config["mcpServers"]["web"]["tools"][0]["confirmation_required"] =
        serde_json::Value::Bool(true);
    let config = write_config(config);
    let assessment = layerfault::agent_security::inspect_agent_config("agent", config.path(), None)
        .expect("inspect config");
    let chain = assessment
        .graph
        .dangerous_chains
        .iter()
        .find(|chain| chain.id == "secret-read-to-network-egress")
        .expect("chain still reported when mitigated");
    assert_eq!(
        chain.reachability,
        layerfault::agent_security::PathReachability::ReachableWithControl
    );
}

#[test]
fn unrelated_capabilities_on_different_servers_still_do_not_chain() {
    // Two servers, two capabilities, but not a source/sink pair for any
    // defined chain: filesystem read (from a "path" field) and database
    // read. This must not produce any dangerous chain — proving the model
    // still requires an actual defined source/sink relationship, not just
    // "the agent has multiple capabilities somewhere".
    let config = write_config(serde_json::json!({
        "mcpServers": {
            "files": {
                "command": "files-server",
                "tools": [{"name": "read_file", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}}]
            },
            "db": {
                "command": "db-server",
                "tools": [{"name": "query", "inputSchema": {"type": "object", "properties": {"sql": {"type": "string"}}}}]
            }
        }
    }));
    let assessment = layerfault::agent_security::inspect_agent_config("agent", config.path(), None)
        .expect("inspect config");
    assert!(assessment.graph.dangerous_chains.is_empty());
}
