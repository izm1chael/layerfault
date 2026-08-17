//! Diffing between two capability graph observations of the same agent,
//! taken at different points in time.
//!
//! The continuous-assurance layer already tracks *that* an agent
//! configuration's identity changed (`SecurityComponent::AgentConfiguration`
//! / `McpServers` / `ToolSchemas`). That answers "did something change?" but
//! not "what, concretely, can the agent do now that it could not do
//! before?" — which is the question that actually matters for a trust
//! decision. This module answers the second question from two already
//! computed `CapabilityGraph`s; it performs no discovery or analysis of its
//! own.

use super::{CapabilityGraph, DangerousCapabilityChain};
use std::collections::BTreeSet;

/// The set of newly observed capabilities, servers, tools and reachable
/// dangerous paths between a baseline graph (e.g. the graph recorded at
/// admission) and a current one. Anything present in the baseline and
/// absent in the current graph is deliberately not reported here —
/// contraction is not an expansion risk, though a caller comparing symmetric
/// difference for other purposes can still diff the two graphs directly.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct CapabilityExpansion {
    pub added_servers: Vec<String>,
    pub added_tools: Vec<AddedTool>,
    pub added_capabilities: Vec<super::CapabilityGrant>,
    pub newly_reachable_chains: Vec<DangerousCapabilityChain>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AddedTool {
    pub server: String,
    pub tool: String,
}

impl CapabilityExpansion {
    pub fn is_empty(&self) -> bool {
        self.added_servers.is_empty()
            && self.added_tools.is_empty()
            && self.added_capabilities.is_empty()
            && self.newly_reachable_chains.is_empty()
    }
}

/// Compute what expanded between `baseline` and `current`. Both graphs are
/// assumed to describe the same agent; this does not verify that (callers
/// diffing unrelated agents will simply get a large, uninformative
/// expansion — the graph's own `agent.identity` is the caller's signal to
/// check first).
pub fn expansion(baseline: &CapabilityGraph, current: &CapabilityGraph) -> CapabilityExpansion {
    let baseline_servers: BTreeSet<&str> = baseline
        .servers
        .iter()
        .map(|server| server.name.as_str())
        .collect();
    let added_servers: Vec<String> = current
        .servers
        .iter()
        .filter(|server| !baseline_servers.contains(server.name.as_str()))
        .map(|server| server.name.clone())
        .collect();

    let baseline_tools: BTreeSet<(&str, &str)> = baseline
        .servers
        .iter()
        .flat_map(|server| {
            server
                .tools
                .iter()
                .map(move |tool| (server.name.as_str(), tool.name.as_str()))
        })
        .collect();
    let added_tools: Vec<AddedTool> = current
        .servers
        .iter()
        .flat_map(|server| {
            let baseline_tools = &baseline_tools;
            server
                .tools
                .iter()
                .filter(move |tool| {
                    !baseline_tools.contains(&(server.name.as_str(), tool.name.as_str()))
                })
                .map(|tool| AddedTool {
                    server: server.name.clone(),
                    tool: tool.name.clone(),
                })
        })
        .collect();

    let baseline_capabilities: BTreeSet<&super::CapabilityGrant> =
        baseline.agent.capabilities.iter().collect();
    let added_capabilities: Vec<super::CapabilityGrant> = current
        .agent
        .capabilities
        .iter()
        .filter(|grant| !baseline_capabilities.contains(grant))
        .cloned()
        .collect();

    let baseline_chains: BTreeSet<_> = baseline
        .dangerous_chains
        .iter()
        .map(|chain| {
            (
                chain.id.as_str(),
                &chain.source,
                &chain.sink,
                chain.reachability,
            )
        })
        .collect();
    let newly_reachable_chains: Vec<DangerousCapabilityChain> = current
        .dangerous_chains
        .iter()
        .filter(|chain| {
            !baseline_chains.contains(&(
                chain.id.as_str(),
                &chain.source,
                &chain.sink,
                chain.reachability,
            ))
        })
        .cloned()
        .collect();

    CapabilityExpansion {
        added_servers,
        added_tools,
        added_capabilities,
        newly_reachable_chains,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_security::inspect_agent_config;
    use std::io::Write;

    fn graph_for(json: serde_json::Value) -> CapabilityGraph {
        let mut file = tempfile::Builder::new().suffix(".json").tempfile().unwrap();
        file.write_all(json.to_string().as_bytes()).unwrap();
        inspect_agent_config("agent", file.path(), None)
            .unwrap()
            .graph
    }

    #[test]
    fn identical_graphs_have_no_expansion() {
        let config = serde_json::json!({
            "mcpServers": {"fs": {"command": "server", "tools": [
                {"name": "read_file", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}}
            ]}}
        });
        let baseline = graph_for(config.clone());
        let current = graph_for(config);
        assert!(expansion(&baseline, &current).is_empty());
    }

    #[test]
    fn a_new_server_and_its_tools_are_reported_as_expansion() {
        let baseline = graph_for(serde_json::json!({
            "mcpServers": {"fs": {"command": "server"}}
        }));
        let current = graph_for(serde_json::json!({
            "mcpServers": {
                "fs": {"command": "server"},
                "shell": {"command": "server", "tools": [
                    {"name": "run_command", "inputSchema": {"type": "object"}}
                ]}
            }
        }));
        let delta = expansion(&baseline, &current);
        assert_eq!(delta.added_servers, vec!["shell".to_owned()]);
        assert_eq!(delta.added_tools.len(), 1);
        assert_eq!(delta.added_tools[0].tool, "run_command");
    }

    #[test]
    fn a_removed_server_is_not_reported_as_an_expansion() {
        let baseline = graph_for(serde_json::json!({
            "mcpServers": {
                "fs": {"command": "server"},
                "shell": {"command": "server"}
            }
        }));
        let current = graph_for(serde_json::json!({
            "mcpServers": {"fs": {"command": "server"}}
        }));
        assert!(expansion(&baseline, &current).is_empty());
    }

    #[test]
    fn adding_a_tool_to_an_existing_server_does_not_relabel_the_server_as_new() {
        let baseline = graph_for(serde_json::json!({
            "mcpServers": {"fs": {"command": "server"}}
        }));
        let current = graph_for(serde_json::json!({
            "mcpServers": {"fs": {"command": "server", "tools": [
                {"name": "read_file", "inputSchema": {"type": "object"}}
            ]}}
        }));
        let delta = expansion(&baseline, &current);
        assert!(delta.added_servers.is_empty());
        assert_eq!(delta.added_tools.len(), 1);
    }
}
