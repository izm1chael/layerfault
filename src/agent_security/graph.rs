use super::{
    AgentDefinition, CapabilityGrant, CapabilityGraph, CapabilityKind, DangerousCapabilityChain,
    McpServer,
};
use crate::assurance::AnalysisCompleteness;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub fn build(
    agent_name: &str,
    composition_identity: Option<&str>,
    mut servers: Vec<McpServer>,
) -> Result<CapabilityGraph> {
    servers.sort_by(|a, b| a.name.cmp(&b.name));
    let mut capabilities = Vec::<CapabilityGrant>::new();
    let mut limitations = Vec::new();
    let mut schema_analysis_complete = true;
    for server in &servers {
        limitations.extend(
            server
                .limitations
                .iter()
                .map(|value| format!("{}: {value}", server.name)),
        );
        for tool in &server.tools {
            let (grants, outcome) = super::schema::capabilities_for_tool(&server.name, tool);
            capabilities.extend(grants);
            if outcome.completeness != AnalysisCompleteness::Complete {
                schema_analysis_complete = false;
            }
            limitations.extend(outcome.limitations);
        }
    }
    capabilities.sort();
    capabilities.dedup();
    limitations.sort();
    limitations.dedup();
    // Check emptiness first: an empty server list satisfies `.all(...)`
    // vacuously, so checking that branch first would report a config with no
    // MCP servers at all (or `{"mcpServers":{}}`) as fully Complete instead
    // of Unknown.
    let completeness = if servers.is_empty() {
        AnalysisCompleteness::Unknown
    } else if schema_analysis_complete
        && servers
            .iter()
            .all(|server| server.completeness == AnalysisCompleteness::Complete)
    {
        AnalysisCompleteness::Complete
    } else {
        AnalysisCompleteness::Partial
    };
    let identity =
        super::identity::agent_identity(agent_name, composition_identity, &servers, &capabilities)?;
    let mut agent = AgentDefinition {
        name: agent_name.to_owned(),
        identity,
        model_composition_identity: composition_identity.map(str::to_owned),
        server_identities: servers
            .iter()
            .map(|server| server.identity.clone())
            .collect(),
        capabilities,
        completeness,
        limitations,
    };
    agent.server_identities.sort();
    let server_completeness: BTreeMap<String, AnalysisCompleteness> = servers
        .iter()
        .map(|server| (server.name.clone(), server.completeness))
        .collect();
    let dangerous_chains = dangerous_chains(&agent.capabilities, &server_completeness);
    let graph_identity = super::identity::graph_identity(&agent, &servers)?;
    Ok(CapabilityGraph {
        version: 2,
        agent,
        servers,
        dangerous_chains,
        graph_identity,
        completeness,
    })
}

/// Whether a potential path from a source capability to a sink capability,
/// mediated by the model, is available for an agent to actually exercise.
///
/// Static graph reachability is potential, not proof: none of these states
/// assert that data has actually flowed from source to sink, only what the
/// agent's capability graph makes possible. Consumers must not present
/// `Reachable`/`ReachableWithControl` as evidence that exfiltration
/// occurred, and must not treat `Indeterminate` as equivalent to `Blocked`
/// — insufficient evidence is not evidence of absence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathReachability {
    /// The agent can invoke both capabilities and no barrier or control is
    /// known. This is Layerfault's default assumption for any two tools the
    /// same agent can invoke: under the standard MCP flow, a tool's result
    /// is visible in model context and the model can use it to construct
    /// arguments for another tool call.
    Reachable,
    /// Reachable, but a mitigating control is known to sit in front of the
    /// sink (mandatory human approval, restrictive policy, limited scope).
    /// Still dangerous — the control can fail open, be misconfigured, or be
    /// bypassed — but materially different from an uncontrolled path.
    ReachableWithControl,
    /// A real isolation barrier is known to apply: the result never reaches
    /// the model, the tool is unavailable to this agent, the two run in
    /// incompatible isolated execution contexts, or the data flow is fixed
    /// and non-model-mediated. Not reported as a dangerous chain.
    Blocked,
    /// There is not enough evidence to determine reachability (for example,
    /// capability discovery for the source or sink server is incomplete).
    /// Must not be treated as `Blocked`: an unknown path is not a safe one.
    Indeterminate,
}

/// Decide reachability for one source/sink pair. See `PathReachability` for
/// what each outcome does and does not claim.
///
/// The signals available to this decision are deliberately limited to what
/// the current static MCP parser can actually produce:
/// `CapabilityGrant::isolation_barrier` (not yet populated by any real
/// parser — a hook for later Discovery/Posture evidence),
/// `CapabilityGrant::confirmation_required` (the one control signal already
/// present in tool annotations), and per-server `AnalysisCompleteness`. Any
/// other barrier or control described in `PathReachability`'s documentation
/// (sub-agent isolation, policy barriers, scope incompatibility) has no
/// producing signal yet and so cannot make a path `Blocked` or
/// `ReachableWithControl` today; that is a coverage limitation to close in
/// later units, not something to fake here.
fn path_reachability(
    source: &CapabilityGrant,
    sink: &CapabilityGrant,
    server_completeness: &BTreeMap<String, AnalysisCompleteness>,
) -> (PathReachability, Option<String>) {
    if let Some(reason) = source
        .isolation_barrier
        .as_deref()
        .or(sink.isolation_barrier.as_deref())
    {
        return (PathReachability::Blocked, Some(reason.to_owned()));
    }

    let completeness_for = |grant: &CapabilityGrant| {
        grant
            .server
            .as_deref()
            .map(|name| {
                server_completeness
                    .get(name)
                    .copied()
                    .unwrap_or(AnalysisCompleteness::Unknown)
            })
            .unwrap_or(AnalysisCompleteness::Unknown)
    };
    if completeness_for(source) != AnalysisCompleteness::Complete
        || completeness_for(sink) != AnalysisCompleteness::Complete
    {
        return (
            PathReachability::Indeterminate,
            Some(
                "capability discovery for the source or sink server is incomplete, so reachability cannot be established"
                    .to_owned(),
            ),
        );
    }

    if sink.confirmation_required == Some(true) {
        return (
            PathReachability::ReachableWithControl,
            Some("the sink tool requires explicit user confirmation before execution".to_owned()),
        );
    }

    (PathReachability::Reachable, None)
}

/// (id, title, impact, source capability, sink capability). Each definition
/// names a source/sink capability pair whose combination is security
/// relevant regardless of which server or tool exposes either half — see
/// the module documentation on cross-server reachability.
const CHAIN_DEFINITIONS: &[(&str, &str, &str, CapabilityKind, CapabilityKind)] = &[
    ("secret-read-to-network-egress", "Secret Read → Internet Egress", "A tool-capable agent can read secret material and has a path to transmit data outside the local trust boundary.", CapabilityKind::SecretRead, CapabilityKind::NetworkInternetEgress),
    ("repository-write-to-shell", "Repository Write → Shell Execution", "The agent can modify source-controlled content and execute commands, creating a path from generated changes to code execution.", CapabilityKind::GitWrite, CapabilityKind::ProcessShell),
    ("repository-write-to-push", "Repository Write → Git Push", "The agent can modify repository content and publish those modifications to a remote repository.", CapabilityKind::GitWrite, CapabilityKind::GitPush),
    ("database-read-to-network-egress", "Database Read → Internet Egress", "The agent can read database content and transmit data to internet destinations.", CapabilityKind::DatabaseRead, CapabilityKind::NetworkInternetEgress),
    ("cloud-identity-to-admin", "Cloud Identity → Cloud Admin", "The agent can use cloud identity material and exercise administrative cloud operations.", CapabilityKind::CloudIdentity, CapabilityKind::CloudAdmin),
    ("browser-credentials-to-network-egress", "Browser Credentials → Internet Egress", "The agent can access browser credential material and communicate with internet destinations.", CapabilityKind::BrowserCredentials, CapabilityKind::NetworkInternetEgress),
    ("kubernetes-admin-to-secret-read", "Kubernetes Admin → Secret Read", "Cluster administration and secret-read capability can expose credentials and workload data across a cluster.", CapabilityKind::KubernetesAdmin, CapabilityKind::SecretRead),
    // `container-admin-to-host` (ContainerAdmin + FilesystemOutsideWorkspace)
    // is deliberately absent: no classifier in `schema.rs` ever produces
    // `CapabilityKind::FilesystemOutsideWorkspace`, so that chain could
    // never fire. Do not "fix" this by adding a weak lexical classifier
    // just to make it reachable — that would trade a dead detector for a
    // noisy one. Restore it once `FilesystemOutsideWorkspace` has a real,
    // tested source of evidence.
];

/// Find every potential dangerous path in the agent's capability graph.
///
/// This does not require the source and sink capabilities to come from the
/// same server or tool: an agent that can invoke server A's tool exposing
/// `secret.read` and server B's tool exposing `network.internet_egress` has
/// a genuine potential path if A's result is visible to the model and the
/// model can use it to construct B's call arguments, which is the default
/// assumption for any two tools the same agent can invoke (see
/// `PathReachability::Reachable`). Requiring same-server locality would
/// trade today's false positives (unrelated capabilities on the same
/// server treated as chained) for false negatives (genuinely chainable
/// capabilities on different servers treated as unrelated) — it is not a
/// fix.
///
/// `Blocked` paths are not returned: a path that is genuinely not dangerous
/// does not belong in a list of dangerous chains. `Indeterminate` paths are
/// returned, not omitted — insufficient evidence must not be presented as
/// evidence of absence. One entry is produced per concrete (source, sink)
/// grant pair, not a single representative per chain id, so the exact path
/// (which server, which tool) is always visible in the output.
pub fn dangerous_chains(
    grants: &[CapabilityGrant],
    server_completeness: &BTreeMap<String, AnalysisCompleteness>,
) -> Vec<DangerousCapabilityChain> {
    let mut out = Vec::new();
    for (id, title, impact, source_kind, sink_kind) in CHAIN_DEFINITIONS {
        let sources: Vec<&CapabilityGrant> = grants
            .iter()
            .filter(|grant| grant.capability == *source_kind)
            .collect();
        let sinks: Vec<&CapabilityGrant> = grants
            .iter()
            .filter(|grant| grant.capability == *sink_kind)
            .collect();
        for source in &sources {
            for sink in &sinks {
                let (reachability, barrier) = path_reachability(source, sink, server_completeness);
                if reachability == PathReachability::Blocked {
                    continue;
                }
                out.push(DangerousCapabilityChain {
                    id: (*id).into(),
                    title: (*title).into(),
                    impact: (*impact).into(),
                    reachability,
                    source: (*source).clone(),
                    sink: (*sink).clone(),
                    barrier,
                });
            }
        }
    }
    out.sort_by(|a, b| {
        a.id.cmp(&b.id)
            .then_with(|| a.source.cmp(&b.source))
            .then_with(|| a.sink.cmp(&b.sink))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_security::{CapabilityConfidence, CapabilityEvidenceKind, CapabilityScope};

    #[test]
    fn empty_server_list_is_unknown_not_complete() {
        let graph = build("agent", None, Vec::new()).expect("build graph");
        assert_eq!(graph.completeness, AnalysisCompleteness::Unknown);
    }

    fn grant(capability: CapabilityKind, server: &str, tool: &str) -> CapabilityGrant {
        CapabilityGrant {
            capability,
            scope: CapabilityScope::Unknown,
            source: "test".into(),
            server: Some(server.into()),
            tool: Some(tool.into()),
            confirmation_required: None,
            evidence_kind: CapabilityEvidenceKind::LexicallyInferred,
            confidence: CapabilityConfidence::Medium,
            isolation_barrier: None,
        }
    }

    fn complete_map(servers: &[&str]) -> BTreeMap<String, AnalysisCompleteness> {
        servers
            .iter()
            .map(|name| ((*name).to_owned(), AnalysisCompleteness::Complete))
            .collect()
    }

    #[test]
    fn container_admin_to_host_chain_is_not_active_even_when_both_capabilities_are_present() {
        let grants = vec![
            grant(CapabilityKind::ContainerAdmin, "a", "t1"),
            grant(CapabilityKind::FilesystemOutsideWorkspace, "a", "t2"),
        ];
        let chains = dangerous_chains(&grants, &complete_map(&["a"]));
        assert!(!chains
            .iter()
            .any(|chain| chain.id == "container-admin-to-host"));
    }

    #[test]
    fn cross_server_reachable_path_is_reported_with_the_concrete_path() {
        // Deliberately two different servers: cross-server reachability is
        // the default, not something that requires same-server locality.
        let grants = vec![
            grant(CapabilityKind::SecretRead, "server-a", "read_secret"),
            grant(
                CapabilityKind::NetworkInternetEgress,
                "server-b",
                "http_post",
            ),
        ];
        let chains = dangerous_chains(&grants, &complete_map(&["server-a", "server-b"]));
        let chain = chains
            .iter()
            .find(|chain| chain.id == "secret-read-to-network-egress")
            .expect("chain reported");
        assert_eq!(chain.reachability, PathReachability::Reachable);
        assert_eq!(chain.source.server.as_deref(), Some("server-a"));
        assert_eq!(chain.source.tool.as_deref(), Some("read_secret"));
        assert_eq!(chain.sink.server.as_deref(), Some("server-b"));
        assert_eq!(chain.sink.tool.as_deref(), Some("http_post"));
    }

    #[test]
    fn genuinely_blocked_path_is_not_reported_as_a_dangerous_chain() {
        let mut sink = grant(
            CapabilityKind::NetworkInternetEgress,
            "server-b",
            "http_post",
        );
        sink.isolation_barrier =
            Some("sink runs in an isolated sub-agent with no shared model context".into());
        let grants = vec![
            grant(CapabilityKind::SecretRead, "server-a", "read_secret"),
            sink,
        ];
        let chains = dangerous_chains(&grants, &complete_map(&["server-a", "server-b"]));
        assert!(!chains
            .iter()
            .any(|chain| chain.id == "secret-read-to-network-egress"));
    }

    #[test]
    fn mitigating_control_is_reachable_with_control_not_reachable_or_blocked() {
        let mut sink = grant(
            CapabilityKind::NetworkInternetEgress,
            "server-b",
            "http_post",
        );
        sink.confirmation_required = Some(true);
        let grants = vec![
            grant(CapabilityKind::SecretRead, "server-a", "read_secret"),
            sink,
        ];
        let chains = dangerous_chains(&grants, &complete_map(&["server-a", "server-b"]));
        let chain = chains
            .iter()
            .find(|chain| chain.id == "secret-read-to-network-egress")
            .expect("chain reported, not dropped");
        assert_eq!(chain.reachability, PathReachability::ReachableWithControl);
        assert!(chain.barrier.is_some());
    }

    #[test]
    fn incomplete_discovery_is_indeterminate_not_silently_dropped() {
        let grants = vec![
            grant(CapabilityKind::SecretRead, "server-a", "read_secret"),
            grant(
                CapabilityKind::NetworkInternetEgress,
                "server-b",
                "http_post",
            ),
        ];
        let mut completeness = complete_map(&["server-a"]);
        completeness.insert("server-b".to_owned(), AnalysisCompleteness::Partial);
        let chains = dangerous_chains(&grants, &completeness);
        let chain = chains
            .iter()
            .find(|chain| chain.id == "secret-read-to-network-egress")
            .expect("indeterminate path is reported, not omitted");
        assert_eq!(chain.reachability, PathReachability::Indeterminate);
    }
}
