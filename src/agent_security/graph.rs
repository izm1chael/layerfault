use super::{
    AgentDefinition, CapabilityGrant, CapabilityGraph, CapabilityKind, DangerousCapabilityChain,
    McpServer,
};
use crate::assurance::AnalysisCompleteness;
use anyhow::Result;
use std::collections::BTreeMap;

pub fn build(
    agent_name: &str,
    composition_identity: Option<&str>,
    mut servers: Vec<McpServer>,
) -> Result<CapabilityGraph> {
    servers.sort_by(|a, b| a.name.cmp(&b.name));
    let mut capabilities = Vec::<CapabilityGrant>::new();
    let mut limitations = Vec::new();
    for server in &servers {
        limitations.extend(
            server
                .limitations
                .iter()
                .map(|value| format!("{}: {value}", server.name)),
        );
        for tool in &server.tools {
            capabilities.extend(super::schema::capabilities_for_tool(&server.name, tool));
        }
    }
    capabilities.sort();
    capabilities.dedup();
    limitations.sort();
    limitations.dedup();
    let completeness = if servers
        .iter()
        .all(|server| server.completeness == AnalysisCompleteness::Complete)
    {
        AnalysisCompleteness::Complete
    } else if servers.is_empty() {
        AnalysisCompleteness::Unknown
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
    let dangerous_chains = dangerous_chains(&agent.capabilities);
    let graph_identity = super::identity::graph_identity(&agent, &servers)?;
    Ok(CapabilityGraph {
        version: 1,
        agent,
        servers,
        dangerous_chains,
        graph_identity,
        completeness,
    })
}

pub fn dangerous_chains(grants: &[CapabilityGrant]) -> Vec<DangerousCapabilityChain> {
    let by_kind = grants.iter().fold(
        BTreeMap::<CapabilityKind, Vec<&CapabilityGrant>>::new(),
        |mut map, grant| {
            map.entry(grant.capability).or_default().push(grant);
            map
        },
    );
    let definitions: &[(&str, &str, &str, &[CapabilityKind])] = &[
        ("secret-read-to-network-egress", "Secret Read → Internet Egress", "A tool-capable agent can read secret material and has a path to transmit data outside the local trust boundary.", &[CapabilityKind::SecretRead, CapabilityKind::NetworkInternetEgress]),
        ("repository-write-to-shell", "Repository Write → Shell Execution", "The agent can modify source-controlled content and execute commands, creating a path from generated changes to code execution.", &[CapabilityKind::GitWrite, CapabilityKind::ProcessShell]),
        ("repository-write-to-push", "Repository Write → Git Push", "The agent can modify repository content and publish those modifications to a remote repository.", &[CapabilityKind::GitWrite, CapabilityKind::GitPush]),
        ("database-read-to-network-egress", "Database Read → Internet Egress", "The agent can read database content and transmit data to internet destinations.", &[CapabilityKind::DatabaseRead, CapabilityKind::NetworkInternetEgress]),
        ("cloud-identity-to-admin", "Cloud Identity → Cloud Admin", "The agent can use cloud identity material and exercise administrative cloud operations.", &[CapabilityKind::CloudIdentity, CapabilityKind::CloudAdmin]),
        ("browser-credentials-to-network-egress", "Browser Credentials → Internet Egress", "The agent can access browser credential material and communicate with internet destinations.", &[CapabilityKind::BrowserCredentials, CapabilityKind::NetworkInternetEgress]),
        ("container-admin-to-host", "Container Admin → Host Filesystem", "Administrative container access combines with broad filesystem access and can cross expected workload boundaries.", &[CapabilityKind::ContainerAdmin, CapabilityKind::FilesystemOutsideWorkspace]),
        ("kubernetes-admin-to-secret-read", "Kubernetes Admin → Secret Read", "Cluster administration and secret-read capability can expose credentials and workload data across a cluster.", &[CapabilityKind::KubernetesAdmin, CapabilityKind::SecretRead]),
    ];
    let mut out = Vec::new();
    for (id, title, impact, required) in definitions {
        if required.iter().all(|kind| by_kind.contains_key(kind)) {
            let capabilities = required
                .iter()
                .filter_map(|kind| {
                    by_kind
                        .get(kind)
                        .and_then(|values| values.first())
                        .map(|value| (*value).clone())
                })
                .collect();
            out.push(DangerousCapabilityChain {
                id: (*id).into(),
                title: (*title).into(),
                impact: (*impact).into(),
                capabilities,
            });
        }
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}
