use super::{
    AgentSecurityAssessment, CapabilityGrant, CapabilityGraph, CapabilityKind, McpTransport,
    PathReachability, SecurityState,
};
use crate::finding_evidence::{structural_invariant, EvidenceSubject, FindingBuilder};
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use std::collections::BTreeMap;

pub fn assess(graph: CapabilityGraph) -> AgentSecurityAssessment {
    let mut findings = Vec::new();
    let subject = EvidenceSubject::identity(
        &graph.graph_identity,
        "application/vnd.layerfault.agent-capability-graph+json",
    );
    for server in &graph.servers {
        if matches!(
            server.transport,
            McpTransport::StreamableHttp | McpTransport::LegacyHttpSse
        ) && server.authentication == SecurityState::Absent
        {
            findings.push(server_finding("LF-MCP-AUTH-ABSENT", ScanStatus::Warn, FindingClass::Policy, Confidence::High, &subject, server, "Remote MCP transport has no authentication control represented in the inspected configuration"));
        }
        if matches!(
            server.transport,
            McpTransport::StreamableHttp | McpTransport::LegacyHttpSse
        ) && server.tls == SecurityState::Absent
        {
            findings.push(server_finding(
                "LF-MCP-TLS-ABSENT",
                ScanStatus::Warn,
                FindingClass::Policy,
                Confidence::High,
                &subject,
                server,
                "Remote MCP endpoint uses a plaintext HTTP transport",
            ));
        }
        if server.completeness != crate::assurance::AnalysisCompleteness::Complete {
            findings.push(server_finding(
                "LF-MCP-DISCOVERY-INCOMPLETE",
                ScanStatus::Warn,
                FindingClass::Structural,
                Confidence::Medium,
                &subject,
                server,
                "MCP server capability discovery is incomplete",
            ));
        }
        if server.credential_in_url {
            findings.push(server_finding(
                "LF-MCP-CREDENTIAL-IN-URL",
                ScanStatus::Warn,
                FindingClass::Policy,
                Confidence::High,
                &subject,
                server,
                "MCP server endpoint embeds credentials directly in the URL (userinfo)",
            ));
        }
        if !server.literal_credential_env_names.is_empty() {
            findings.push(server_finding(
                "LF-MCP-CREDENTIAL-ENV-EXPOSURE",
                ScanStatus::Warn,
                FindingClass::Policy,
                Confidence::Medium,
                &subject,
                server,
                "MCP server configuration sets a credential-like environment variable to a literal value rather than an indirection reference",
            ));
        }
        if server.origin_dns_rebinding_exposed {
            findings.push(server_finding(
                "LF-MCP-ORIGIN-UNRESTRICTED",
                ScanStatus::Warn,
                FindingClass::Policy,
                Confidence::Medium,
                &subject,
                server,
                "MCP server is reachable at a local address over plaintext HTTP; local servers without transport security or origin restriction are exposed to DNS rebinding",
            ));
        }
        if let Some(oauth) = &server.oauth {
            if !oauth.resource_declared || !oauth.authorization_servers_declared {
                findings.push(server_finding(
                    "LF-MCP-AUTH-METADATA-MISSING",
                    ScanStatus::Warn,
                    FindingClass::Policy,
                    Confidence::Medium,
                    &subject,
                    server,
                    "MCP server declares OAuth configuration without protected-resource metadata (a declared resource indicator and authorization server list)",
                ));
            }
            if !oauth.audience_declared {
                findings.push(server_finding(
                    "LF-MCP-TOKEN-AUDIENCE-UNBOUND",
                    ScanStatus::Warn,
                    FindingClass::Policy,
                    Confidence::Medium,
                    &subject,
                    server,
                    "MCP server declares OAuth configuration without a declared token audience binding; an unbound token may be replayable against a different resource",
                ));
            }
            if let Some(scope) = &oauth.scope {
                if scope_is_overbroad(scope) {
                    findings.push(server_finding(
                        "LF-MCP-SCOPE-OVERBROAD",
                        ScanStatus::Warn,
                        FindingClass::Policy,
                        Confidence::Medium,
                        &subject,
                        server,
                        "MCP server OAuth configuration declares a broad scope rather than a narrowly scoped grant",
                    ));
                }
            }
        }
    }
    findings.extend(token_passthrough_findings(&graph, &subject));
    findings.extend(annotation_contradiction_findings(&graph, &subject));
    for chain in &graph.dangerous_chains {
        let (confidence, detail) = match chain.reachability {
            PathReachability::Reachable => (
                Confidence::High,
                format!(
                    "{}: {} A potential path exists from {} to {}. Layerfault records this as a graph-reachability claim, not evidence that data has actually flowed.",
                    chain.title,
                    chain.impact,
                    describe_grant(&chain.source),
                    describe_grant(&chain.sink)
                ),
            ),
            PathReachability::ReachableWithControl => (
                Confidence::High,
                format!(
                    "{}: {} A potential path exists from {} to {}, mitigated by a known control: {}.",
                    chain.title,
                    chain.impact,
                    describe_grant(&chain.source),
                    describe_grant(&chain.sink),
                    chain.barrier.as_deref().unwrap_or("an identified control")
                ),
            ),
            PathReachability::Indeterminate => (
                Confidence::Low,
                format!(
                    "{}: {} Whether a path exists from {} to {} could not be determined: {}. This is not evidence that no path exists.",
                    chain.title,
                    chain.impact,
                    describe_grant(&chain.source),
                    describe_grant(&chain.sink),
                    chain.barrier.as_deref().unwrap_or("insufficient evidence")
                ),
            ),
            PathReachability::Blocked => continue, // dangerous_chains() never returns Blocked entries.
        };
        findings.push(
            FindingBuilder::new(
                "LF-AGENT-DANGEROUS-CAPABILITY-CHAIN",
                CheckType::AgentSecurity,
                ScanStatus::Warn,
            )
            .class(FindingClass::Policy)
            .confidence(confidence)
            .subject(subject.clone())
            .detail(detail)
            .evidence(structural_invariant(
                subject.clone(),
                "dangerous capability chain",
                serde_json::json!({
                    "chain_id": chain.id,
                    "title": chain.title,
                    "reachability": chain.reachability,
                    "source": chain.source,
                    "sink": chain.sink,
                    "barrier": chain.barrier,
                }),
            ))
            .finish(),
        );
    }
    for grant in &graph.agent.capabilities {
        if grant.capability.high_impact()
            && grant.scope.broad()
            && grant.confirmation_required != Some(true)
        {
            findings.push(
                FindingBuilder::new("LF-TOOL-HIGH-IMPACT-UNCONFIRMED", CheckType::AgentSecurity, ScanStatus::Warn)
                    .class(FindingClass::Policy)
                    .confidence(Confidence::Medium)
                    .subject(subject.clone())
                    .detail(format!("High-impact capability {} has broad {:?} scope without an observed confirmation requirement", grant.capability.as_str(), grant.scope))
                    .evidence(structural_invariant(subject.clone(), "tool capability grant", serde_json::json!(grant)))
                    .finish(),
            );
        }
    }
    if graph.completeness != crate::assurance::AnalysisCompleteness::Complete {
        findings.push(
            FindingBuilder::new("LF-AGENT-CAPABILITY-INCOMPLETE", CheckType::AgentSecurity, ScanStatus::Warn)
                .class(FindingClass::Structural)
                .confidence(Confidence::Medium)
                .subject(subject.clone())
                .detail("Agent capability analysis is incomplete; absence of a discovered capability is not evidence that the capability is unavailable")
                .evidence(structural_invariant(subject, "capability graph completeness", serde_json::json!({
                    "completeness": graph.completeness,
                    "limitations": graph.agent.limitations,
                })))
                .finish(),
        );
    }
    AgentSecurityAssessment { graph, findings }
}

/// True for a scope string that grants broad access rather than a narrow,
/// task-specific one: a wildcard, or a bare admin/all-shaped token.
/// Deliberately conservative — this flags a small, high-confidence set of
/// patterns rather than attempting to judge every possible scope string.
fn scope_is_overbroad(scope: &str) -> bool {
    let lower = scope.to_ascii_lowercase();
    lower.split_whitespace().any(|token| {
        matches!(
            token,
            "*" | "all" | "admin" | "full_access" | "full-access" | "superuser" | "root"
        )
    }) || lower.contains('*')
}

/// Correlate credential *names* (never values) across servers with
/// different effective identities (endpoint or executable). The same
/// credential-shaped variable name declared for two servers that talk to
/// different things is a pattern worth a human looking at — a classic
/// confused-deputy/token-passthrough shape — even though name equality
/// alone cannot prove the same credential value is actually reused.
fn token_passthrough_findings(
    graph: &CapabilityGraph,
    subject: &EvidenceSubject,
) -> Vec<LayerScanResult> {
    let mut by_credential_name: BTreeMap<&str, Vec<&super::McpServer>> = BTreeMap::new();
    for server in &graph.servers {
        for name in &server.credential_names {
            by_credential_name.entry(name).or_default().push(server);
        }
    }
    let mut findings = Vec::new();
    for (credential_name, servers) in by_credential_name {
        let mut distinct_identities: Vec<&str> = servers
            .iter()
            .map(|server| {
                server
                    .endpoint
                    .as_deref()
                    .or(server.executable.as_deref())
                    .unwrap_or("")
            })
            .collect();
        distinct_identities.sort();
        distinct_identities.dedup();
        if distinct_identities.len() < 2 {
            continue;
        }
        let server_names: Vec<&str> = servers.iter().map(|server| server.name.as_str()).collect();
        findings.push(
            FindingBuilder::new(
                "LF-MCP-TOKEN-PASSTHROUGH-RISK",
                CheckType::McpSecurity,
                ScanStatus::Warn,
            )
            .class(FindingClass::Policy)
            .confidence(Confidence::Low)
            .subject(subject.clone())
            .detail(format!(
                "Credential-like variable '{credential_name}' is declared for multiple MCP servers with different endpoints/executables: {}",
                server_names.join(", ")
            ))
            .evidence(structural_invariant(
                subject.clone(),
                "shared credential name across servers",
                serde_json::json!({
                    "credential_name": credential_name,
                    "servers": server_names,
                }),
            ))
            .finish(),
        );
    }
    findings
}

/// Tool `annotations` are untrusted claims the server makes about its own
/// tools, not facts — the MCP spec is explicit that clients must not treat
/// them as ground truth unless the server itself is otherwise trusted. This
/// cross-references `readOnlyHint`/`destructiveHint` against the
/// capabilities Layerfault independently inferred for the same tool.
fn annotation_contradiction_findings(
    graph: &CapabilityGraph,
    subject: &EvidenceSubject,
) -> Vec<LayerScanResult> {
    const WRITE_SHAPED: &[CapabilityKind] = &[
        CapabilityKind::FilesystemWrite,
        CapabilityKind::FilesystemDelete,
        CapabilityKind::DatabaseWrite,
        CapabilityKind::DatabaseAdmin,
        CapabilityKind::GitWrite,
        CapabilityKind::GitPush,
        CapabilityKind::GitAdmin,
        CapabilityKind::CloudWrite,
        CapabilityKind::CloudAdmin,
        CapabilityKind::ContainerAdmin,
        CapabilityKind::KubernetesWrite,
        CapabilityKind::KubernetesAdmin,
        CapabilityKind::EmailSend,
    ];
    const DESTRUCTIVE_SHAPED: &[CapabilityKind] = &[
        CapabilityKind::FilesystemDelete,
        CapabilityKind::DatabaseAdmin,
        CapabilityKind::GitPush,
        CapabilityKind::GitAdmin,
        CapabilityKind::CloudAdmin,
        CapabilityKind::ContainerAdmin,
        CapabilityKind::KubernetesAdmin,
    ];
    let mut findings = Vec::new();
    for server in &graph.servers {
        for tool in &server.tools {
            let Some(annotations) = tool.annotations.as_object() else {
                continue;
            };
            let read_only_hint = annotations.get("readOnlyHint").and_then(|v| v.as_bool());
            let destructive_hint = annotations.get("destructiveHint").and_then(|v| v.as_bool());
            if read_only_hint != Some(true) && destructive_hint != Some(false) {
                continue;
            }
            let tool_capabilities: Vec<CapabilityKind> = graph
                .agent
                .capabilities
                .iter()
                .filter(|grant| {
                    grant.server.as_deref() == Some(server.name.as_str())
                        && grant.tool.as_deref() == Some(tool.name.as_str())
                })
                .map(|grant| grant.capability)
                .collect();
            let contradiction = if read_only_hint == Some(true)
                && tool_capabilities
                    .iter()
                    .any(|kind| WRITE_SHAPED.contains(kind))
            {
                Some("declares readOnlyHint: true but Layerfault independently inferred a write-shaped capability from its schema")
            } else if destructive_hint == Some(false)
                && tool_capabilities
                    .iter()
                    .any(|kind| DESTRUCTIVE_SHAPED.contains(kind))
            {
                Some("declares destructiveHint: false but Layerfault independently inferred a destructive-shaped capability from its schema")
            } else {
                None
            };
            let Some(reason) = contradiction else {
                continue;
            };
            findings.push(
                FindingBuilder::new(
                    "LF-MCP-CONTRADICTORY-ANNOTATION",
                    CheckType::McpSecurity,
                    ScanStatus::Warn,
                )
                .class(FindingClass::Policy)
                .confidence(Confidence::Medium)
                .subject(subject.clone())
                .detail(format!(
                    "Tool '{}' on server '{}' {reason}",
                    tool.name, server.name
                ))
                .evidence(structural_invariant(
                    subject.clone(),
                    "contradictory tool annotation",
                    serde_json::json!({
                        "server": server.name,
                        "tool": tool.name,
                        "annotations": tool.annotations,
                        "inferred_capabilities": tool_capabilities,
                    }),
                ))
                .finish(),
            );
        }
    }
    findings
}

fn describe_grant(grant: &CapabilityGrant) -> String {
    match (grant.server.as_deref(), grant.tool.as_deref()) {
        (Some(server), Some(tool)) => {
            format!(
                "{} (server '{server}', tool '{tool}')",
                grant.capability.as_str()
            )
        }
        (Some(server), None) => format!("{} (server '{server}')", grant.capability.as_str()),
        _ => grant.capability.as_str().to_owned(),
    }
}

fn server_finding(
    rule_id: &str,
    status: ScanStatus,
    class: FindingClass,
    confidence: Confidence,
    subject: &EvidenceSubject,
    server: &super::McpServer,
    detail: &str,
) -> LayerScanResult {
    FindingBuilder::new(rule_id, CheckType::McpSecurity, status)
        .class(class)
        .confidence(confidence)
        .subject(subject.clone())
        .detail(detail)
        .evidence(structural_invariant(
            subject.clone(),
            "MCP server posture",
            serde_json::json!({
                "server": server.name,
                "identity": server.identity,
                "transport": server.transport,
                "authentication": server.authentication,
                "tls": server.tls,
                "tool_count": server.tools.len(),
                "limitations": server.limitations,
            }),
        ))
        .finish()
}

#[cfg(test)]
mod tests {
    use super::scope_is_overbroad;

    #[test]
    fn overbroad_scope_detection() {
        assert!(scope_is_overbroad("admin"));
        assert!(scope_is_overbroad("read write admin"));
        assert!(scope_is_overbroad("repo:*"));
        assert!(scope_is_overbroad("full_access"));
        assert!(!scope_is_overbroad("repo:read"));
        assert!(!scope_is_overbroad("issues:write pulls:read"));
    }
}
