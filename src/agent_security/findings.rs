use super::{
    AgentSecurityAssessment, CapabilityGrant, CapabilityGraph, McpTransport, PathReachability,
    SecurityState,
};
use crate::finding_evidence::{structural_invariant, EvidenceSubject, FindingBuilder};
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};

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
    }
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
