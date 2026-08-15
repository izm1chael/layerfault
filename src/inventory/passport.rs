use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelSecurityPassport {
    pub version: u32,
    pub generated_unix: u64,
    pub layerfault_version: String,
    pub scanner_revision: String,
    pub ruleset_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intelligence_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intelligence_epoch: Option<u64>,
    pub subject: PassportSubject,
    pub identity: crate::model::identity::LayeredModelIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<PassportSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lineage: Option<crate::model::lineage::LineageVerification>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub composition: Option<PassportCompositionSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<PassportAgentSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<PassportProvenanceSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub behavioural: Option<PassportBehaviourSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completeness: Option<PassportCompleteness>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokenizer: Option<PassportTokenizerSummary>,
    #[serde(default)]
    pub runtime: Vec<PassportRuntimeAssessment>,
    pub findings: PassportFindingSummary,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub framework_mappings: Vec<crate::intelligence::ThreatMapping>,
    pub coverage: crate::coverage::Coverage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PassportPolicyDecision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_digest: Option<String>,
    #[serde(default)]
    pub limitations: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassportSubject {
    pub name: String,
    pub format: String,
    pub size: Option<u64>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassportSource {
    pub source_kind: String,
    pub repository: Option<String>,
    pub revision: Option<String>,
    pub reference: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassportTokenizerSummary {
    pub digest: Option<String>,
    pub finding_count: u64,
    pub chat_template_sha256: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassportFindingSummary {
    pub pass: u64,
    pub warn: u64,
    pub fail: u64,
    pub rule_ids: Vec<String>,
    pub finding_ids: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassportRuntimeAssessment {
    pub runtime: String,
    pub version: Option<String>,
    pub executable_sha256: Option<String>,
    pub compatibility: String,
    pub exploitability: Vec<String>,
    pub posture_findings: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassportPolicyDecision {
    pub profile: String,
    pub action: String,
    pub reasons: Vec<String>,
    pub overrides: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassportCompositionSummary {
    pub identity: String,
    pub component_count: u64,
    pub adapter_count: u64,
    pub completeness: crate::assurance::AnalysisCompleteness,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassportAgentSummary {
    pub agent_identity: String,
    pub capability_graph_identity: String,
    pub server_count: u64,
    pub tool_count: u64,
    #[serde(default)]
    pub high_impact_capabilities: Vec<String>,
    #[serde(default)]
    pub dangerous_chains: Vec<String>,
    pub completeness: crate::assurance::AnalysisCompleteness,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassportProvenanceSummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transformation_chain_sha256: Option<String>,
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builder_identity: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassportBehaviourSummary {
    pub suite_id: String,
    pub suite_version: String,
    pub trial_count: u64,
    pub state: String,
    pub completeness: crate::assurance::AnalysisCompleteness,
    #[serde(default)]
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassportCompleteness {
    #[serde(default)]
    pub domains: std::collections::BTreeMap<String, crate::assurance::AnalysisCompleteness>,
}

impl PassportCompositionSummary {
    pub fn from_assessment(assessment: &crate::model::composition::CompositionAssessment) -> Self {
        Self {
            identity: assessment.identity.value.clone(),
            component_count: assessment.identity.component_count,
            adapter_count: assessment.composition.adapters.len() as u64,
            completeness: assessment.identity.completeness,
        }
    }
}

impl PassportAgentSummary {
    pub fn from_graph(graph: &crate::agent_security::CapabilityGraph) -> Self {
        let tool_count = graph
            .servers
            .iter()
            .map(|server| server.tools.len() as u64)
            .sum();
        let mut high_impact_capabilities = graph
            .agent
            .capabilities
            .iter()
            .filter(|grant| grant.capability.high_impact())
            .map(|grant| {
                format!("{}:{:?}", grant.capability.as_str(), grant.scope).to_ascii_lowercase()
            })
            .collect::<Vec<_>>();
        high_impact_capabilities.sort();
        high_impact_capabilities.dedup();
        let mut dangerous_chains = graph
            .dangerous_chains
            .iter()
            .map(|chain| chain.id.clone())
            .collect::<Vec<_>>();
        dangerous_chains.sort();
        dangerous_chains.dedup();
        Self {
            agent_identity: graph.agent.identity.clone(),
            capability_graph_identity: graph.graph_identity.clone(),
            server_count: graph.servers.len() as u64,
            tool_count,
            high_impact_capabilities,
            dangerous_chains,
            completeness: graph.completeness,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PassportInputs {
    pub generated_unix: u64,
    pub scanner_revision: String,
    pub ruleset_sha256: String,
    pub intelligence_sha256: Option<String>,
    pub intelligence_epoch: Option<u64>,
    pub subject: PassportSubject,
    pub identity: crate::model::identity::LayeredModelIdentity,
    pub source: Option<PassportSource>,
    pub lineage: Option<crate::model::lineage::LineageVerification>,
    pub composition: Option<PassportCompositionSummary>,
    pub agent: Option<PassportAgentSummary>,
    pub provenance: Option<PassportProvenanceSummary>,
    pub behavioural: Option<PassportBehaviourSummary>,
    pub completeness: Option<PassportCompleteness>,
    pub tokenizer: Option<PassportTokenizerSummary>,
    pub runtime: Vec<PassportRuntimeAssessment>,
    pub findings: Vec<crate::scanner::LayerScanResult>,
    #[allow(dead_code)]
    pub mapping_pack: Option<crate::intelligence::IntelligencePack>,
    pub coverage: crate::coverage::Coverage,
    pub policy: Option<PassportPolicyDecision>,
    pub evidence_digest: Option<String>,
    pub limitations: Vec<String>,
}
pub fn build_passport(mut i: PassportInputs) -> Result<ModelSecurityPassport> {
    let mut rules = i
        .findings
        .iter()
        .filter_map(|f| f.rule_id.clone())
        .collect::<Vec<_>>();
    rules.sort();
    rules.dedup();
    let mut ids = i
        .findings
        .iter()
        .filter_map(|f| f.finding_id.clone())
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    let count = |s| i.findings.iter().filter(|f| f.status == s).count() as u64;
    let mut framework_mappings = Vec::new();
    if let Some(pack) = &i.mapping_pack {
        for rule in &rules {
            if let Some(mapping) = crate::intelligence::mapping_for_rule(pack, rule) {
                framework_mappings.push(mapping);
            }
        }
    }
    framework_mappings.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
    i.runtime.sort_by(|a, b| {
        a.runtime
            .cmp(&b.runtime)
            .then(a.executable_sha256.cmp(&b.executable_sha256))
    });
    for r in &mut i.runtime {
        r.exploitability.sort();
        r.posture_findings.sort();
    }
    i.limitations.sort();
    i.limitations.dedup();
    let version = if i.composition.is_some()
        || i.agent.is_some()
        || i.provenance.is_some()
        || i.behavioural.is_some()
        || i.completeness.is_some()
        || i.intelligence_epoch.is_some()
    {
        2
    } else {
        1
    };
    if let Some(agent) = &mut i.agent {
        agent.high_impact_capabilities.sort();
        agent.high_impact_capabilities.dedup();
        agent.dangerous_chains.sort();
        agent.dangerous_chains.dedup();
    }
    if let Some(behavioural) = &mut i.behavioural {
        behavioural.limitations.sort();
        behavioural.limitations.dedup();
    }
    Ok(ModelSecurityPassport {
        version,
        generated_unix: i.generated_unix,
        layerfault_version: env!("CARGO_PKG_VERSION").into(),
        scanner_revision: i.scanner_revision,
        ruleset_sha256: i.ruleset_sha256,
        intelligence_sha256: i.intelligence_sha256,
        intelligence_epoch: i.intelligence_epoch,
        subject: i.subject,
        identity: i.identity,
        source: i.source,
        lineage: i.lineage,
        composition: i.composition,
        agent: i.agent,
        provenance: i.provenance,
        behavioural: i.behavioural,
        completeness: i.completeness,
        tokenizer: i.tokenizer,
        runtime: i.runtime,
        findings: PassportFindingSummary {
            pass: count(crate::scanner::ScanStatus::Pass),
            warn: count(crate::scanner::ScanStatus::Warn),
            fail: count(crate::scanner::ScanStatus::Fail),
            rule_ids: rules,
            finding_ids: ids,
        },
        framework_mappings,
        coverage: i.coverage,
        policy: i.policy,
        evidence_digest: i.evidence_digest,
        limitations: i.limitations,
    })
}
pub fn canonical_passport_bytes(passport: &ModelSecurityPassport) -> Result<Vec<u8>> {
    let mut p = passport.clone();
    p.runtime.sort_by(|a, b| {
        a.runtime
            .cmp(&b.runtime)
            .then(a.executable_sha256.cmp(&b.executable_sha256))
    });
    p.findings.rule_ids.sort();
    p.findings.rule_ids.dedup();
    p.findings.finding_ids.sort();
    p.findings.finding_ids.dedup();
    p.framework_mappings
        .sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
    if let Some(agent) = &mut p.agent {
        agent.high_impact_capabilities.sort();
        agent.high_impact_capabilities.dedup();
        agent.dangerous_chains.sort();
        agent.dangerous_chains.dedup();
    }
    if let Some(behavioural) = &mut p.behavioural {
        behavioural.limitations.sort();
        behavioural.limitations.dedup();
    }
    p.limitations.sort();
    Ok(serde_json::to_vec(&p)?)
}
pub fn passport_sha256(p: &ModelSecurityPassport) -> Result<String> {
    let mut h = Sha256::new();
    h.update(format!("layerfault:security-passport:v{}\0", p.version).as_bytes());
    h.update(canonical_passport_bytes(p)?);
    Ok(format!("sha256:{}", hex::encode(h.finalize())))
}
pub fn security_content_digest(p: &ModelSecurityPassport) -> Result<String> {
    let mut clone = p.clone();
    clone.generated_unix = 0;
    passport_sha256(&clone)
}
