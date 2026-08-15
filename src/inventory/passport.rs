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
    pub subject: PassportSubject,
    pub identity: crate::model::identity::LayeredModelIdentity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<PassportSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lineage: Option<crate::model::lineage::LineageVerification>,
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
#[derive(Debug, Clone)]
pub struct PassportInputs {
    pub generated_unix: u64,
    pub scanner_revision: String,
    pub ruleset_sha256: String,
    pub intelligence_sha256: Option<String>,
    pub subject: PassportSubject,
    pub identity: crate::model::identity::LayeredModelIdentity,
    pub source: Option<PassportSource>,
    pub lineage: Option<crate::model::lineage::LineageVerification>,
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
    Ok(ModelSecurityPassport {
        version: 1,
        generated_unix: i.generated_unix,
        layerfault_version: env!("CARGO_PKG_VERSION").into(),
        scanner_revision: i.scanner_revision,
        ruleset_sha256: i.ruleset_sha256,
        intelligence_sha256: i.intelligence_sha256,
        subject: i.subject,
        identity: i.identity,
        source: i.source,
        lineage: i.lineage,
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
    p.limitations.sort();
    Ok(serde_json::to_vec(&p)?)
}
pub fn passport_sha256(p: &ModelSecurityPassport) -> Result<String> {
    let mut h = Sha256::new();
    h.update(b"layerfault:security-passport:v1\0");
    h.update(canonical_passport_bytes(p)?);
    Ok(format!("sha256:{}", hex::encode(h.finalize())))
}
pub fn security_content_digest(p: &ModelSecurityPassport) -> Result<String> {
    let mut clone = p.clone();
    clone.generated_unix = 0;
    passport_sha256(&clone)
}
