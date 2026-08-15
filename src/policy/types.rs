use crate::scanner::{Confidence, FindingClass};
use anyhow::{anyhow, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyProfile {
    Permissive,
    Workstation,
    Ci,
    Strict,
    PersonalLocal,
    Research,
    Enterprise,
    Production,
    AirGapped,
    HighAssurance,
}

impl PolicyProfile {
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "permissive" => Ok(Self::Permissive),
            "workstation" => Ok(Self::Workstation),
            "ci" => Ok(Self::Ci),
            "strict" => Ok(Self::Strict),
            "personal-local" => Ok(Self::PersonalLocal),
            "research" => Ok(Self::Research),
            "enterprise" => Ok(Self::Enterprise),
            "production" => Ok(Self::Production),
            "air-gapped" => Ok(Self::AirGapped),
            "high-assurance" => Ok(Self::HighAssurance),
            other => Err(anyhow!(
                "Unknown policy profile '{other}'. Use permissive, workstation, ci, strict, personal-local, research, enterprise, production, air-gapped, or high-assurance"
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackdoorSignalAction {
    Ignore,
    Warn,
    BlockMultiSignal,
    BlockAnyReproducibleTrigger,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Suppression {
    pub rule_id: String,
    #[serde(default = "default_model_pattern")]
    pub model: String,
    pub reason: String,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub reference: Option<String>,
    #[serde(default)]
    pub expires_unix: Option<u64>,
}

fn default_model_pattern() -> String {
    "*".to_owned()
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PolicyDocument {
    pub version: u32,
    pub profile: PolicyProfile,
    #[serde(default)]
    pub require_trusted_attestation: Option<bool>,
    #[serde(default)]
    pub block_unknown_layers: Option<bool>,
    #[serde(default)]
    pub block_on_warnings: Option<bool>,
    #[serde(default)]
    pub allowed_model_patterns: Vec<String>,
    #[serde(default)]
    pub denied_rule_ids: Vec<String>,
    #[serde(default)]
    pub suppressions: Vec<Suppression>,
    #[serde(default)]
    pub allowed_sources: Vec<String>,
    #[serde(default)]
    pub allowed_formats: Vec<String>,
    #[serde(default)]
    pub allowed_architectures: Vec<String>,
    #[serde(default)]
    pub allowed_quantizations: Vec<String>,
    #[serde(default)]
    pub max_model_bytes: Option<u64>,
    #[serde(default)]
    pub minimum_trusted_signatures: Option<usize>,
    #[serde(default)]
    pub required_signer_fingerprints: Vec<String>,
    #[serde(default)]
    pub block_finding_classes: Vec<FindingClass>,
    #[serde(default)]
    pub block_confidence_at_or_above: Option<Confidence>,
    #[serde(default)]
    pub require_complete_coverage: Option<bool>,
    #[serde(default)]
    pub require_current_intelligence: Option<bool>,
    #[serde(default)]
    pub max_intelligence_age_days: Option<u64>,
    #[serde(default)]
    pub block_known_runtime_exploitability: Option<bool>,
    #[serde(default)]
    pub require_runtime_compatibility: Option<bool>,
    #[serde(default)]
    pub allow_custom_code: Option<bool>,
    #[serde(default)]
    pub require_pinned_remote_revision: Option<bool>,
    #[serde(default)]
    pub require_admission_receipt: Option<bool>,
    #[serde(default)]
    pub require_layered_identity: Option<bool>,
    #[serde(default)]
    pub require_lineage_for_derived_models: Option<bool>,
    #[serde(default)]
    pub require_complete_composition: Option<bool>,
    #[serde(default)]
    pub require_independent_adapter_scan: Option<bool>,
    #[serde(default)]
    pub allow_unsigned_adapters: Option<bool>,
    #[serde(default)]
    pub require_verified_provenance: Option<bool>,
    #[serde(default)]
    pub require_complete_agent_capabilities: Option<bool>,
    #[serde(default)]
    pub block_dangerous_capability_chains: Option<bool>,
    #[serde(default)]
    pub denied_capability_chain_ids: Vec<String>,
    #[serde(default)]
    pub require_behavioural_assurance: Option<bool>,
    #[serde(default)]
    pub require_fresh_evidence: Option<bool>,
    #[serde(default)]
    pub backdoor_signal_action: Option<BackdoorSignalAction>,
}

impl Default for PolicyDocument {
    fn default() -> Self {
        Self {
            version: 1,
            profile: PolicyProfile::Workstation,
            require_trusted_attestation: None,
            block_unknown_layers: None,
            block_on_warnings: None,
            allowed_model_patterns: Vec::new(),
            denied_rule_ids: Vec::new(),
            suppressions: Vec::new(),
            allowed_sources: Vec::new(),
            allowed_formats: Vec::new(),
            allowed_architectures: Vec::new(),
            allowed_quantizations: Vec::new(),
            max_model_bytes: None,
            minimum_trusted_signatures: None,
            required_signer_fingerprints: Vec::new(),
            block_finding_classes: Vec::new(),
            block_confidence_at_or_above: None,
            require_complete_coverage: None,
            require_current_intelligence: None,
            max_intelligence_age_days: None,
            block_known_runtime_exploitability: None,
            require_runtime_compatibility: None,
            allow_custom_code: None,
            require_pinned_remote_revision: None,
            require_admission_receipt: None,
            require_layered_identity: None,
            require_lineage_for_derived_models: None,
            require_complete_composition: None,
            require_independent_adapter_scan: None,
            allow_unsigned_adapters: None,
            require_verified_provenance: None,
            require_complete_agent_capabilities: None,
            block_dangerous_capability_chains: None,
            denied_capability_chain_ids: Vec::new(),
            require_behavioural_assurance: None,
            require_fresh_evidence: None,
            backdoor_signal_action: None,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct EffectivePolicy {
    pub profile: PolicyProfile,
    pub require_trusted_attestation: bool,
    pub block_unknown_layers: bool,
    pub block_on_warnings: bool,
    pub allowed_model_patterns: Vec<String>,
    pub denied_rule_ids: Vec<String>,
    pub suppressions: Vec<Suppression>,
    pub allowed_sources: Vec<String>,
    pub allowed_formats: Vec<String>,
    pub allowed_architectures: Vec<String>,
    pub allowed_quantizations: Vec<String>,
    pub max_model_bytes: Option<u64>,
    pub minimum_trusted_signatures: usize,
    pub required_signer_fingerprints: Vec<String>,
    pub block_finding_classes: Vec<FindingClass>,
    pub block_confidence_at_or_above: Option<Confidence>,
    pub require_complete_coverage: bool,
    pub require_current_intelligence: bool,
    pub max_intelligence_age_days: Option<u64>,
    pub block_known_runtime_exploitability: bool,
    pub require_runtime_compatibility: bool,
    pub allow_custom_code: bool,
    pub require_pinned_remote_revision: bool,
    pub require_admission_receipt: bool,
    pub require_layered_identity: bool,
    pub require_lineage_for_derived_models: bool,
    pub require_complete_composition: bool,
    pub require_independent_adapter_scan: bool,
    pub allow_unsigned_adapters: bool,
    pub require_verified_provenance: bool,
    pub require_complete_agent_capabilities: bool,
    pub block_dangerous_capability_chains: bool,
    pub denied_capability_chain_ids: Vec<String>,
    pub require_behavioural_assurance: bool,
    pub require_fresh_evidence: bool,
    pub backdoor_signal_action: BackdoorSignalAction,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PolicyContext {
    pub source: Option<String>,
    pub format: Option<String>,
    pub architecture: Option<String>,
    pub quantization: Option<String>,
    pub model_size: Option<u64>,
    pub trusted_signatures: usize,
    pub signer_fingerprints: Vec<String>,
    pub now_unix: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_compatibility: Option<crate::runtime_security::CompatibilityState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_complete: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intelligence_age_days: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intelligence_verified: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_exploitability_blocking: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_code_present: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_revision_pinned: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission_receipt_present: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layered_identity_complete: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derived_model: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lineage_consistency: Option<crate::model::lineage::LineageConsistency>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub composition_complete: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapters_independently_scanned: Option<bool>,
    #[serde(default)]
    pub unsigned_adapter_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance_verified: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_capabilities_complete: Option<bool>,
    #[serde(default)]
    pub dangerous_capability_chain_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub behavioural_assurance_complete: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_fresh: Option<bool>,
    #[serde(default)]
    pub backdoor_static_signals: u32,
    #[serde(default)]
    pub reproducible_trigger_signals: u32,
    #[serde(default)]
    pub backdoor_multi_signal: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PolicyAction {
    Allow,
    Warn,
    Block,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PolicyDecision {
    pub profile: PolicyProfile,
    pub action: PolicyAction,
    pub reasons: Vec<String>,
    pub suppressed_rule_ids: Vec<String>,
    /// Evidence that references the underlying scanner findings behind
    /// finding-derived reasons above, so policy never appears to have
    /// discovered the technical condition itself. Reasons with no associated
    /// scanner finding (allowlist/size/signer-count checks) have none here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<crate::finding_evidence::FindingEvidence>,
}
