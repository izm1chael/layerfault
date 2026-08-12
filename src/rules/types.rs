/// What evidence a rule is expected to produce when it fires at WARN or FAIL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceRequirement {
    /// The detector knows a concrete location and/or content and must attach it.
    Required,
    /// The detector can only produce structured facts: no excerpt, no location.
    /// Used where precision would have to be invented rather than measured.
    StructuredOnly,
    /// Evidence is meaningless for this rule (PASS-only or informational).
    NotApplicable,
}

/// Complete detector rule metadata in the single authoritative catalogue.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RuleMetadata {
    pub rule_id: &'static str,
    pub rule_version: u32,
    pub detector_family: &'static str,
    pub title: &'static str,
    pub meaning: &'static str,
    pub why_it_matters: &'static str,
    pub remediation: &'static str,
    pub limitations: &'static str,
    pub evidence_requirement: EvidenceRequirement,
    pub requirement_reason: &'static str,
}

pub type RuleExplanation = RuleMetadata;
