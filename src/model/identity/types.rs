use crate::assurance::AnalysisCompleteness;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayeredModelIdentity {
    pub version: u32,
    pub subject: String,
    pub byte: Option<IdentityValue>,
    pub package: Option<IdentityValue>,
    pub structural: Option<IdentityValue>,
    pub tokenizer: Option<IdentityValue>,
    pub weight_sample: Option<IdentityValue>,
    pub behavioural: Option<IdentityValue>,
    pub provenance: Option<IdentityValue>,
    pub completeness: AnalysisCompleteness,
    pub limitations: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityValue {
    pub algorithm: String,
    pub value: String,
    pub strength: IdentityStrength,
    pub coverage: IdentityCoverage,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityStrength {
    Exact,
    Structural,
    Sampled,
    Behavioural,
    ClaimBound,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityCoverage {
    pub complete: bool,
    pub detail: String,
}
#[derive(Debug, Clone, Default)]
pub struct IdentityBuildOptions {
    pub include_weight_sample: bool,
    pub include_behavioural: bool,
}
