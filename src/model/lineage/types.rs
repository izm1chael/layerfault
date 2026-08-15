use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageClaim {
    pub relation: ClaimedRelation,
    pub parent_identity: String,
    pub child_identity: String,
    #[serde(default)]
    pub evidence: Vec<String>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimedRelation {
    Repackaged,
    Quantized,
    AdapterMerged,
    Converted,
    FineTuned,
    Derived,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineageVerification {
    pub structural: VerificationState,
    pub tokenizer: VerificationState,
    pub transformation: VerificationState,
    pub identity: VerificationState,
    pub consistency: LineageConsistency,
    pub reasons: Vec<String>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationState {
    Verified,
    Contradicted,
    Unverified,
    NotApplicable,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LineageConsistency {
    Consistent,
    Inconsistent,
    PartiallyVerified,
    Unknown,
}
