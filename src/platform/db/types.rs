use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub id: String,
    pub kind: String,
    pub payload: serde_json::Value,
    pub attempts: i64,
    pub max_attempts: i64,
    pub lease_owner: String,
    pub lease_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelRow {
    pub id: String,
    pub name: String,
    pub latest_revision: Option<String>,
    pub latest_review: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewRow {
    pub id: String,
    pub revision_id: String,
    pub final_decision: String,
    pub created_at: i64,
    pub body: serde_json::Value,
}

pub(super) struct PreparedFinding {
    pub(super) id: String,
    pub(super) review_id: String,
    pub(super) rule: String,
    pub(super) domain: String,
    pub(super) status: String,
    pub(super) confidence: String,
    pub(super) detail: String,
    pub(super) created_at: i64,
}

pub(super) struct PreparedAdvisory {
    pub(super) id: String,
    pub(super) review_id: String,
    pub(super) title: String,
    pub(super) body: String,
    pub(super) created_at: i64,
}

pub(super) struct PreparedReviewIndex {
    pub(super) findings: Vec<PreparedFinding>,
    pub(super) advisory: Option<PreparedAdvisory>,
}

pub fn stable_id(prefix: &str, parts: &[&[u8]]) -> String {
    let mut h = Sha256::new();
    h.update(prefix.as_bytes());
    h.update([0]);
    for p in parts {
        h.update((p.len() as u64).to_le_bytes());
        h.update(p);
    }
    format!("{prefix}:sha256:{}", hex::encode(h.finalize()))
}

pub(super) fn now_i64() -> i64 {
    i64::try_from(crate::paths::now_unix()).unwrap_or(i64::MAX)
}

pub(super) fn truncate(value: &str, cap: usize) -> String {
    if value.len() <= cap {
        return value.to_owned();
    }
    let mut end = cap;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}
