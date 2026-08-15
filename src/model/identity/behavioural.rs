use super::{IdentityCoverage, IdentityStrength, IdentityValue};
use sha2::{Digest, Sha256};
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BehaviourIdentityInput {
    pub runtime_kind: String,
    pub runtime_version: String,
    pub runtime_digest: String,
    pub probe_suite_digest: String,
    pub response_digests: Vec<String>,
    pub deterministic: bool,
}
pub fn identity(i: &BehaviourIdentityInput) -> Option<IdentityValue> {
    if !i.deterministic || i.runtime_digest.is_empty() {
        return None;
    }
    let mut responses = i.response_digests.clone();
    responses.sort();
    let bytes = serde_json::to_vec(&(
        &i.runtime_kind,
        &i.runtime_version,
        &i.runtime_digest,
        &i.probe_suite_digest,
        responses,
    ))
    .ok()?;
    let mut h = Sha256::new();
    h.update(b"layerfault:model-behaviour:v1\0");
    h.update(bytes);
    Some(IdentityValue {
        algorithm: "layerfault-model-behaviour-v1-sha256".into(),
        value: format!("lfmodel:behaviour:v1:sha256:{}", hex::encode(h.finalize())),
        strength: IdentityStrength::Behavioural,
        coverage: IdentityCoverage {
            complete: true,
            detail: "deterministic pinned-runtime probe digest".into(),
        },
    })
}
