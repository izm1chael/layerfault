use super::{IdentityCoverage, IdentityStrength, IdentityValue};
use sha2::{Digest, Sha256};
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct ProvenanceIdentityInput {
    pub source_identity: Option<String>,
    pub revision: Option<String>,
    pub signer_fingerprints: Vec<String>,
    pub attestation_digests: Vec<String>,
    pub transformation_digests: Vec<String>,
}
pub fn identity(i: &ProvenanceIdentityInput) -> Option<IdentityValue> {
    if i.source_identity.is_none()
        && i.signer_fingerprints.is_empty()
        && i.attestation_digests.is_empty()
    {
        return None;
    }
    let mut s = i.signer_fingerprints.clone();
    let mut a = i.attestation_digests.clone();
    let mut t = i.transformation_digests.clone();
    s.sort();
    a.sort();
    t.sort();
    let bytes = serde_json::to_vec(&(&i.source_identity, &i.revision, s, a, t)).ok()?;
    let mut h = Sha256::new();
    h.update(b"layerfault:model-provenance:v1\0");
    h.update(bytes);
    Some(IdentityValue {
        algorithm: "layerfault-model-provenance-v1-sha256".into(),
        value: format!("lfmodel:provenance:v1:sha256:{}", hex::encode(h.finalize())),
        strength: IdentityStrength::ClaimBound,
        coverage: IdentityCoverage {
            complete: true,
            detail: "claim-bound provenance identity; does not prove weight equality".into(),
        },
    })
}
