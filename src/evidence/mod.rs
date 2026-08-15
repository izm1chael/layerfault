pub mod bundle;

use crate::advisory::RuntimeEvaluation;
use crate::binding::BindingRecord;
use crate::safeio::{open_readonly_nofollow, read_all_from_file};
use crate::trust::{self, TrustStore};
use anyhow::{anyhow, Context, Result};
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const MAX_EVIDENCE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePayload {
    pub version: u32,
    pub created_unix: u64,
    pub subject: String,
    pub source: String,
    pub subject_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merkle_identity: Option<String>,
    pub layerfault_version: String,
    pub build_id: String,
    pub detector_contract: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scanner_revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ruleset_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intelligence_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_passport_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission_receipt: Option<crate::admission::AdmissionReceiptContext>,
    pub policy_sha256: String,
    pub trust_store_sha256: String,
    pub runtime: Option<Value>,
    pub execution_binding: Option<Value>,
    pub decision: String,
    pub details: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceEnvelope {
    pub envelope_version: u32,
    pub payload: EvidencePayload,
    pub key_fingerprint: String,
    pub public_key_hex: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceVerification {
    pub valid_signature: bool,
    pub key_fingerprint: String,
    pub trusted: bool,
    pub authorized_for_subject: bool,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct EvidenceContext<'a> {
    pub subject: &'a str,
    pub source: &'a str,
    pub subject_fingerprint: Option<&'a str>,
    pub merkle_identity: Option<&'a str>,
    pub policy: &'a crate::policy::EffectivePolicy,
    pub trust_store: &'a TrustStore,
    pub runtime: Option<&'a RuntimeEvaluation>,
    pub binding: Option<&'a BindingRecord>,
    pub intelligence_sha256: Option<&'a str>,
    pub security_passport_sha256: Option<&'a str>,
    pub admission_receipt: Option<&'a crate::admission::AdmissionReceiptContext>,
    pub decision: &'a str,
    pub details: Value,
}

pub fn create_signed(context: EvidenceContext<'_>, private_key: &Path) -> Result<EvidenceEnvelope> {
    let policy_bytes = serde_json::to_vec(context.policy)?;
    let trust_bytes = serde_json::to_vec(context.trust_store)?;
    let payload = EvidencePayload {
        version: 1,
        created_unix: crate::paths::now_unix(),
        subject: context.subject.to_owned(),
        source: context.source.to_owned(),
        subject_fingerprint: context.subject_fingerprint.map(ToOwned::to_owned),
        merkle_identity: context.merkle_identity.map(ToOwned::to_owned),
        layerfault_version: env!("CARGO_PKG_VERSION").to_owned(),
        build_id: env!("LAYERFAULT_BUILD_ID").to_owned(),
        detector_contract: "layerfault-security-contract".to_owned(),
        scanner_revision: Some(crate::explain::scanner_revision().to_owned()),
        ruleset_sha256: Some(crate::explain::ruleset_sha256().to_owned()),
        intelligence_sha256: context.intelligence_sha256.map(ToOwned::to_owned),
        security_passport_sha256: context.security_passport_sha256.map(ToOwned::to_owned),
        admission_receipt: context.admission_receipt.cloned(),
        policy_sha256: digest(&policy_bytes),
        trust_store_sha256: digest(&trust_bytes),
        runtime: context.runtime.map(serde_json::to_value).transpose()?,
        execution_binding: context.binding.map(serde_json::to_value).transpose()?,
        decision: context.decision.to_owned(),
        details: context.details,
    };
    sign_payload(payload, private_key)
}

pub fn write_signed(path: &Path, envelope: &EvidenceEnvelope) -> Result<()> {
    crate::paths::write_private(path, &serde_json::to_vec_pretty(envelope)?)
}

pub fn load(path: &Path) -> Result<EvidenceEnvelope> {
    let file = open_readonly_nofollow(path)?;
    let bytes = read_all_from_file(&file, MAX_EVIDENCE_BYTES)?;
    let envelope: EvidenceEnvelope = serde_json::from_slice(&bytes)
        .with_context(|| format!("Evidence '{}' is not valid JSON", path.display()))?;
    if envelope.envelope_version != 1 || envelope.payload.version != 1 {
        return Err(anyhow!("Unsupported Layerfault evidence version"));
    }
    Ok(envelope)
}

pub fn verify(path: &Path, trust_store: Option<&TrustStore>) -> Result<EvidenceVerification> {
    let envelope = load(path)?;
    let public_bytes =
        hex::decode(&envelope.public_key_hex).context("Evidence public key is not hexadecimal")?;
    let array: [u8; 32] = public_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("Evidence public key must be 32 Ed25519 bytes"))?;
    let key = VerifyingKey::from_bytes(&array).context("Evidence public key is invalid")?;
    let fingerprint = trust::fingerprint(&key);
    if !fingerprint.eq_ignore_ascii_case(&envelope.key_fingerprint) {
        return Ok(EvidenceVerification {
            valid_signature: false,
            key_fingerprint: fingerprint,
            trusted: false,
            authorized_for_subject: false,
            detail: "Evidence key fingerprint does not match embedded public key".to_owned(),
        });
    }
    let signature_bytes =
        hex::decode(&envelope.signature_hex).context("Evidence signature is not hexadecimal")?;
    let signature =
        Signature::from_slice(&signature_bytes).context("Evidence signature is not Ed25519")?;
    let payload_bytes = serde_json::to_vec(&envelope.payload)?;
    if key.verify(&payload_bytes, &signature).is_err() {
        return Ok(EvidenceVerification {
            valid_signature: false,
            key_fingerprint: fingerprint,
            trusted: false,
            authorized_for_subject: false,
            detail: "Evidence payload signature is invalid or the record has been modified"
                .to_owned(),
        });
    }
    let (trusted, authorized) = match trust_store {
        Some(store) => match store.find_by_fingerprint(&fingerprint) {
            Some(record) => (
                store.key_active(record, crate::paths::now_unix()),
                store.authorized_for(record, &envelope.payload.subject),
            ),
            None => (false, false),
        },
        None => (false, false),
    };
    Ok(EvidenceVerification {
        valid_signature: true,
        key_fingerprint: fingerprint,
        trusted,
        authorized_for_subject: authorized,
        detail: if trust_store.is_some() {
            if trusted && authorized {
                "Evidence signature is valid and the signing key is trusted for this subject"
                    .to_owned()
            } else {
                "Evidence signature is cryptographically valid but does not establish configured subject trust".to_owned()
            }
        } else {
            "Evidence signature is cryptographically valid; no Layerfault trust store was supplied for publisher authorization".to_owned()
        },
    })
}

fn sign_payload(payload: EvidencePayload, private_key_path: &Path) -> Result<EvidenceEnvelope> {
    let file = open_readonly_nofollow(private_key_path)?;
    let pem = String::from_utf8(read_all_from_file(&file, 128 * 1024)?)
        .map_err(|_| anyhow!("Evidence signing key must be PKCS#8 PEM UTF-8"))?;
    let signing_key =
        SigningKey::from_pkcs8_pem(&pem).context("Unable to parse Ed25519 evidence signing key")?;
    let verifying_key = signing_key.verifying_key();
    let payload_bytes = serde_json::to_vec(&payload)?;
    let signature = signing_key.sign(&payload_bytes);
    Ok(EvidenceEnvelope {
        envelope_version: 1,
        payload,
        key_fingerprint: trust::fingerprint(&verifying_key),
        public_key_hex: hex::encode(verifying_key.to_bytes()),
        signature_hex: hex::encode(signature.to_bytes()),
    })
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

pub fn default_evidence_path(subject: &str) -> Result<PathBuf> {
    let short = hex::encode(Sha256::digest(subject.as_bytes()));
    Ok(crate::paths::config_dir()?.join("evidence").join(format!(
        "{}-{}.json",
        crate::paths::now_unix(),
        &short[..16]
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_path_is_stable_shape() -> Result<()> {
        let path = default_evidence_path("model:test")?;
        assert_eq!(path.extension().and_then(|v| v.to_str()), Some("json"));
        Ok(())
    }
}
