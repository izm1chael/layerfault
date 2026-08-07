use crate::manifest;
use crate::paths;
use crate::provenance::{self, AttestationEnvelope};
use crate::safeio::{open_readonly_nofollow, read_all_from_file};
use crate::trust::{self, TrustStore};
use anyhow::{anyhow, Context, Result};
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const MAX_BASELINE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct BaselineModel {
    pub manifest_digest: String,
    pub descriptors: Vec<String>,
    #[serde(default)]
    pub attestation_fingerprints: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BaselineChange {
    pub updated_unix: u64,
    pub reason: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Baseline {
    pub version: u32,
    pub created_unix: u64,
    #[serde(default)]
    pub updated_unix: u64,
    #[serde(default)]
    pub history: Vec<BaselineChange>,
    pub models: BTreeMap<String, BaselineModel>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ChangedModel {
    pub model: String,
    pub previous_manifest_digest: String,
    pub current_manifest_digest: String,
    pub added_descriptors: Vec<String>,
    pub removed_descriptors: Vec<String>,
    pub added_attestation_fingerprints: Vec<String>,
    pub removed_attestation_fingerprints: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BaselineVerification {
    pub baseline_path: String,
    pub unchanged_models: usize,
    pub added_models: Vec<String>,
    pub removed_models: Vec<String>,
    pub changed_models: Vec<ChangedModel>,
    pub matches: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BaselineSignature {
    pub version: u32,
    pub baseline_sha256: String,
    pub key_fingerprint: String,
    pub signature_hex: String,
    pub created_unix: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BaselineSignatureVerification {
    pub present: bool,
    pub valid: bool,
    pub trusted: bool,
    pub key_fingerprint: Option<String>,
    pub detail: String,
}

impl Baseline {
    pub fn capture(base_dir: &Path) -> Result<Self> {
        let mut models = BTreeMap::new();
        for model_ref in manifest::discover_all_models(base_dir)? {
            let model = manifest::load_model(&model_ref)
                .with_context(|| format!("Cannot baseline invalid model '{}'", model_ref.name))?;
            let mut descriptors = model
                .descriptors()
                .map(|layer| layer.digest.clone())
                .collect::<Vec<_>>();
            descriptors.sort();
            descriptors.dedup();
            let mut attestation_fingerprints = Vec::new();
            for envelope_path in provenance::envelope_paths(base_dir, &model.digest)? {
                let file = open_readonly_nofollow(&envelope_path)?;
                let bytes = read_all_from_file(&file, 256 * 1024)?;
                if let Ok(envelope) = serde_json::from_slice::<AttestationEnvelope>(&bytes) {
                    attestation_fingerprints.push(envelope.key_fingerprint);
                }
            }
            attestation_fingerprints.sort();
            attestation_fingerprints.dedup();
            models.insert(
                model.name,
                BaselineModel {
                    manifest_digest: model.digest,
                    descriptors,
                    attestation_fingerprints,
                },
            );
        }
        let now = paths::now_unix();
        Ok(Self {
            version: 1,
            created_unix: now,
            updated_unix: now,
            history: Vec::new(),
            models,
        })
    }

    pub fn updated(base_dir: &Path, previous: &Baseline, reason: String) -> Result<Self> {
        if reason.trim().len() < 8 {
            return Err(anyhow!(
                "Baseline update requires a meaningful reason (at least 8 characters)"
            ));
        }
        let mut next = Self::capture(base_dir)?;
        next.created_unix = previous.created_unix;
        next.history = previous.history.clone();
        next.history.push(BaselineChange {
            updated_unix: next.updated_unix,
            reason,
        });
        Ok(next)
    }

    pub fn default_path(name: &str) -> Result<PathBuf> {
        validate_name(name)?;
        Ok(paths::config_dir()?
            .join("baselines")
            .join(format!("{name}.json")))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        paths::write_private(path, &serde_json::to_vec_pretty(self)?)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let file = open_readonly_nofollow(path)?;
        let bytes = read_all_from_file(&file, MAX_BASELINE_BYTES)?;
        let mut baseline: Self = serde_json::from_slice(&bytes)
            .with_context(|| format!("Baseline '{}' is not valid JSON", path.display()))?;
        if baseline.version != 1 {
            return Err(anyhow!("Unsupported baseline version {}", baseline.version));
        }
        if baseline.updated_unix == 0 {
            baseline.updated_unix = baseline.created_unix;
        }
        Ok(baseline)
    }

    pub fn verify(&self, base_dir: &Path, path: &Path) -> Result<BaselineVerification> {
        let current = Self::capture(base_dir)?;
        let previous_names = self.models.keys().cloned().collect::<BTreeSet<_>>();
        let current_names = current.models.keys().cloned().collect::<BTreeSet<_>>();
        let added_models = current_names
            .difference(&previous_names)
            .cloned()
            .collect::<Vec<_>>();
        let removed_models = previous_names
            .difference(&current_names)
            .cloned()
            .collect::<Vec<_>>();
        let mut unchanged = 0_usize;
        let mut changed_models = Vec::new();
        for name in previous_names.intersection(&current_names) {
            let before = &self.models[name];
            let after = &current.models[name];
            if before == after {
                unchanged += 1;
                continue;
            }
            let before_set = before.descriptors.iter().cloned().collect::<BTreeSet<_>>();
            let after_set = after.descriptors.iter().cloned().collect::<BTreeSet<_>>();
            let before_signers = before
                .attestation_fingerprints
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>();
            let after_signers = after
                .attestation_fingerprints
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>();
            changed_models.push(ChangedModel {
                model: name.clone(),
                previous_manifest_digest: before.manifest_digest.clone(),
                current_manifest_digest: after.manifest_digest.clone(),
                added_descriptors: after_set.difference(&before_set).cloned().collect(),
                removed_descriptors: before_set.difference(&after_set).cloned().collect(),
                added_attestation_fingerprints: after_signers
                    .difference(&before_signers)
                    .cloned()
                    .collect(),
                removed_attestation_fingerprints: before_signers
                    .difference(&after_signers)
                    .cloned()
                    .collect(),
            });
        }
        Ok(BaselineVerification {
            baseline_path: path.display().to_string(),
            unchanged_models: unchanged,
            matches: added_models.is_empty()
                && removed_models.is_empty()
                && changed_models.is_empty(),
            added_models,
            removed_models,
            changed_models,
        })
    }
}

pub fn signature_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.sig.json", path.display()))
}

pub fn sign(path: &Path, private_key: &Path) -> Result<BaselineSignature> {
    let baseline_file = open_readonly_nofollow(path)?;
    let baseline_bytes = read_all_from_file(&baseline_file, MAX_BASELINE_BYTES)?;
    let key_file = open_readonly_nofollow(private_key)?;
    let key_bytes = read_all_from_file(&key_file, 128 * 1024)?;
    let pem = std::str::from_utf8(&key_bytes)
        .map_err(|_| anyhow!("Private key PEM must be valid UTF-8"))?;
    let signing =
        SigningKey::from_pkcs8_pem(pem).context("Unable to parse Ed25519 PKCS#8 private key")?;
    let signature = signing.sign(&baseline_bytes);
    let envelope = BaselineSignature {
        version: 1,
        baseline_sha256: format!("sha256:{}", hex::encode(Sha256::digest(&baseline_bytes))),
        key_fingerprint: trust::fingerprint(&signing.verifying_key()),
        signature_hex: hex::encode(signature.to_bytes()),
        created_unix: paths::now_unix(),
    };
    paths::write_private(
        &signature_path(path),
        &serde_json::to_vec_pretty(&envelope)?,
    )?;
    Ok(envelope)
}

pub fn verify_signature(
    path: &Path,
    trust_store: &TrustStore,
) -> Result<BaselineSignatureVerification> {
    let sig_path = signature_path(path);
    if !sig_path.exists() {
        return Ok(BaselineSignatureVerification {
            present: false,
            valid: false,
            trusted: false,
            key_fingerprint: None,
            detail: "No signed baseline envelope is present".to_owned(),
        });
    }
    let baseline_file = open_readonly_nofollow(path)?;
    let bytes = read_all_from_file(&baseline_file, MAX_BASELINE_BYTES)?;
    let sig_file = open_readonly_nofollow(&sig_path)?;
    let sig_bytes = read_all_from_file(&sig_file, 64 * 1024)?;
    let envelope: BaselineSignature =
        serde_json::from_slice(&sig_bytes).context("Invalid baseline signature envelope")?;
    let computed = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
    if envelope.version != 1 || !computed.eq_ignore_ascii_case(&envelope.baseline_sha256) {
        return Ok(BaselineSignatureVerification {
            present: true,
            valid: false,
            trusted: false,
            key_fingerprint: Some(envelope.key_fingerprint),
            detail: "Baseline bytes do not match the signed digest".to_owned(),
        });
    }
    let Some(key) = trust_store.find_by_fingerprint(&envelope.key_fingerprint) else {
        return Ok(BaselineSignatureVerification {
            present: true,
            valid: false,
            trusted: false,
            key_fingerprint: Some(envelope.key_fingerprint),
            detail: "Baseline signer is not in the trust store".to_owned(),
        });
    };
    if !trust_store.key_active(key, paths::now_unix()) {
        return Ok(BaselineSignatureVerification {
            present: true,
            valid: false,
            trusted: false,
            key_fingerprint: Some(key.fingerprint.clone()),
            detail: "Baseline signing key is revoked, expired or not yet active".to_owned(),
        });
    }
    let signature_raw =
        hex::decode(&envelope.signature_hex).context("Baseline signature is not hex")?;
    let signature = Signature::from_slice(&signature_raw)
        .map_err(|_| anyhow!("Baseline signature is not Ed25519"))?;
    let verifying = trust::parse_public_key_pem(&key.public_key_pem)?;
    let valid = verifying.verify(&bytes, &signature).is_ok();
    Ok(BaselineSignatureVerification {
        present: true,
        valid,
        trusted: valid,
        key_fingerprint: Some(key.fingerprint.clone()),
        detail: if valid {
            format!(
                "Baseline signature verified with trusted key '{}'",
                key.name
            )
        } else {
            "Baseline signature verification failed".to_owned()
        },
    })
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(anyhow!(
            "Baseline name may contain only ASCII letters, numbers, '-' and '_'"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn baseline_names_are_path_safe() {
        assert!(validate_name("workstation-1").is_ok());
        assert!(validate_name("../escape").is_err());
    }
}
