use crate::manifest::ResolvedModel;
use crate::paths;
use crate::safeio::{open_readonly_nofollow, read_all_from_file};
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use crate::trust::{self, TrustStore};
use anyhow::{anyhow, Context, Result};
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

const MAX_ATTESTATION_BYTES: u64 = 64 * 1024;
const MAX_SIGNATURE_BYTES: u64 = 4096;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AttestationEnvelope {
    pub version: u32,
    pub model: String,
    pub manifest_digest: String,
    pub key_fingerprint: String,
    pub signature_hex: String,
    pub created_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustState {
    Trusted,
    LocallyVerified,
    Unsigned,
    UntrustedKey,
    RevokedKey,
    NamespaceMismatch,
    Invalid,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProvenanceEvaluation {
    pub state: TrustState,
    pub key_fingerprint: Option<String>,
    pub key_name: Option<String>,
    pub trusted_signatures: usize,
    pub valid_signatures: usize,
    pub signer_fingerprints: Vec<String>,
    pub finding: LayerScanResult,
}

pub fn envelope_path(base_dir: &Path, manifest_digest: &str) -> PathBuf {
    base_dir.join("blobs").join(format!(
        "{}.attestation.json",
        manifest_digest.replace(':', "-")
    ))
}

pub fn envelope_paths(base_dir: &Path, manifest_digest: &str) -> Result<Vec<PathBuf>> {
    let blobs = base_dir.join("blobs");
    let stem = manifest_digest.replace(':', "-");
    let primary = envelope_path(base_dir, manifest_digest);
    let mut out = Vec::new();
    if artifact_present(&primary)? {
        out.push(primary);
    }
    if blobs.is_dir() {
        let prefix = format!("{stem}.attestation.");
        let entries = fs::read_dir(&blobs)?; // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
        for entry in entries {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(&prefix) && name.ends_with(".json") {
                out.push(entry.path());
            }
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn attestation_path_for_key(
    base_dir: &Path,
    manifest_digest: &str,
    fingerprint: &str,
) -> Result<PathBuf> {
    let primary = envelope_path(base_dir, manifest_digest);
    if !artifact_present(&primary)? {
        return Ok(primary);
    }
    if let Ok(file) = open_readonly_nofollow(&primary) {
        if let Ok(bytes) = read_all_from_file(&file, MAX_ATTESTATION_BYTES) {
            if let Ok(existing) = serde_json::from_slice::<AttestationEnvelope>(&bytes) {
                if existing.key_fingerprint.eq_ignore_ascii_case(fingerprint) {
                    return Ok(primary);
                }
            }
        }
    }
    let short = fingerprint
        .trim_start_matches("sha256:")
        .chars()
        .take(16)
        .collect::<String>();
    Ok(base_dir.join("blobs").join(format!(
        "{}.attestation.{short}.json",
        manifest_digest.replace(':', "-")
    )))
}

fn legacy_signature_path(base_dir: &Path, manifest_digest: &str) -> PathBuf {
    base_dir
        .join("blobs")
        .join(format!("{}.sig", manifest_digest.replace(':', "-")))
}

pub fn sign_model(
    base_dir: &Path,
    model: &ResolvedModel,
    private_key_path: &Path,
) -> Result<AttestationEnvelope> {
    let file = open_readonly_nofollow(private_key_path)?;
    let bytes = read_all_from_file(&file, 128 * 1024)?;
    let pem =
        std::str::from_utf8(&bytes).map_err(|_| anyhow!("Private key PEM must be valid UTF-8"))?;
    let signing_key =
        SigningKey::from_pkcs8_pem(pem).context("Unable to parse Ed25519 PKCS#8 private key")?;
    let verifying_key = signing_key.verifying_key();
    let signature = signing_key.sign(&model.manifest_bytes);
    let fingerprint = trust::fingerprint(&verifying_key);
    let envelope = AttestationEnvelope {
        version: 1,
        model: model.name.clone(),
        manifest_digest: model.digest.clone(),
        key_fingerprint: fingerprint.clone(),
        signature_hex: hex::encode(signature.to_bytes()),
        created_unix: paths::now_unix(),
    };
    let path = attestation_path_for_key(base_dir, &model.digest, &fingerprint)?;
    paths::write_private(&path, &serde_json::to_vec_pretty(&envelope)?)?;
    Ok(envelope)
}

pub fn verify_model(
    base_dir: &Path,
    model: &ResolvedModel,
    trust_store: &TrustStore,
    fallback_key: Option<&VerifyingKey>,
) -> Result<ProvenanceEvaluation> {
    let started = Instant::now();
    let paths = envelope_paths(base_dir, &model.digest)?;
    if !paths.is_empty() {
        let mut evaluations = Vec::new();
        for path in paths {
            evaluations.push(verify_envelope(&path, model, trust_store, started)?);
        }
        return Ok(aggregate(model, evaluations, started));
    }

    let legacy = legacy_signature_path(base_dir, &model.digest);
    if artifact_present(&legacy)? {
        return verify_legacy(&legacy, model, fallback_key, started);
    }

    Ok(ProvenanceEvaluation {
        state: TrustState::Unsigned,
        key_fingerprint: None,
        key_name: None,
        trusted_signatures: 0,
        valid_signatures: 0,
        signer_fingerprints: Vec::new(),
        finding: finding(
            model,
            ScanStatus::Warn,
            "[LF-PROV-UNSIGNED]",
            "No Layerfault attestation is present for this manifest".to_owned(),
            elapsed_ms(started),
        ),
    })
}

fn aggregate(
    model: &ResolvedModel,
    evaluations: Vec<ProvenanceEvaluation>,
    started: Instant,
) -> ProvenanceEvaluation {
    let trusted = evaluations
        .iter()
        .filter(|value| value.state == TrustState::Trusted)
        .count();
    let valid = evaluations
        .iter()
        .filter(|value| {
            matches!(
                value.state,
                TrustState::Trusted | TrustState::LocallyVerified
            )
        })
        .count();
    let signer_fingerprints = evaluations
        .iter()
        .filter(|value| value.state == TrustState::Trusted)
        .filter_map(|value| value.key_fingerprint.clone())
        .collect::<Vec<_>>();
    let fatal = evaluations.iter().find(|value| {
        matches!(
            value.state,
            TrustState::Invalid | TrustState::RevokedKey | TrustState::NamespaceMismatch
        )
    });
    let state = if let Some(value) = fatal {
        value.state
    } else if trusted > 0 {
        TrustState::Trusted
    } else if evaluations
        .iter()
        .any(|value| value.state == TrustState::LocallyVerified)
    {
        TrustState::LocallyVerified
    } else {
        TrustState::UntrustedKey
    };
    let (status, rule, detail) = if let Some(value) = fatal {
        (
            ScanStatus::Fail,
            "[LF-PROV-MULTI]",
            format!("One of {} attestation(s) is a hard provenance failure ({:?}); {} trusted signature(s) remain", evaluations.len(), value.state, trusted),
        )
    } else if trusted > 0 {
        (
            ScanStatus::Pass,
            "[LF-PROV-TRUSTED]",
            format!(
                "{} trusted attestation(s) verified across {} observed attestation(s)",
                trusted,
                evaluations.len()
            ),
        )
    } else {
        (
            ScanStatus::Warn,
            "[LF-PROV-UNTRUSTED]",
            format!(
                "{} attestation(s) were observed but none establish configured publisher trust",
                evaluations.len()
            ),
        )
    };
    let key = evaluations
        .iter()
        .find(|value| value.state == TrustState::Trusted)
        .or_else(|| evaluations.first());
    ProvenanceEvaluation {
        state,
        key_fingerprint: key.and_then(|value| value.key_fingerprint.clone()),
        key_name: key.and_then(|value| value.key_name.clone()),
        trusted_signatures: trusted,
        valid_signatures: valid,
        signer_fingerprints,
        finding: finding(model, status, rule, detail, elapsed_ms(started)),
    }
}

fn artifact_present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn verify_envelope(
    path: &Path,
    model: &ResolvedModel,
    trust_store: &TrustStore,
    started: Instant,
) -> Result<ProvenanceEvaluation> {
    let file = open_readonly_nofollow(path)?;
    let bytes = read_all_from_file(&file, MAX_ATTESTATION_BYTES)?;
    let envelope: AttestationEnvelope = serde_json::from_slice(&bytes)
        .with_context(|| format!("Attestation '{}' is not valid JSON", path.display()))?;

    if envelope.version != 1
        || envelope.model != model.name
        || !envelope.manifest_digest.eq_ignore_ascii_case(&model.digest)
    {
        return Ok(single(
            model,
            TrustState::Invalid,
            Some(envelope.key_fingerprint),
            None,
            ScanStatus::Fail,
            "[LF-PROV-BINDING]",
            "Attestation identity/digest binding does not match the scanned model",
            started,
        ));
    }

    let signature_bytes = match hex::decode(&envelope.signature_hex) {
        Ok(bytes) => bytes,
        Err(_) => {
            return Ok(single(
                model,
                TrustState::Invalid,
                Some(envelope.key_fingerprint),
                None,
                ScanStatus::Fail,
                "[LF-PROV-SIGNATURE]",
                "Attestation signature is not valid hexadecimal",
                started,
            ))
        }
    };
    let signature = match Signature::from_slice(&signature_bytes) {
        Ok(value) => value,
        Err(_) => {
            return Ok(single(
                model,
                TrustState::Invalid,
                Some(envelope.key_fingerprint),
                None,
                ScanStatus::Fail,
                "[LF-PROV-SIGNATURE]",
                "Attestation signature is not a 64-byte Ed25519 signature",
                started,
            ))
        }
    };

    let Some(key) = trust_store.find_by_fingerprint(&envelope.key_fingerprint) else {
        return Ok(single(
            model,
            TrustState::UntrustedKey,
            Some(envelope.key_fingerprint),
            None,
            ScanStatus::Warn,
            "[LF-PROV-UNTRUSTED]",
            "Attestation was made by a key that is not in the Layerfault trust store",
            started,
        ));
    };
    if key.revoked {
        return Ok(single(
            model,
            TrustState::RevokedKey,
            Some(key.fingerprint.clone()),
            Some(key.name.clone()),
            ScanStatus::Fail,
            "[LF-PROV-REVOKED]",
            &format!("Attestation key '{}' is revoked", key.name),
            started,
        ));
    }
    let now = paths::now_unix();
    if !trust_store.key_active(key, now) {
        return Ok(single(
            model,
            TrustState::UntrustedKey,
            Some(key.fingerprint.clone()),
            Some(key.name.clone()),
            ScanStatus::Warn,
            "[LF-PROV-INACTIVE]",
            &format!(
                "Attestation key '{}' is outside its configured activation window",
                key.name
            ),
            started,
        ));
    }
    if !key
        .namespaces
        .iter()
        .any(|pattern| trust::glob_match(pattern, &model.name))
    {
        return Ok(single(
            model,
            TrustState::NamespaceMismatch,
            Some(key.fingerprint.clone()),
            Some(key.name.clone()),
            ScanStatus::Fail,
            "[LF-PROV-NAMESPACE]",
            &format!(
                "Trusted key '{}' is not authorized to attest model '{}'",
                key.name, model.name
            ),
            started,
        ));
    }

    let verifying_key = trust::parse_public_key_pem(&key.public_key_pem)?;
    if verifying_key
        .verify(&model.manifest_bytes, &signature)
        .is_err()
    {
        return Ok(single(
            model,
            TrustState::Invalid,
            Some(key.fingerprint.clone()),
            Some(key.name.clone()),
            ScanStatus::Fail,
            "[LF-PROV-SIGNATURE]",
            &format!("Attestation signature from '{}' is invalid", key.name),
            started,
        ));
    }
    Ok(ProvenanceEvaluation {
        state: TrustState::Trusted,
        key_fingerprint: Some(key.fingerprint.clone()),
        key_name: Some(key.name.clone()),
        trusted_signatures: 1,
        valid_signatures: 1,
        signer_fingerprints: vec![key.fingerprint.clone()],
        finding: finding(
            model,
            ScanStatus::Pass,
            "[LF-PROV-TRUSTED]",
            format!(
                "Manifest is attested by trusted key '{}' ({}) authorized for this model identity",
                key.name, key.fingerprint
            ),
            elapsed_ms(started),
        ),
    })
}

#[allow(clippy::too_many_arguments)]
fn single(
    model: &ResolvedModel,
    state: TrustState,
    fingerprint: Option<String>,
    name: Option<String>,
    status: ScanStatus,
    rule: &str,
    detail: &str,
    started: Instant,
) -> ProvenanceEvaluation {
    let trusted = usize::from(state == TrustState::Trusted);
    let valid = usize::from(matches!(
        state,
        TrustState::Trusted | TrustState::LocallyVerified
    ));
    ProvenanceEvaluation {
        state,
        key_fingerprint: fingerprint.clone(),
        key_name: name,
        trusted_signatures: trusted,
        valid_signatures: valid,
        signer_fingerprints: if state == TrustState::Trusted {
            fingerprint.into_iter().collect()
        } else {
            Vec::new()
        },
        finding: finding(model, status, rule, detail.to_owned(), elapsed_ms(started)),
    }
}

fn verify_legacy(
    path: &Path,
    model: &ResolvedModel,
    fallback_key: Option<&VerifyingKey>,
    started: Instant,
) -> Result<ProvenanceEvaluation> {
    let Some(key) = fallback_key else {
        return Ok(single(
            model,
            TrustState::UntrustedKey,
            None,
            None,
            ScanStatus::Warn,
            "[LF-PROV-LEGACY]",
            "Legacy detached signature exists but no --public-key was supplied",
            started,
        ));
    };
    let file = open_readonly_nofollow(path)?;
    let bytes = read_all_from_file(&file, MAX_SIGNATURE_BYTES)?;
    let signature = Signature::from_slice(&bytes)
        .map_err(|_| anyhow!("Legacy signature is not a 64-byte Ed25519 signature"))?;
    let fingerprint = trust::fingerprint(key);
    if key.verify(&model.manifest_bytes, &signature).is_ok() {
        Ok(ProvenanceEvaluation {
            state: TrustState::LocallyVerified,
            key_fingerprint: Some(fingerprint.clone()),
            key_name: None,
            trusted_signatures: 0,
            valid_signatures: 1,
            signer_fingerprints: Vec::new(),
            finding: finding(model, ScanStatus::Pass, "[LF-PROV-LOCAL]", format!("Legacy detached signature verified by supplied key {fingerprint}; trust/identity binding is not established"), elapsed_ms(started)),
        })
    } else {
        Ok(single(
            model,
            TrustState::Invalid,
            Some(fingerprint),
            None,
            ScanStatus::Fail,
            "[LF-PROV-SIGNATURE]",
            "Legacy detached signature does not verify against the scanned manifest bytes",
            started,
        ))
    }
}

fn finding(
    model: &ResolvedModel,
    status: ScanStatus,
    rule_id: &str,
    detail: String,
    duration_ms: u64,
) -> LayerScanResult {
    LayerScanResult {
        layer_digest: model.digest.clone(),
        media_type: "application/vnd.ollama.image.manifest".to_owned(),
        check_type: CheckType::Provenance,
        status,
        finding_class: FindingClass::Attestation,
        confidence: Confidence::High,
        detail: Some(detail),
        matches: vec![format!("{rule_id} provenance")],
        duration_ms,
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}
