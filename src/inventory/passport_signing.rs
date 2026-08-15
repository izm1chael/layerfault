use super::{canonical_passport_bytes, passport_sha256, ModelSecurityPassport};
use anyhow::{bail, Context, Result};
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::path::Path;

const MAX_SIGNED_PASSPORT_BYTES: u64 = 72 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedSecurityPassport {
    pub version: u32,
    pub passport: ModelSecurityPassport,
    pub issuer_fingerprint: String,
    pub public_key_hex: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPassportVerification {
    pub valid_signature: bool,
    pub passport_sha256: String,
    pub issuer_fingerprint: String,
    pub trusted_issuer: bool,
    pub authorized_for_subject: bool,
    pub subject: String,
}

pub fn sign_passport(
    passport: ModelSecurityPassport,
    private_key_path: &Path,
) -> Result<SignedSecurityPassport> {
    let file = crate::safeio::open_readonly_nofollow(private_key_path)?;
    let bytes = crate::safeio::read_all_from_file(&file, 64 * 1024)?;
    let pem = std::str::from_utf8(&bytes).context("passport signing key must be UTF-8 PEM")?;
    let signing =
        SigningKey::from_pkcs8_pem(pem).context("unable to parse Ed25519 passport signing key")?;
    let verifying = signing.verifying_key();
    let payload = canonical_passport_bytes(&passport)?;
    let signature = signing.sign(&payload);
    Ok(SignedSecurityPassport {
        version: 1,
        passport,
        issuer_fingerprint: crate::trust::fingerprint(&verifying),
        public_key_hex: hex::encode(verifying.to_bytes()),
        signature_hex: hex::encode(signature.to_bytes()),
    })
}

pub fn write_signed_passport(path: &Path, signed: &SignedSecurityPassport) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(signed)?;
    crate::paths::write_private(path, &bytes)
}

pub fn load_signed_passport(path: &Path) -> Result<SignedSecurityPassport> {
    let file = crate::safeio::open_readonly_nofollow(path)?;
    let bytes = crate::safeio::read_all_from_file(&file, MAX_SIGNED_PASSPORT_BYTES)?;
    let signed: SignedSecurityPassport = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "signed security passport '{}' is invalid JSON",
            path.display()
        )
    })?;
    validate_envelope(&signed)?;
    Ok(signed)
}

pub fn verify_signed_passport(
    signed: &SignedSecurityPassport,
    trust_store: Option<&crate::trust::TrustStore>,
) -> Result<SignedPassportVerification> {
    validate_envelope(signed)?;
    super::passport_io::validate_passport(&signed.passport)?;
    let public_key = decode_public_key(&signed.public_key_hex)?;
    let computed_fingerprint = crate::trust::fingerprint(&public_key);
    if !computed_fingerprint.eq_ignore_ascii_case(&signed.issuer_fingerprint) {
        bail!("signed passport issuer fingerprint does not match embedded public key");
    }
    let signature_bytes = hex::decode(&signed.signature_hex)
        .context("signed passport signature is not hexadecimal")?;
    let signature = Signature::from_slice(&signature_bytes)
        .context("signed passport signature is not a valid Ed25519 signature")?;
    let valid_signature = public_key
        .verify(&canonical_passport_bytes(&signed.passport)?, &signature)
        .is_ok();
    let trusted_key =
        trust_store.and_then(|store| store.find_by_fingerprint(&computed_fingerprint));
    let trusted_issuer = trusted_key
        .zip(trust_store)
        .is_some_and(|(key, store)| store.key_active(key, crate::paths::now_unix()));
    let authorized_for_subject = trusted_key
        .zip(trust_store)
        .is_some_and(|(key, store)| store.authorized_for(key, &signed.passport.subject.name));
    Ok(SignedPassportVerification {
        valid_signature,
        passport_sha256: passport_sha256(&signed.passport)?,
        issuer_fingerprint: computed_fingerprint,
        trusted_issuer,
        authorized_for_subject,
        subject: signed.passport.subject.name.clone(),
    })
}

fn validate_envelope(signed: &SignedSecurityPassport) -> Result<()> {
    if signed.version != 1 {
        bail!(
            "unsupported signed passport envelope version {}",
            signed.version
        );
    }
    if signed.issuer_fingerprint.len() != 71 || !signed.issuer_fingerprint.starts_with("sha256:") {
        bail!("signed passport issuer fingerprint is not canonical SHA-256");
    }
    if signed.public_key_hex.len() != 64 {
        bail!("signed passport public key must contain 32 bytes");
    }
    if signed.signature_hex.len() != 128 {
        bail!("signed passport Ed25519 signature must contain 64 bytes");
    }
    Ok(())
}

fn decode_public_key(value: &str) -> Result<VerifyingKey> {
    let bytes = hex::decode(value).context("signed passport public key is not hexadecimal")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("signed passport public key must contain 32 bytes"))?;
    VerifyingKey::from_bytes(&bytes).context("signed passport public key is invalid")
}
