use super::{load_pack, IntelligencePack};
use crate::safeio::{open_readonly_nofollow, read_all_from_file};
use anyhow::{Context, Result};
use ed25519_dalek::pkcs8::DecodePublicKey;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, Clone, serde::Serialize)]
pub struct VerifiedIntelligencePack {
    pub pack: IntelligencePack,
    #[serde(skip_serializing)]
    pub raw_bytes: Vec<u8>,
    pub sha256: String,
    pub signer_sha256: String,
}

pub fn verify_detached(
    bytes: &[u8],
    signature_bytes: &[u8],
    public_key_pem: &[u8],
) -> Result<String> {
    let signature_text = std::str::from_utf8(signature_bytes)
        .context("intelligence signature must be UTF-8 hexadecimal")?;
    let signature_raw =
        hex::decode(signature_text.trim()).context("intelligence signature is not hexadecimal")?;
    let signature = Signature::from_slice(&signature_raw)
        .context("intelligence signature is not a valid Ed25519 signature")?;
    let pem =
        std::str::from_utf8(public_key_pem).context("intelligence public key must be PEM UTF-8")?;
    let key = VerifyingKey::from_public_key_pem(pem)
        .context("unable to parse intelligence Ed25519 public key")?;
    key.verify(bytes, &signature)
        .context("intelligence pack signature verification failed")?;
    Ok(format!(
        "sha256:{}",
        hex::encode(Sha256::digest(public_key_pem))
    ))
}

pub fn load_verified(
    pack_path: &Path,
    signature_path: &Path,
    public_key_path: &Path,
) -> Result<VerifiedIntelligencePack> {
    let (pack, raw_bytes) = load_pack(pack_path)?;
    let sig_file = open_readonly_nofollow(signature_path)?;
    let signature_bytes = read_all_from_file(&sig_file, 4096)?;
    let key_file = open_readonly_nofollow(public_key_path)?;
    let public_key_pem = read_all_from_file(&key_file, 64 * 1024)?;
    let signer_sha256 = verify_detached(&raw_bytes, &signature_bytes, &public_key_pem)?;
    let sha256 = format!("sha256:{}", hex::encode(Sha256::digest(&raw_bytes)));
    Ok(VerifiedIntelligencePack {
        pack,
        raw_bytes,
        sha256,
        signer_sha256,
    })
}
