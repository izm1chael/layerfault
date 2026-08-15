use super::{parse_pack, verify_detached, VerifiedIntelligencePack, MAX_PACK_BYTES};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

const MAX_BUNDLE_BYTES: u64 = 40 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfflineIntelligenceBundle {
    pub version: u32,
    /// Hex encoding preserves the exact signed pack bytes without adding a
    /// binary archive format or executable update mechanism.
    pub pack_hex: String,
    pub signature_hex: String,
    pub public_key_pem: String,
}

pub fn export_bundle(
    pack: &Path,
    signature: &Path,
    public_key: &Path,
    output: &Path,
) -> Result<()> {
    let pack_file = crate::safeio::open_readonly_nofollow(pack)?;
    let pack_bytes = crate::safeio::read_all_from_file(&pack_file, MAX_PACK_BYTES)?;
    let _ = parse_pack(&pack_bytes)?;
    let sig_file = crate::safeio::open_readonly_nofollow(signature)?;
    let sig_bytes = crate::safeio::read_all_from_file(&sig_file, 4096)?;
    let signature_hex = std::str::from_utf8(&sig_bytes)
        .context("intelligence signature is not UTF-8")?
        .trim()
        .to_owned();
    let key_file = crate::safeio::open_readonly_nofollow(public_key)?;
    let key_bytes = crate::safeio::read_all_from_file(&key_file, 64 * 1024)?;
    let public_key_pem = std::str::from_utf8(&key_bytes)
        .context("intelligence public key is not UTF-8")?
        .to_owned();
    let _ = verify_detached(
        &pack_bytes,
        signature_hex.as_bytes(),
        public_key_pem.as_bytes(),
    )?;
    let bundle = OfflineIntelligenceBundle {
        version: 1,
        pack_hex: hex::encode(pack_bytes),
        signature_hex,
        public_key_pem,
    };
    let bytes = serde_json::to_vec_pretty(&bundle)?;
    if bytes.len() as u64 > MAX_BUNDLE_BYTES {
        bail!("offline intelligence bundle exceeds the safety limit");
    }
    crate::paths::write_private(output, &bytes)
}

pub fn verify_bundle(path: &Path) -> Result<VerifiedIntelligencePack> {
    let file = crate::safeio::open_readonly_nofollow(path)?;
    let bytes = crate::safeio::read_all_from_file(&file, MAX_BUNDLE_BYTES)?;
    let bundle: OfflineIntelligenceBundle =
        serde_json::from_slice(&bytes).context("offline intelligence bundle is invalid JSON")?;
    if bundle.version != 1 {
        bail!(
            "unsupported offline intelligence bundle version {}",
            bundle.version
        );
    }
    if bundle.pack_hex.len() > MAX_PACK_BYTES as usize * 2 {
        bail!("offline intelligence pack exceeds the safety limit");
    }
    let raw_bytes = hex::decode(&bundle.pack_hex)
        .context("offline intelligence pack is not valid hexadecimal")?;
    let pack = parse_pack(&raw_bytes)?;
    let signer_sha256 = verify_detached(
        &raw_bytes,
        bundle.signature_hex.as_bytes(),
        bundle.public_key_pem.as_bytes(),
    )?;
    let sha256 = format!("sha256:{}", hex::encode(Sha256::digest(&raw_bytes)));
    Ok(VerifiedIntelligencePack {
        pack,
        raw_bytes,
        sha256,
        signer_sha256,
    })
}

pub fn import_bundle(
    path: &Path,
    pack_output: &Path,
    signature_output: &Path,
    public_key_output: &Path,
) -> Result<VerifiedIntelligencePack> {
    let verified = verify_bundle(path)?;
    let file = crate::safeio::open_readonly_nofollow(path)?;
    let bytes = crate::safeio::read_all_from_file(&file, MAX_BUNDLE_BYTES)?;
    let bundle: OfflineIntelligenceBundle = serde_json::from_slice(&bytes)?;
    crate::paths::write_private(pack_output, &verified.raw_bytes)?;
    crate::paths::write_private(signature_output, bundle.signature_hex.as_bytes())?;
    crate::paths::write_private(public_key_output, bundle.public_key_pem.as_bytes())?;
    Ok(verified)
}
