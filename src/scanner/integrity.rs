use crate::finding_evidence::{hash_mismatch, signature_evidence, EvidenceSubject, FindingBuilder};
use crate::manifest::{resolve_blob_path, Layer};
use crate::safeio::{open_readonly_nofollow, read_all_from_file};
use crate::scanner::{
    binary::BinaryStreamScanner, duration_ms, CheckType, Confidence, FindingClass, LayerScanResult,
    ScanStatus,
};
use anyhow::{anyhow, Result};
use digest::Digest;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Sha256, Sha512};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::Instant;

const BUFFER_BYTES: usize = 8 * 1024 * 1024;
const MAX_SIGNATURE_BYTES: u64 = 4096;

pub struct VerifiedBlob {
    pub file: File,
    pub len: u64,
    pub binary_scan: Option<LayerScanResult>,
}

pub struct IntegrityScanner;

impl IntegrityScanner {
    /// Open a manifest descriptor without following symlinks, validate its declared
    /// byte length and content digest, then return the same open descriptor for all
    /// downstream scanners. This makes integrity verification the trust boundary.
    pub fn open_and_verify(
        base_dir: &Path,
        layer: &Layer,
        m: &indicatif::MultiProgress,
    ) -> Result<(LayerScanResult, Option<VerifiedBlob>)> {
        Self::open_and_verify_internal(base_dir, layer, m, None)
    }

    /// Integrity verification with executable-object discovery fused into the
    /// same sequential read. This avoids reading multi-gigabyte model/tensor
    /// descriptors a second time solely for ELF/PE/Mach-O/WASM discovery.
    pub fn open_and_verify_with_binary(
        base_dir: &Path,
        layer: &Layer,
        m: &indicatif::MultiProgress,
        binary_media_type: &str,
    ) -> Result<(LayerScanResult, Option<VerifiedBlob>)> {
        Self::open_and_verify_internal(base_dir, layer, m, Some(binary_media_type))
    }

    fn open_and_verify_internal(
        base_dir: &Path,
        layer: &Layer,
        m: &indicatif::MultiProgress,
        binary_media_type: Option<&str>,
    ) -> Result<(LayerScanResult, Option<VerifiedBlob>)> {
        let started = Instant::now();
        let blob_path = resolve_blob_path(base_dir, &layer.digest)?;

        let file = match open_readonly_nofollow(&blob_path) {
            Ok(file) => file,
            Err(error) => {
                return Ok((
                    result(
                        layer,
                        ScanStatus::Fail,
                        Some(format!("Blob cannot be opened safely: {error}")),
                        duration_ms(started),
                    ),
                    None,
                ));
            }
        };

        let actual_size = file.metadata()?.len();
        if actual_size != layer.size {
            return Ok((
                result_with(
                    layer,
                    ScanStatus::Fail,
                    Some(format!(
                        "Descriptor size mismatch: manifest declares {} bytes, file contains {actual_size} bytes",
                        layer.size
                    )),
                    duration_ms(started),
                    "LF-INTEGRITY-SIZE-MISMATCH",
                    Some(hash_mismatch(
                        EvidenceSubject::identity(&layer.digest, &layer.media_type),
                        &layer.size.to_string(),
                        &actual_size.to_string(),
                    )),
                ),
                None,
            ));
        }

        let pb = m.add(indicatif::ProgressBar::new(actual_size));
        pb.set_style(indicatif::ProgressStyle::with_template(
            "[{elapsed_precise}] {bar:40.cyan/blue} {bytes}/{total_bytes} ({eta})",
        )?);

        let mut binary = binary_media_type.map(|_| BinaryStreamScanner::new());
        let mut reader = pb.wrap_read(file.try_clone()?);
        let computed = hash_reader(&layer.digest, &mut reader, |bytes| {
            if let Some(scanner) = binary.as_mut() {
                scanner.observe(&file, actual_size, bytes)?;
            }
            Ok(())
        })?;
        pb.finish_and_clear();

        let expected = layer
            .digest
            .split_once(':')
            .map(|(_, encoded)| encoded)
            .ok_or_else(|| anyhow!("Malformed digest '{}'", layer.digest))?;

        if !computed.eq_ignore_ascii_case(expected) {
            return Ok((
                result_with(
                    layer,
                    ScanStatus::Fail,
                    Some(format!(
                        "Digest mismatch: expected {expected}, got {computed}"
                    )),
                    duration_ms(started),
                    "LF-INTEGRITY-DIGEST-MISMATCH",
                    Some(hash_mismatch(
                        EvidenceSubject::identity(&layer.digest, &layer.media_type),
                        expected,
                        &computed,
                    )),
                ),
                None,
            ));
        }

        let binary_scan = match (binary, binary_media_type) {
            (Some(scanner), Some(media)) => Some(scanner.finish(&layer.digest, media)),
            _ => None,
        };
        Ok((
            result(layer, ScanStatus::Pass, None, duration_ms(started)),
            Some(VerifiedBlob {
                file,
                len: actual_size,
                binary_scan,
            }),
        ))
    }

    /// Verify a detached Ed25519 signature against the exact manifest bytes that
    /// were parsed for scanning. This is local attestation unless the operator
    /// separately establishes who owns/trusts the supplied public key.
    pub fn verify_attestation(
        base_dir: &Path,
        manifest_bytes: &[u8],
        manifest_digest: &str,
        verifying_key: Option<&VerifyingKey>,
    ) -> Result<LayerScanResult> {
        let started = Instant::now();
        let sig_name = manifest_digest.replace(':', "-") + ".sig";
        let sig_path = base_dir.join("blobs").join(sig_name);

        match std::fs::symlink_metadata(&sig_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(attestation_result(
                    manifest_digest,
                    ScanStatus::Warn,
                    Some(
                        "No detached signature found; local attestation is unavailable".to_owned(),
                    ),
                    vec!["[T13-001] Missing local attestation signature".to_owned()],
                    duration_ms(started),
                    Confidence::High,
                    "T13-001",
                    None,
                ));
            }
            Err(error) => {
                return Ok(attestation_result(
                    manifest_digest,
                    ScanStatus::Fail,
                    Some(format!(
                        "Signature path cannot be inspected safely: {error}"
                    )),
                    vec!["[T13-002] Unsafe or unreadable signature path".to_owned()],
                    duration_ms(started),
                    Confidence::High,
                    "T13-002",
                    None,
                ));
            }
            Ok(_) => {}
        }

        let sig_file = match open_readonly_nofollow(&sig_path) {
            Ok(file) => file,
            Err(error) => {
                return Ok(attestation_result(
                    manifest_digest,
                    ScanStatus::Fail,
                    Some(format!("Signature file cannot be opened safely: {error}")),
                    vec!["[T13-002] Unsafe or unreadable signature file".to_owned()],
                    duration_ms(started),
                    Confidence::High,
                    "T13-002",
                    None,
                ));
            }
        };

        let sig_bytes = read_all_from_file(&sig_file, MAX_SIGNATURE_BYTES)?;
        let signature = match Signature::from_slice(&sig_bytes) {
            Ok(signature) => signature,
            Err(_) => {
                return Ok(attestation_result(
                    manifest_digest,
                    ScanStatus::Fail,
                    Some(format!(
                        "Signature file is malformed ({} bytes, expected 64)",
                        sig_bytes.len()
                    )),
                    vec!["[T13-002] Invalid Ed25519 signature encoding".to_owned()],
                    duration_ms(started),
                    Confidence::High,
                    "T13-002",
                    Some(signature_evidence(
                        EvidenceSubject::identity(
                            manifest_digest,
                            "application/vnd.ollama.image.manifest",
                        ),
                        serde_json::json!({ "signature_bytes": sig_bytes.len(), "expected_bytes": 64 }),
                    )),
                ));
            }
        };

        let key = match verifying_key {
            Some(key) => key,
            None => {
                return Ok(attestation_result(
                    manifest_digest,
                    ScanStatus::Warn,
                    Some(
                        "Signature present but no public key supplied; use --public-key to verify local attestation"
                            .to_owned(),
                    ),
                    vec!["[T13-001] Unverified local attestation signature".to_owned()],
                    duration_ms(started),
                    Confidence::High,
                    "T13-001",
                    None,
                ));
            }
        };

        let fingerprint = key_fingerprint(key);
        match key.verify(manifest_bytes, &signature) {
            Ok(()) => Ok(attestation_result(
                manifest_digest,
                ScanStatus::Pass,
                Some(format!(
                    "Manifest bytes verified by supplied Ed25519 key ({fingerprint}); key ownership/trust is operator-defined"
                )),
                vec![format!("Verified local attestation key {fingerprint}")],
                duration_ms(started),
                Confidence::High,
                "LF-PROV-LOCAL-VERIFIED",
                Some(signature_evidence(
                    EvidenceSubject::identity(manifest_digest, "application/vnd.ollama.image.manifest"),
                    serde_json::json!({ "key_fingerprint": fingerprint, "verified": true }),
                )),
            )),
            Err(_) => Ok(attestation_result(
                manifest_digest,
                ScanStatus::Fail,
                Some("Ed25519 verification failed for the scanned manifest bytes".to_owned()),
                vec!["[T13-002] Invalid local attestation signature".to_owned()],
                duration_ms(started),
                Confidence::High,
                "T13-002",
                Some(signature_evidence(
                    EvidenceSubject::identity(
                        manifest_digest,
                        "application/vnd.ollama.image.manifest",
                    ),
                    serde_json::json!({ "key_fingerprint": fingerprint, "verified": false }),
                )),
            )),
        }
    }
}

fn hash_reader<F>(expected_digest: &str, reader: &mut impl Read, mut observe: F) -> Result<String>
where
    F: FnMut(&[u8]) -> Result<()>,
{
    let algorithm = expected_digest
        .split_once(':')
        .map(|(algorithm, _)| algorithm)
        .ok_or_else(|| anyhow!("Malformed digest '{expected_digest}'"))?;
    let mut buffer = vec![0_u8; BUFFER_BYTES];

    match algorithm {
        "sha256" => {
            let mut hasher = Sha256::new();
            loop {
                let count = reader.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                hasher.update(&buffer[..count]);
                observe(&buffer[..count])?;
            }
            Ok(hex::encode(hasher.finalize()))
        }
        "sha512" => {
            let mut hasher = Sha512::new();
            loop {
                let count = reader.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                hasher.update(&buffer[..count]);
                observe(&buffer[..count])?;
            }
            Ok(hex::encode(hasher.finalize()))
        }
        other => Err(anyhow!("Unsupported digest algorithm '{other}'")),
    }
}

fn result(
    layer: &Layer,
    status: ScanStatus,
    detail: Option<String>,
    elapsed: u64,
) -> LayerScanResult {
    result_with(
        layer,
        status,
        detail,
        elapsed,
        "LF-INTEGRITY-VERIFIED",
        None,
    )
}

/// Build an integrity finding, optionally with the digest/size evidence that
/// caused it to fire. `PASS` and open-failure findings have nothing to attach:
/// a verified digest match is not itself security-relevant evidence, and an
/// I/O error has no digest to compare.
fn result_with(
    layer: &Layer,
    status: ScanStatus,
    detail: Option<String>,
    elapsed: u64,
    rule_id: &str,
    evidence: Option<crate::finding_evidence::FindingEvidence>,
) -> LayerScanResult {
    let subject = EvidenceSubject::identity(&layer.digest, &layer.media_type)
        .with_sha256(Some(layer.digest.clone()))
        .with_size(Some(layer.size));
    let mut builder = FindingBuilder::new(rule_id, CheckType::IntegrityHash, status)
        .class(FindingClass::Integrity)
        .confidence(Confidence::High)
        .digest(&layer.digest)
        .media_type(&layer.media_type)
        .subject(subject)
        .duration_ms(elapsed);
    if let Some(detail) = detail {
        builder = builder.detail(detail);
    }
    builder = match evidence {
        Some(record) => builder.evidence(record),
        None if status == ScanStatus::Pass => builder.evidence_not_applicable(),
        None => builder.evidence_unavailable(
            "the blob could not be opened or measured, so no digest comparison exists",
        ),
    };
    builder.finish()
}

#[allow(clippy::too_many_arguments)]
fn attestation_result(
    digest: &str,
    status: ScanStatus,
    detail: Option<String>,
    matches: Vec<String>,
    elapsed: u64,
    confidence: Confidence,
    rule_id: &str,
    evidence: Option<crate::finding_evidence::FindingEvidence>,
) -> LayerScanResult {
    let media_type = "application/vnd.ollama.image.manifest";
    let subject =
        EvidenceSubject::identity(digest, media_type).with_sha256(Some(digest.to_owned()));
    let mut builder = FindingBuilder::new(rule_id, CheckType::Provenance, status)
        .class(FindingClass::Attestation)
        .confidence(confidence)
        .digest(digest)
        .media_type(media_type)
        .subject(subject)
        .duration_ms(elapsed);
    if let Some(detail) = detail {
        builder = builder.detail(detail);
    }
    for note in matches.iter().skip(1) {
        builder = builder.match_note(note.clone());
    }
    builder = match evidence {
        Some(record) => builder.evidence(record),
        None if status == ScanStatus::Warn
            && matches.first().is_some_and(|m| m.contains("Missing")) =>
        {
            builder.evidence_unavailable("no signature file exists at the expected path")
        }
        None => builder.evidence_unavailable(
            "attestation state was determined without a comparable signature value",
        ),
    };
    let mut finding = builder.finish();
    if !matches.is_empty() {
        finding.matches = matches;
    }
    finding
}

fn key_fingerprint(key: &VerifyingKey) -> String {
    let digest = Sha256::digest(key.to_bytes());
    format!("sha256:{}", &hex::encode(digest)[..16])
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::fs;

    const TEST_DIGEST: &str =
        "sha256:0000000000000000000000000000000000000000000000000000000000000001";
    const MANIFEST_CONTENT: &[u8] = b"test manifest content";

    fn setup(name: &str) -> std::path::PathBuf {
        let base = std::env::temp_dir().join(format!("layerfault_attestation_{name}"));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("blobs")).unwrap();
        base
    }

    fn sig_path(base: &Path) -> std::path::PathBuf {
        base.join("blobs")
            .join("sha256-0000000000000000000000000000000000000000000000000000000000000001.sig")
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[42_u8; 32])
    }

    fn layer_for(data: &[u8]) -> Layer {
        Layer {
            media_type: "application/vnd.ollama.image.template".to_owned(),
            digest: format!("sha256:{}", hex::encode(Sha256::digest(data))),
            size: data.len() as u64,
        }
    }

    #[test]
    fn descriptor_size_and_digest_are_both_verified() -> Result<()> {
        let base = setup("blob_integrity");
        let data = b"verified bytes";
        let layer = layer_for(data);
        let path = resolve_blob_path(&base, &layer.digest)?;
        fs::write(&path, data)?;
        let progress = indicatif::MultiProgress::new();

        let (pass, verified) = IntegrityScanner::open_and_verify(&base, &layer, &progress)?;
        assert_eq!(pass.status, ScanStatus::Pass);
        assert!(verified.is_some());

        fs::write(&path, b"tampered bytes")?;
        let mut same_size = layer.clone();
        same_size.size = b"tampered bytes".len() as u64;
        let (failed, verified) = IntegrityScanner::open_and_verify(&base, &same_size, &progress)?;
        assert_eq!(failed.status, ScanStatus::Fail);
        assert!(verified.is_none());

        let mut wrong_size = layer.clone();
        wrong_size.size = 999;
        let (failed, verified) = IntegrityScanner::open_and_verify(&base, &wrong_size, &progress)?;
        assert_eq!(failed.status, ScanStatus::Fail);
        assert!(verified.is_none());

        let _ = fs::remove_dir_all(base);
        Ok(())
    }

    #[test]
    fn missing_signature_warns() -> Result<()> {
        let base = setup("missing");
        let result =
            IntegrityScanner::verify_attestation(&base, MANIFEST_CONTENT, TEST_DIGEST, None)?;
        assert_eq!(result.status, ScanStatus::Warn);
        let _ = fs::remove_dir_all(base);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn dangling_signature_symlink_is_not_treated_as_missing() -> Result<()> {
        use std::os::unix::fs::symlink;
        let base = setup("dangling_symlink");
        symlink(base.join("does-not-exist"), sig_path(&base))?;
        let result =
            IntegrityScanner::verify_attestation(&base, MANIFEST_CONTENT, TEST_DIGEST, None)?;
        assert_eq!(result.status, ScanStatus::Fail);
        assert!(result
            .detail
            .as_deref()
            .is_some_and(|detail| detail.contains("opened safely")));
        let _ = fs::remove_dir_all(base);
        Ok(())
    }

    #[test]
    fn exact_manifest_bytes_are_verified() -> Result<()> {
        let base = setup("exact_bytes");
        let key = signing_key();
        fs::write(sig_path(&base), key.sign(MANIFEST_CONTENT).to_bytes())?;
        let result = IntegrityScanner::verify_attestation(
            &base,
            MANIFEST_CONTENT,
            TEST_DIGEST,
            Some(&key.verifying_key()),
        )?;
        assert_eq!(result.status, ScanStatus::Pass);
        let changed = IntegrityScanner::verify_attestation(
            &base,
            b"different manifest bytes",
            TEST_DIGEST,
            Some(&key.verifying_key()),
        )?;
        assert_eq!(changed.status, ScanStatus::Fail);
        let _ = fs::remove_dir_all(base);
        Ok(())
    }
}
