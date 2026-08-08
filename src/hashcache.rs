//! Conservative persistent cache for expensive local artifact hashing and scan evidence.
//!
//! The cache is a performance optimization for repeated scans of unchanged local files.
//! It is not a substitute for a strict re-hash when the caller requires fresh cryptographic
//! verification. `layerfault --no-cache ...` disables reuse for that invocation.

use anyhow::{anyhow, Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

const CACHE_SCHEMA_VERSION: u32 = 1;
const DIGEST_CACHE_REVISION: &str = "sha256-v1";
const EVIDENCE_CACHE_REVISION: &str = env!("LAYERFAULT_SCANNER_REVISION");
const DEFAULT_MIN_CACHE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RECORD_BYTES: u64 = 16 * 1024 * 1024;
const GUARD_BYTES: usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileIdentity {
    canonical_path: String,
    len: u64,
    modified_secs: Option<u64>,
    modified_nanos: Option<u32>,
    created_secs: Option<u64>,
    created_nanos: Option<u32>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    ctime_secs: i64,
    #[cfg(unix)]
    ctime_nanos: i64,
}

#[derive(Debug, Clone)]
pub struct HashOutcome {
    pub sha256: String,
    pub cache_hit: bool,
    pub identity: FileIdentity,
}

#[derive(Debug, Serialize, Deserialize)]
struct DigestRecord {
    schema_version: u32,
    scanner_revision: String,
    identity: FileIdentity,
    guard_sha256: String,
    sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct EvidenceRecord<T> {
    schema_version: u32,
    scanner_revision: String,
    identity: FileIdentity,
    guard_sha256: String,
    discriminator: String,
    value: T,
}

pub fn enabled() -> bool {
    match std::env::var("LAYERFAULT_HASH_CACHE") {
        Ok(value) => !matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "off" | "no" | "strict"
        ),
        Err(_) => true,
    }
}

pub fn eligible(size: u64) -> bool {
    enabled() && size >= min_cache_bytes()
}

pub fn sha256_prefixed(path: &Path, file: &File) -> Result<HashOutcome> {
    let before = capture_identity(path, file)?;
    if eligible(before.len) {
        if let Some(record) = load_digest_record(&before)? {
            let guard = guard_sha256(file, before.len)?;
            let after = capture_identity(path, file)?;
            if after == before && guard == record.guard_sha256 {
                return Ok(HashOutcome {
                    sha256: record.sha256,
                    cache_hit: true,
                    identity: before,
                });
            }
        }
    }

    let sha256 = sha256_uncached_prefixed(file)?;
    let after = capture_identity(path, file)?;
    if after != before {
        return Err(anyhow!(
            "File '{}' changed while its SHA-256 was being computed",
            path.display()
        ));
    }

    if eligible(after.len) {
        let guard_sha256 = guard_sha256(file, after.len)?;
        let final_identity = capture_identity(path, file)?;
        if final_identity != after {
            return Err(anyhow!(
                "File '{}' changed while its cache guard was being computed",
                path.display()
            ));
        }
        let record = DigestRecord {
            schema_version: CACHE_SCHEMA_VERSION,
            scanner_revision: DIGEST_CACHE_REVISION.to_owned(),
            identity: final_identity.clone(),
            guard_sha256,
            sha256: sha256.clone(),
        };
        store_record("digests", &final_identity, "sha256", &record)?;
        return Ok(HashOutcome {
            sha256,
            cache_hit: false,
            identity: final_identity,
        });
    }

    Ok(HashOutcome {
        sha256,
        cache_hit: false,
        identity: after,
    })
}

/// Hash a file while exposing each freshly-read chunk to a caller. When the
/// digest cache is valid no full read occurs and `streamed` is false; callers
/// can then perform whatever single pass they still require. This lets cold
/// artifact admission fuse hashing with executable discovery without weakening
/// the conservative cache guard/identity checks.
pub fn sha256_prefixed_with_observer<F>(
    path: &Path,
    file: &File,
    mut observe: F,
) -> Result<(HashOutcome, bool)>
where
    F: FnMut(&[u8]) -> Result<()>,
{
    let before = capture_identity(path, file)?;
    if eligible(before.len) {
        if let Some(record) = load_digest_record(&before)? {
            let guard = guard_sha256(file, before.len)?;
            let after = capture_identity(path, file)?;
            if after == before && guard == record.guard_sha256 {
                return Ok((
                    HashOutcome {
                        sha256: record.sha256,
                        cache_hit: true,
                        identity: before,
                    },
                    false,
                ));
            }
        }
    }

    let sha256 = sha256_uncached_prefixed_with_observer(file, &mut observe)?;
    let after = capture_identity(path, file)?;
    if after != before {
        return Err(anyhow!(
            "File '{}' changed while its SHA-256 was being computed",
            path.display()
        ));
    }

    if eligible(after.len) {
        let guard_sha256 = guard_sha256(file, after.len)?;
        let final_identity = capture_identity(path, file)?;
        if final_identity != after {
            return Err(anyhow!(
                "File '{}' changed while its cache guard was being computed",
                path.display()
            ));
        }
        let record = DigestRecord {
            schema_version: CACHE_SCHEMA_VERSION,
            scanner_revision: DIGEST_CACHE_REVISION.to_owned(),
            identity: final_identity.clone(),
            guard_sha256,
            sha256: sha256.clone(),
        };
        store_record("digests", &final_identity, "sha256", &record)?;
        return Ok((
            HashOutcome {
                sha256,
                cache_hit: false,
                identity: final_identity,
            },
            true,
        ));
    }

    Ok((
        HashOutcome {
            sha256,
            cache_hit: false,
            identity: after,
        },
        true,
    ))
}

pub fn sha256_hex(path: &Path, file: &File) -> Result<HashOutcome> {
    let mut outcome = sha256_prefixed(path, file)?;
    let value = outcome
        .sha256
        .strip_prefix("sha256:")
        .unwrap_or(&outcome.sha256)
        .to_owned();
    outcome.sha256 = value;
    Ok(outcome)
}

pub fn sha256_uncached_prefixed(file: &File) -> Result<String> {
    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn sha256_uncached_prefixed_with_observer<F>(file: &File, observe: &mut F) -> Result<String>
where
    F: FnMut(&[u8]) -> Result<()>,
{
    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        observe(&buffer[..count])?;
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

pub fn identity_unchanged(path: &Path, file: &File, before: &FileIdentity) -> Result<bool> {
    Ok(capture_identity(path, file)? == *before)
}

pub fn load_evidence<T>(
    namespace: &str,
    path: &Path,
    file: &File,
    discriminator: &str,
) -> Result<Option<T>>
where
    T: DeserializeOwned,
{
    let current = capture_identity(path, file)?;
    if !eligible(current.len) {
        return Ok(None);
    }
    let record_path = record_path(namespace, &current, discriminator)?;
    let Some(record) = read_record::<EvidenceRecord<T>>(&record_path)? else {
        return Ok(None);
    };
    if record.schema_version != CACHE_SCHEMA_VERSION
        || record.scanner_revision != EVIDENCE_CACHE_REVISION
        || record.identity != current
        || record.discriminator != discriminator
    {
        return Ok(None);
    }
    let guard = guard_sha256(file, current.len)?;
    let after = capture_identity(path, file)?;
    if after != current || guard != record.guard_sha256 {
        return Ok(None);
    }
    Ok(Some(record.value))
}

pub fn store_evidence<T>(
    namespace: &str,
    path: &Path,
    file: &File,
    expected_identity: &FileIdentity,
    discriminator: &str,
    value: &T,
) -> Result<()>
where
    T: Serialize,
{
    let current = capture_identity(path, file)?;
    if current != *expected_identity || !eligible(current.len) {
        return Ok(());
    }
    let guard_sha256 = guard_sha256(file, current.len)?;
    let after = capture_identity(path, file)?;
    if after != current {
        return Ok(());
    }
    let record = EvidenceRecord {
        schema_version: CACHE_SCHEMA_VERSION,
        scanner_revision: EVIDENCE_CACHE_REVISION.to_owned(),
        guard_sha256,
        identity: current.clone(),
        discriminator: discriminator.to_owned(),
        value,
    };
    store_record(namespace, &current, discriminator, &record)
}

pub fn capture_identity(path: &Path, file: &File) -> Result<FileIdentity> {
    let metadata = file.metadata()?;
    let canonical_path = std::fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .into_owned();
    let (modified_secs, modified_nanos) = system_time_parts(metadata.modified().ok());
    let (created_secs, created_nanos) = system_time_parts(metadata.created().ok());

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(FileIdentity {
            canonical_path,
            len: metadata.len(),
            modified_secs,
            modified_nanos,
            created_secs,
            created_nanos,
            device: metadata.dev(),
            inode: metadata.ino(),
            ctime_secs: metadata.ctime(),
            ctime_nanos: metadata.ctime_nsec(),
        })
    }

    #[cfg(not(unix))]
    {
        Ok(FileIdentity {
            canonical_path,
            len: metadata.len(),
            modified_secs,
            modified_nanos,
            created_secs,
            created_nanos,
        })
    }
}

fn system_time_parts(value: Option<std::time::SystemTime>) -> (Option<u64>, Option<u32>) {
    let Some(value) = value else {
        return (None, None);
    };
    let Ok(duration) = value.duration_since(std::time::UNIX_EPOCH) else {
        return (None, None);
    };
    (Some(duration.as_secs()), Some(duration.subsec_nanos()))
}

fn min_cache_bytes() -> u64 {
    std::env::var("LAYERFAULT_HASH_CACHE_MIN_BYTES")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_MIN_CACHE_BYTES)
}

fn cache_root() -> Result<PathBuf> {
    Ok(crate::paths::cache_dir()?.join("file-evidence-v1"))
}

fn record_path(namespace: &str, identity: &FileIdentity, discriminator: &str) -> Result<PathBuf> {
    let mut hasher = Sha256::new();
    hasher.update(b"layerfault-file-cache-key\0");
    hasher.update(identity.canonical_path.as_bytes());
    #[cfg(unix)]
    {
        hasher.update(identity.device.to_le_bytes());
        hasher.update(identity.inode.to_le_bytes());
    }
    hasher.update(discriminator.as_bytes());
    let key = hex::encode(hasher.finalize());
    Ok(cache_root()?.join(namespace).join(format!("{key}.json")))
}

fn load_digest_record(identity: &FileIdentity) -> Result<Option<DigestRecord>> {
    let path = record_path("digests", identity, "sha256")?;
    let Some(record) = read_record::<DigestRecord>(&path)? else {
        return Ok(None);
    };
    if record.schema_version != CACHE_SCHEMA_VERSION
        || record.scanner_revision != DIGEST_CACHE_REVISION
        || record.identity != *identity
        || !valid_prefixed_sha256(&record.sha256)
    {
        return Ok(None);
    }
    Ok(Some(record))
}

fn read_record<T>(path: &Path) -> Result<Option<T>>
where
    T: DeserializeOwned,
{
    if !path.exists() {
        return Ok(None);
    }
    let file = match crate::safeio::open_readonly_nofollow(path) {
        Ok(file) => file,
        Err(_) => return Ok(None),
    };
    let bytes = match crate::safeio::read_all_from_file(&file, MAX_RECORD_BYTES) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(None),
    };
    match serde_json::from_slice(&bytes) {
        Ok(record) => Ok(Some(record)),
        Err(_) => Ok(None),
    }
}

fn store_record<T>(
    namespace: &str,
    identity: &FileIdentity,
    discriminator: &str,
    record: &T,
) -> Result<()>
where
    T: Serialize,
{
    let path = record_path(namespace, identity, discriminator)?;
    let bytes =
        serde_json::to_vec(record).context("Unable to serialize Layerfault cache record")?;
    crate::paths::write_private(&path, &bytes)
}

fn guard_sha256(file: &File, len: u64) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(b"layerfault-file-guard-v1\0");
    hasher.update(len.to_le_bytes());
    for offset in guard_offsets(len) {
        let bytes = read_guard(file, offset, len)?;
        hasher.update(offset.to_le_bytes());
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn guard_offsets(len: u64) -> Vec<u64> {
    if len == 0 {
        return vec![0];
    }
    let chunk = GUARD_BYTES as u64;
    let first = 0;
    let middle = (len / 2).saturating_sub(chunk / 2);
    let last = len.saturating_sub(chunk);
    let mut offsets = vec![first, middle, last];
    offsets.sort_unstable();
    offsets.dedup();
    offsets
}

fn read_guard(file: &File, offset: u64, len: u64) -> Result<Vec<u8>> {
    if offset >= len {
        return Ok(Vec::new());
    }
    let available = len.saturating_sub(offset).min(GUARD_BYTES as u64);
    let count = usize::try_from(available).context("Guard read size does not fit usize")?;
    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(offset))?;
    let mut bytes = vec![0_u8; count];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn valid_prefixed_sha256(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn test_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "layerfault-hashcache-{name}-{}-{}",
            std::process::id(),
            crate::paths::now_unix()
        ))
    }

    #[test]
    fn guard_changes_when_sampled_content_changes() -> Result<()> {
        let root = test_root("guard");
        std::fs::create_dir_all(&root)?;
        let path = root.join("model.bin");
        let mut file = File::create(&path)?;
        file.write_all(&vec![b'a'; GUARD_BYTES * 4])?;
        drop(file);

        let file = crate::safeio::open_readonly_nofollow(&path)?;
        let before = guard_sha256(&file, file.metadata()?.len())?;
        drop(file);

        let mut file = std::fs::OpenOptions::new().write(true).open(&path)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(b"changed")?;
        drop(file);

        let file = crate::safeio::open_readonly_nofollow(&path)?;
        let after = guard_sha256(&file, file.metadata()?.len())?;
        assert_ne!(before, after);
        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn identity_changes_after_size_change() -> Result<()> {
        let root = test_root("identity");
        std::fs::create_dir_all(&root)?;
        let path = root.join("model.bin");
        std::fs::write(&path, b"one")?;
        let file = crate::safeio::open_readonly_nofollow(&path)?;
        let before = capture_identity(&path, &file)?;
        drop(file);

        std::fs::write(&path, b"two-two")?;
        let file = crate::safeio::open_readonly_nofollow(&path)?;
        let after = capture_identity(&path, &file)?;
        assert_ne!(before, after);
        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }
}
