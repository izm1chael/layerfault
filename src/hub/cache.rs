//! Verified Hugging Face Content Object Cache.
//!
//! Stores verified immutable objects keyed strictly by canonical `sha256:<digest>`
//! under `objects/sha256/ab/abcdef...` and metadata under `objects/meta/sha256/ab/abcdef....json`.
//! Only objects whose observed SHA-256 matches the expected Hub LFS SHA-256 digest enter the cache.

use crate::paths::{cache_dir, ensure_private_dir, now_unix, write_private};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

const OBJECT_CACHE_SCHEMA_VERSION: u32 = 1;
const DEFAULT_MAX_CACHE_BYTES: u64 = 50 * 1024 * 1024 * 1024; // 50 GiB
const DEFAULT_MIN_FREE_BYTES: u64 = 5 * 1024 * 1024 * 1024; // 5 GiB
const GUARD_BYTES: usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceObservation {
    pub repo: String,
    pub revision: String,
    pub path: String,
    pub lfs_oid: String,
    pub observed_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectMetadata {
    pub schema_version: u32,
    pub canonical_key: String,
    pub size: u64,
    pub file_identity: crate::hashcache::FileIdentity,
    pub guard_sha256: String,
    pub source_observations: Vec<SourceObservation>,
}

pub fn enabled() -> bool {
    match std::env::var("LAYERFAULT_OBJECT_CACHE") {
        Ok(val) => !matches!(
            val.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "off" | "no"
        ),
        Err(_) => true,
    }
}

pub fn strict_mode() -> bool {
    let mode_var = std::env::var("LAYERFAULT_OBJECT_CACHE")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let strict_var = std::env::var("LAYERFAULT_OBJECT_CACHE_STRICT")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    mode_var == "strict" || matches!(strict_var.as_str(), "1" | "true" | "yes")
}

pub fn max_cache_bytes() -> u64 {
    std::env::var("LAYERFAULT_OBJECT_CACHE_MAX_BYTES")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_MAX_CACHE_BYTES)
}

pub fn min_free_bytes() -> u64 {
    std::env::var("LAYERFAULT_OBJECT_CACHE_MIN_FREE_BYTES")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_MIN_FREE_BYTES)
}

pub fn parse_canonical_sha256(raw: &str) -> Result<(String, String)> {
    let raw_trimmed = raw.trim();
    let hex_part = if let Some(stripped) = raw_trimmed.strip_prefix("sha256:") {
        stripped
    } else if raw_trimmed.contains(':') {
        bail!("unsupported digest scheme in key '{raw_trimmed}'");
    } else {
        raw_trimmed
    };

    if hex_part.len() != 64 || !hex_part.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("digest '{raw_trimmed}' is not a valid 64-character hex SHA-256");
    }

    let hex_lower = hex_part.to_ascii_lowercase();
    Ok((format!("sha256:{hex_lower}"), hex_lower))
}

pub fn object_store_dir() -> Result<PathBuf> {
    Ok(cache_dir()?.join("objects"))
}

pub fn object_path(canonical_key: &str) -> Result<PathBuf> {
    let (_, hex) = parse_canonical_sha256(canonical_key)?;
    let prefix = &hex[..2];
    Ok(object_store_dir()?.join("sha256").join(prefix).join(&hex))
}

pub fn meta_path(canonical_key: &str) -> Result<PathBuf> {
    let (_, hex) = parse_canonical_sha256(canonical_key)?;
    let prefix = &hex[..2];
    Ok(object_store_dir()?
        .join("meta")
        .join("sha256")
        .join(prefix)
        .join(format!("{hex}.json")))
}

pub fn compute_guard_sha256(file: &File, size: u64) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(b"layerfault-object-guard-v1\0");
    hasher.update(size.to_le_bytes());

    let mut f = file;
    let head_len = GUARD_BYTES.min(size as usize);
    let mut head = vec![0_u8; head_len];
    f.seek(SeekFrom::Start(0))?;
    let head_read = f.read(&mut head)?;
    hasher.update(&head[..head_read]);

    let tail_start = size.saturating_sub(GUARD_BYTES as u64);
    let tail_len = (size - tail_start) as usize;
    let mut tail = vec![0_u8; tail_len];
    f.seek(SeekFrom::Start(tail_start))?;
    let tail_read = f.read(&mut tail)?;
    hasher.update(&tail[..tail_read]);

    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

pub fn compute_full_sha256(file: &File) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut f = file;
    f.seek(SeekFrom::Start(0))?;
    let mut buf = [0_u8; 64 * 1024];
    loop {
        let read = f.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

pub fn purge_object(canonical_key: &str) {
    if let Ok(obj_p) = object_path(canonical_key) {
        if obj_p.exists() {
            #[cfg(unix)]
            {
                let _ = fs::set_permissions(&obj_p, fs::Permissions::from_mode(0o600));
            }
            let _ = fs::remove_file(obj_p);
        }
    }
    if let Ok(meta_p) = meta_path(canonical_key) {
        if meta_p.exists() {
            #[cfg(unix)]
            {
                let _ = fs::set_permissions(&meta_p, fs::Permissions::from_mode(0o600));
            }
            let _ = fs::remove_file(meta_p);
        }
    }
}

pub fn lookup_and_stage(
    expected_sha256: &str,
    expected_size: u64,
    repo: &str,
    revision: &str,
    member_path: &str,
    destination: &Path,
) -> Result<Option<crate::hub::DownloadResult>> {
    if !enabled() {
        return Ok(None);
    }

    let (canonical_key, _) = match parse_canonical_sha256(expected_sha256) {
        Ok(res) => res,
        Err(_) => return Ok(None),
    };

    let obj_p = object_path(&canonical_key)?;
    let meta_p = meta_path(&canonical_key)?;

    if !obj_p.is_file() || !meta_p.is_file() {
        return Ok(None);
    }

    let file = match File::open(&obj_p) {
        Ok(f) => f,
        Err(_) => return Ok(None),
    };

    let meta_bytes = match fs::read(&meta_p) {
        Ok(b) => b,
        Err(_) => return Ok(None),
    };

    let mut metadata: ObjectMetadata = match serde_json::from_slice(&meta_bytes) {
        Ok(m) => m,
        Err(_) => {
            purge_object(&canonical_key);
            return Ok(None);
        }
    };

    if metadata.schema_version != OBJECT_CACHE_SCHEMA_VERSION
        || metadata.canonical_key != canonical_key
        || metadata.size != expected_size
    {
        purge_object(&canonical_key);
        return Ok(None);
    }

    let start_time = std::time::Instant::now();

    let identity_ok = crate::hashcache::identity_unchanged(&obj_p, &file, &metadata.file_identity)
        .unwrap_or(false);
    let guard_ok = compute_guard_sha256(&file, expected_size)
        .map(|g| g == metadata.guard_sha256)
        .unwrap_or(false);

    let require_full_hash = strict_mode() || !identity_ok || !guard_ok;

    if require_full_hash {
        let full_sha = compute_full_sha256(&file)?;
        if full_sha != canonical_key {
            purge_object(&canonical_key);
            return Ok(None);
        }
        if let Ok(new_ident) = crate::hashcache::capture_identity(&obj_p, &file) {
            metadata.file_identity = new_ident;
        }
    }

    let obs = SourceObservation {
        repo: repo.to_owned(),
        revision: revision.to_owned(),
        path: member_path.to_owned(),
        lfs_oid: canonical_key.clone(),
        observed_unix: now_unix(),
    };
    if !metadata.source_observations.contains(&obs) {
        metadata.source_observations.push(obs);
    }

    let _ = save_metadata(&meta_p, &metadata);

    stage_object(&obj_p, destination)?;

    let elapsed_ms = u64::try_from(start_time.elapsed().as_millis()).unwrap_or(u64::MAX);

    Ok(Some(crate::hub::DownloadResult {
        repo: repo.to_owned(),
        revision: revision.to_owned(),
        file: member_path.to_owned(),
        path: destination.display().to_string(),
        bytes: expected_size,
        sha256: canonical_key.clone(),
        elapsed_ms,
        expected_sha256: Some(canonical_key),
        expected_bytes: Some(expected_size),
        integrity_result: crate::hub::IntegrityResult::Match,
    }))
}

pub fn insert_verified_object(
    partial_path: &Path,
    expected_sha256: &str,
    expected_size: u64,
    repo: &str,
    revision: &str,
    member_path: &str,
    destination: &Path,
) -> Result<()> {
    if !enabled() {
        if destination.exists() {
            let _ = fs::remove_file(partial_path);
            bail!(
                "staging destination '{}' already exists",
                destination.display()
            );
        }
        fs::rename(partial_path, destination)?;
        return Ok(());
    }

    let (canonical_key, _) = parse_canonical_sha256(expected_sha256)?;
    let obj_p = object_path(&canonical_key)?;
    let meta_p = meta_path(&canonical_key)?;

    if let Some(parent) = obj_p.parent() {
        ensure_private_dir(parent)?;
    }
    if let Some(parent) = meta_p.parent() {
        ensure_private_dir(parent)?;
    }

    let inserted = if obj_p.is_file() {
        false
    } else {
        install_object_noclobber(partial_path, &obj_p)?
    };

    if inserted {
        #[cfg(unix)]
        {
            let _ = fs::set_permissions(&obj_p, fs::Permissions::from_mode(0o400));
        }

        let file = File::open(&obj_p)?;
        let file_identity = crate::hashcache::capture_identity(&obj_p, &file)?;
        let guard_sha256 = compute_guard_sha256(&file, expected_size)?;

        let metadata = ObjectMetadata {
            schema_version: OBJECT_CACHE_SCHEMA_VERSION,
            canonical_key: canonical_key.clone(),
            size: expected_size,
            file_identity,
            guard_sha256,
            source_observations: vec![SourceObservation {
                repo: repo.to_owned(),
                revision: revision.to_owned(),
                path: member_path.to_owned(),
                lfs_oid: canonical_key.clone(),
                observed_unix: now_unix(),
            }],
        };

        save_metadata(&meta_p, &metadata)?;
    } else if let Ok(meta_bytes) = fs::read(&meta_p) {
        if let Ok(mut metadata) = serde_json::from_slice::<ObjectMetadata>(&meta_bytes) {
            let obs = SourceObservation {
                repo: repo.to_owned(),
                revision: revision.to_owned(),
                path: member_path.to_owned(),
                lfs_oid: canonical_key.clone(),
                observed_unix: now_unix(),
            };
            if !metadata.source_observations.contains(&obs) {
                metadata.source_observations.push(obs);
                let _ = save_metadata(&meta_p, &metadata);
            }
        }
    }

    if destination.exists() {
        let _ = fs::remove_file(partial_path);
        bail!(
            "staging destination '{}' already exists",
            destination.display()
        );
    }

    if let Err(err) = fs::rename(partial_path, destination) {
        fs::copy(partial_path, destination).map_err(|_| err)?;
        let _ = fs::remove_file(partial_path);
    }

    #[cfg(unix)]
    {
        let _ = fs::set_permissions(destination, fs::Permissions::from_mode(0o600));
    }

    let _ = gc::run();

    Ok(())
}

fn install_object_noclobber(source: &Path, destination: &Path) -> Result<bool> {
    let parent = destination.parent().with_context(|| {
        format!(
            "object cache destination '{}' has no parent directory",
            destination.display()
        )
    })?;
    let staged = tempfile::NamedTempFile::new_in(parent).with_context(|| {
        format!(
            "unable to create temporary object beside '{}'",
            destination.display()
        )
    })?;
    fs::copy(source, staged.path()).with_context(|| {
        format!(
            "unable to copy verified object into temporary cache file beside '{}'",
            destination.display()
        )
    })?;
    staged.as_file().sync_all().with_context(|| {
        format!(
            "unable to sync temporary object beside '{}'",
            destination.display()
        )
    })?;

    match staged.persist_noclobber(destination) {
        Ok(_) => Ok(true),
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(error.error).with_context(|| {
            format!(
                "unable to atomically install object in cache '{}'",
                destination.display()
            )
        }),
    }
}

fn save_metadata(path: &Path, metadata: &ObjectMetadata) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(metadata)?;
    write_private(path, &bytes)?;
    #[cfg(unix)]
    {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o440));
    }
    Ok(())
}

fn stage_object(obj_path: &Path, destination: &Path) -> Result<()> {
    if destination.exists() {
        bail!(
            "staging destination '{}' already exists",
            destination.display()
        );
    }
    if let Some(parent) = destination.parent() {
        ensure_private_dir(parent)?;
    }
    fs::copy(obj_path, destination).with_context(|| {
        format!(
            "unable to stage cached object to '{}'",
            destination.display()
        )
    })?;

    #[cfg(unix)]
    {
        let _ = fs::set_permissions(destination, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

pub mod gc {
    use super::*;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct GcCandidate {
        pub canonical_key: String,
        pub obj_path: PathBuf,
        pub meta_path: PathBuf,
        pub size: u64,
        pub last_accessed_unix: u64,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct GcPlan {
        pub total_entries: usize,
        pub total_bytes: u64,
        pub free_disk_bytes: u64,
        pub candidates: Vec<GcCandidate>,
        pub bytes_to_reclaim: u64,
        pub stale_part_files: Vec<PathBuf>,
    }

    pub fn plan() -> Result<GcPlan> {
        let root = object_store_dir()?;
        let mut entries = Vec::new();
        let mut total_bytes = 0_u64;

        let obj_base = root.join("sha256");
        let meta_base = root.join("meta").join("sha256");

        if obj_base.is_dir() {
            for entry in walkdir::WalkDir::new(&obj_base).min_depth(2).max_depth(2) {
                let entry = match entry {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                if !entry.file_type().is_file() {
                    continue;
                }
                let obj_p = entry.path().to_path_buf();
                let hex_name = match obj_p.file_name().and_then(|n| n.to_str()) {
                    Some(name) => name.to_string(),
                    None => continue,
                };
                if hex_name.len() != 64 {
                    continue;
                }
                let canonical_key = format!("sha256:{hex_name}");
                let prefix = &hex_name[..2];
                let meta_p = meta_base.join(prefix).join(format!("{hex_name}.json"));

                let object_size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                total_bytes += object_size;

                let last_accessed = get_last_accessed(&obj_p, &meta_p);

                entries.push(GcCandidate {
                    canonical_key,
                    obj_path: obj_p,
                    meta_path: meta_p,
                    size: object_size,
                    last_accessed_unix: last_accessed,
                });
            }
        }

        entries.sort_by_key(|c| c.last_accessed_unix);

        let mut stale_parts = Vec::new();
        if let Ok(base_cache) = cache_dir() {
            let cutoff = now_unix().saturating_sub(24 * 3600);
            if base_cache.is_dir() {
                for e in walkdir::WalkDir::new(&base_cache).into_iter().flatten() {
                    if e.file_type().is_file() {
                        if let Some(name) = e.file_name().to_str() {
                            if name.ends_with(".layerfault-part") {
                                let mtime = e.metadata().ok().and_then(|m| m.modified().ok());
                                let secs = mtime
                                    .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
                                    .map(|d| d.as_secs())
                                    .unwrap_or(0);
                                if secs < cutoff {
                                    stale_parts.push(e.path().to_path_buf());
                                }
                            }
                        }
                    }
                }
            }
        }

        let free_disk = free_disk_space(&root).unwrap_or(u64::MAX);
        let max_bytes = max_cache_bytes();
        let min_free = min_free_bytes();

        let mut bytes_to_reclaim = 0_u64;
        if total_bytes > max_bytes {
            bytes_to_reclaim = bytes_to_reclaim.max(total_bytes - max_bytes);
        }
        if free_disk < min_free {
            let disk_deficit = min_free - free_disk;
            bytes_to_reclaim = bytes_to_reclaim.max(disk_deficit);
        }

        let mut candidates = Vec::new();
        let mut reclaimed_acc = 0_u64;

        if bytes_to_reclaim > 0 {
            for entry in entries.iter() {
                if reclaimed_acc >= bytes_to_reclaim {
                    break;
                }
                candidates.push(entry.clone());
                reclaimed_acc += entry.size;
            }
        }

        Ok(GcPlan {
            total_entries: entries.len(),
            total_bytes,
            free_disk_bytes: free_disk,
            candidates,
            bytes_to_reclaim,
            stale_part_files: stale_parts,
        })
    }

    pub fn execute(plan: &GcPlan) -> Result<u64> {
        let mut freed = 0_u64;
        for c in &plan.candidates {
            if c.obj_path.exists() {
                #[cfg(unix)]
                {
                    let _ = fs::set_permissions(&c.obj_path, fs::Permissions::from_mode(0o600));
                }
                let _ = fs::remove_file(&c.obj_path);
            }
            if c.meta_path.exists() {
                #[cfg(unix)]
                {
                    let _ = fs::set_permissions(&c.meta_path, fs::Permissions::from_mode(0o600));
                }
                let _ = fs::remove_file(&c.meta_path);
            }
            freed += c.size;
        }
        for part in &plan.stale_part_files {
            if part.exists() {
                let _ = fs::remove_file(part);
            }
        }
        Ok(freed)
    }

    pub fn run() -> Result<u64> {
        let plan = plan()?;
        if !plan.candidates.is_empty() || !plan.stale_part_files.is_empty() {
            execute(&plan)
        } else {
            Ok(0)
        }
    }
}

fn get_last_accessed(obj_p: &Path, meta_p: &Path) -> u64 {
    let m1 = fs::metadata(obj_p)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let m2 = fs::metadata(meta_p)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    // Metadata is rewritten whenever a new source observation is recorded, so
    // its mtime already captures that activity with filesystem precision. The
    // embedded observation timestamp is only second-resolution; mixing it into
    // this value makes rapid inserts tie and leaves eviction order dependent on
    // directory traversal order.
    m1.max(m2)
}

pub fn free_disk_space(path: &Path) -> Result<u64> {
    #[cfg(unix)]
    {
        let target = if path.exists() {
            path.to_path_buf()
        } else if let Ok(c) = cache_dir() {
            c
        } else {
            PathBuf::from(".")
        };
        let stat = rustix::fs::statvfs(&target)?;
        Ok((stat.f_bavail as u64).saturating_mul(stat.f_frsize as u64))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(u64::MAX)
    }
}
