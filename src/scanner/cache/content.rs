//! Content-addressed cache for expensive, content-intrinsic scan evidence.
//!
//! Unlike [`crate::scanner::cache::identity`] (keyed by file *identity*: canonical path plus
//! inode/mtime, so a hit only ever short-circuits a re-scan of the exact same
//! file in place), this cache is keyed by the artifact's verified content
//! SHA-256. Identical bytes hit regardless of the path, package, source or
//! revision they were discovered under.
//!
//! Security boundary: this module must only ever store *content-intrinsic*
//! evidence — facts derivable purely from the bytes themselves under a fixed
//! scanner/ruleset revision (structural parser output, pickle opcode/global
//! analysis, embedded executable discovery, Python AST facts). It must never
//! store *contextual* evidence (package-relative path meaning, auto_map
//! relationships, cross-file correlation, package fingerprints, provenance,
//! trust or policy outcomes) — callers are responsible for keeping those out
//! of the values they pass to [`store`], and this module additionally strips
//! path-shaped fields via [`normalize_for_cache`] for the one caller
//! (structural artifact findings) that needs it.
//!
//! A cache hit here can therefore never become a stale PASS/BLOCK: policy,
//! decision and correlation always run afresh, downstream, over whatever
//! finding list is in hand, whether freshly parsed or replayed from here.

use crate::finding_evidence::FindingEvidence;
use crate::scanner::LayerScanResult;
use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

const CONTENT_CACHE_SCHEMA_VERSION: u32 = 1;
const CONTENT_CACHE_REVISION: &str = env!("LAYERFAULT_SCANNER_REVISION");
/// Well below hashcache's 4/16 MiB thresholds — structural/AST parsing is
/// worth reusing even for modest files — but high enough that hand-written
/// test fixtures (typically well under 1 KiB) never trigger a real write,
/// so `cargo test` cannot leak cache entries into a developer's actual
/// `$HOME`/`$XDG_CACHE_HOME` without an explicit `LAYERFAULT_CACHE_DIR`
/// override. Tests that need to exercise small-content caching set
/// `LAYERFAULT_CONTENT_CACHE_MIN_BYTES=0` explicitly inside an isolated
/// temporary cache directory.
const DEFAULT_MIN_CACHE_BYTES: u64 = 64 * 1024;
const MAX_RECORD_BYTES: u64 = 16 * 1024 * 1024;

/// Whether the content cache is enabled at all. Independent of
/// [`crate::scanner::cache::identity::enabled`] — the two caches have different key
/// schemes and operators may want to control them separately.
pub fn enabled() -> bool {
    match std::env::var("LAYERFAULT_CONTENT_CACHE") {
        Ok(value) => !matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "off" | "no" | "strict"
        ),
        Err(_) => true,
    }
}

/// Whether a piece of content is large/expensive enough to bother caching.
/// Defaults to zero: unlike raw hashing, structural/AST parsing is often
/// worth reusing even for small files.
pub fn eligible(size: u64) -> bool {
    enabled() && size >= min_cache_bytes()
}

fn min_cache_bytes() -> u64 {
    std::env::var("LAYERFAULT_CONTENT_CACHE_MIN_BYTES")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_MIN_CACHE_BYTES)
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ContentCachePolicy {
    pub enabled: bool,
    pub min_bytes: u64,
    pub scanner_revision: &'static str,
    pub ruleset_sha256: String,
}

pub fn cache_policy() -> ContentCachePolicy {
    ContentCachePolicy {
        enabled: enabled(),
        min_bytes: min_cache_bytes(),
        scanner_revision: CONTENT_CACHE_REVISION,
        ruleset_sha256: crate::explain::ruleset_sha256().to_owned(),
    }
}

/// The versioned, deterministic identity of a cached content-evidence entry.
///
/// Intentionally excludes path: content identity must never be inferred from
/// or contaminated by where the bytes were found.
struct ContentCacheKey<'a> {
    content_sha256: &'a str,
    size: u64,
    scanner_revision: &'static str,
    ruleset_sha256: &'a str,
    parser_discriminator: &'a str,
    schema_version: u32,
}

impl ContentCacheKey<'_> {
    fn digest_hex(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"layerfault-content-cache-key\0");
        hasher.update(self.content_sha256.as_bytes());
        hasher.update([0]);
        hasher.update(self.size.to_le_bytes());
        hasher.update([0]);
        hasher.update(self.scanner_revision.as_bytes());
        hasher.update([0]);
        hasher.update(self.ruleset_sha256.as_bytes());
        hasher.update([0]);
        hasher.update(self.parser_discriminator.as_bytes());
        hasher.update([0]);
        hasher.update(self.schema_version.to_le_bytes());
        hex::encode(hasher.finalize())
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct ContentEvidenceRecord<T> {
    schema_version: u32,
    key_digest: String,
    content_sha256: String,
    size: u64,
    scanner_revision: String,
    ruleset_sha256: String,
    parser_discriminator: String,
    value: T,
}

/// Look up a previously cached content-intrinsic value.
///
/// `content_sha256` must already be an exactly-verified content digest
/// (e.g. from [`crate::scanner::cache::identity::sha256_prefixed`] or a
/// [`crate::scanner::ScanSession`] run) — this function never computes or
/// re-derives it, and never infers content identity from size/mtime/path.
///
/// Any I/O error, deserialization failure, or self-validation mismatch
/// (schema version, key digest, content sha256, size, scanner revision,
/// ruleset, or discriminator) is treated as a plain cache miss: corrupt or
/// stale cache data is an operational cache failure, never an artifact
/// security failure, and must never be surfaced as an error.
pub fn lookup<T>(content_sha256: &str, size: u64, parser_discriminator: &str) -> Result<Option<T>>
where
    T: DeserializeOwned,
{
    if !eligible(size) {
        return Ok(None);
    }
    let ruleset_sha256 = crate::explain::ruleset_sha256();
    let key = ContentCacheKey {
        content_sha256,
        size,
        scanner_revision: CONTENT_CACHE_REVISION,
        ruleset_sha256,
        parser_discriminator,
        schema_version: CONTENT_CACHE_SCHEMA_VERSION,
    };
    let key_digest = key.digest_hex();
    let path = record_path(&key_digest)?;
    let Some(record) = read_record::<ContentEvidenceRecord<T>>(&path)? else {
        crate::perf_metrics::record_cache_miss();
        return Ok(None);
    };
    let valid = record.schema_version == CONTENT_CACHE_SCHEMA_VERSION
        && record.key_digest == key_digest
        && record.content_sha256 == content_sha256
        && record.size == size
        && record.scanner_revision == CONTENT_CACHE_REVISION
        && record.ruleset_sha256 == ruleset_sha256
        && record.parser_discriminator == parser_discriminator;
    if !valid {
        crate::perf_metrics::record_cache_miss();
        return Ok(None);
    }
    crate::perf_metrics::record_cache_hit();
    Ok(Some(record.value))
}

/// Store a content-intrinsic value under the given content identity and
/// scanner semantics. Best-effort: failures to write are swallowed by
/// callers (the cache is a performance mechanism, never load-bearing), but
/// this function itself still reports write errors so a caller can decide
/// whether to log them.
pub fn store<T>(
    content_sha256: &str,
    size: u64,
    parser_discriminator: &str,
    value: &T,
) -> Result<()>
where
    T: Serialize,
{
    if !eligible(size) {
        return Ok(());
    }
    let ruleset_sha256 = crate::explain::ruleset_sha256().to_owned();
    let key = ContentCacheKey {
        content_sha256,
        size,
        scanner_revision: CONTENT_CACHE_REVISION,
        ruleset_sha256: &ruleset_sha256,
        parser_discriminator,
        schema_version: CONTENT_CACHE_SCHEMA_VERSION,
    };
    let key_digest = key.digest_hex();
    let record = ContentEvidenceRecord {
        schema_version: CONTENT_CACHE_SCHEMA_VERSION,
        key_digest: key_digest.clone(),
        content_sha256: content_sha256.to_owned(),
        size,
        scanner_revision: CONTENT_CACHE_REVISION.to_owned(),
        ruleset_sha256,
        parser_discriminator: parser_discriminator.to_owned(),
        value,
    };
    let path = record_path(&key_digest)?;
    let bytes = serde_json::to_vec(&record).context("Unable to serialize content cache record")?;
    crate::paths::write_private_noclobber(&path, &bytes)?;
    maybe_sample_gc();
    Ok(())
}

/// Root directory for the content-evidence store:
/// `<cache_dir>/content-evidence/v1/sha256`.
fn cache_root() -> Result<PathBuf> {
    Ok(crate::paths::cache_dir()?
        .join("content-evidence")
        .join("v1")
        .join("sha256"))
}

fn record_path(key_digest: &str) -> Result<PathBuf> {
    let shard = &key_digest[..key_digest.len().min(2)];
    Ok(cache_root()?.join(shard).join(format!("{key_digest}.json")))
}

fn read_record<T>(path: &std::path::Path) -> Result<Option<T>>
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

/// Strip contextual, path-shaped fields from findings before they enter the
/// content cache. `path` and `package_relative_path` are always contextual
/// (the same bytes can legitimately live at any path/package member) and
/// must never be replayed verbatim across a cache hit at a different path.
pub fn normalize_for_cache(results: &[LayerScanResult]) -> Vec<LayerScanResult> {
    results
        .iter()
        .cloned()
        .map(|mut result| {
            if let Some(subject) = result.subject.as_mut() {
                subject.path = None;
                subject.package_relative_path = None;
            }
            for evidence in &mut result.evidence {
                evidence.subject.path = None;
                evidence.subject.package_relative_path = None;
            }
            result
        })
        .collect()
}

/// Re-attach the current call's path to findings replayed from the content
/// cache. Only fills in subjects that plausibly identified a filesystem
/// member (i.e. those that had a path stripped by [`normalize_for_cache`]
/// upstream); subjects that never carried path information (pure
/// `EvidenceSubject::identity(...)` subjects) are left untouched.
pub fn rehydrate_path(results: &mut [LayerScanResult], path: &str) {
    for result in results.iter_mut() {
        if let Some(subject) = result.subject.as_mut() {
            if subject.identity.is_none() {
                subject.path = Some(path.to_owned());
            }
        }
        for evidence in &mut result.evidence {
            if evidence.subject.identity.is_none() {
                evidence.subject.path = Some(path.to_owned());
            }
        }
    }
}

#[allow(dead_code)]
fn evidence_touches_path(evidence: &FindingEvidence) -> bool {
    evidence.subject.path.is_some()
}

fn maybe_sample_gc() {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    if !count.is_multiple_of(256) {
        return;
    }
    if let Err(error) = gc::maybe_run_sampled() {
        // GC is a best-effort housekeeping pass; never let it fail a scan. The
        // failure is emitted at `Info` (silent by default; visible under
        // `LAYERFAULT_LOG=info`) so a failing sweep stops being invisible
        // without adding noise to the default scan output.
        crate::diagnostics::emit(
            crate::diagnostics::Level::Info,
            "cache_io",
            &format!("background gc sweep skipped: {error:#}"),
        );
    }
}

pub mod gc {
    //! Bounded size/entry-count housekeeping for the content-evidence store.
    //!
    //! Eviction is LRU-by-mtime. Lookups never write (no touch-on-read), so
    //! access-time bookkeeping is unnecessary and would otherwise defeat the
    //! purpose of avoiding write amplification.

    use super::cache_root;
    use anyhow::{Context, Result};
    use std::path::PathBuf;
    use std::time::SystemTime;

    const DEFAULT_MAX_BYTES: u64 = 512 * 1024 * 1024;
    const DEFAULT_MAX_ENTRIES: u64 = 50_000;
    /// Only trigger a sampled GC pass once usage clears this margin above the
    /// configured bound, to avoid oscillating around the exact limit.
    const SAMPLE_TRIGGER_MARGIN_NUM: u64 = 11;
    const SAMPLE_TRIGGER_MARGIN_DEN: u64 = 10;

    fn max_bytes() -> u64 {
        std::env::var("LAYERFAULT_CONTENT_CACHE_MAX_BYTES")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(DEFAULT_MAX_BYTES)
    }

    fn max_entries() -> u64 {
        std::env::var("LAYERFAULT_CONTENT_CACHE_MAX_ENTRIES")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(DEFAULT_MAX_ENTRIES)
    }

    struct Entry {
        path: PathBuf,
        size: u64,
        modified: SystemTime,
    }

    pub struct ContentCacheGcPlan {
        pub total_entries: u64,
        pub total_bytes: u64,
        pub evict: Vec<PathBuf>,
        pub bytes_reclaimed: u64,
    }

    /// Enumerate the flat two-level shard tree and decide which records to
    /// evict, oldest-`mtime`-first, until both bounds are satisfied. Stat-only
    /// (no JSON parsing) to keep the walk cheap.
    pub fn plan() -> Result<ContentCacheGcPlan> {
        let root = cache_root()?;
        let mut entries = Vec::new();
        if root.is_dir() {
            for shard in std::fs::read_dir(&root)
                .with_context(|| format!("Unable to list '{}'", root.display()))?
                .filter_map(Result::ok)
            {
                let shard_path = shard.path();
                if !shard_path.is_dir() {
                    continue;
                }
                let Ok(files) = std::fs::read_dir(&shard_path) else {
                    continue;
                };
                for file in files.filter_map(Result::ok) {
                    let path = file.path();
                    let Ok(metadata) = file.metadata() else {
                        continue;
                    };
                    if !metadata.is_file() {
                        continue;
                    }
                    let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                    entries.push(Entry {
                        path,
                        size: metadata.len(),
                        modified,
                    });
                }
            }
        }

        let total_entries = entries.len() as u64;
        let total_bytes: u64 = entries.iter().map(|entry| entry.size).sum();

        entries.sort_by_key(|entry| entry.modified);

        let bytes_cap = max_bytes();
        let entries_cap = max_entries();
        let mut remaining_bytes = total_bytes;
        let mut remaining_entries = total_entries;
        let mut evict = Vec::new();
        let mut bytes_reclaimed = 0_u64;

        for entry in entries {
            if remaining_bytes <= bytes_cap && remaining_entries <= entries_cap {
                break;
            }
            remaining_bytes = remaining_bytes.saturating_sub(entry.size);
            remaining_entries = remaining_entries.saturating_sub(1);
            bytes_reclaimed += entry.size;
            evict.push(entry.path);
        }

        Ok(ContentCacheGcPlan {
            total_entries,
            total_bytes,
            evict,
            bytes_reclaimed,
        })
    }

    /// Execute a plan produced by [`plan`]. Re-verifies each candidate's
    /// parent directory is exactly the expected shard root immediately
    /// before unlinking (defence in depth against an unexpected path making
    /// it into a plan), and tolerates concurrent removal (a file already
    /// gone is not an error — another process's GC pass may have won the
    /// race).
    pub fn execute(plan: &ContentCacheGcPlan) -> Result<u64> {
        let root = cache_root()?;
        let mut removed = 0_u64;
        for path in &plan.evict {
            let Some(parent) = path.parent() else {
                continue;
            };
            let Some(parent_name) = parent.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            if parent.parent() != Some(root.as_path()) || parent_name.len() != 2 {
                continue;
            }
            match std::fs::remove_file(path) {
                Ok(()) => removed += 1,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("Unable to remove content cache entry"),
            }
        }
        Ok(removed)
    }

    /// Cheap sampled trigger invoked from a small fraction of writes: only
    /// pays the cost of a full directory walk when usage plausibly exceeds
    /// the configured bound by a safety margin.
    pub fn maybe_run_sampled() -> Result<()> {
        let quick = plan()?;
        let over_bytes = quick.total_bytes.saturating_mul(SAMPLE_TRIGGER_MARGIN_DEN)
            > max_bytes().saturating_mul(SAMPLE_TRIGGER_MARGIN_NUM);
        let over_entries = quick
            .total_entries
            .saturating_mul(SAMPLE_TRIGGER_MARGIN_DEN)
            > max_entries().saturating_mul(SAMPLE_TRIGGER_MARGIN_NUM);
        if !over_bytes && !over_entries {
            return Ok(());
        }
        execute(&quick)?;
        Ok(())
    }
}

/// Shared across every `#[cfg(test)]` module in this crate (not just this
/// one) that mutates `LAYERFAULT_CACHE_DIR`/`LAYERFAULT_CONTENT_CACHE*`: env
/// vars are process-global, and `cargo test` runs all tests within one
/// binary as concurrent threads of the same process, so two independent
/// per-module `Mutex`es would not actually exclude each other.
#[cfg(test)]
pub(crate) static ENV_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding_evidence::{EvidenceState, EvidenceSubject};
    use crate::scanner::{CheckType, Confidence, FindingClass, ScanStatus};

    use super::ENV_TEST_LOCK as ENV_LOCK;

    fn test_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "layerfault-content-cache-{name}-{}-{}",
            std::process::id(),
            crate::paths::now_unix()
        ))
    }

    struct EnvGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        root: PathBuf,
    }

    impl EnvGuard {
        fn new(name: &str) -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
            let root = test_root(name);
            std::fs::create_dir_all(&root).expect("create cache root");
            std::env::set_var("LAYERFAULT_CACHE_DIR", &root);
            std::env::set_var("LAYERFAULT_CONTENT_CACHE", "on");
            // Tests use tiny synthetic fixtures; opt back into caching them
            // within this isolated temp directory only (production default
            // is a nonzero floor precisely so real cache dirs aren't
            // polluted by incidental small-file activity).
            std::env::set_var("LAYERFAULT_CONTENT_CACHE_MIN_BYTES", "0");
            Self { _lock: lock, root }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            std::env::remove_var("LAYERFAULT_CACHE_DIR");
            std::env::remove_var("LAYERFAULT_CONTENT_CACHE");
            std::env::remove_var("LAYERFAULT_CONTENT_CACHE_MIN_BYTES");
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn sample_result(subject_path: Option<&str>) -> LayerScanResult {
        let mut subject = EvidenceSubject::identity("sha256:deadbeef", "application/x-gguf");
        subject.path = subject_path.map(|value| value.to_owned());
        LayerScanResult {
            layer_digest: "sha256:deadbeef".to_owned(),
            media_type: "application/x-gguf".to_owned(),
            check_type: CheckType::GGUFMetadata,
            status: ScanStatus::Pass,
            finding_class: FindingClass::Structural,
            confidence: Confidence::High,
            detail: Some("structural facts".to_owned()),
            matches: vec![],
            duration_ms: 0,
            rule_id: Some("LF-TEST".to_owned()),
            subject: Some(subject),
            evidence: vec![],
            evidence_state: Some(EvidenceState::Available),
            evidence_reason: None,
            finding_id: None,
        }
    }

    #[test]
    fn identical_bytes_same_path_hits() {
        let _guard = EnvGuard::new("same-path");
        let results = vec![sample_result(None)];
        store("sha256:aaaa", 1024, "artifact:gguf:full", &results).expect("store");
        let hit = lookup::<Vec<LayerScanResult>>("sha256:aaaa", 1024, "artifact:gguf:full")
            .expect("lookup")
            .expect("hit");
        assert_eq!(hit.len(), 1);
        assert_eq!(hit[0].rule_id.as_deref(), Some("LF-TEST"));
    }

    #[test]
    fn identical_bytes_different_path_hits_and_rehydrates_path() {
        let _guard = EnvGuard::new("diff-path");
        let mut member_subject = EvidenceSubject::member("weights.bin");
        member_subject.path = Some("/scan/path-a/weights.bin".to_owned());
        let mut result = sample_result(None);
        result.subject = Some(member_subject);
        let normalized = normalize_for_cache(std::slice::from_ref(&result));
        assert!(normalized[0].subject.as_ref().unwrap().path.is_none());

        store("sha256:bbbb", 2048, "artifact:pickle:full", &normalized).expect("store");
        let mut hit = lookup::<Vec<LayerScanResult>>("sha256:bbbb", 2048, "artifact:pickle:full")
            .expect("lookup")
            .expect("hit");
        rehydrate_path(&mut hit, "/scan/path-b/weights.bin");
        assert_eq!(
            hit[0].subject.as_ref().unwrap().path.as_deref(),
            Some("/scan/path-b/weights.bin")
        );
    }

    #[test]
    fn scanner_revision_change_is_miss() {
        let _guard = EnvGuard::new("revision-miss");
        let results = vec![sample_result(None)];
        store("sha256:cccc", 4096, "artifact:onnx:full", &results).expect("store");

        let key = ContentCacheKey {
            content_sha256: "sha256:cccc",
            size: 4096,
            scanner_revision: CONTENT_CACHE_REVISION,
            ruleset_sha256: crate::explain::ruleset_sha256(),
            parser_discriminator: "artifact:onnx:full",
            schema_version: CONTENT_CACHE_SCHEMA_VERSION,
        };
        let path = record_path(&key.digest_hex()).unwrap();
        let mut record: ContentEvidenceRecord<Vec<LayerScanResult>> =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        record.scanner_revision = "sha256:stale-revision".to_owned();
        std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();

        let hit = lookup::<Vec<LayerScanResult>>("sha256:cccc", 4096, "artifact:onnx:full")
            .expect("lookup should not error on stale revision");
        assert!(hit.is_none());
    }

    #[test]
    fn scan_mode_change_is_separate_record() {
        let _guard = EnvGuard::new("mode-separate");
        let full = vec![sample_result(None)];
        store("sha256:dddd", 8192, "artifact:gguf:full", &full).expect("store full");
        let structure_hit =
            lookup::<Vec<LayerScanResult>>("sha256:dddd", 8192, "artifact:gguf:structure")
                .expect("lookup");
        assert!(structure_hit.is_none());
        let full_hit = lookup::<Vec<LayerScanResult>>("sha256:dddd", 8192, "artifact:gguf:full")
            .expect("lookup")
            .expect("full mode still hits");
        assert_eq!(full_hit.len(), 1);
    }

    #[test]
    fn corrupt_json_is_rebuilt_not_failed() {
        let _guard = EnvGuard::new("corrupt");
        let key = ContentCacheKey {
            content_sha256: "sha256:eeee",
            size: 128,
            scanner_revision: CONTENT_CACHE_REVISION,
            ruleset_sha256: crate::explain::ruleset_sha256(),
            parser_discriminator: "artifact:pickle:full",
            schema_version: CONTENT_CACHE_SCHEMA_VERSION,
        };
        let path = record_path(&key.digest_hex()).unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"{ not valid json").unwrap();

        let hit = lookup::<Vec<LayerScanResult>>("sha256:eeee", 128, "artifact:pickle:full")
            .expect("corrupt record must be treated as a miss, not an error");
        assert!(hit.is_none());

        let results = vec![sample_result(None)];
        store("sha256:eeee", 128, "artifact:pickle:full", &results).expect("store after corrupt");
        let rebuilt = lookup::<Vec<LayerScanResult>>("sha256:eeee", 128, "artifact:pickle:full")
            .expect("lookup")
            .expect("rebuilt record hits");
        assert_eq!(rebuilt.len(), 1);
    }

    #[test]
    fn cache_disabled_forces_fresh_analysis() {
        let _guard = EnvGuard::new("disabled");
        std::env::set_var("LAYERFAULT_CONTENT_CACHE", "off");
        let results = vec![sample_result(None)];
        store("sha256:ffff", 256, "artifact:gguf:full", &results).expect("store no-op");
        let hit = lookup::<Vec<LayerScanResult>>("sha256:ffff", 256, "artifact:gguf:full")
            .expect("lookup");
        assert!(hit.is_none());

        let key = ContentCacheKey {
            content_sha256: "sha256:ffff",
            size: 256,
            scanner_revision: CONTENT_CACHE_REVISION,
            ruleset_sha256: crate::explain::ruleset_sha256(),
            parser_discriminator: "artifact:gguf:full",
            schema_version: CONTENT_CACHE_SCHEMA_VERSION,
        };
        let path = record_path(&key.digest_hex()).unwrap();
        assert!(!path.exists(), "disabled cache must not write a record");
    }

    #[test]
    fn contextual_fields_never_present_in_intrinsic_record() {
        let _guard = EnvGuard::new("no-context");
        let mut member_subject = EvidenceSubject::member("weights.bin");
        member_subject.path = Some("/scan/somewhere/weights.bin".to_owned());
        let mut result = sample_result(None);
        result.subject = Some(member_subject);
        let normalized = normalize_for_cache(std::slice::from_ref(&result));
        assert!(normalized[0].subject.as_ref().unwrap().path.is_none());
        assert!(normalized[0]
            .subject
            .as_ref()
            .unwrap()
            .package_relative_path
            .is_none());

        store("sha256:0101", 512, "artifact:gguf:full", &normalized).expect("store");
        let key = ContentCacheKey {
            content_sha256: "sha256:0101",
            size: 512,
            scanner_revision: CONTENT_CACHE_REVISION,
            ruleset_sha256: crate::explain::ruleset_sha256(),
            parser_discriminator: "artifact:gguf:full",
            schema_version: CONTENT_CACHE_SCHEMA_VERSION,
        };
        let path = record_path(&key.digest_hex()).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("/scan/somewhere/weights.bin"));
        assert!(!raw.contains("package_relative_path"));
        for marker in [
            "policy_outcome",
            "trust_level",
            "provenance",
            "package_fingerprint",
            "\"path\":",
        ] {
            assert!(
                !raw.contains(marker),
                "unexpected contextual marker '{marker}' in cached record"
            );
        }
    }

    #[test]
    fn concurrent_writers_produce_valid_record() {
        let _guard = EnvGuard::new("concurrent");
        let handles: Vec<_> = (0..8)
            .map(|i| {
                std::thread::spawn(move || {
                    let results = vec![sample_result(None)];
                    store(
                        "sha256:concurrent",
                        999,
                        "artifact:safetensors:full",
                        &results,
                    )
                    .unwrap_or_else(|error| panic!("writer {i} failed: {error}"));
                })
            })
            .collect();
        for handle in handles {
            handle.join().expect("writer thread panicked");
        }
        let hit =
            lookup::<Vec<LayerScanResult>>("sha256:concurrent", 999, "artifact:safetensors:full")
                .expect("lookup")
                .expect("some writer's record must be present and valid");
        assert_eq!(hit.len(), 1);
    }

    #[test]
    fn gc_evicts_oldest_entries_beyond_bound() {
        let _guard = EnvGuard::new("gc-bound");
        for i in 0..20 {
            let results = vec![sample_result(None)];
            store(
                &format!("sha256:gc{i:04}"),
                64,
                "artifact:gguf:full",
                &results,
            )
            .expect("store");
            // Ensure distinct mtimes so oldest-first ordering is deterministic.
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        std::env::set_var("LAYERFAULT_CONTENT_CACHE_MAX_ENTRIES", "5");
        let plan = gc::plan().expect("plan");
        assert!(plan.evict.len() >= 15);
        let removed = gc::execute(&plan).expect("execute");
        assert_eq!(removed as usize, plan.evict.len());
        let after = gc::plan().expect("plan after gc");
        assert!(after.total_entries <= 5);
        std::env::remove_var("LAYERFAULT_CONTENT_CACHE_MAX_ENTRIES");
    }
}
