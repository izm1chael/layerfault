//! Append-only trust event journal.
//!
//! Each line is a [`JournalRecord`]: a `TrustEvent` plus a monotonic
//! `sequence` number and a SHA-256 `record_hash` binding it to the sequence
//! and to the previous record's hash. This hash chain detects alteration or
//! removal of any record *before* the tail of the journal — a record whose
//! predecessor was tampered with will no longer verify.
//!
//! **What the hash chain does not do**: detect truncation of the tail.
//! Deleting the final N records leaves a perfectly valid, shorter chain —
//! every remaining `previous_record_hash` still matches. [`write_head_anchor`]
//! / [`verify_head_anchor`] address that by recording the last record's
//! sequence and hash in a location separate from the journal file itself, so
//! a comparison against that anchor can detect a shortened journal. This is
//! *not* a cryptographic signature — Layerfault holds no private signing key
//! anywhere in this codebase, and claiming one here would overstate the
//! guarantee. The anchor only detects truncation if it is itself protected
//! from being deleted or overwritten by whatever could truncate the journal
//! (different permissions, a different volume, an external record) —
//! Layerfault provides the mechanism, not that protection.

use super::TrustEvent;
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_EVENTS: usize = 100_000;
const LOCK_TIMEOUT: Duration = Duration::from_secs(60);
const STALE_LOCK_AGE: Duration = Duration::from_secs(5 * 60);

/// One journal line: a trust event plus the chain metadata that binds it to
/// its position and predecessor. See the module documentation for exactly
/// what this chain does and does not prove.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalRecord {
    /// 0-based, strictly increasing within one journal file.
    pub sequence: u64,
    /// `record_hash` of the previous record. `None` only when `sequence == 0`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_record_hash: Option<String>,
    /// SHA-256 binding `sequence`, `previous_record_hash` and `event`
    /// together, computed by [`record_hash`].
    pub record_hash: String,
    pub event: TrustEvent,
}

/// The external anchor written by [`write_head_anchor`]: the tail record's
/// position and hash, recorded outside the journal file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalHead {
    pub sequence: u64,
    pub record_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum ChainVerification {
    /// Every record's sequence, previous-hash link and own hash are
    /// consistent, and (when a head was supplied) the tail matches it.
    Intact,
    /// The chain breaks at the named sequence number, for the given reason.
    /// Everything at or after this point is untrusted; nothing before it
    /// is implicated.
    Broken { at_sequence: u64, reason: String },
    /// The chain itself verifies, but the journal's tail does not match a
    /// supplied external head — consistent with truncation (or the anchor
    /// being stale, if the journal is expected to have grown since).
    TruncationSuspected {
        anchored_sequence: u64,
        tail_sequence: Option<u64>,
    },
}

pub fn record_hash(
    sequence: u64,
    previous_record_hash: Option<&str>,
    event: &TrustEvent,
) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(b"layerfault:trust-journal-record:v1\0");
    hasher.update(sequence.to_le_bytes());
    hasher.update(previous_record_hash.unwrap_or("").as_bytes());
    hasher.update(serde_json::to_vec(event)?);
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

pub fn load(path: &Path) -> Result<Vec<JournalRecord>> {
    let _lock = JournalLock::acquire(path)?;
    load_unlocked(path)
}

fn load_unlocked(path: &Path) -> Result<Vec<JournalRecord>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = crate::safeio::open_readonly_nofollow(path)?;
    let bytes = crate::safeio::read_all_from_file(&file, MAX_JOURNAL_BYTES)?;
    let mut records = Vec::new();
    for (line_number, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        if line.is_empty() {
            continue;
        }
        if records.len() >= MAX_EVENTS {
            bail!("trust journal exceeds the {MAX_EVENTS}-event safety limit");
        }
        let record: JournalRecord = serde_json::from_slice(line)
            .with_context(|| format!("trust journal line {} is invalid JSON", line_number + 1))?;
        if record.event.version != 1 {
            bail!("unsupported trust event version {}", record.event.version);
        }
        records.push(record);
    }
    Ok(records)
}

/// Verify that `records` form a consistent, sequential hash chain. Pass
/// `expected_head` (typically loaded via [`load_head_anchor`]) to also check
/// the tail against an externally anchored position — without it, this
/// cannot detect truncation, only mid-chain alteration.
pub fn verify_chain(
    records: &[JournalRecord],
    expected_head: Option<&JournalHead>,
) -> Result<ChainVerification> {
    let mut previous_hash: Option<String> = None;
    for (index, record) in records.iter().enumerate() {
        let expected_sequence = index as u64;
        if record.sequence != expected_sequence {
            return Ok(ChainVerification::Broken {
                at_sequence: record.sequence,
                reason: format!(
                    "expected sequence {expected_sequence}, found {}",
                    record.sequence
                ),
            });
        }
        if record.previous_record_hash.as_deref() != previous_hash.as_deref() {
            return Ok(ChainVerification::Broken {
                at_sequence: record.sequence,
                reason: "previous_record_hash does not match the prior record's hash".to_owned(),
            });
        }
        let expected_hash = record_hash(record.sequence, previous_hash.as_deref(), &record.event)?;
        if record.record_hash != expected_hash {
            return Ok(ChainVerification::Broken {
                at_sequence: record.sequence,
                reason: "record_hash does not match its own sequence/previous-hash/event"
                    .to_owned(),
            });
        }
        previous_hash = Some(record.record_hash.clone());
    }
    if let Some(head) = expected_head {
        let tail_sequence = records.last().map(|record| record.sequence);
        let tail_hash = records.last().map(|record| record.record_hash.as_str());
        if tail_sequence != Some(head.sequence) || tail_hash != Some(head.record_hash.as_str()) {
            return Ok(ChainVerification::TruncationSuspected {
                anchored_sequence: head.sequence,
                tail_sequence,
            });
        }
    }
    Ok(ChainVerification::Intact)
}

/// Record the current tail's position and hash outside the journal file, so
/// a later [`verify_chain`] call can detect the journal having been made
/// shorter. Call this after every [`append`] that the caller wants
/// truncation-protected. See the module documentation for what this anchor
/// does and does not protect against.
pub fn write_head_anchor(anchor_path: &Path, records: &[JournalRecord]) -> Result<()> {
    let Some(tail) = records.last() else {
        bail!("cannot anchor an empty journal");
    };
    let head = JournalHead {
        sequence: tail.sequence,
        record_hash: tail.record_hash.clone(),
    };
    let parent = anchor_path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    crate::paths::ensure_private_dir(parent)?;
    crate::paths::write_private(anchor_path, &serde_json::to_vec(&head)?)
}

pub fn load_head_anchor(anchor_path: &Path) -> Result<Option<JournalHead>> {
    if !anchor_path.exists() {
        return Ok(None);
    }
    let file = crate::safeio::open_readonly_nofollow(anchor_path)?;
    let bytes = crate::safeio::read_all_from_file(&file, 4096)?;
    Ok(Some(serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "journal head anchor '{}' is invalid JSON",
            anchor_path.display()
        )
    })?))
}

/// Append `event` to the journal, stamping it with the next sequence number
/// and chaining it to the current tail. Returns the written record.
pub fn append(path: &Path, event: &TrustEvent) -> Result<JournalRecord> {
    if event.version != 1 {
        bail!("unsupported trust event version {}", event.version);
    }
    let _lock = JournalLock::acquire(path)?;
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!("trust journal '{}' must be a regular file", path.display());
        }
        if metadata.len() >= MAX_JOURNAL_BYTES {
            bail!("trust journal exceeds the 64 MiB safety limit");
        }
    }
    let existing = load_unlocked(path)?;
    if existing.len() >= MAX_EVENTS {
        bail!("trust journal exceeds the {MAX_EVENTS}-event safety limit");
    }
    let sequence = existing.len() as u64;
    let previous_record_hash = existing.last().map(|record| record.record_hash.clone());
    let hash = record_hash(sequence, previous_record_hash.as_deref(), event)?;
    let record = JournalRecord {
        sequence,
        previous_record_hash,
        record_hash: hash,
        event: event.clone(),
    };

    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    crate::paths::ensure_private_dir(parent)?;
    let mut line = serde_json::to_vec(&record)?;
    line.push(b'\n');
    if line.len() as u64 > MAX_JOURNAL_BYTES {
        bail!("trust event exceeds the journal safety limit");
    }
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("unable to open trust journal '{}'", path.display()))?;
    file.write_all(&line)
        .map_err(|error| anyhow!("unable to append trust event: {error}"))?;
    file.sync_data()?;
    Ok(record)
}

struct JournalLock {
    path: PathBuf,
}

impl JournalLock {
    fn acquire(journal: &Path) -> Result<Self> {
        let parent = journal
            .parent()
            .filter(|value| !value.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        crate::paths::ensure_private_dir(parent)?;
        let name = journal
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| anyhow!("trust journal path has no UTF-8 filename"))?;
        let path = parent.join(format!(".{name}.lock"));
        let started = Instant::now();
        loop {
            let mut options = OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
            }
            match options.open(&path) {
                Ok(mut file) => {
                    writeln!(file, "{}", std::process::id())?;
                    file.sync_data()?;
                    return Ok(Self { path });
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::AlreadyExists
                        || error.kind() == std::io::ErrorKind::PermissionDenied =>
                {
                    if lock_is_stale(&path) {
                        match std::fs::remove_file(&path) {
                            Ok(()) => continue,
                            Err(remove_error)
                                if remove_error.kind() == std::io::ErrorKind::NotFound =>
                            {
                                continue;
                            }
                            Err(_) => {}
                        }
                    }
                    if started.elapsed() >= LOCK_TIMEOUT {
                        bail!("timed out waiting for trust journal lock");
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error).context("unable to acquire trust journal lock"),
            }
        }
    }
}

impl Drop for JournalLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn lock_is_stale(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| modified.elapsed().ok())
        .is_some_and(|age| age >= STALE_LOCK_AGE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::continuous::TrustState;
    use std::sync::Arc;

    fn event(id: usize) -> TrustEvent {
        TrustEvent {
            version: 1,
            timestamp_unix: id as u64,
            entity: format!("entity-{id}"),
            previous_state: TrustState::Unknown,
            new_state: TrustState::Scanning,
            cause: "test".into(),
            changed_components: Vec::new(),
            invalidated_evidence: Vec::new(),
            finding_ids: Vec::new(),
            rule_ids: Vec::new(),
            policy_decision: None,
            operator_action: None,
        }
    }

    #[test]
    fn concurrent_appends_do_not_lose_events() {
        let dir = tempfile::tempdir().unwrap();
        let path = Arc::new(dir.path().join("trust.jsonl"));
        let threads = (0..8)
            .map(|worker| {
                let path = Arc::clone(&path);
                std::thread::spawn(move || {
                    for offset in 0..25 {
                        append(&path, &event(worker * 25 + offset)).unwrap();
                    }
                })
            })
            .collect::<Vec<_>>();
        for thread in threads {
            thread.join().unwrap();
        }
        let records = load(&path).unwrap();
        assert_eq!(records.len(), 200);
    }

    #[test]
    fn sequential_appends_form_a_verified_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.jsonl");
        for id in 0..5 {
            append(&path, &event(id)).unwrap();
        }
        let records = load(&path).unwrap();
        assert_eq!(records.len(), 5);
        for (index, record) in records.iter().enumerate() {
            assert_eq!(record.sequence, index as u64);
        }
        assert!(records[0].previous_record_hash.is_none());
        assert_eq!(
            records[1].previous_record_hash.as_deref(),
            Some(records[0].record_hash.as_str())
        );
        assert_eq!(
            verify_chain(&records, None).unwrap(),
            ChainVerification::Intact
        );
    }

    #[test]
    fn altering_a_middle_record_breaks_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.jsonl");
        for id in 0..5 {
            append(&path, &event(id)).unwrap();
        }
        let mut records = load(&path).unwrap();
        records[2].event.cause = "tampered".to_owned();
        let result = verify_chain(&records, None).unwrap();
        assert!(matches!(
            result,
            ChainVerification::Broken { at_sequence: 2, .. }
        ));
    }

    #[test]
    fn truncating_the_tail_is_invisible_to_the_chain_alone_but_caught_by_the_anchor() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.jsonl");
        for id in 0..5 {
            append(&path, &event(id)).unwrap();
        }
        let full = load(&path).unwrap();
        write_head_anchor(&dir.path().join("trust.jsonl.head"), &full).unwrap();

        // Truncate: keep only the first 3 records, which is itself a
        // perfectly valid, internally consistent shorter chain.
        let truncated: Vec<JournalRecord> = full[..3].to_vec();
        assert_eq!(
            verify_chain(&truncated, None).unwrap(),
            ChainVerification::Intact,
            "a truncated chain is indistinguishable from a shorter honest one without an anchor"
        );

        let head = load_head_anchor(&dir.path().join("trust.jsonl.head"))
            .unwrap()
            .unwrap();
        let result = verify_chain(&truncated, Some(&head)).unwrap();
        assert!(matches!(
            result,
            ChainVerification::TruncationSuspected {
                anchored_sequence: 4,
                tail_sequence: Some(2),
            }
        ));
    }

    #[test]
    fn anchor_matching_the_full_chain_verifies_intact() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("trust.jsonl");
        for id in 0..5 {
            append(&path, &event(id)).unwrap();
        }
        let records = load(&path).unwrap();
        let anchor_path = dir.path().join("trust.jsonl.head");
        write_head_anchor(&anchor_path, &records).unwrap();
        let head = load_head_anchor(&anchor_path).unwrap().unwrap();
        assert_eq!(
            verify_chain(&records, Some(&head)).unwrap(),
            ChainVerification::Intact
        );
    }
}
