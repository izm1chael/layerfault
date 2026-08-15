use super::TrustEvent;
use anyhow::{anyhow, bail, Context, Result};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_EVENTS: usize = 100_000;
const LOCK_TIMEOUT: Duration = Duration::from_secs(60);
const STALE_LOCK_AGE: Duration = Duration::from_secs(5 * 60);

pub fn load(path: &Path) -> Result<Vec<TrustEvent>> {
    let _lock = JournalLock::acquire(path)?;
    load_unlocked(path)
}

fn load_unlocked(path: &Path) -> Result<Vec<TrustEvent>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file = crate::safeio::open_readonly_nofollow(path)?;
    let bytes = crate::safeio::read_all_from_file(&file, MAX_JOURNAL_BYTES)?;
    let mut events = Vec::new();
    for (line_number, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        if line.is_empty() {
            continue;
        }
        if events.len() >= MAX_EVENTS {
            bail!("trust journal exceeds the {MAX_EVENTS}-event safety limit");
        }
        let event: TrustEvent = serde_json::from_slice(line)
            .with_context(|| format!("trust journal line {} is invalid JSON", line_number + 1))?;
        if event.version != 1 {
            bail!("unsupported trust event version {}", event.version);
        }
        events.push(event);
    }
    Ok(events)
}

pub fn append(path: &Path, event: &TrustEvent) -> Result<()> {
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
        if load_unlocked(path)?.len() >= MAX_EVENTS {
            bail!("trust journal exceeds the {MAX_EVENTS}-event safety limit");
        }
    }
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    crate::paths::ensure_private_dir(parent)?;
    let mut line = serde_json::to_vec(event)?;
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
    Ok(())
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
                        || (error.kind() == std::io::ErrorKind::PermissionDenied
                            && path.exists()) =>
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
        let events = load(&path).unwrap();
        assert_eq!(events.len(), 200);
    }
}
