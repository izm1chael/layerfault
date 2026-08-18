use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const MAX_SNAPSHOT_FILES: usize = 4096;
const MAX_TRACE_BYTES: u64 = 32 * 1024 * 1024;
pub(crate) const MAX_TELEMETRY_ROWS: usize = 128;

/// Which telemetry backend produced a `SandboxTelemetry` instance. Distinct
/// from `SandboxKind`, which describes sandbox *isolation* (bwrap/microvm),
/// not the mechanism used to observe behaviour inside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TelemetryBackendKind {
    #[default]
    Strace,
    Ebpf,
}

impl std::fmt::Display for TelemetryBackendKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Strace => write!(f, "strace"),
            Self::Ebpf => write!(f, "ebpf"),
        }
    }
}

impl std::str::FromStr for TelemetryBackendKind {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "strace" => Ok(Self::Strace),
            "ebpf" => Ok(Self::Ebpf),
            other => {
                anyhow::bail!(
                    "unsupported telemetry backend '{other}' (expected 'strace' or 'ebpf')"
                )
            }
        }
    }
}

/// Normalizes behavioural evidence collected by whichever `TelemetryBackend`
/// observed a sandbox run, so evaluation/correlation never depends on the
/// backend that produced it.
pub trait TelemetryBackend {
    fn kind(&self) -> TelemetryBackendKind;

    /// Read and normalize backend-specific evidence (e.g. strace trace files)
    /// from `telemetry_root` into `telemetry`. Filesystem-mutation diffing is
    /// backend-independent and stays in `Workspace::collect_telemetry`.
    fn collect(&self, telemetry_root: &Path, telemetry: &mut SandboxTelemetry) -> Result<()>;
}

/// Default backend: parses `strace`'s per-PID trace files written into the
/// workspace telemetry root.
pub struct StraceTelemetryBackend;

impl TelemetryBackend for StraceTelemetryBackend {
    fn kind(&self) -> TelemetryBackendKind {
        TelemetryBackendKind::Strace
    }

    fn collect(&self, telemetry_root: &Path, telemetry: &mut SandboxTelemetry) -> Result<()> {
        parse_trace_files(telemetry_root, telemetry)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SandboxTelemetry {
    pub filesystem_mutations: Vec<FileMutation>,
    pub filesystem_write_attempts: Vec<String>,
    pub network_attempts: Vec<String>,
    pub process_exec_attempts: Vec<String>,
    pub sensitive_path_accesses: Vec<String>,
    pub canary_accesses: Vec<String>,
    /// Process-exit events. Only ever populated by backends that observe
    /// exits (e.g. an eBPF backend); strace-sourced telemetry always leaves
    /// this empty, which is not evidence of a clean run.
    pub process_exit_events: Vec<String>,
    pub trace_available: bool,
    pub trace_truncated: bool,
    pub snapshot_overflow: bool,
    pub total_filesystem_mutations: usize,
    pub suspicious_filesystem_mutations: usize,
    /// Per-category event counts observed before any truncation, so
    /// aggregate risk signal survives bounded-evidence-vector truncation.
    pub events_seen: BTreeMap<String, u64>,
    /// Events rejected by backend protocol validation (oversized, malformed,
    /// out of scope, unknown schema version) rather than silently dropped.
    pub events_dropped: u64,
    /// Set when a backend hit its total per-run byte/frame ceiling.
    pub buffer_overflow: bool,
    /// Set with a human-readable reason when `auto` backend selection fell
    /// back from a preferred backend to a less-capable one, or a backend
    /// reported a partial/degraded run. `None` for a clean run.
    pub backend_degraded: Option<String>,
    /// Which backend actually produced this telemetry.
    pub telemetry_backend: TelemetryBackendKind,
    pub cgroup: Option<crate::behaviour::cgroup::CgroupTelemetry>,
}

impl SandboxTelemetry {
    pub fn suspicious(&self) -> bool {
        !self.filesystem_write_attempts.is_empty()
            || !self.network_attempts.is_empty()
            || !self.process_exec_attempts.is_empty()
            || !self.sensitive_path_accesses.is_empty()
            || !self.canary_accesses.is_empty()
            || self.suspicious_filesystem_mutations > 0
            || self.snapshot_overflow
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMutation {
    pub path: String,
    pub kind: String,
    pub expected_runtime_artifact: bool,
}

#[derive(Debug, Clone)]
struct SnapshotEntry {
    len: u64,
    modified_ns: u128,
}

#[derive(Debug, Default)]
struct Snapshot {
    entries: BTreeMap<String, SnapshotEntry>,
    overflow: bool,
}

#[derive(Debug)]
pub struct Workspace {
    pub root: PathBuf,
    pub home: PathBuf,
    telemetry_root: PathBuf,
    baseline: Snapshot,
}

impl Workspace {
    pub fn create(canaries: &[&str]) -> Result<Self> {
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        let nonce = format!(
            "{}-{now_ns}-{}",
            std::process::id(),
            std::thread::current()
                .name()
                .unwrap_or("worker")
                .replace('/', "_")
        );
        let root = std::env::temp_dir().join(format!("layerfault-behaviour-{nonce}"));
        let telemetry_root =
            std::env::temp_dir().join(format!("layerfault-behaviour-telemetry-{nonce}"));
        let home = root.join("home");
        crate::paths::ensure_private_dir(&home)?;
        crate::paths::ensure_private_dir(&root.join("workspace"))?;
        crate::paths::ensure_private_dir(&telemetry_root)?;
        std::fs::write(
            root.join("workspace").join("README.txt"),
            b"Synthetic Layerfault behavioural workspace. No host credentials are intentionally placed here.\n",
        )?;

        // Decoys are deliberately synthetic. They let syscall tracing distinguish
        // package/runtime attempts to harvest credentials from normal inference.
        let canary_a = canaries.first().copied().unwrap_or("LF_CANARY_A_UNSET");
        let canary_b = canaries.get(1).copied().unwrap_or("LF_CANARY_B_UNSET");
        crate::paths::ensure_private_dir(&home.join(".ssh"))?;
        crate::paths::ensure_private_dir(&root.join("workspace").join("secrets"))?;
        std::fs::write(
            home.join(".ssh").join("id_ed25519"),
            format!("-----BEGIN SYNTHETIC KEY-----\n{canary_a}\n-----END SYNTHETIC KEY-----\n"),
        )?;
        std::fs::write(
            root.join("workspace").join(".env"),
            format!("LAYERFAULT_SYNTHETIC_SECRET={canary_b}\n"),
        )?;
        std::fs::write(
            root.join("workspace").join("secrets").join("api_token.txt"),
            format!("{canary_a}:{canary_b}\n"),
        )?;

        let baseline = snapshot_tree(&root)?;
        Ok(Self {
            root,
            home,
            telemetry_root,
            baseline,
        })
    }

    pub fn trace_prefix(&self) -> PathBuf {
        self.telemetry_root.join("strace")
    }

    pub fn collect_telemetry(&self, trace_enabled: bool) -> Result<SandboxTelemetry> {
        let backend = trace_enabled.then_some(StraceTelemetryBackend);
        let backend: Option<&dyn TelemetryBackend> = backend
            .as_ref()
            .map(|backend| backend as &dyn TelemetryBackend);
        self.collect_telemetry_with(backend)
    }

    /// Same as `collect_telemetry`, but dispatches backend-specific evidence
    /// collection through an explicit `TelemetryBackend` rather than assuming
    /// strace. `None` means no telemetry backend ran for this session.
    pub fn collect_telemetry_with(
        &self,
        backend: Option<&dyn TelemetryBackend>,
    ) -> Result<SandboxTelemetry> {
        let current = snapshot_tree(&self.root)?;
        let mut telemetry = SandboxTelemetry {
            trace_available: backend.is_some(),
            snapshot_overflow: self.baseline.overflow || current.overflow,
            telemetry_backend: backend.map(TelemetryBackend::kind).unwrap_or_default(),
            ..SandboxTelemetry::default()
        };

        let mut paths: BTreeSet<String> = self.baseline.entries.keys().cloned().collect();
        paths.extend(current.entries.keys().cloned());
        let mut mutations = Vec::new();
        for path in paths {
            let before = self.baseline.entries.get(&path);
            let after = current.entries.get(&path);
            let kind = match (before, after) {
                (None, Some(_)) => Some("CREATED"),
                (Some(_), None) => Some("DELETED"),
                (Some(a), Some(b)) if a.len != b.len || a.modified_ns != b.modified_ns => {
                    Some("MODIFIED")
                }
                _ => None,
            };
            if let Some(kind) = kind {
                mutations.push(FileMutation {
                    expected_runtime_artifact: expected_runtime_artifact(&path),
                    path,
                    kind: kind.to_owned(),
                });
            }
        }
        telemetry.total_filesystem_mutations = mutations.len();
        telemetry.suspicious_filesystem_mutations = mutations
            .iter()
            .filter(|mutation| !mutation.expected_runtime_artifact)
            .count();
        // Bounded evidence must never become bounded detection: retain unexpected
        // mutations first, then fill the remaining report budget with expected
        // runtime cache/artifact churn. Aggregate counts above preserve risk even
        // when the evidence vector is truncated.
        mutations.sort_by_key(|mutation| mutation.expected_runtime_artifact);
        mutations.truncate(MAX_TELEMETRY_ROWS);
        telemetry.filesystem_mutations = mutations;

        if let Some(backend) = backend {
            backend.collect(&self.telemetry_root, &mut telemetry)?;
        }
        Ok(telemetry)
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
        let _ = std::fs::remove_dir_all(&self.telemetry_root);
    }
}

fn snapshot_tree(root: &Path) -> Result<Snapshot> {
    let mut out = BTreeMap::new();
    let mut overflow = false;
    for entry in walkdir::WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|entry| entry.ok())
    {
        if out.len() >= MAX_SNAPSHOT_FILES {
            overflow = true;
            break;
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(root)
            .unwrap_or(entry.path())
            .to_string_lossy()
            .replace('\\', "/");
        let metadata = entry.metadata()?;
        let modified_ns = metadata
            .modified()
            .ok()
            .and_then(|value| value.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|value| value.as_nanos())
            .unwrap_or_default();
        out.insert(
            relative,
            SnapshotEntry {
                len: metadata.len(),
                modified_ns,
            },
        );
    }
    Ok(Snapshot {
        entries: out,
        overflow,
    })
}

fn expected_runtime_artifact(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.starts_with("home/.cache/")
        || lower.contains("__pycache__")
        || lower.ends_with(".pyc")
        || lower.starts_with("workspace/layerfault_")
}

fn parse_trace_files(root: &Path, telemetry: &mut SandboxTelemetry) -> Result<()> {
    let mut consumed = 0_u64;
    let mut files: Vec<PathBuf> = crate::safeio::read_dir_nofollow(root)?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.starts_with("strace"))
        })
        .collect();
    files.sort();
    for path in files {
        let remaining = MAX_TRACE_BYTES.saturating_sub(consumed);
        if remaining == 0 {
            telemetry.trace_truncated = true;
            break;
        }
        let file = crate::safeio::open_readonly_nofollow(&path)?;
        let len = file.metadata()?.len();
        let take = remaining.min(len);
        if take < len {
            telemetry.trace_truncated = true;
        }
        let mut bytes = Vec::with_capacity(usize::try_from(take).unwrap_or(0));
        use std::io::{Read as _, Take};
        let mut bounded: Take<std::fs::File> = file.take(take);
        bounded.read_to_end(&mut bytes)?;
        consumed = consumed.saturating_add(bytes.len() as u64);
        let text = String::from_utf8_lossy(&bytes);
        // strace -ff writes one file per traced pid, so every line in this
        // file was produced by the same process. Establish once, from that
        // process's own exec, whether it is the interpreter and lifecycle
        // stage Python's multiprocessing.resource_tracker helper runs as,
        // before classifying any of its individual syscalls. This is the
        // actor half of the attribution check in `classify_trace_line`; a
        // process that merely writes a matching path without being this
        // exact helper does not qualify.
        let actor_is_resource_tracker = is_resource_tracker_actor(&text);
        for line in text.lines() {
            classify_trace_line(line, telemetry, actor_is_resource_tracker);
        }
    }
    // The sandbox launcher itself performs exactly one expected exec of the
    // audited runtime at /runtime. Record every exec first, then remove a
    // single /runtime entry so additional self-runtime executions remain
    // visible regardless of strace per-PID file ordering.
    discard_one_expected_runtime_exec(telemetry);
    Ok(())
}

fn discard_one_expected_runtime_exec(telemetry: &mut SandboxTelemetry) {
    if let Some(index) = telemetry
        .process_exec_attempts
        .iter()
        .position(|line| line.to_ascii_lowercase().contains("execve(\"/runtime\""))
    {
        telemetry.process_exec_attempts.remove(index);
    }
}

fn trace_syscall_succeeded(lower: &str) -> bool {
    let Some((_, result)) = lower.rsplit_once(" = ") else {
        return false;
    };
    !result.trim_start().starts_with("-1")
}

fn is_internet_network_attempt(lower: &str) -> bool {
    (lower.contains("connect(") || lower.contains("sendto(") || lower.contains("sendmsg("))
        && (lower.contains("af_inet6") || lower.contains("af_inet"))
}

/// True when a trace file's own process exec identifies it as CPython's
/// `multiprocessing.resource_tracker` helper: the interpreter path contains
/// "python" and its command line names the `resource_tracker` module, which
/// is how the standard library actually launches it
/// (`python -c "from multiprocessing.resource_tracker import main;..."`).
/// This is the actor half of trusted-runtime-housekeeping attribution — see
/// `is_trusted_resource_tracker_cleanup`.
fn is_resource_tracker_actor(text: &str) -> bool {
    text.lines().any(|line| {
        let lower = line.to_ascii_lowercase();
        lower.contains("execve(") && lower.contains("python") && lower.contains("resource_tracker")
    })
}

/// True when a syscall line is `multiprocessing.resource_tracker`'s expected
/// unlink of a leaked POSIX semaphore/shared-memory object under `/dev/shm/`
/// — the only filesystem-mutating operation that helper performs, and the
/// only path prefix it operates on. Both the actor (`actor_is_resource_tracker`,
/// established from that process's own exec) and this operation/path match
/// must hold; neither alone is enough, so a process that merely names itself
/// "resource_tracker" without this exact operation and path, or that reaches
/// this path from a process that isn't the helper, still gets reported
/// normally.
fn is_trusted_resource_tracker_cleanup(lower: &str, actor_is_resource_tracker: bool) -> bool {
    actor_is_resource_tracker
        && (lower.contains("unlink(\"/dev/shm/")
            || lower.contains("unlinkat(") && lower.contains("\"/dev/shm/"))
}

fn classify_trace_line(
    line: &str,
    telemetry: &mut SandboxTelemetry,
    actor_is_resource_tracker: bool,
) {
    let lower = line.to_ascii_lowercase();
    if is_internet_network_attempt(&lower) && telemetry.network_attempts.len() < MAX_TELEMETRY_ROWS
    {
        // A denied/unreachable AF_INET/AF_INET6 connect still proves attempted
        // egress. Local AF_UNIX/AF_NETLINK IPC is not Internet egress.
        telemetry.network_attempts.push(excerpt(line));
    }

    let write_like = (lower.contains("open(") || lower.contains("openat("))
        && ["o_wronly", "o_rdwr", "o_creat", "o_trunc", "o_append"]
            .iter()
            .any(|flag| lower.contains(flag));
    let mutate_like = [
        "unlink(",
        "unlinkat(",
        "rename(",
        "renameat(",
        "renameat2(",
        "mkdir(",
        "mkdirat(",
        "rmdir(",
        "chmod(",
        "fchmodat(",
        "chown(",
        "symlink(",
        "symlinkat(",
        "link(",
        "linkat(",
    ]
    .iter()
    .any(|call| lower.contains(call));
    let trusted_housekeeping =
        is_trusted_resource_tracker_cleanup(&lower, actor_is_resource_tracker);
    if (write_like || mutate_like)
        && !trusted_housekeeping
        && telemetry.filesystem_write_attempts.len() < MAX_TELEMETRY_ROWS
    {
        telemetry.filesystem_write_attempts.push(excerpt(line));
    }

    if lower.contains("execve(")
        && !lower.contains("/bwrap\"")
        && !lower.contains("/strace\"")
        && !lower.contains("/prlimit\"")
        && telemetry.process_exec_attempts.len() < MAX_TELEMETRY_ROWS
    {
        telemetry.process_exec_attempts.push(excerpt(line));
    }

    if is_canary_evidence(&lower)
        && trace_syscall_succeeded(&lower)
        && telemetry.canary_accesses.len() < MAX_TELEMETRY_ROWS
    {
        // Failed import-resolution/stat probes are not successful secret access.
        telemetry.canary_accesses.push(excerpt(line));
    }

    if is_sensitive_evidence(&lower) && telemetry.sensitive_path_accesses.len() < MAX_TELEMETRY_ROWS
    {
        telemetry.sensitive_path_accesses.push(excerpt(line));
    }
}

/// Shared canary-path detection, reused by both the strace text-line
/// classifier and the eBPF frame normalizer so evidence classification stays
/// backend-independent.
pub(crate) fn is_canary_evidence(lower: &str) -> bool {
    [
        "/workspace/home/.ssh/",
        "/workspace/workspace/.env",
        "/workspace/workspace/secrets/",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

/// Shared sensitive-path detection, reused by both the strace text-line
/// classifier and the eBPF frame normalizer.
pub(crate) fn is_sensitive_evidence(lower: &str) -> bool {
    [
        "/etc/shadow",
        "/root/",
        "/proc/self/environ",
        "/proc/1/environ",
        "/.ssh/",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

pub(crate) fn excerpt(value: &str) -> String {
    let mut out: String = value.chars().take(512).collect();
    if value.chars().count() > 512 {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_classification_detects_network_exec_and_canary_access() {
        let mut telemetry = SandboxTelemetry::default();
        classify_trace_line(
            r#"connect(7, {sa_family=AF_INET, sin_port=htons(443)}, 16) = -1 ENETUNREACH"#,
            &mut telemetry,
            false,
        );
        classify_trace_line(
            r#"execve("/bin/sh", ["sh"], 0x0) = 0"#,
            &mut telemetry,
            false,
        );
        classify_trace_line(
            r#"openat(AT_FDCWD, "/workspace/workspace/.env", O_RDONLY) = 4"#,
            &mut telemetry,
            false,
        );
        classify_trace_line(
            r#"openat(AT_FDCWD, "/model/package/config.json", O_WRONLY|O_TRUNC) = -1 EROFS"#,
            &mut telemetry,
            false,
        );
        classify_trace_line(
            r#"openat(AT_FDCWD, "/proc/self/mem", O_WRONLY) = -1 EACCES"#,
            &mut telemetry,
            false,
        );
        classify_trace_line(
            r#"openat(AT_FDCWD, "/tmp/dropper", O_WRONLY|O_CREAT) = 4"#,
            &mut telemetry,
            false,
        );
        assert_eq!(telemetry.network_attempts.len(), 1);
        assert_eq!(telemetry.process_exec_attempts.len(), 1);
        assert_eq!(telemetry.canary_accesses.len(), 1);
        assert_eq!(telemetry.filesystem_write_attempts.len(), 3);
    }

    #[test]
    fn local_ipc_is_not_internet_egress_and_failed_canary_probe_is_not_access() {
        let mut telemetry = SandboxTelemetry::default();
        classify_trace_line(
            r#"connect(5, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = -1 ENOENT"#,
            &mut telemetry,
            false,
        );
        classify_trace_line(
            r#"openat(AT_FDCWD, "/workspace/workspace/secrets/api_token.txt", O_RDONLY) = -1 ENOENT"#,
            &mut telemetry,
            false,
        );
        assert!(telemetry.network_attempts.is_empty());
        assert!(telemetry.canary_accesses.is_empty());

        classify_trace_line(
            r#"connect(7, {sa_family=AF_INET6, sin6_port=htons(443)}, 28) = -1 ENETUNREACH"#,
            &mut telemetry,
            false,
        );
        classify_trace_line(
            r#"openat(AT_FDCWD, "/workspace/workspace/secrets/api_token.txt", O_RDONLY) = 4"#,
            &mut telemetry,
            false,
        );
        assert_eq!(telemetry.network_attempts.len(), 1);
        assert_eq!(telemetry.canary_accesses.len(), 1);
    }

    #[test]
    fn only_the_first_runtime_exec_is_treated_as_expected() {
        let mut telemetry = SandboxTelemetry::default();
        classify_trace_line(
            r#"execve("/runtime", ["/runtime", "runner.py"], 0x0) = 0"#,
            &mut telemetry,
            false,
        );
        classify_trace_line(
            r#"execve("/runtime", ["/runtime", "-c", "payload"], 0x0) = 0"#,
            &mut telemetry,
            false,
        );
        discard_one_expected_runtime_exec(&mut telemetry);
        assert_eq!(telemetry.process_exec_attempts.len(), 1);
    }

    #[test]
    fn expected_runtime_artifacts_are_separated_from_unexpected_mutations() {
        assert!(expected_runtime_artifact("home/.cache/huggingface/x"));
        assert!(!expected_runtime_artifact("workspace/dropper.sh"));
    }

    const RESOURCE_TRACKER_EXEC: &str = r#"execve("/usr/bin/python3.11", ["python3", "-c", "from multiprocessing.resource_tracker import main;main(6)"], 0x7ffe /* 12 vars */) = 0"#;
    const RESOURCE_TRACKER_UNLINK: &str = r#"unlink("/dev/shm/sem.mp-abc123") = 0"#;

    #[test]
    fn resource_tracker_semaphore_cleanup_is_not_a_filesystem_write_finding() {
        let mut telemetry = SandboxTelemetry::default();
        let actor = is_resource_tracker_actor(RESOURCE_TRACKER_EXEC);
        assert!(actor);
        classify_trace_line(RESOURCE_TRACKER_EXEC, &mut telemetry, actor);
        classify_trace_line(RESOURCE_TRACKER_UNLINK, &mut telemetry, actor);
        assert!(
            telemetry.filesystem_write_attempts.is_empty(),
            "expected resource_tracker's own semaphore cleanup to be suppressed: {:?}",
            telemetry.filesystem_write_attempts
        );
    }

    #[test]
    fn unlink_outside_dev_shm_by_resource_tracker_actor_is_still_reported() {
        // Even a process that genuinely is the resource_tracker helper must
        // still be reported if it unlinks something outside its known
        // housekeeping path — the path match is not optional.
        let mut telemetry = SandboxTelemetry::default();
        let actor = is_resource_tracker_actor(RESOURCE_TRACKER_EXEC);
        assert!(actor);
        classify_trace_line(
            r#"unlink("/workspace/workspace/.env") = 0"#,
            &mut telemetry,
            actor,
        );
        assert_eq!(telemetry.filesystem_write_attempts.len(), 1);
    }

    #[test]
    fn dev_shm_unlink_without_resource_tracker_actor_is_still_reported() {
        // A process that unlinks a /dev/shm path but was never established
        // as the resource_tracker helper (no matching exec observed in its
        // own trace file) must not be suppressed just by path shape alone.
        let mut telemetry = SandboxTelemetry::default();
        classify_trace_line(RESOURCE_TRACKER_UNLINK, &mut telemetry, false);
        assert_eq!(telemetry.filesystem_write_attempts.len(), 1);
    }

    #[test]
    fn spoofed_resource_tracker_argv_without_python_is_not_trusted() {
        // "GOOD" example from the housekeeping rule: an arbitrary child
        // merely naming "resource_tracker" in its command line, without
        // actually being the Python interpreter running that module, must
        // not gain trusted status.
        let spoofed = r#"execve("/bin/sh", ["sh", "-c", "echo resource_tracker && rm -rf /dev/shm/sem.fake"], 0x0) = 0"#;
        assert!(!is_resource_tracker_actor(spoofed));

        let mut telemetry = SandboxTelemetry::default();
        classify_trace_line(spoofed, &mut telemetry, false);
        classify_trace_line(RESOURCE_TRACKER_UNLINK, &mut telemetry, false);
        assert_eq!(
            telemetry.filesystem_write_attempts.len(),
            1,
            "unlink must still be reported when the actor was never confirmed as resource_tracker"
        );
    }

    #[test]
    fn genuine_arbitrary_writes_are_unaffected_by_the_housekeeping_rule() {
        let mut telemetry = SandboxTelemetry::default();
        let actor = is_resource_tracker_actor(RESOURCE_TRACKER_EXEC);
        classify_trace_line(
            r#"openat(AT_FDCWD, "/tmp/payload", O_WRONLY|O_CREAT) = 4"#,
            &mut telemetry,
            actor,
        );
        classify_trace_line(
            r#"openat(AT_FDCWD, "/root/.ssh/authorized_keys", O_WRONLY|O_CREAT) = 4"#,
            &mut telemetry,
            actor,
        );
        assert_eq!(telemetry.filesystem_write_attempts.len(), 2);
    }

    #[test]
    fn parse_trace_files_attributes_housekeeping_per_pid_file() -> Result<()> {
        // `strace -ff` writes one file per traced pid. Model that layout: a
        // model/probe process (pid 100) that writes an arbitrary file, and a
        // separate resource_tracker helper process (pid 105) that only ever
        // unlinks its own semaphore. Attribution must be established from
        // each file's own content, independent of file processing order.
        let root = std::env::temp_dir().join(format!(
            "layerfault-trace-attribution-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root)?;
        std::fs::write(
            root.join("strace.100"),
            r#"openat(AT_FDCWD, "/tmp/payload", O_WRONLY|O_CREAT) = 4
"#,
        )?;
        std::fs::write(
            root.join("strace.105"),
            format!("{RESOURCE_TRACKER_EXEC}\n{RESOURCE_TRACKER_UNLINK}\n"),
        )?;

        let mut telemetry = SandboxTelemetry::default();
        parse_trace_files(&root, &mut telemetry)?;

        assert_eq!(
            telemetry.filesystem_write_attempts.len(),
            1,
            "the probe's own write must still be reported while the helper's cleanup is suppressed: {:?}",
            telemetry.filesystem_write_attempts
        );
        assert!(telemetry.filesystem_write_attempts[0].contains("/tmp/payload"));

        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn snapshot_overflow_is_explicit() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "layerfault-snapshot-overflow-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root)?;
        for index in 0..=MAX_SNAPSHOT_FILES {
            std::fs::write(root.join(format!("f-{index:05}")), b"x")?;
        }
        let snapshot = snapshot_tree(&root)?;
        assert!(snapshot.overflow);
        assert!(snapshot.entries.len() <= MAX_SNAPSHOT_FILES);
        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }
}
