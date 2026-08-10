use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

const MAX_SNAPSHOT_FILES: usize = 4096;
const MAX_TRACE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_TELEMETRY_ROWS: usize = 128;
const MIN_ADDRESS_SPACE_LIMIT_MB: u64 = 512;
const MAX_ADDRESS_SPACE_LIMIT_MB: u64 = 256 * 1024;
const ACTIVE_MODEL_ENTRY_LIMIT: usize = 100_000;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SandboxCapabilities {
    pub workspace_isolated: bool,
    pub home_isolated: bool,
    pub environment_scrubbed: bool,
    pub network_isolation: bool,
    pub network_mechanism: Option<String>,
    pub host_files_hidden: bool,
    pub real_tools_disabled: bool,
    pub process_namespace_isolated: bool,
    pub ipc_namespace_isolated: bool,
    pub uts_namespace_isolated: bool,
    pub capabilities_dropped: bool,
    pub resource_limits: bool,
    pub address_space_limit_bytes: Option<u64>,
    /// Seccomp is deliberately not enabled: the supported ML runtimes have a
    /// broad, version-dependent syscall surface. Namespace, mount, capability,
    /// and rlimit isolation remain mandatory and are reported separately.
    pub seccomp_filter: bool,
    pub syscall_trace: bool,
    pub syscall_trace_mechanism: Option<String>,
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
    pub trace_available: bool,
    pub trace_truncated: bool,
    pub snapshot_overflow: bool,
    pub total_filesystem_mutations: usize,
    pub suspicious_filesystem_mutations: usize,
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
        let current = snapshot_tree(&self.root)?;
        let mut telemetry = SandboxTelemetry {
            trace_available: trace_enabled,
            snapshot_overflow: self.baseline.overflow || current.overflow,
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

        if trace_enabled {
            parse_trace_files(&self.telemetry_root, &mut telemetry)?;
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

/// Put a spawned behavioural command in its own host-side process group where
/// the platform supports it. Bubblewrap creates additional namespaces/sessions
/// internally, so teardown also enumerates descendants instead of relying on
/// the process group alone.
pub fn configure_process_group(command: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
}

/// Terminate and reap the complete behavioural process tree without using
/// unsafe signal syscalls in Layerfault itself. On Linux, descendants are
/// enumerated from /proc and signalled explicitly; elsewhere Child::kill is the
/// conservative fallback. This is used for timeout, cancellation and failed
/// session startup.
pub fn terminate_process_tree(child: &mut Child, grace: Duration) -> Result<()> {
    if child.try_wait()?.is_some() {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        let root = child.id();
        signal_linux_tree(root, "-TERM");
        let started = Instant::now();
        while started.elapsed() < grace {
            if child.try_wait()?.is_some() {
                // A dead parent can still leave descendants if an inner
                // namespace/session escaped group signalling. Recheck /proc.
                if linux_descendants(root).is_empty() {
                    return Ok(());
                }
            }
            if linux_descendants(root).is_empty() {
                let _ = child.try_wait()?;
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        signal_linux_tree(root, "-KILL");
        let kill_started = Instant::now();
        while kill_started.elapsed() < Duration::from_secs(2) {
            if child.try_wait()?.is_some() && linux_descendants(root).is_empty() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = child.kill();
        let _ = child.wait();
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = child.kill();
        let _ = child.wait();
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn signal_linux_tree(root: u32, signal: &str) {
    let mut pids = linux_descendants(root);
    pids.push(root);
    // Descendants first so a parent cannot immediately respawn a child after
    // its child was terminated but before the parent receives the signal.
    pids.sort_unstable_by(|a, b| b.cmp(a));
    pids.dedup();
    let Some(kill) = crate::sources::find_executable("kill") else {
        return;
    };
    for pid in pids {
        if let Ok(mut command) = crate::safeio::command_for_executable(&kill) {
            let _ = command
                .arg(signal)
                .arg("--")
                .arg(pid.to_string())
                .env_clear()
                .status();
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_descendants(root: u32) -> Vec<u32> {
    let mut parent_by_pid = BTreeMap::<u32, u32>::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
            continue;
        };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        let Some(close) = stat.rfind(')') else {
            continue;
        };
        let mut fields = stat[close + 1..].split_whitespace();
        let _state = fields.next();
        let Some(ppid) = fields.next().and_then(|value| value.parse::<u32>().ok()) else {
            continue;
        };
        parent_by_pid.insert(pid, ppid);
    }
    let mut found = BTreeSet::new();
    let mut frontier = vec![root];
    while let Some(parent) = frontier.pop() {
        for (&pid, &ppid) in &parent_by_pid {
            if ppid == parent && found.insert(pid) {
                frontier.push(pid);
            }
        }
    }
    found.into_iter().collect()
}

/// Return a sandbox launcher only when it can provide both a private filesystem
/// view and a private network namespace. External behavioural execution is
/// deliberately unavailable without this boundary.
pub fn detect_network_wrapper() -> Option<(PathBuf, String)> {
    #[cfg(target_os = "linux")]
    {
        if let Some(path) = crate::sources::find_executable("bwrap") {
            return Some((path, "bwrap-fs-net-pid-ipc-uts".to_owned()));
        }
    }
    None
}

pub fn capabilities(wrapper: Option<&(PathBuf, String)>) -> SandboxCapabilities {
    let strong = wrapper.is_some_and(|(_, mechanism)| mechanism.starts_with("bwrap-fs-net"));
    let trace = strong && crate::sources::find_executable("strace").is_some();
    let limits = strong && crate::sources::find_executable("prlimit").is_some();
    SandboxCapabilities {
        workspace_isolated: strong,
        home_isolated: strong,
        environment_scrubbed: strong,
        network_isolation: strong,
        network_mechanism: wrapper.map(|value| value.1.clone()),
        host_files_hidden: strong,
        real_tools_disabled: strong,
        process_namespace_isolated: strong,
        ipc_namespace_isolated: strong,
        uts_namespace_isolated: strong,
        capabilities_dropped: strong,
        resource_limits: limits,
        address_space_limit_bytes: limits.then(configured_address_space_limit_bytes),
        seccomp_filter: false,
        syscall_trace: trace,
        syscall_trace_mechanism: trace.then_some("strace-file-process-network".to_owned()),
    }
}

/// Every external active execution requires namespace isolation and resource
/// limiting. This prevents a model/runtime failure from becoming a trivial
/// host memory/process/file-descriptor exhaustion path.
pub fn require_external_execution_stack() -> Result<()> {
    if detect_network_wrapper().is_none() {
        bail!("external active analysis requires bubblewrap (bwrap)");
    }
    if crate::sources::find_executable("prlimit").is_none() {
        bail!("external active analysis requires prlimit so CPU/process/address-space limits are enforced");
    }
    Ok(())
}

/// High-risk active analysis (executing statically blocked packages or custom
/// Hugging Face loader code) additionally requires syscall telemetry. Failing
/// closed here prevents a missing lab dependency from silently degrading a
/// hostile-code run.
pub fn require_high_risk_observation_stack() -> Result<()> {
    require_external_execution_stack()?;
    if crate::sources::find_executable("strace").is_none() {
        bail!("high-risk active analysis requires strace so loader/runtime side effects are observable");
    }
    Ok(())
}

fn configured_memory_budget_bytes() -> u64 {
    crate::doctor::recommended_active_memory_budget_bytes()
        .unwrap_or(4 * 1024 * 1024 * 1024)
        .clamp(
            MIN_ADDRESS_SPACE_LIMIT_MB * 1024 * 1024,
            MAX_ADDRESS_SPACE_LIMIT_MB * 1024 * 1024,
        )
}

fn configured_address_space_limit_bytes() -> u64 {
    let budget = if let Ok(value) = std::env::var("LAYERFAULT_BEHAVIOUR_ADDRESS_SPACE_MB") {
        if let Ok(mb) = value.parse::<u64>() {
            mb.clamp(MIN_ADDRESS_SPACE_LIMIT_MB, MAX_ADDRESS_SPACE_LIMIT_MB)
                .saturating_mul(1024 * 1024)
        } else {
            configured_memory_budget_bytes()
        }
    } else {
        configured_memory_budget_bytes()
    };
    // RLIMIT_AS constrains virtual address space, not resident memory. Keep it
    // above the conservative physical-memory admission budget so runtimes such
    // as PyTorch can map shared libraries/arenas without being rejected purely
    // because of virtual mappings, while still bounding runaway allocation.
    let expanded = (budget.saturating_mul(3) / 2).saturating_add(512 * 1024 * 1024);
    expanded.clamp(
        MIN_ADDRESS_SPACE_LIMIT_MB * 1024 * 1024,
        MAX_ADDRESS_SPACE_LIMIT_MB * 1024 * 1024,
    )
}

fn active_target_bytes(path: &Path) -> Result<u64> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("unable to inspect active target '{}'", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("active target may not be a symlink");
    }
    if metadata.is_file() {
        return Ok(metadata.len());
    }
    if !metadata.is_dir() {
        bail!("active target must be a regular file or directory");
    }
    let mut total = 0_u64;
    let mut entries = 0_usize;
    for entry in walkdir::WalkDir::new(path).follow_links(false) {
        let entry = entry.with_context(|| format!("unable to enumerate '{}'", path.display()))?;
        entries = entries.saturating_add(1);
        if entries > ACTIVE_MODEL_ENTRY_LIMIT {
            bail!(
                "active target contains too many filesystem entries for bounded memory preflight"
            );
        }
        if entry.file_type().is_symlink() {
            bail!(
                "active target contains symlink '{}', which is not allowed",
                entry.path().display()
            );
        }
        let metadata = entry.metadata()?;
        if metadata.is_file() {
            total = total.saturating_add(metadata.len());
        }
    }
    Ok(total)
}

#[cfg(unix)]
fn pinned_active_target_bytes(file: &File, display_path: &Path) -> Result<u64> {
    use std::os::fd::AsRawFd;

    let metadata = file.metadata().with_context(|| {
        format!(
            "unable to inspect active target '{}'",
            display_path.display()
        )
    })?;
    if metadata.is_file() {
        return Ok(metadata.len());
    }
    if !metadata.is_dir() {
        bail!("active target must be a regular file or directory");
    }
    let descriptor_path = PathBuf::from(format!("/proc/self/fd/{}/.", file.as_raw_fd()));
    active_target_bytes(&descriptor_path)
}

#[cfg(not(unix))]
fn pinned_active_target_bytes(_file: &File, _display_path: &Path) -> Result<u64> {
    bail!("descriptor-pinned behavioural sandbox inputs require Unix")
}

fn estimated_runtime_memory_bytes(
    runtime: &Path,
    model: &File,
    model_path: &Path,
    base: Option<(&File, &Path)>,
) -> Result<u64> {
    let model_bytes = pinned_active_target_bytes(model, model_path)?;
    let base_bytes = base
        .map(|(file, path)| pinned_active_target_bytes(file, path))
        .transpose()?
        .unwrap_or(0);
    let weights = model_bytes.saturating_add(base_bytes);
    let runtime_name = runtime
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let (numerator, denominator, overhead) = if runtime_name.contains("python") {
        // Transformers frequently materializes weights plus allocator/runtime
        // state beyond the serialized file size. Stay conservative on small
        // CPU-only hosts: a skipped active run is safer than host OOM.
        (2_u64, 1_u64, 1024_u64 * 1024 * 1024)
    } else {
        (5_u64, 4_u64, 768_u64 * 1024 * 1024)
    };
    Ok((weights.saturating_mul(numerator) / denominator).saturating_add(overhead))
}

fn ensure_active_target_fits(
    runtime: &Path,
    model: &File,
    model_path: &Path,
    base: Option<(&File, &Path)>,
) -> Result<()> {
    let budget = configured_memory_budget_bytes();
    let estimate = estimated_runtime_memory_bytes(runtime, model, model_path, base)?;
    if estimate > budget {
        bail!(
            "active analysis skipped: estimated runtime memory {:.1} GiB exceeds safe host budget {:.1} GiB; static analysis remains available (override with LAYERFAULT_BEHAVIOUR_MEMORY_MB only when the host can safely support it)",
            estimate as f64 / 1073741824.0,
            budget as f64 / 1073741824.0
        );
    }
    Ok(())
}

pub struct SandboxedCommand {
    pub command: std::process::Command,
    pub model_argument: PathBuf,
    pub base_argument: Option<PathBuf>,
    pub runtime_support_arguments: Vec<PathBuf>,
    pub trace_enabled: bool,
    pub pinned_inputs: Vec<File>,
}

#[cfg(unix)]
fn pin_active_path(path: &Path) -> Result<File> {
    let file = File::open(path)
        .with_context(|| format!("unable to pin active path '{}'", path.display()))?;
    // Clearing CLOEXEC is required because prlimit/strace may exec before
    // bwrap consumes the descriptor; `SandboxedCommand` keeps it alive.
    let mut flags = rustix::io::fcntl_getfd(&file)?;
    flags.remove(rustix::io::FdFlags::CLOEXEC);
    rustix::io::fcntl_setfd(&file, flags)
        .context("unable to make pinned sandbox input inheritable")?;
    Ok(file)
}

#[cfg(not(unix))]
fn pin_active_path(_path: &Path) -> Result<File> {
    bail!("descriptor-pinned behavioural sandbox inputs require Unix")
}

#[cfg(unix)]
fn pinned_fd(file: &File) -> std::ffi::OsString {
    use std::os::fd::AsRawFd;
    file.as_raw_fd().to_string().into()
}

#[cfg(not(unix))]
fn pinned_fd(_file: &File) -> std::ffi::OsString {
    "unsupported".into()
}

#[allow(clippy::too_many_arguments)]
pub fn command_for(
    runtime: &Path,
    model: &Path,
    base: Option<&Path>,
    runtime_support: &[PathBuf],
    workspace: &Workspace,
    wrapper: Option<&(PathBuf, String)>,
    timeout_seconds: u64,
) -> Result<SandboxedCommand> {
    let Some((bwrap, mechanism)) = wrapper else {
        bail!("strong behavioural sandbox is unavailable; install bubblewrap (bwrap) rather than exposing the host filesystem/network");
    };
    if !mechanism.starts_with("bwrap-fs-net") {
        bail!("unsupported behavioural sandbox mechanism '{mechanism}'");
    }

    let canonical_runtime = std::fs::canonicalize(runtime)
        .with_context(|| format!("unable to canonicalize runtime '{}'", runtime.display()))?;
    let canonical_model = std::fs::canonicalize(model)
        .with_context(|| format!("unable to canonicalize model '{}'", model.display()))?;
    let canonical_base = base
        .map(std::fs::canonicalize)
        .transpose()
        .context("unable to canonicalize behavioural base model")?;
    let pinned_runtime = pin_active_path(&canonical_runtime)?;
    let pinned_model = pin_active_path(&canonical_model)?;
    let pinned_base = canonical_base.as_deref().map(pin_active_path).transpose()?;
    ensure_active_target_fits(
        &canonical_runtime,
        &pinned_model,
        &canonical_model,
        pinned_base.as_ref().zip(canonical_base.as_deref()),
    )?;
    let mut canonical_runtime_support = Vec::new();
    let mut pinned_runtime_support = Vec::new();
    for path in runtime_support {
        let canonical = std::fs::canonicalize(path).with_context(|| {
            format!(
                "unable to canonicalize runtime support path '{}'",
                path.display()
            )
        })?;
        if !canonical.is_dir() {
            bail!(
                "runtime support path '{}' must resolve to a directory",
                path.display()
            );
        }
        canonical_runtime_support.push(canonical);
        pinned_runtime_support.push(pin_active_path(
            canonical_runtime_support
                .last()
                .expect("path was just pushed"),
        )?);
    }

    let model_argument = if canonical_model.is_dir() {
        PathBuf::from("/model/package")
    } else {
        PathBuf::from("/model/artifact")
    };
    let base_argument = canonical_base.as_ref().map(|path| {
        if path.is_dir() {
            PathBuf::from("/base/package")
        } else {
            PathBuf::from("/base/artifact")
        }
    });

    let mut bwrap_args: Vec<std::ffi::OsString> = vec![
        "--unshare-net".into(),
        "--unshare-pid".into(),
        "--unshare-ipc".into(),
        "--unshare-uts".into(),
        "--unshare-cgroup-try".into(),
        "--die-with-parent".into(),
        "--new-session".into(),
        "--cap-drop".into(),
        "ALL".into(),
        "--proc".into(),
        "/proc".into(),
        "--dev".into(),
        "/dev".into(),
        "--tmpfs".into(),
        "/tmp".into(),
        "--dir".into(),
        "/workspace".into(),
        "--bind".into(),
        workspace.root.as_os_str().to_owned(),
        "/workspace".into(),
        "--dir".into(),
        "/model".into(),
        "--ro-bind-fd".into(),
        pinned_fd(&pinned_model),
        model_argument.as_os_str().to_owned(),
        "--ro-bind-fd".into(),
        pinned_fd(&pinned_runtime),
        "/runtime".into(),
    ];
    if let (Some(base), Some(argument)) = (pinned_base.as_ref(), base_argument.as_ref()) {
        bwrap_args.extend([
            "--dir".into(),
            "/base".into(),
            "--ro-bind-fd".into(),
            pinned_fd(base),
            argument.as_os_str().to_owned(),
        ]);
    }
    let mut runtime_support_arguments = Vec::new();
    if !canonical_runtime_support.is_empty() {
        bwrap_args.extend(["--dir".into(), "/runtime-support".into()]);
        for (index, support) in pinned_runtime_support.iter().enumerate() {
            let argument = PathBuf::from(format!("/runtime-support/{index}"));
            bwrap_args.extend([
                "--dir".into(),
                argument.as_os_str().to_owned(),
                "--ro-bind-fd".into(),
                pinned_fd(support),
                argument.as_os_str().to_owned(),
            ]);
            runtime_support_arguments.push(argument);
        }
    }

    // Dynamic runtimes need their standard libraries. User homes, arbitrary
    // mounts, repository roots and host configuration remain hidden.
    for directory in ["/usr/lib", "/usr/lib64", "/usr/local/lib", "/lib", "/lib64"] {
        if Path::new(directory).exists() {
            bwrap_args.extend(["--ro-bind".into(), directory.into(), directory.into()]);
        }
    }
    for file in ["/etc/ld.so.cache", "/etc/ld.so.conf"] {
        if Path::new(file).is_file() {
            bwrap_args.extend(["--ro-bind".into(), file.into(), file.into()]);
        }
    }
    if Path::new("/etc/ld.so.conf.d").is_dir() {
        bwrap_args.extend([
            "--ro-bind".into(),
            "/etc/ld.so.conf.d".into(),
            "/etc/ld.so.conf.d".into(),
        ]);
    }
    bwrap_args.extend([
        "--setenv".into(),
        "HOME".into(),
        "/workspace/home".into(),
        "--setenv".into(),
        "TMPDIR".into(),
        "/tmp".into(),
        "--setenv".into(),
        "HF_HUB_OFFLINE".into(),
        "1".into(),
        "--setenv".into(),
        "TRANSFORMERS_OFFLINE".into(),
        "1".into(),
        "--setenv".into(),
        "TOKENIZERS_PARALLELISM".into(),
        "false".into(),
        "--setenv".into(),
        "PYTHONDONTWRITEBYTECODE".into(),
        "1".into(),
        "--chdir".into(),
        "/workspace/workspace".into(),
        "--".into(),
        "/runtime".into(),
    ]);

    let trace = crate::sources::find_executable("strace");
    let prlimit = crate::sources::find_executable("prlimit");
    let mut command;
    if let Some(prlimit_path) = prlimit {
        command = crate::safeio::command_for_executable(&prlimit_path)?;
        command
            .arg(format!(
                "--cpu={}",
                timeout_seconds.saturating_add(10).max(10)
            ))
            .arg(format!("--as={}", configured_address_space_limit_bytes()))
            .arg("--fsize=67108864")
            .arg("--nofile=256")
            .arg("--core=0")
            .arg("--");
        if let Some(strace_path) = trace.as_ref() {
            append_strace(&mut command, strace_path, workspace);
        }
        command.arg(bwrap);
    } else if let Some(strace_path) = trace.as_ref() {
        command = crate::safeio::command_for_executable(strace_path)?;
        append_strace_args(&mut command, workspace);
        command.arg(bwrap);
    } else {
        command = crate::safeio::command_for_executable(bwrap)?;
    }
    command.args(bwrap_args);
    configure_process_group(&mut command);

    let mut pinned_inputs = vec![pinned_runtime, pinned_model];
    if let Some(base) = pinned_base {
        pinned_inputs.push(base);
    }
    pinned_inputs.extend(pinned_runtime_support);
    Ok(SandboxedCommand {
        command,
        model_argument,
        base_argument,
        runtime_support_arguments,
        trace_enabled: trace.is_some(),
        pinned_inputs,
    })
}

fn append_strace(command: &mut std::process::Command, strace: &Path, workspace: &Workspace) {
    command.arg(strace);
    append_strace_args(command, workspace);
}

fn append_strace_args(command: &mut std::process::Command, workspace: &Workspace) {
    command
        .arg("-ff")
        .arg("-qq")
        .arg("-s")
        .arg("1024")
        .arg("-e")
        .arg("trace=%file,%process,%network")
        .arg("-o")
        .arg(workspace.trace_prefix());
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
        for line in text.lines() {
            classify_trace_line(line, telemetry);
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

fn classify_trace_line(line: &str, telemetry: &mut SandboxTelemetry) {
    let lower = line.to_ascii_lowercase();
    if (lower.contains("connect(") || lower.contains("sendto(") || lower.contains("sendmsg("))
        && telemetry.network_attempts.len() < MAX_TELEMETRY_ROWS
    {
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
    if (write_like || mutate_like) && telemetry.filesystem_write_attempts.len() < MAX_TELEMETRY_ROWS
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

    let canary = [
        "/workspace/home/.ssh/",
        "/workspace/workspace/.env",
        "/workspace/workspace/secrets/",
    ]
    .iter()
    .any(|needle| lower.contains(needle));
    if canary && telemetry.canary_accesses.len() < MAX_TELEMETRY_ROWS {
        telemetry.canary_accesses.push(excerpt(line));
    }

    let sensitive = [
        "/etc/shadow",
        "/root/",
        "/proc/self/environ",
        "/proc/1/environ",
        "/.ssh/",
    ]
    .iter()
    .any(|needle| lower.contains(needle));
    if sensitive && telemetry.sensitive_path_accesses.len() < MAX_TELEMETRY_ROWS {
        telemetry.sensitive_path_accesses.push(excerpt(line));
    }
}

fn excerpt(value: &str) -> String {
    let mut out: String = value.chars().take(512).collect();
    if value.chars().count() > 512 {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn active_target_preflight_rejects_nested_symlinks() -> Result<()> {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir()?;
        let outside = tempfile::NamedTempFile::new()?;
        symlink(outside.path(), root.path().join("weights.bin"))?;
        let error = active_target_bytes(root.path()).unwrap_err();
        assert!(error.to_string().contains("contains symlink"));
        let pinned = pin_active_path(root.path())?;
        let error = pinned_active_target_bytes(&pinned, root.path()).unwrap_err();
        assert!(error.to_string().contains("contains symlink"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn pinned_active_input_survives_path_replacement() -> Result<()> {
        use std::io::{Read as _, Seek as _, SeekFrom};

        let root = tempfile::tempdir()?;
        let path = root.path().join("model.bin");
        std::fs::write(&path, b"admitted")?;
        let mut pinned = pin_active_path(&path)?;
        std::fs::rename(&path, root.path().join("old.bin"))?;
        std::fs::write(&path, b"replacement")?;
        pinned.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        pinned.read_to_end(&mut bytes)?;
        assert_eq!(bytes, b"admitted");
        Ok(())
    }

    #[test]
    fn trace_classification_detects_network_exec_and_canary_access() {
        let mut telemetry = SandboxTelemetry::default();
        classify_trace_line(
            r#"connect(7, {sa_family=AF_INET, sin_port=htons(443)}, 16) = -1 ENETUNREACH"#,
            &mut telemetry,
        );
        classify_trace_line(r#"execve("/bin/sh", ["sh"], 0x0) = 0"#, &mut telemetry);
        classify_trace_line(
            r#"openat(AT_FDCWD, "/workspace/workspace/.env", O_RDONLY) = 4"#,
            &mut telemetry,
        );
        classify_trace_line(
            r#"openat(AT_FDCWD, "/model/package/config.json", O_WRONLY|O_TRUNC) = -1 EROFS"#,
            &mut telemetry,
        );
        classify_trace_line(
            r#"openat(AT_FDCWD, "/proc/self/mem", O_WRONLY) = -1 EACCES"#,
            &mut telemetry,
        );
        classify_trace_line(
            r#"openat(AT_FDCWD, "/tmp/dropper", O_WRONLY|O_CREAT) = 4"#,
            &mut telemetry,
        );
        assert_eq!(telemetry.network_attempts.len(), 1);
        assert_eq!(telemetry.process_exec_attempts.len(), 1);
        assert_eq!(telemetry.canary_accesses.len(), 1);
        assert_eq!(telemetry.filesystem_write_attempts.len(), 3);
    }

    #[test]
    fn only_the_first_runtime_exec_is_treated_as_expected() {
        let mut telemetry = SandboxTelemetry::default();
        classify_trace_line(
            r#"execve("/runtime", ["/runtime", "runner.py"], 0x0) = 0"#,
            &mut telemetry,
        );
        classify_trace_line(
            r#"execve("/runtime", ["/runtime", "-c", "payload"], 0x0) = 0"#,
            &mut telemetry,
        );
        discard_one_expected_runtime_exec(&mut telemetry);
        assert_eq!(telemetry.process_exec_attempts.len(), 1);
    }

    #[test]
    fn expected_runtime_artifacts_are_separated_from_unexpected_mutations() {
        assert!(expected_runtime_artifact("home/.cache/huggingface/x"));
        assert!(!expected_runtime_artifact("workspace/dropper.sh"));
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

    #[cfg(target_os = "linux")]
    #[test]
    fn timeout_teardown_kills_sigterm_ignoring_descendant() -> Result<()> {
        let root =
            std::env::temp_dir().join(format!("layerfault-process-tree-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root)?;
        let pidfile = root.join("child.pid");
        let mut command = Command::new("sh");
        command.arg("-c").arg(format!(
            "trap '' TERM; (trap '' TERM; while :; do sleep 1; done) & echo $! > '{}'; while :; do sleep 1; done",
            pidfile.display()
        ));
        configure_process_group(&mut command);
        let mut child = command.spawn()?;
        let started = Instant::now();
        while !pidfile.is_file() && started.elapsed() < Duration::from_secs(2) {
            std::thread::sleep(Duration::from_millis(20));
        }
        let descendant: u32 = std::fs::read_to_string(&pidfile)?.trim().parse()?;
        terminate_process_tree(&mut child, Duration::from_millis(100))?;
        assert!(child.try_wait()?.is_some());
        let proc_stat = std::fs::read_to_string(format!("/proc/{descendant}/stat")).ok();
        if let Some(stat) = proc_stat {
            let state = stat
                .rsplit_once(')')
                .and_then(|(_, tail)| tail.split_whitespace().next());
            assert_eq!(
                state,
                Some("Z"),
                "descendant remained live after teardown: {stat}"
            );
        }
        let _ = std::fs::remove_dir_all(root);
        Ok(())
    }
}
