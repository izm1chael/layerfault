use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

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
}

impl SandboxTelemetry {
    pub fn suspicious(&self) -> bool {
        !self.filesystem_write_attempts.is_empty()
            || !self.network_attempts.is_empty()
            || !self.process_exec_attempts.is_empty()
            || !self.sensitive_path_accesses.is_empty()
            || !self.canary_accesses.is_empty()
            || self
                .filesystem_mutations
                .iter()
                .any(|value| !value.expected_runtime_artifact)
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

#[derive(Debug)]
pub struct Workspace {
    pub root: PathBuf,
    pub home: PathBuf,
    telemetry_root: PathBuf,
    baseline: BTreeMap<String, SnapshotEntry>,
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
            ..SandboxTelemetry::default()
        };

        let mut paths: BTreeSet<String> = self.baseline.keys().cloned().collect();
        paths.extend(current.keys().cloned());
        for path in paths {
            let before = self.baseline.get(&path);
            let after = current.get(&path);
            let kind = match (before, after) {
                (None, Some(_)) => Some("CREATED"),
                (Some(_), None) => Some("DELETED"),
                (Some(a), Some(b)) if a.len != b.len || a.modified_ns != b.modified_ns => {
                    Some("MODIFIED")
                }
                _ => None,
            };
            if let Some(kind) = kind {
                telemetry.filesystem_mutations.push(FileMutation {
                    expected_runtime_artifact: expected_runtime_artifact(&path),
                    path,
                    kind: kind.to_owned(),
                });
            }
        }
        telemetry.filesystem_mutations.truncate(MAX_TELEMETRY_ROWS);

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
    if let Ok(value) = std::env::var("LAYERFAULT_BEHAVIOUR_ADDRESS_SPACE_MB") {
        if let Ok(mb) = value.parse::<u64>() {
            return mb
                .clamp(MIN_ADDRESS_SPACE_LIMIT_MB, MAX_ADDRESS_SPACE_LIMIT_MB)
                .saturating_mul(1024 * 1024);
        }
    }
    let budget = configured_memory_budget_bytes();
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
            continue;
        }
        let metadata = entry.metadata()?;
        if metadata.is_file() {
            total = total.saturating_add(metadata.len());
        }
    }
    Ok(total)
}

fn estimated_runtime_memory_bytes(
    runtime: &Path,
    model: &Path,
    base: Option<&Path>,
) -> Result<u64> {
    let model_bytes = active_target_bytes(model)?;
    let base_bytes = base.map(active_target_bytes).transpose()?.unwrap_or(0);
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

fn ensure_active_target_fits(runtime: &Path, model: &Path, base: Option<&Path>) -> Result<()> {
    let budget = configured_memory_budget_bytes();
    let estimate = estimated_runtime_memory_bytes(runtime, model, base)?;
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
    ensure_active_target_fits(&canonical_runtime, model, base)?;
    let canonical_model = std::fs::canonicalize(model)
        .with_context(|| format!("unable to canonicalize model '{}'", model.display()))?;
    let canonical_base = base
        .map(std::fs::canonicalize)
        .transpose()
        .context("unable to canonicalize behavioural base model")?;
    let mut canonical_runtime_support = Vec::new();
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
        "--ro-bind".into(),
        canonical_model.as_os_str().to_owned(),
        model_argument.as_os_str().to_owned(),
        "--ro-bind".into(),
        canonical_runtime.as_os_str().to_owned(),
        "/runtime".into(),
    ];
    if let (Some(base), Some(argument)) = (canonical_base.as_ref(), base_argument.as_ref()) {
        bwrap_args.extend([
            "--dir".into(),
            "/base".into(),
            "--ro-bind".into(),
            base.as_os_str().to_owned(),
            argument.as_os_str().to_owned(),
        ]);
    }
    let mut runtime_support_arguments = Vec::new();
    if !canonical_runtime_support.is_empty() {
        bwrap_args.extend(["--dir".into(), "/runtime-support".into()]);
        for (index, support) in canonical_runtime_support.iter().enumerate() {
            let argument = PathBuf::from(format!("/runtime-support/{index}"));
            bwrap_args.extend([
                "--dir".into(),
                argument.as_os_str().to_owned(),
                "--ro-bind".into(),
                support.as_os_str().to_owned(),
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
            .arg("--nproc=128")
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

    Ok(SandboxedCommand {
        command,
        model_argument,
        base_argument,
        runtime_support_arguments,
        trace_enabled: trace.is_some(),
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

fn snapshot_tree(root: &Path) -> Result<BTreeMap<String, SnapshotEntry>> {
    let mut out = BTreeMap::new();
    for entry in walkdir::WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(|entry| entry.ok())
    {
        if out.len() >= MAX_SNAPSHOT_FILES {
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
    Ok(out)
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
    let protected_target = ["/model/", "/base/", "/etc/", "/root/", "/usr/", "/lib/"]
        .iter()
        .any(|path| lower.contains(path));
    if (write_like || mutate_like)
        && protected_target
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
        assert_eq!(telemetry.network_attempts.len(), 1);
        assert_eq!(telemetry.process_exec_attempts.len(), 1);
        assert_eq!(telemetry.canary_accesses.len(), 1);
        assert_eq!(telemetry.filesystem_write_attempts.len(), 1);
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
}
