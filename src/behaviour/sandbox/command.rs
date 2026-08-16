use super::limits::{configured_address_space_limit_bytes, ensure_active_target_fits};
use super::process::configure_process_group;
use super::seccomp::seccomp_filter_file;
use super::telemetry::Workspace;
use anyhow::{bail, Context, Result};
use std::fs::File;
use std::path::{Path, PathBuf};

pub struct SandboxedCommand {
    pub command: std::process::Command,
    pub model_argument: PathBuf,
    pub base_argument: Option<PathBuf>,
    pub runtime_support_arguments: Vec<PathBuf>,
    pub trace_enabled: bool,
    pub pinned_inputs: Vec<File>,
}

#[cfg(unix)]
pub(crate) fn pin_active_path(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    options.custom_flags(libc::O_NOFOLLOW);
    let file = options
        .open(path)
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
pub(crate) fn pin_active_path(_path: &Path) -> Result<File> {
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
    let seccomp_filter = seccomp_filter_file()?;
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
        "--seccomp".into(),
        pinned_fd(&seccomp_filter),
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

    let mut pinned_inputs = vec![pinned_runtime, pinned_model, seccomp_filter];
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
