use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxCapabilities {
    pub workspace_isolated: bool,
    pub home_isolated: bool,
    pub environment_scrubbed: bool,
    pub network_isolation: bool,
    pub network_mechanism: Option<String>,
    pub host_files_hidden: bool,
    pub real_tools_disabled: bool,
}

#[derive(Debug)]
pub struct Workspace {
    pub root: PathBuf,
    pub home: PathBuf,
}

impl Workspace {
    pub fn create() -> Result<Self> {
        let nonce = format!(
            "{}-{}-{}",
            std::process::id(),
            crate::paths::now_unix(),
            std::thread::current()
                .name()
                .unwrap_or("worker")
                .replace('/', "_")
        );
        let root = std::env::temp_dir().join(format!("layerfault-behaviour-{nonce}"));
        let home = root.join("home");
        crate::paths::ensure_private_dir(&home)?;
        crate::paths::ensure_private_dir(&root.join("workspace"))?;
        std::fs::write(
            root.join("workspace").join("README.txt"),
            b"Synthetic Layerfault behavioural workspace. No host credentials are intentionally placed here.\n",
        )?;
        Ok(Self { root, home })
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Return a sandbox launcher only when it can provide both a private filesystem
/// view and a private network namespace. `unshare -n` alone is intentionally not
/// accepted because it would still expose the host filesystem to an adversarial
/// inference process.
pub fn detect_network_wrapper() -> Option<(PathBuf, String)> {
    #[cfg(target_os = "linux")]
    {
        if let Some(path) = crate::sources::find_executable("bwrap") {
            return Some((path, "bwrap-fs-net".to_owned()));
        }
    }
    None
}

pub fn capabilities(wrapper: Option<&(PathBuf, String)>) -> SandboxCapabilities {
    let strong = wrapper.is_some_and(|(_, mechanism)| mechanism == "bwrap-fs-net");
    SandboxCapabilities {
        workspace_isolated: true,
        home_isolated: true,
        environment_scrubbed: true,
        network_isolation: strong,
        network_mechanism: wrapper.map(|value| value.1.clone()),
        host_files_hidden: strong,
        real_tools_disabled: true,
    }
}

pub struct SandboxedCommand {
    pub command: std::process::Command,
    pub model_argument: PathBuf,
}

pub fn command_for(
    runtime: &Path,
    model: &Path,
    workspace: &Workspace,
    wrapper: Option<&(PathBuf, String)>,
) -> Result<SandboxedCommand> {
    match wrapper {
        Some((path, mechanism)) if mechanism == "bwrap-fs-net" => {
            let canonical_runtime = std::fs::canonicalize(runtime).with_context(|| {
                format!("unable to canonicalize runtime '{}'", runtime.display())
            })?;
            let canonical_model = std::fs::canonicalize(model)
                .with_context(|| format!("unable to canonicalize model '{}'", model.display()))?;
            let mut command = std::process::Command::new(path);
            command
                .arg("--unshare-net")
                .arg("--die-with-parent")
                .arg("--new-session")
                .arg("--proc")
                .arg("/proc")
                .arg("--dev")
                .arg("/dev")
                .arg("--tmpfs")
                .arg("/tmp")
                .arg("--dir")
                .arg("/workspace")
                .arg("--bind")
                .arg(&workspace.root)
                .arg("/workspace")
                .arg("--ro-bind")
                .arg(&canonical_model)
                .arg("/model.gguf")
                .arg("--ro-bind")
                .arg(&canonical_runtime)
                .arg("/runtime");

            // Dynamic llama.cpp builds need the host runtime libraries. Expose
            // only standard runtime/library trees, not user homes, mounts or the
            // repository/model source directory.
            for directory in ["/usr", "/lib", "/lib64", "/bin"] {
                if Path::new(directory).exists() {
                    command.arg("--ro-bind").arg(directory).arg(directory);
                }
            }
            for file in ["/etc/ld.so.cache", "/etc/ld.so.conf"] {
                if Path::new(file).is_file() {
                    command.arg("--ro-bind").arg(file).arg(file);
                }
            }
            if Path::new("/etc/ld.so.conf.d").is_dir() {
                command
                    .arg("--ro-bind")
                    .arg("/etc/ld.so.conf.d")
                    .arg("/etc/ld.so.conf.d");
            }
            command
                .arg("--setenv")
                .arg("HOME")
                .arg("/workspace/home")
                .arg("--setenv")
                .arg("TMPDIR")
                .arg("/tmp")
                .arg("--chdir")
                .arg("/workspace/workspace")
                .arg("--")
                .arg("/runtime");
            Ok(SandboxedCommand {
                command,
                model_argument: PathBuf::from("/model.gguf"),
            })
        }
        _ => {
            #[cfg(target_os = "linux")]
            bail!("strong behavioural sandbox is unavailable; install bubblewrap (bwrap) rather than exposing the host filesystem/network");
            #[cfg(not(target_os = "linux"))]
            {
                let command = std::process::Command::new(runtime);
                Ok(SandboxedCommand {
                    command,
                    model_argument: model.to_path_buf(),
                })
            }
        }
    }
}
