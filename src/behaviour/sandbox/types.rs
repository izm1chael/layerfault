use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SandboxKind {
    #[default]
    Bwrap,
    Microvm,
}

impl std::fmt::Display for SandboxKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bwrap => write!(f, "bwrap"),
            Self::Microvm => write!(f, "microvm"),
        }
    }
}

impl std::str::FromStr for SandboxKind {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "bwrap" | "bubblewrap" => Ok(Self::Bwrap),
            "microvm" | "vm" | "firecracker" | "qemu" => Ok(Self::Microvm),
            other => bail!("unsupported sandbox kind '{other}' (expected 'bwrap' or 'microvm')"),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SandboxCapabilities {
    pub sandbox_kind: SandboxKind,
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
    /// Whether Layerfault's seccomp-bpf kernel-attack-surface filter is active.
    pub seccomp_filter: bool,
    pub syscall_trace: bool,
    pub syscall_trace_mechanism: Option<String>,
    pub microvm_available: bool,
    pub microvm_kvm_accelerated: bool,
    pub microvm_hypervisor: Option<String>,
    pub microvm_image_hash: Option<String>,
    #[serde(default)]
    pub cgroup: crate::behaviour::cgroup::CgroupCapabilities,
}
