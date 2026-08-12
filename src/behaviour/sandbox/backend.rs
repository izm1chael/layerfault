use super::limits::configured_address_space_limit_bytes;
use super::seccomp::seccomp_filter_supported;
use super::types::{SandboxCapabilities, SandboxKind};
use crate::behaviour::ActiveExecutionOptions;
use anyhow::{bail, Result};
use std::path::PathBuf;

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
    let hypervisor = crate::behaviour::microvm::detect_hypervisor();
    let microvm_avail = hypervisor.is_some();
    let kvm = hypervisor
        .as_ref()
        .map(|h| h.kvm_available)
        .unwrap_or(false);

    SandboxCapabilities {
        sandbox_kind: SandboxKind::Bwrap,
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
        seccomp_filter: strong && seccomp_filter_supported(),
        syscall_trace: trace,
        syscall_trace_mechanism: trace.then_some("strace-file-process-network".to_owned()),
        microvm_available: microvm_avail,
        microvm_kvm_accelerated: kvm,
        microvm_hypervisor: hypervisor.map(|h| h.name),
        microvm_image_hash: None,
        cgroup: crate::behaviour::cgroup::detect_host_capabilities(),
    }
}

pub trait SandboxBackend: Send + Sync {
    fn kind(&self) -> SandboxKind;
    fn capabilities(&self) -> SandboxCapabilities;
    fn require_execution_stack(&self, active: ActiveExecutionOptions) -> Result<()>;
}

pub struct BwrapBackend;

impl SandboxBackend for BwrapBackend {
    fn kind(&self) -> SandboxKind {
        SandboxKind::Bwrap
    }

    fn capabilities(&self) -> SandboxCapabilities {
        capabilities(detect_network_wrapper().as_ref())
    }

    fn require_execution_stack(&self, active: ActiveExecutionOptions) -> Result<()> {
        require_external_execution_stack_options(&active)?;
        if active.allow_static_blocked || active.execute_custom_code {
            require_high_risk_observation_stack_options(&active)?;
        }
        Ok(())
    }
}

pub fn get_backend(
    kind: SandboxKind,
    microvm_config: crate::behaviour::microvm::MicrovmConfig,
) -> Box<dyn SandboxBackend> {
    match kind {
        SandboxKind::Bwrap => Box::new(BwrapBackend),
        SandboxKind::Microvm => Box::new(crate::behaviour::microvm::MicrovmBackend::new(
            microvm_config,
        )),
    }
}

/// Every external active execution requires namespace isolation and resource
/// limiting. This prevents a model/runtime failure from becoming a trivial
/// host memory/process/file-descriptor exhaustion path.
pub fn require_external_execution_stack() -> Result<()> {
    require_external_execution_stack_options(&ActiveExecutionOptions::default())
}

pub fn require_external_execution_stack_options(active: &ActiveExecutionOptions) -> Result<()> {
    if detect_network_wrapper().is_none() {
        bail!("external active analysis requires bubblewrap (bwrap)");
    }
    if crate::sources::find_executable("prlimit").is_none() {
        bail!("external active analysis requires prlimit so CPU/process/address-space limits are enforced");
    }
    if active.require_cgroup {
        let caps = crate::behaviour::cgroup::detect_host_capabilities();
        if !caps.cgroup_v2
            || !caps.delegated_writable
            || !caps.memory_controller
            || !caps.pids_controller
            || !caps.cpu_controller
        {
            bail!(
                "require_cgroup policy enforced but cgroup v2 is unavailable or missing required controllers: {}",
                caps.unavailable_reason.unwrap_or_else(|| "cgroup v2 unavailable".to_owned())
            );
        }
    }
    Ok(())
}

/// High-risk active analysis (executing statically blocked packages or custom
/// Hugging Face loader code) additionally requires syscall telemetry. Failing
/// closed here prevents a missing lab dependency from silently degrading a
/// hostile-code run.
pub fn require_high_risk_observation_stack() -> Result<()> {
    require_high_risk_observation_stack_options(&ActiveExecutionOptions::default())
}

pub fn require_high_risk_observation_stack_options(active: &ActiveExecutionOptions) -> Result<()> {
    require_external_execution_stack_options(active)?;
    if crate::sources::find_executable("strace").is_none() {
        bail!("high-risk active analysis requires strace so loader/runtime side effects are observable");
    }
    Ok(())
}
