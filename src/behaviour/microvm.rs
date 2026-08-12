//! MicroVM isolation backend for active behavioural analysis.
//!
//! Provides hypervisor-enforced VM isolation (via Firecracker or QEMU/KVM)
//! for active analysis of high-risk statically BLOCKed packages and custom code.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::behaviour::sandbox::{SandboxCapabilities, SandboxKind, SandboxTelemetry};
use crate::behaviour::ActiveExecutionOptions;

pub const GUEST_PROTOCOL_VERSION: &str = "v1";
pub const MAX_GUEST_RESPONSE_BYTES: usize = 16 * 1024 * 1024; // 16 MB protocol limit

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MicrovmConfig {
    pub image_path: Option<PathBuf>,
    pub expected_image_hash: Option<String>,
    pub vcpu_count: Option<u32>,
    pub memory_mb: Option<u64>,
}

impl MicrovmConfig {
    pub fn from_env_and_args(
        image_path: Option<PathBuf>,
        expected_image_hash: Option<String>,
    ) -> Self {
        let image_path =
            image_path.or_else(|| std::env::var_os("LAYERFAULT_MICROVM_IMAGE").map(PathBuf::from));
        let expected_image_hash =
            expected_image_hash.or_else(|| std::env::var("LAYERFAULT_MICROVM_IMAGE_HASH").ok());
        let vcpu_count = std::env::var("LAYERFAULT_MICROVM_VCPUS")
            .ok()
            .and_then(|v| v.parse().ok());
        let memory_mb = std::env::var("LAYERFAULT_MICROVM_MEMORY_MB")
            .ok()
            .and_then(|v| v.parse().ok());
        Self {
            image_path,
            expected_image_hash,
            vcpu_count,
            memory_mb,
        }
    }

    pub fn resolve_image(&self) -> Result<(PathBuf, String)> {
        let Some(path) = &self.image_path else {
            bail!("microVM active analysis requires a configured guest image path (use --microvm-image or set LAYERFAULT_MICROVM_IMAGE)");
        };
        if !path.exists() {
            bail!(
                "configured microVM guest image '{}' does not exist",
                path.display()
            );
        }
        if !path.is_file() {
            bail!(
                "configured microVM guest image '{}' must be a regular file",
                path.display()
            );
        }
        let canonical = std::fs::canonicalize(path).with_context(|| {
            format!(
                "unable to canonicalize microVM guest image '{}'",
                path.display()
            )
        })?;

        let hash = crate::safeio::sha256_path(&canonical).with_context(|| {
            format!(
                "unable to calculate SHA-256 for microVM guest image '{}'",
                canonical.display()
            )
        })?;

        if let Some(expected) = &self.expected_image_hash {
            let expected_clean = expected.trim().to_ascii_lowercase();
            if hash != expected_clean {
                bail!(
                    "microVM guest image SHA-256 hash mismatch for '{}': expected {}, calculated {}",
                    canonical.display(),
                    expected_clean,
                    hash
                );
            }
        }
        Ok((canonical, hash))
    }
}

/// Hypervisor execution info detected on the host system.
#[derive(Debug, Clone)]
pub struct HypervisorInfo {
    pub name: String,
    pub executable: PathBuf,
    pub kvm_available: bool,
}

pub fn detect_hypervisor() -> Option<HypervisorInfo> {
    let kvm_available = Path::new("/dev/kvm").exists()
        && std::fs::metadata("/dev/kvm")
            .map(|m| !m.permissions().readonly())
            .unwrap_or(false);

    if let Some(fc_path) = crate::sources::find_executable("firecracker") {
        return Some(HypervisorInfo {
            name: "firecracker".to_string(),
            executable: fc_path,
            kvm_available,
        });
    }

    let qemu_bin = if cfg!(target_arch = "x86_64") {
        "qemu-system-x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "qemu-system-aarch64"
    } else {
        "qemu-system"
    };

    if let Some(qemu_path) = crate::sources::find_executable(qemu_bin) {
        return Some(HypervisorInfo {
            name: "qemu-kvm".to_string(),
            executable: qemu_path,
            kvm_available,
        });
    }

    None
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostExecutionRequest {
    pub protocol_version: String,
    pub staged_package_fingerprint: String,
    pub probe_suite_id: String,
    pub probe_prompts: Vec<GuestProbePromptPayload>,
    pub canary_a: String,
    pub canary_b: String,
    pub allow_static_blocked: bool,
    pub execute_custom_code: bool,
    pub resource_limits: MicrovmLimitsPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuestProbePromptPayload {
    pub id: String,
    pub category: String,
    pub prompt: String,
    pub max_tokens: usize,
    pub seed: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicrovmLimitsPayload {
    pub vcpu_count: u32,
    pub memory_mb: u64,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuestExecutionResponse {
    pub protocol_version: String,
    pub agent_version: String,
    pub guest_kernel_hash: Option<String>,
    pub runtime_identity: String,
    pub executions: Vec<GuestProbeExecutionPayload>,
    pub telemetry: SandboxTelemetry,
    pub exit_status: u32,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuestProbeExecutionPayload {
    pub probe_id: String,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    pub exit_code: i32,
    pub timed_out: bool,
}

/// Enforce protocol limits and deserialize guest response safely.
pub fn parse_guest_response(bytes: &[u8]) -> Result<GuestExecutionResponse> {
    if bytes.len() > MAX_GUEST_RESPONSE_BYTES {
        bail!(
            "microVM guest response size {} bytes exceeded max protocol limit of {} bytes",
            bytes.len(),
            MAX_GUEST_RESPONSE_BYTES
        );
    }
    let response: GuestExecutionResponse = serde_json::from_slice(bytes)
        .context("malformed guest protocol response JSON from microVM")?;
    if !response.protocol_version.starts_with("v1") {
        bail!(
            "unsupported microVM guest protocol version '{}': expected 'v1'",
            response.protocol_version
        );
    }
    Ok(response)
}

/// MicroVM Backend implementation of `SandboxBackend`.
pub struct MicrovmBackend {
    config: MicrovmConfig,
}

impl MicrovmBackend {
    pub fn new(config: MicrovmConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &MicrovmConfig {
        &self.config
    }
}

impl crate::behaviour::sandbox::SandboxBackend for MicrovmBackend {
    fn kind(&self) -> SandboxKind {
        SandboxKind::Microvm
    }

    fn capabilities(&self) -> SandboxCapabilities {
        let hypervisor = detect_hypervisor();
        let (image_avail, hash) = self
            .config
            .resolve_image()
            .map(|(_path, hash)| (true, Some(hash)))
            .unwrap_or((false, None));

        let available = hypervisor.is_some() && image_avail;
        let kvm = hypervisor
            .as_ref()
            .map(|h| h.kvm_available)
            .unwrap_or(false);

        SandboxCapabilities {
            sandbox_kind: SandboxKind::Microvm,
            workspace_isolated: available,
            home_isolated: available,
            environment_scrubbed: available,
            network_isolation: available,
            network_mechanism: hypervisor.as_ref().map(|h| format!("{}-kvm-vsock", h.name)),
            host_files_hidden: available,
            real_tools_disabled: available,
            process_namespace_isolated: available,
            ipc_namespace_isolated: available,
            uts_namespace_isolated: available,
            capabilities_dropped: available,
            resource_limits: available,
            address_space_limit_bytes: available
                .then(|| self.config.memory_mb.unwrap_or(2048) * 1024 * 1024),
            seccomp_filter: available,
            syscall_trace: available,
            syscall_trace_mechanism: available.then(|| "microvm-guest-agent-audit".to_string()),
            microvm_available: available,
            microvm_kvm_accelerated: kvm,
            microvm_hypervisor: hypervisor.map(|h| h.name),
            microvm_image_hash: hash,
            cgroup: crate::behaviour::cgroup::detect_host_capabilities(),
        }
    }

    fn require_execution_stack(&self, _active: ActiveExecutionOptions) -> Result<()> {
        let hypervisor = detect_hypervisor().ok_or_else(|| {
            anyhow!(
                "microVM active analysis requires a hypervisor binary (firecracker or qemu-system-x86_64) on PATH"
            )
        })?;

        if !hypervisor.kvm_available {
            bail!("microVM active analysis requires accessible hardware virtualization (/dev/kvm)");
        }

        // Resolving the image enforces exists, regular file, and SHA-256 match.
        let (_image_path, _hash) = self.config.resolve_image()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::behaviour::sandbox::SandboxBackend;

    #[test]
    fn test_microvm_unconfigured_image_fails_closed() {
        let config = MicrovmConfig::default();
        let result = config.resolve_image();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("microVM active analysis requires a configured guest image path"));
    }

    #[test]
    fn test_microvm_missing_file_fails_closed() {
        let config = MicrovmConfig {
            image_path: Some(PathBuf::from("/nonexistent/path/to/guest.ext4")),
            expected_image_hash: None,
            vcpu_count: None,
            memory_mb: None,
        };
        let result = config.resolve_image();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("does not exist"));
    }

    #[test]
    fn test_microvm_image_hash_verification() -> Result<()> {
        let temp_dir = std::env::temp_dir().join("layerfault_microvm_test");
        let _ = std::fs::create_dir_all(&temp_dir);
        let img_path = temp_dir.join("test_guest.img");
        std::fs::write(&img_path, b"synthetic microvm image bytes")?;

        let actual_hash = crate::safeio::sha256_path(&img_path)?;

        // Correct hash succeeds
        let valid_config = MicrovmConfig {
            image_path: Some(img_path.clone()),
            expected_image_hash: Some(actual_hash.clone()),
            vcpu_count: None,
            memory_mb: None,
        };
        let (path, hash) = valid_config.resolve_image()?;
        assert_eq!(path, std::fs::canonicalize(&img_path)?);
        assert_eq!(hash, actual_hash);

        // Mismatched hash fails closed
        let invalid_config = MicrovmConfig {
            image_path: Some(img_path.clone()),
            expected_image_hash: Some(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
            ),
            vcpu_count: None,
            memory_mb: None,
        };
        let err = invalid_config.resolve_image().unwrap_err().to_string();
        assert!(err.contains("SHA-256 hash mismatch"));

        let _ = std::fs::remove_dir_all(temp_dir);
        Ok(())
    }

    #[test]
    fn test_parse_guest_response_protocol_limits() -> Result<()> {
        // Valid response
        let valid_json = serde_json::to_vec(&GuestExecutionResponse {
            protocol_version: "v1".to_string(),
            agent_version: "1.0.0".to_string(),
            guest_kernel_hash: Some("sha256:abcd".to_string()),
            runtime_identity: "python-transformers".to_string(),
            executions: vec![],
            telemetry: SandboxTelemetry::default(),
            exit_status: 0,
            error_message: None,
        })?;
        let parsed = parse_guest_response(&valid_json)?;
        assert_eq!(parsed.protocol_version, "v1");
        assert_eq!(parsed.agent_version, "1.0.0");

        // Unsupported protocol version
        let bad_ver_json = serde_json::to_vec(&serde_json::json!({
            "protocol_version": "v2",
            "agent_version": "2.0.0",
            "guest_kernel_hash": null,
            "runtime_identity": "test",
            "executions": [],
            "telemetry": {},
            "exit_status": 0,
            "error_message": null
        }))?;
        let err = parse_guest_response(&bad_ver_json).unwrap_err().to_string();
        assert!(err.contains("unsupported microVM guest protocol version"));

        // Oversized payload
        let oversized = vec![0u8; MAX_GUEST_RESPONSE_BYTES + 1];
        let err = parse_guest_response(&oversized).unwrap_err().to_string();
        assert!(err.contains("exceeded max protocol limit"));

        Ok(())
    }

    #[test]
    fn test_backend_no_silent_fallback() {
        let backend = MicrovmBackend::new(MicrovmConfig::default());
        let active = ActiveExecutionOptions {
            sandbox_kind: SandboxKind::Microvm,
            microvm_config: MicrovmConfig::default(),
            allow_static_blocked: false,
            execute_custom_code: false,
            closure_level: crate::behaviour::closure::ClosureLevel::Standard,
            require_cgroup: false,
        };
        // Requiring execution stack without valid microvm image MUST error
        let result = backend.require_execution_stack(active);
        assert!(result.is_err());
    }
}
