use crate::sources;
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize)]
pub struct DoctorCheck {
    pub name: String,
    pub status: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
}

/// Recursive on-disk footprint of a directory, in bytes. Best-effort: a
/// permission error or a raced-away entry mid-walk drops that one entry
/// rather than failing the whole doctor pass, since this exists to answer
/// "roughly how big" for triage, not to be a byte-exact accounting tool.
fn dir_size_bytes(path: &Path) -> Option<u64> {
    if !path.is_dir() {
        return None;
    }
    let mut total = 0_u64;
    for entry in walkdir::WalkDir::new(path).follow_links(false) {
        let Ok(entry) = entry else { continue };
        if entry.file_type().is_file() {
            if let Ok(metadata) = entry.metadata() {
                total = total.saturating_add(metadata.len());
            }
        }
    }
    Some(total)
}

#[derive(Debug, Clone, Serialize)]
pub struct CapabilityReport {
    pub os: String,
    pub architecture: String,
    pub physical_memory_bytes: Option<u64>,
    pub available_memory_bytes: Option<u64>,
    pub recommended_active_memory_budget_bytes: Option<u64>,
    pub accelerator: String,
    pub static_analysis: bool,
    pub active_sandbox: bool,
    pub custom_code_sandbox: bool,
    pub microvm_sandbox: bool,
    pub microvm_hypervisor: Option<String>,
    pub llama_active_analysis: bool,
    pub transformers_active_analysis: bool,
    pub ebpf_telemetry: bool,
    pub managed_python_runtime: Option<String>,
    pub reflink_staging: bool,
    pub tools: BTreeMap<String, bool>,
    pub notes: Vec<String>,
}

pub fn run() -> Vec<DoctorCheck> {
    let mut checks = Vec::new();
    for binary in [
        "ollama",
        "lms",
        "llama-cli",
        "llama-server",
        "cosign",
        "bwrap",
        "prlimit",
        "strace",
        "layerfault-ebpf-telemetry",
    ] {
        match sources::find_executable(binary) {
            Some(path) => checks.push(DoctorCheck {
                name: binary.to_owned(),
                status: "available".to_owned(),
                detail: path.display().to_string(),
                size_bytes: None,
            }),
            None => checks.push(DoctorCheck {
                name: binary.to_owned(),
                status: "not-found".to_owned(),
                detail: if matches!(binary, "bwrap" | "prlimit" | "strace") {
                    "required for some active-analysis modes".to_owned()
                } else if binary == "layerfault-ebpf-telemetry" {
                    "optional lower-overhead telemetry backend; strace remains the default fallback"
                        .to_owned()
                } else {
                    "optional integration unavailable".to_owned()
                },
                size_bytes: None,
            }),
        }
    }

    let capabilities = capabilities();
    checks.push(DoctorCheck {
        name: "active-sandbox".to_owned(),
        status: if capabilities.active_sandbox {
            "ready"
        } else {
            "not-ready"
        }
        .to_owned(),
        detail: format!(
            "memory-budget={} accelerator={}",
            capabilities
                .recommended_active_memory_budget_bytes
                .map(human_bytes)
                .unwrap_or_else(|| "unknown".to_owned()),
            capabilities.accelerator
        ),
        size_bytes: None,
    });
    checks.push(DoctorCheck {
        name: "transformers-active".to_owned(),
        status: if capabilities.transformers_active_analysis {
            "ready"
        } else {
            "not-ready"
        }
        .to_owned(),
        detail: capabilities
            .managed_python_runtime
            .clone()
            .unwrap_or_else(|| "managed Python runtime not found/import-ready".to_owned()),
        size_bytes: None,
    });
    checks.push(DoctorCheck {
        name: "llama-active".to_owned(),
        status: if capabilities.llama_active_analysis {
            "ready"
        } else {
            "not-ready"
        }
        .to_owned(),
        detail: sources::find_executable("llama-server")
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "llama-server not found".to_owned()),
        size_bytes: None,
    });
    checks.push(DoctorCheck {
        name: "microvm-sandbox".to_owned(),
        status: if capabilities.microvm_sandbox {
            "ready"
        } else {
            "not-ready"
        }
        .to_owned(),
        detail: format!(
            "hypervisor={} kvm={}",
            capabilities.microvm_hypervisor.as_deref().unwrap_or("none"),
            Path::new("/dev/kvm").exists()
        ),
        size_bytes: None,
    });
    checks.push(DoctorCheck {
        name: "ebpf-telemetry".to_owned(),
        status: if capabilities.ebpf_telemetry {
            "ready"
        } else {
            "not-ready"
        }
        .to_owned(),
        detail: match crate::behaviour::ebpf_verify::locate_and_verify_helper() {
            Ok(verified) => format!(
                "helper verified at {} (version {}); strace remains the default backend",
                verified.path.display(),
                verified.version
            ),
            Err(reason) => format!("strace fallback active: {reason}"),
        },
        size_bytes: None,
    });

    for (name, kind) in [
        ("ollama-security", crate::advisory::RuntimeKind::Ollama),
        ("lmstudio-security", crate::advisory::RuntimeKind::LmStudio),
        ("llama-cpp-security", crate::advisory::RuntimeKind::LlamaCpp),
    ] {
        if crate::advisory::detect_runtime(kind).is_ok() {
            checks.push(match crate::advisory::evaluate(kind, None) {
                Ok(value) => DoctorCheck {
                    name: name.to_owned(),
                    status: if value.blocking {
                        "blocked"
                    } else if value
                        .findings
                        .iter()
                        .any(|f| f.status == crate::scanner::ScanStatus::Warn)
                    {
                        "warning"
                    } else {
                        "pass"
                    }
                    .to_owned(),
                    detail: format!(
                        "version={} advisory-db={}",
                        value
                            .runtime
                            .parsed_version
                            .as_deref()
                            .unwrap_or("unparsed"),
                        value.database_sha256
                    ),
                    size_bytes: None,
                },
                Err(error) => DoctorCheck {
                    name: name.to_owned(),
                    status: "warning".to_owned(),
                    detail: error.to_string(),
                    size_bytes: None,
                },
            });
        }
    }
    let ollama = crate::app::resolve_base_dir(None);
    checks.push(match ollama {
        Ok(path) => DoctorCheck {
            name: "ollama-store".to_owned(),
            status: if path.is_dir() {
                "available"
            } else {
                "not-found"
            }
            .to_owned(),
            detail: path.display().to_string(),
            size_bytes: dir_size_bytes(&path),
        },
        Err(error) => DoctorCheck {
            name: "ollama-store".to_owned(),
            status: "not-found".to_owned(),
            detail: error.to_string(),
            size_bytes: None,
        },
    });
    let hf = sources::hf_cache_root(None).unwrap_or_else(|_| PathBuf::from("<unknown>"));
    checks.push(DoctorCheck {
        name: "hf-cache".to_owned(),
        status: if hf.is_dir() {
            "available"
        } else {
            "not-found"
        }
        .to_owned(),
        detail: hf.display().to_string(),
        size_bytes: dir_size_bytes(&hf),
    });
    let config = crate::paths::config_dir().unwrap_or_else(|_| PathBuf::from("<unknown>"));
    checks.push(DoctorCheck {
        name: "config".to_owned(),
        status: "configured".to_owned(),
        detail: config.display().to_string(),
        size_bytes: dir_size_bytes(&config),
    });

    // Every other cache/staging namespace `gc --target all` can reclaim from,
    // so the full on-disk footprint is visible in one place instead of
    // requiring a manual `du -sh` across each directory by hand.
    if let Ok(roots) = crate::binding::staging_roots() {
        for root in roots {
            let name = root
                .file_name()
                .map(|value| value.to_string_lossy().into_owned())
                .unwrap_or_else(|| "staging".to_owned());
            checks.push(DoctorCheck {
                name,
                status: if root.is_dir() { "present" } else { "empty" }.to_owned(),
                detail: root.display().to_string(),
                size_bytes: dir_size_bytes(&root),
            });
        }
    }
    if let Ok(plan) = crate::content_cache::gc::plan() {
        checks.push(DoctorCheck {
            name: "content-cache".to_owned(),
            status: "present".to_owned(),
            detail: "reclaimable via `gc --target content-cache`".to_owned(),
            size_bytes: Some(plan.total_bytes),
        });
    }
    if let Ok(plan) = crate::object_cache::gc::plan() {
        checks.push(DoctorCheck {
            name: "object-cache".to_owned(),
            status: "present".to_owned(),
            detail: "reclaimable via `gc --target object-cache`".to_owned(),
            size_bytes: Some(plan.total_bytes),
        });
    }
    checks
}

pub fn capabilities() -> CapabilityReport {
    let physical = meminfo_kib("MemTotal").map(|value| value.saturating_mul(1024));
    let available = meminfo_kib("MemAvailable").map(|value| value.saturating_mul(1024));
    let budget = recommended_active_memory_budget_bytes();
    let managed_python = managed_python_runtime();
    let python_ready = managed_python
        .as_ref()
        .is_some_and(|python| python_ml_runtime_ready(python));

    let mut tools = BTreeMap::new();
    for tool in [
        "bwrap",
        "prlimit",
        "strace",
        "llama-cli",
        "llama-server",
        "nvidia-smi",
        "rocm-smi",
        "layerfault-ebpf-telemetry",
    ] {
        tools.insert(tool.to_owned(), sources::find_executable(tool).is_some());
    }

    let (bwrap_verified, bwrap_note) = if cfg!(target_os = "linux") {
        sources::find_executable("bwrap")
            .map(|path| match bwrap_selftest(&path) {
                Ok(()) => (true, None),
                Err(reason) => (false, Some(reason)),
            })
            .unwrap_or((
                false,
                Some("bubblewrap (bwrap) is not installed".to_owned()),
            ))
    } else {
        (
            false,
            Some("active Bubblewrap sandbox analysis is currently Linux-only".to_owned()),
        )
    };
    let active_sandbox = bwrap_verified && tools.get("prlimit").copied().unwrap_or(false);
    let custom_code_sandbox = active_sandbox && tools.get("strace").copied().unwrap_or(false);
    let accelerator = if tools.get("nvidia-smi").copied().unwrap_or(false) {
        "cuda-capable-host"
    } else if tools.get("rocm-smi").copied().unwrap_or(false) {
        "rocm-capable-host"
    } else {
        "cpu"
    }
    .to_owned();

    let mut notes = Vec::new();
    if let Some(note) = bwrap_note {
        notes.push(format!("sandbox preflight: {note}"));
    }
    if tools.get("bwrap").copied().unwrap_or(false)
        && !tools.get("prlimit").copied().unwrap_or(false)
    {
        notes.push(
            "sandbox preflight: prlimit is required for bounded external active execution"
                .to_owned(),
        );
    }
    let cgroup_caps = crate::behaviour::cgroup::detect_host_capabilities();
    if cgroup_caps.cgroup_v2 {
        if cgroup_caps.delegated_writable
            && cgroup_caps.memory_controller
            && cgroup_caps.pids_controller
            && cgroup_caps.cpu_controller
        {
            notes.push(format!(
                "cgroup v2 preflight: ready at /sys/fs/cgroup/{} (controllers: {})",
                cgroup_caps.cgroup_path.as_deref().unwrap_or(""),
                cgroup_caps.enabled_controllers.join(", ")
            ));
        } else if let Some(reason) = cgroup_caps.unavailable_reason {
            notes.push(format!("cgroup v2 preflight: {reason}"));
        }
    } else {
        notes.push("cgroup v2 preflight: cgroup v2 unified hierarchy is not active".to_owned());
    }

    if let (Some(total), Some(limit)) = (physical, budget) {
        if total <= 8 * 1024 * 1024 * 1024 {
            notes.push(format!(
                "low-memory host: active runs are preflighted against a {} safe budget",
                human_bytes(limit)
            ));
        }
    }
    if !python_ready {
        notes.push("Transformers/PEFT active analysis requires the managed Python runtime or LAYERFAULT_PYTHON_RUNTIME".to_owned());
    }

    let hypervisor = crate::behaviour::microvm::detect_hypervisor();
    let microvm_sandbox = hypervisor
        .as_ref()
        .map(|h| h.kvm_available)
        .unwrap_or(false);
    let microvm_hypervisor = hypervisor.map(|h| h.name);

    let ebpf_telemetry = crate::behaviour::telemetry_backend::resolve(
        crate::behaviour::telemetry_backend::TelemetryBackendMode::Ebpf,
    )
    .is_ok();
    if !ebpf_telemetry {
        if let Err(reason) = crate::behaviour::ebpf_verify::locate_and_verify_helper() {
            notes.push(format!("eBPF telemetry preflight: {reason}"));
        } else {
            notes.push(
                "eBPF telemetry preflight: helper identity verified, but live collection is not yet wired into this build".to_owned(),
            );
        }
    }

    CapabilityReport {
        os: std::env::consts::OS.to_owned(),
        architecture: std::env::consts::ARCH.to_owned(),
        physical_memory_bytes: physical,
        available_memory_bytes: available,
        recommended_active_memory_budget_bytes: budget,
        accelerator,
        static_analysis: true,
        active_sandbox,
        custom_code_sandbox,
        microvm_sandbox,
        microvm_hypervisor,
        llama_active_analysis: active_sandbox
            && tools.get("llama-server").copied().unwrap_or(false),
        transformers_active_analysis: active_sandbox && python_ready,
        ebpf_telemetry,
        managed_python_runtime: managed_python.map(|path| path.display().to_string()),
        reflink_staging: crate::binding::probe_reflink_support(),
        tools,
        notes,
    }
}

/// Conservative physical-memory budget for active execution. An explicit
/// LAYERFAULT_BEHAVIOUR_MEMORY_MB override wins; otherwise Layerfault reserves
/// host headroom and never assumes a large fixed-memory lab machine.
pub fn recommended_active_memory_budget_bytes() -> Option<u64> {
    if let Ok(value) = std::env::var("LAYERFAULT_BEHAVIOUR_MEMORY_MB") {
        if let Ok(mb) = value.parse::<u64>() {
            return Some(mb.clamp(512, 256 * 1024).saturating_mul(1024 * 1024));
        }
    }
    let total = meminfo_kib("MemTotal")?.saturating_mul(1024);
    let available = meminfo_kib("MemAvailable")
        .map(|value| value.saturating_mul(1024))
        .unwrap_or(total);
    let gib = 1024_u64 * 1024 * 1024;
    let reserve = (total / 4).clamp(1024 * 1024 * 1024, 4 * gib);
    let budget = available.saturating_sub(reserve).max(512 * 1024 * 1024);
    Some(
        budget
            .min(total.saturating_sub(512 * 1024 * 1024))
            .max(512 * 1024 * 1024),
    )
}

fn bwrap_selftest(path: &Path) -> Result<(), String> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        return Err("Bubblewrap self-test is Linux-only".to_owned());
    }

    #[cfg(target_os = "linux")]
    {
        // This self-test intentionally exposes the host root read-only only to a
        // fixed /bin/sh probe. It does not execute any model or user-controlled
        // code. The probe proves that a new network namespace is available and
        // that a nominal host path cannot be modified from inside the sandbox.
        const PROBE: &str = r#"
set -eu
marker=/etc/.layerfault-bwrap-doctor-$$
if touch "$marker" >/dev/null 2>&1; then
  rm -f "$marker" >/dev/null 2>&1 || true
  exit 41
fi
awk -F: 'NR > 2 { gsub(/[[:space:]]/, "", $1); if ($1 != "lo") exit 42 }' /proc/net/dev
"#;
        let mut command = crate::safeio::command_for_executable(path)
            .map_err(|error| format!("invalid bubblewrap executable: {error}"))?;
        let output = command
            .args([
                "--unshare-net",
                "--unshare-pid",
                "--unshare-ipc",
                "--unshare-uts",
                "--die-with-parent",
                "--new-session",
                "--cap-drop",
                "ALL",
                "--ro-bind",
                "/",
                "/",
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--tmpfs",
                "/tmp",
                "/bin/sh",
                "-c",
                PROBE,
            ])
            .output()
            .map_err(|error| format!("unable to execute bwrap self-test: {error}"))?;
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        let reason = stderr.trim();
        if reason.is_empty() {
            Err(format!(
                "bwrap isolation self-test failed with status {} (user namespaces or host policy may deny sandbox creation)",
                output.status
            ))
        } else {
            Err(format!(
                "bwrap isolation self-test failed: {}",
                reason.chars().take(600).collect::<String>()
            ))
        }
    }
}

fn managed_python_runtime() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("LAYERFAULT_PYTHON_RUNTIME").map(PathBuf::from) {
        if path.is_file() {
            return Some(path);
        }
    }
    [
        PathBuf::from("/opt/layerfault/runtimes/python/bin/python"),
        PathBuf::from("/opt/layerfault/runtime/python/bin/python"),
    ]
    .into_iter()
    .find(|path| path.is_file())
}

fn python_ml_runtime_ready(path: &Path) -> bool {
    let mut command = match crate::safeio::command_for_executable(path) {
        Ok(command) => command,
        Err(_) => return false,
    };
    command
        .args([
            "-c",
            "import torch, transformers, peft, safetensors, sentencepiece, tiktoken; print('ok')",
        ])
        .output()
        .is_ok_and(|output| output.status.success())
}

fn meminfo_kib(key: &str) -> Option<u64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        if fields.next()?.trim_end_matches(':') == key {
            return fields.next()?.parse::<u64>().ok();
        }
    }
    None
}

pub fn human_bytes(bytes: u64) -> String {
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.1}GiB", bytes as f64 / GIB)
    } else {
        format!("{:.0}MiB", bytes as f64 / MIB)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_report_always_has_static_analysis() {
        assert!(capabilities().static_analysis);
    }
}
