use super::adapters::{adapter_for, all_adapters};
use super::posture::evaluate_posture;
use super::{
    RuntimeDiscoveryMethod, RuntimeInstallation, RuntimeKind, RuntimePosture, RuntimeProcess,
};
use crate::coverage::Coverage;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};

fn sha256_file(path: &Path) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Some(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn fixed_version(path: &Path, kind: RuntimeKind) -> (Option<String>, Option<String>) {
    let adapter = adapter_for(kind);
    if adapter.version_args().is_empty() {
        return (None, None);
    }
    let mut command = match crate::safeio::command_for_executable(path) {
        Ok(c) => c,
        Err(_) => return (None, None),
    };
    let output = match command.args(adapter.version_args()).output() {
        Ok(v) => v,
        Err(_) => return (None, None),
    };
    let raw = if !output.stdout.is_empty() {
        String::from_utf8_lossy(&output.stdout).into_owned()
    } else {
        String::from_utf8_lossy(&output.stderr).into_owned()
    };
    let raw = raw.trim().to_owned();
    if raw.is_empty() {
        return (None, None);
    }
    let parsed = adapter.parse_version(&raw);
    (Some(raw), parsed)
}

fn distribution_version(root: &Path, distribution: &str) -> Option<(String, String)> {
    let mut candidates = Vec::new();
    for base in [root.join("Lib/site-packages"), root.join("lib")] {
        if base.ends_with("lib") {
            if let Ok(entries) = std::fs::read_dir(&base) {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if name.starts_with("python") {
                        candidates.push(entry.path().join("site-packages"));
                        candidates.push(entry.path().join("dist-packages"));
                    }
                }
            }
        } else {
            candidates.push(base);
        }
    }
    candidates.sort();
    let prefix = format!("{}-", distribution.to_ascii_lowercase().replace('-', "_"));
    for site in candidates {
        let Ok(entries) = std::fs::read_dir(&site) else {
            continue;
        };
        let mut dirs = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
                    n.to_ascii_lowercase().starts_with(&prefix) && n.ends_with(".dist-info")
                })
            })
            .collect::<Vec<_>>();
        dirs.sort();
        for dir in dirs {
            let metadata = dir.join("METADATA");
            let Ok(file) = crate::safeio::open_readonly_nofollow(&metadata) else {
                continue;
            };
            let Ok(bytes) = crate::safeio::read_all_from_file(&file, 1024 * 1024) else {
                continue;
            };
            let text = String::from_utf8_lossy(&bytes);
            if let Some(version) = text.lines().find_map(|line| line.strip_prefix("Version: ")) {
                return Some((
                    version.trim().to_owned(),
                    dir.to_string_lossy().into_owned(),
                ));
            }
        }
    }
    None
}

fn python_distribution_installations() -> Vec<RuntimeInstallation> {
    let mut roots = Vec::<PathBuf>::new();
    for name in ["VIRTUAL_ENV", "CONDA_PREFIX"] {
        if let Some(path) = std::env::var_os(name)
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
        {
            roots.push(path);
        }
    }
    let mut out = Vec::new();
    for root in roots {
        for (kind, dist) in [
            (RuntimeKind::Vllm, "vllm"),
            (RuntimeKind::Transformers, "transformers"),
            (RuntimeKind::Mlx, "mlx_lm"),
        ] {
            if let Some((version, package_root)) = distribution_version(&root, dist) {
                out.push(RuntimeInstallation {
                    runtime: kind,
                    executable: None,
                    executable_sha256: None,
                    raw_version: Some(version.clone()),
                    parsed_version: Some(version),
                    discovery: RuntimeDiscoveryMethod::PythonDistribution,
                    package_root: Some(package_root),
                    process_ids: Vec::new(),
                });
            }
        }
    }
    out
}

fn process_kind(process: &RuntimeProcess) -> Option<RuntimeKind> {
    let base = Path::new(&process.executable)
        .file_name()?
        .to_string_lossy()
        .to_ascii_lowercase();
    for adapter in all_adapters() {
        if adapter.executable_names().iter().any(|name| {
            base == name.to_ascii_lowercase()
                || base == format!("{}.exe", name.to_ascii_lowercase())
        }) {
            return Some(adapter.kind());
        }
    }
    // Common Python entrypoints where executable is python but argv names the runtime.
    let joined = process
        .args
        .iter()
        .take(4)
        .map(|v| v.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" ");
    if joined.contains("vllm") {
        Some(RuntimeKind::Vllm)
    } else if joined.contains("text_generation_server")
        || joined.contains("text-generation-launcher")
    {
        Some(RuntimeKind::TextGenerationInference)
    } else if joined.contains("text-generation-webui") || joined.contains("oobabooga") {
        Some(RuntimeKind::TextGenerationWebUi)
    } else {
        None
    }
}

pub fn discover_running() -> Vec<RuntimeProcess> {
    let mut processes = super::process::enumerate();
    processes.retain(|p| process_kind(p).is_some());
    processes.sort_by(|a, b| a.executable.cmp(&b.executable).then(a.pid.cmp(&b.pid)));
    processes
}

pub fn discover_installed() -> Vec<RuntimeInstallation> {
    let running = discover_running();
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for adapter in all_adapters() {
        for name in adapter.executable_names() {
            let Some(path) = crate::sources::find_executable(name) else {
                continue;
            };
            let key = (adapter.kind(), path.to_string_lossy().into_owned());
            if !seen.insert(key.clone()) {
                continue;
            }
            let (raw_version, parsed_version) = fixed_version(&path, adapter.kind());
            let pids = running
                .iter()
                .filter(|p| process_kind(p) == Some(adapter.kind()) && p.executable == key.1)
                .map(|p| p.pid)
                .collect();
            out.push(RuntimeInstallation {
                runtime: adapter.kind(),
                executable: Some(key.1),
                executable_sha256: sha256_file(&path),
                raw_version,
                parsed_version,
                discovery: RuntimeDiscoveryMethod::PathExecutable,
                package_root: None,
                process_ids: pids,
            });
        }
    }
    out.extend(python_distribution_installations());
    // Include runtime processes not found in PATH.
    for process in &running {
        let Some(kind) = process_kind(process) else {
            continue;
        };
        let key = (kind, process.executable.clone());
        if seen.insert(key.clone()) {
            let path = Path::new(&process.executable);
            let (raw_version, parsed_version) = fixed_version(path, kind);
            out.push(RuntimeInstallation {
                runtime: kind,
                executable: Some(process.executable.clone()),
                executable_sha256: sha256_file(path),
                raw_version,
                parsed_version,
                discovery: RuntimeDiscoveryMethod::RunningProcess,
                package_root: None,
                process_ids: vec![process.pid],
            });
        }
    }
    out.sort_by(|a, b| {
        a.runtime
            .as_str()
            .cmp(b.runtime.as_str())
            .then(a.executable.cmp(&b.executable))
            .then(a.process_ids.cmp(&b.process_ids))
    });
    out
}

pub fn audit_all() -> Vec<RuntimePosture> {
    let processes = discover_running();
    discover_installed().into_iter().map(|installation| {
        let adapter = adapter_for(installation.runtime);
        let related = processes.iter().filter(|p| process_kind(p) == Some(installation.runtime) && installation.executable.as_deref().is_none_or(|e| e == p.executable)).collect::<Vec<_>>();
        let mut coverage = Coverage::complete(1, 0);
        let configuration = if let Some(process) = related.first() {
            adapter.inspect_process(process)
        } else {
            let env = std::env::vars().filter(|(k,_)| crate::runtime_security::adapter::is_safe_environment_name(k)).collect::<BTreeMap<_,_>>();
            let config = adapter.inspect_environment(&env);
            coverage.complete = false;
            coverage.reasons.push("runtime is installed but no readable matching process was available; process posture is unknown".to_owned());
            config
        };
        evaluate_posture(installation, configuration, coverage)
    }).collect()
}

pub fn audit_kind(kind: RuntimeKind) -> Vec<RuntimePosture> {
    audit_all()
        .into_iter()
        .filter(|p| p.installation.runtime == kind)
        .collect()
}
