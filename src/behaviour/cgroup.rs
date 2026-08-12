//! cgroup v2 process-tree resource management for sandboxed active analysis.
//!
//! Provides capability detection, rootless delegated cgroup creation, process
//! tree migration, limit enforcement (`memory.max`, `pids.max`, `cpu.max`),
//! telemetry event collection (`memory.events`, `pids.events`, `cpu.stat`),
//! and safe teardown (`cgroup.kill` / signal iteration and directory cleanup).

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static CGROUP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CgroupCapabilities {
    pub cgroup_v2: bool,
    pub cgroup_path: Option<String>,
    pub delegated_writable: bool,
    pub available_controllers: Vec<String>,
    pub enabled_controllers: Vec<String>,
    pub memory_controller: bool,
    pub pids_controller: bool,
    pub cpu_controller: bool,
    pub swap_controller: bool,
    pub unavailable_reason: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CgroupEnforcedLimits {
    pub memory_max_bytes: Option<u64>,
    pub memory_high_bytes: Option<u64>,
    pub memory_swap_max_bytes: Option<u64>,
    pub pids_max: Option<u64>,
    pub cpu_max: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CgroupTelemetry {
    pub enabled: bool,
    pub cgroup_path: Option<String>,
    pub controllers: Vec<String>,
    pub enforced_limits: CgroupEnforcedLimits,
    pub memory_peak_bytes: Option<u64>,
    pub oom_events: u64,
    pub oom_kill_events: u64,
    pub pids_current: Option<u64>,
    pub pids_peak: Option<u64>,
    pub pids_events_max: u64,
    pub cpu_quota_us: Option<u64>,
    pub cpu_period_us: Option<u64>,
    pub cpu_usage_us: Option<u64>,
    pub cleanup_state: String,
}

pub trait CgroupFs: Send + Sync {
    fn is_cgroup_v2(&self) -> bool;
    fn current_cgroup_path(&self) -> Result<String>;
    fn read_file(&self, path: &Path) -> Result<String>;
    fn write_file(&self, path: &Path, content: &str) -> Result<()>;
    fn create_dir(&self, path: &Path) -> Result<()>;
    fn remove_dir(&self, path: &Path) -> Result<()>;
    fn path_exists(&self, path: &Path) -> bool;
}

/// Host cgroup v2 filesystem implementation.
pub struct HostCgroupFs {
    root: PathBuf,
}

impl Default for HostCgroupFs {
    fn default() -> Self {
        Self {
            root: PathBuf::from("/sys/fs/cgroup"),
        }
    }
}

impl HostCgroupFs {
    pub fn new() -> Self {
        Self::default()
    }
}

impl CgroupFs for HostCgroupFs {
    fn is_cgroup_v2(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            let controllers = self.root.join("cgroup.controllers");
            if crate::safeio::open_readonly_nofollow(&controllers).is_ok() {
                return true;
            }
            // Check filesystem magic type via rustix if available
            if let Ok(stat) = rustix::fs::statfs(&self.root) {
                // CGROUP2_SUPER_MAGIC = 0x63677270
                return stat.f_type == 0x6367_7270;
            }
        }
        false
    }

    fn current_cgroup_path(&self) -> Result<String> {
        #[cfg(target_os = "linux")]
        {
            let text = std::fs::read_to_string("/proc/self/cgroup")
                .context("unable to read /proc/self/cgroup")?;
            for line in text.lines() {
                // cgroup v2 line format is 0::<path>
                if let Some(rest) = line.strip_prefix("0::") {
                    return Ok(rest.to_owned());
                }
            }
            bail!("no cgroup v2 unified hierarchy entry (0::<path>) found in /proc/self/cgroup");
        }
        #[cfg(not(target_os = "linux"))]
        {
            bail!("cgroup v2 is only supported on Linux");
        }
    }

    fn read_file(&self, path: &Path) -> Result<String> {
        let full = if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.root.join(path)
        };
        let mut file = crate::safeio::open_readonly_nofollow(&full)
            .with_context(|| format!("unable to read cgroup file '{}'", full.display()))?;
        use std::io::Read as _;
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        Ok(content)
    }

    fn write_file(&self, path: &Path, content: &str) -> Result<()> {
        let full = if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.root.join(path)
        };
        let mut options = std::fs::OpenOptions::new();
        options.write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let mut file = options
            .open(&full)
            .with_context(|| format!("unable to safely open cgroup file '{}'", full.display()))?;
        file.write_all(content.as_bytes())
            .with_context(|| format!("unable to write cgroup file '{}'", full.display()))
    }

    fn create_dir(&self, path: &Path) -> Result<()> {
        let full = if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.root.join(path)
        };
        crate::paths::ensure_private_dir(&full)
    }

    fn remove_dir(&self, path: &Path) -> Result<()> {
        let full = if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.root.join(path)
        };
        std::fs::remove_dir(&full)
            .with_context(|| format!("unable to remove cgroup directory '{}'", full.display()))
    }

    fn path_exists(&self, path: &Path) -> bool {
        let full = if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.root.join(path)
        };
        full.exists()
    }
}

pub fn detect_capabilities(fs: &dyn CgroupFs) -> CgroupCapabilities {
    if !fs.is_cgroup_v2() {
        return CgroupCapabilities {
            cgroup_v2: false,
            unavailable_reason: Some(
                "cgroup v2 unified hierarchy is not mounted at /sys/fs/cgroup".to_owned(),
            ),
            ..Default::default()
        };
    }

    let raw_rel = match fs.current_cgroup_path() {
        Ok(path) => path,
        Err(err) => {
            return CgroupCapabilities {
                cgroup_v2: true,
                unavailable_reason: Some(format!("unable to determine current cgroup: {err}")),
                ..Default::default()
            };
        }
    };

    let rel_path = match normalized_cgroup_path(&raw_rel) {
        Some(path) => path,
        None => {
            return CgroupCapabilities {
                cgroup_v2: true,
                unavailable_reason: Some(
                    "current cgroup path is not a safe kernel path".to_owned(),
                ),
                ..Default::default()
            };
        }
    };
    let available_controllers = parse_space_separated(
        &fs.read_file(&rel_path.join("cgroup.controllers"))
            .unwrap_or_default(),
    );
    let enabled_controllers = parse_space_separated(
        &fs.read_file(&rel_path.join("cgroup.subtree_control"))
            .unwrap_or_default(),
    );

    let mut combined_enabled = enabled_controllers.clone();
    // Check if we can enable missing required controllers in current cgroup subtree_control
    let required_set = ["memory", "pids", "cpu"];
    let mut missing_in_subtree = Vec::new();
    for req in required_set {
        if available_controllers.contains(&req.to_string())
            && !combined_enabled.contains(&req.to_string())
        {
            missing_in_subtree.push(format!("+{req}"));
        }
    }
    if !missing_in_subtree.is_empty() {
        let enable_cmd = missing_in_subtree.join(" ");
        if fs
            .write_file(&rel_path.join("cgroup.subtree_control"), &enable_cmd)
            .is_ok()
        {
            let updated = parse_space_separated(
                &fs.read_file(&rel_path.join("cgroup.subtree_control"))
                    .unwrap_or_default(),
            );
            combined_enabled = updated;
        }
    }

    let probe_dir = rel_path.join(format!(
        "layerfault-cap-probe-{}-{}",
        std::process::id(),
        CGROUP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let writable = if fs.create_dir(&probe_dir).is_ok() {
        let _ = fs.remove_dir(&probe_dir);
        true
    } else {
        false
    };

    let mem_ok = combined_enabled.iter().any(|c| c == "memory");
    let pids_ok = combined_enabled.iter().any(|c| c == "pids");
    let cpu_ok = combined_enabled.iter().any(|c| c == "cpu");
    let swap_ok = combined_enabled.iter().any(|c| c == "memory")
        && fs.path_exists(&rel_path.join("memory.swap.max"));

    let mut missing = Vec::new();
    if !mem_ok {
        missing.push("memory");
    }
    if !pids_ok {
        missing.push("pids");
    }
    if !cpu_ok {
        missing.push("cpu");
    }

    let unavailable_reason = if !writable {
        Some(format!(
            "current cgroup location '/sys/fs/cgroup/{raw_rel}' is not writable / delegated"
        ))
    } else if !missing.is_empty() {
        Some(format!(
            "cgroup v2 controller(s) missing or not enabled in subtree_control: {}",
            missing.join(", ")
        ))
    } else {
        None
    };

    CgroupCapabilities {
        cgroup_v2: true,
        cgroup_path: Some(raw_rel),
        delegated_writable: writable,
        available_controllers,
        enabled_controllers: combined_enabled,
        memory_controller: mem_ok,
        pids_controller: pids_ok,
        cpu_controller: cpu_ok,
        swap_controller: swap_ok,
        unavailable_reason,
    }
}

fn normalized_cgroup_path(raw: &str) -> Option<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in Path::new(raw.trim_start_matches('/')).components() {
        match component {
            std::path::Component::Normal(value) => normalized.push(value),
            std::path::Component::CurDir => {}
            _ => return None,
        }
    }
    Some(normalized)
}

pub fn detect_host_capabilities() -> CgroupCapabilities {
    detect_capabilities(&HostCgroupFs::new())
}

fn parse_space_separated(text: &str) -> Vec<String> {
    text.split_whitespace().map(ToOwned::to_owned).collect()
}

pub fn sanitize_cgroup_nonce(nonce: &str) -> String {
    let sanitized: String = nonce
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .take(64)
        .collect();
    if sanitized.is_empty() {
        "sandbox-run".to_owned()
    } else {
        sanitized
    }
}

pub struct CgroupLimits {
    pub memory_max_bytes: u64,
    pub pids_max: u64,
    pub cpu_quota_us: Option<u64>,
    pub cpu_period_us: u64,
    pub memory_swap_max_bytes: Option<u64>,
    pub memory_high_bytes: Option<u64>,
}

impl Default for CgroupLimits {
    fn default() -> Self {
        Self {
            memory_max_bytes: 4 * 1024 * 1024 * 1024,
            pids_max: 512,
            cpu_quota_us: Some(100_000),
            cpu_period_us: 100_000,
            memory_swap_max_bytes: Some(0),
            memory_high_bytes: None,
        }
    }
}

/// RAII Guard for active child cgroup lifecycle.
pub struct CgroupGuard {
    fs: std::sync::Arc<dyn CgroupFs>,
    rel_path: PathBuf,
    enforced_limits: CgroupEnforcedLimits,
    active: bool,
}

impl CgroupGuard {
    pub fn create(
        fs: std::sync::Arc<dyn CgroupFs>,
        caps: &CgroupCapabilities,
        limits: &CgroupLimits,
        nonce: &str,
    ) -> Result<Self> {
        if !caps.cgroup_v2
            || !caps.delegated_writable
            || !caps.memory_controller
            || !caps.pids_controller
            || !caps.cpu_controller
        {
            bail!("required delegated cgroup v2 controllers are unavailable");
        }
        if limits.memory_max_bytes == 0
            || limits.pids_max == 0
            || limits.cpu_period_us == 0
            || limits.cpu_quota_us == Some(0)
        {
            bail!("cgroup limits must be positive numeric values");
        }
        let parent_rel = caps
            .cgroup_path
            .as_deref()
            .unwrap_or("")
            .trim_start_matches('/');
        let safe_nonce = sanitize_cgroup_nonce(nonce);
        let folder_name = format!(
            "layerfault-bwrap-{}-{}-{}",
            std::process::id(),
            CGROUP_SEQUENCE.fetch_add(1, Ordering::Relaxed),
            safe_nonce
        );
        let rel_path = PathBuf::from(parent_rel).join(folder_name);

        fs.create_dir(&rel_path)
            .with_context(|| format!("unable to create child cgroup '{}'", rel_path.display()))?;

        let mut enforced = CgroupEnforcedLimits::default();

        if caps.memory_controller {
            let mem_str = limits.memory_max_bytes.to_string();
            if let Err(err) = fs.write_file(&rel_path.join("memory.max"), &mem_str) {
                let _ = fs.remove_dir(&rel_path);
                return Err(err).context("unable to enforce memory.max");
            }
            enforced.memory_max_bytes = Some(limits.memory_max_bytes);

            if let Some(swap) = limits.memory_swap_max_bytes {
                let swap_str = swap.to_string();
                if fs
                    .write_file(&rel_path.join("memory.swap.max"), &swap_str)
                    .is_ok()
                {
                    enforced.memory_swap_max_bytes = Some(swap);
                }
            }
            if let Some(high) = limits.memory_high_bytes {
                let high_str = high.to_string();
                if fs
                    .write_file(&rel_path.join("memory.high"), &high_str)
                    .is_ok()
                {
                    enforced.memory_high_bytes = Some(high);
                }
            }
        }

        if caps.pids_controller {
            let pids_str = limits.pids_max.to_string();
            if let Err(err) = fs.write_file(&rel_path.join("pids.max"), &pids_str) {
                let _ = fs.remove_dir(&rel_path);
                return Err(err).context("unable to enforce pids.max");
            }
            enforced.pids_max = Some(limits.pids_max);
        }

        if caps.cpu_controller {
            let cpu_val = match limits.cpu_quota_us {
                Some(quota) => format!("{quota} {}", limits.cpu_period_us),
                None => format!("max {}", limits.cpu_period_us),
            };
            if let Err(err) = fs.write_file(&rel_path.join("cpu.max"), &cpu_val) {
                let _ = fs.remove_dir(&rel_path);
                return Err(err).context("unable to enforce cpu.max");
            }
            enforced.cpu_max = Some(cpu_val);
        }

        Ok(Self {
            fs,
            rel_path,
            enforced_limits: enforced,
            active: true,
        })
    }

    pub fn rel_path(&self) -> &Path {
        &self.rel_path
    }

    pub fn attach_process(&self, pid: u32) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        let pid_str = pid.to_string();
        self.fs
            .write_file(&self.rel_path.join("cgroup.procs"), &pid_str)
            .with_context(|| format!("unable to migrate PID {pid} to cgroup"))?;

        // Race condition defense: scan any descendants that spawned early
        #[cfg(target_os = "linux")]
        {
            let descendants = linux_descendants(pid);
            for d_pid in descendants {
                let _ = self
                    .fs
                    .write_file(&self.rel_path.join("cgroup.procs"), &d_pid.to_string());
            }
        }

        Ok(())
    }

    pub fn collect_telemetry(&self) -> CgroupTelemetry {
        if !self.active {
            return CgroupTelemetry::default();
        }
        let mut telemetry = CgroupTelemetry {
            enabled: true,
            cgroup_path: Some(self.rel_path.to_string_lossy().to_string()),
            enforced_limits: self.enforced_limits.clone(),
            controllers: enforced_controllers(&self.enforced_limits),
            cleanup_state: "active".to_owned(),
            ..Default::default()
        };

        if let Ok(current) = self.fs.read_file(&self.rel_path.join("memory.current")) {
            if let Ok(val) = current.trim().parse::<u64>() {
                telemetry.memory_peak_bytes = Some(val);
            }
        }
        if let Ok(peak) = self.fs.read_file(&self.rel_path.join("memory.peak")) {
            if let Ok(val) = peak.trim().parse::<u64>() {
                telemetry.memory_peak_bytes = Some(val);
            }
        }

        if let Ok(events) = self.fs.read_file(&self.rel_path.join("memory.events")) {
            for line in events.lines() {
                let mut parts = line.split_whitespace();
                let key = parts.next().unwrap_or("");
                let val = parts.next().unwrap_or("0").parse::<u64>().unwrap_or(0);
                match key {
                    "oom" => telemetry.oom_events = val,
                    "oom_kill" => telemetry.oom_kill_events = val,
                    _ => {}
                }
            }
        }

        if let Ok(p_current) = self.fs.read_file(&self.rel_path.join("pids.current")) {
            if let Ok(val) = p_current.trim().parse::<u64>() {
                telemetry.pids_current = Some(val);
                telemetry.pids_peak = Some(val);
            }
        }
        if let Ok(p_peak) = self.fs.read_file(&self.rel_path.join("pids.peak")) {
            if let Ok(val) = p_peak.trim().parse::<u64>() {
                telemetry.pids_peak = Some(val);
            }
        }
        if let Ok(events) = self.fs.read_file(&self.rel_path.join("pids.events")) {
            for line in events.lines() {
                let mut parts = line.split_whitespace();
                let key = parts.next().unwrap_or("");
                let val = parts.next().unwrap_or("0").parse::<u64>().unwrap_or(0);
                if key == "max" {
                    telemetry.pids_events_max = val;
                }
            }
        }

        if let Ok(cpu_stat) = self.fs.read_file(&self.rel_path.join("cpu.stat")) {
            for line in cpu_stat.lines() {
                let mut parts = line.split_whitespace();
                let key = parts.next().unwrap_or("");
                let val = parts.next().unwrap_or("0").parse::<u64>().unwrap_or(0);
                if key == "usage_usec" {
                    telemetry.cpu_usage_us = Some(val);
                }
            }
        }

        telemetry.cpu_quota_us = self.enforced_limits.cpu_max.as_deref().and_then(|value| {
            value
                .split_whitespace()
                .next()
                .and_then(|quota| quota.parse().ok())
        });
        telemetry.cpu_period_us = self.enforced_limits.cpu_max.as_deref().and_then(|value| {
            value
                .split_whitespace()
                .nth(1)
                .and_then(|period| period.parse().ok())
        });

        telemetry
    }

    pub fn teardown(&mut self) -> String {
        if !self.active {
            return "already_cleared".to_owned();
        }
        self.active = false;

        let _ = self.fs.write_file(&self.rel_path.join("cgroup.kill"), "1");

        let mut clean = false;
        for _attempt in 0..10 {
            let procs = self
                .fs
                .read_file(&self.rel_path.join("cgroup.procs"))
                .unwrap_or_default();
            let pids: Vec<u32> = procs
                .lines()
                .filter_map(|line| line.trim().parse::<u32>().ok())
                .collect();
            if pids.is_empty() {
                clean = true;
                break;
            }
            #[cfg(target_os = "linux")]
            {
                let kill = crate::sources::find_executable("kill");
                for pid in pids {
                    if let Some(kill) = kill.as_ref() {
                        if let Ok(mut command) = crate::safeio::command_for_executable(kill) {
                            let _ = command
                                .arg("-KILL")
                                .arg("--")
                                .arg(pid.to_string())
                                .env_clear()
                                .status();
                        }
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }

        if fs_remove_cgroup_dir(self.fs.as_ref(), &self.rel_path).is_ok() {
            if clean {
                "cleaned".to_owned()
            } else {
                "cleaned_after_forced_kill".to_owned()
            }
        } else {
            format!("failed_rmdir: {}", self.rel_path.display())
        }
    }
}

fn enforced_controllers(limits: &CgroupEnforcedLimits) -> Vec<String> {
    let mut controllers = Vec::new();
    if limits.memory_max_bytes.is_some() {
        controllers.push("memory".to_owned());
    }
    if limits.pids_max.is_some() {
        controllers.push("pids".to_owned());
    }
    if limits.cpu_max.is_some() {
        controllers.push("cpu".to_owned());
    }
    controllers
}

impl Drop for CgroupGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = self.teardown();
        }
    }
}

fn fs_remove_cgroup_dir(fs: &dyn CgroupFs, path: &Path) -> Result<()> {
    fs.remove_dir(path)
}

#[cfg(target_os = "linux")]
fn linux_descendants(root: u32) -> Vec<u32> {
    let mut parent_by_pid = std::collections::BTreeMap::<u32, u32>::new();
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
