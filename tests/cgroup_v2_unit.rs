use anyhow::{bail, Result};
use layerfault::behaviour::cgroup::{
    detect_capabilities, sanitize_cgroup_nonce, CgroupFs, CgroupGuard, CgroupLimits,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Thread-safe in-memory mock implementation of `CgroupFs`.
#[derive(Default)]
struct MockCgroupFs {
    v2_active: Mutex<bool>,
    current_path: Mutex<String>,
    files: Mutex<BTreeMap<PathBuf, String>>,
    directories: Mutex<BTreeMap<PathBuf, bool>>,
    fail_create_dir: Mutex<bool>,
}

impl MockCgroupFs {
    fn new() -> Self {
        let mock = Self::default();
        *mock.v2_active.lock().unwrap() = true;
        *mock.current_path.lock().unwrap() =
            "user.slice/user-1000.slice/user@1000.service".to_string();
        mock.add_dir(Path::new("user.slice/user-1000.slice/user@1000.service"));
        mock
    }

    fn add_dir(&self, path: &Path) {
        self.directories
            .lock()
            .unwrap()
            .insert(path.to_path_buf(), true);
    }

    fn set_file_content(&self, path: &Path, content: &str) {
        self.files
            .lock()
            .unwrap()
            .insert(path.to_path_buf(), content.to_string());
    }
}

impl CgroupFs for MockCgroupFs {
    fn is_cgroup_v2(&self) -> bool {
        *self.v2_active.lock().unwrap()
    }

    fn current_cgroup_path(&self) -> Result<String> {
        Ok(self.current_path.lock().unwrap().clone())
    }

    fn read_file(&self, path: &Path) -> Result<String> {
        let clean = PathBuf::from(path.to_string_lossy().trim_start_matches('/'));
        self.files
            .lock()
            .unwrap()
            .get(&clean)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("mock file not found: {}", clean.display()))
    }

    fn write_file(&self, path: &Path, content: &str) -> Result<()> {
        let clean = PathBuf::from(path.to_string_lossy().trim_start_matches('/'));
        self.files
            .lock()
            .unwrap()
            .insert(clean, content.to_string());
        Ok(())
    }

    fn create_dir(&self, path: &Path) -> Result<()> {
        if *self.fail_create_dir.lock().unwrap() {
            bail!("mock permission denied: delegated directory creation prohibited");
        }
        let clean = PathBuf::from(path.to_string_lossy().trim_start_matches('/'));
        self.directories.lock().unwrap().insert(clean, true);
        Ok(())
    }

    fn remove_dir(&self, path: &Path) -> Result<()> {
        let clean = PathBuf::from(path.to_string_lossy().trim_start_matches('/'));
        self.directories.lock().unwrap().remove(&clean);
        Ok(())
    }

    fn path_exists(&self, path: &Path) -> bool {
        let clean = PathBuf::from(path.to_string_lossy().trim_start_matches('/'));
        self.directories.lock().unwrap().contains_key(&clean)
            || self.files.lock().unwrap().contains_key(&clean)
    }
}

#[test]
fn test_cgroup_v1_vs_v2_detection() {
    let mock = MockCgroupFs::new();
    *mock.v2_active.lock().unwrap() = false;
    let caps = detect_capabilities(&mock);
    assert!(!caps.cgroup_v2);
    assert!(caps
        .unavailable_reason
        .unwrap_or_default()
        .contains("not mounted"));
}

#[test]
fn test_cgroup_missing_controllers_reported() {
    let mock = MockCgroupFs::new();
    let current = Path::new("user.slice/user-1000.slice/user@1000.service");
    mock.set_file_content(&current.join("cgroup.controllers"), "memory");
    mock.set_file_content(&current.join("cgroup.subtree_control"), "memory");

    let caps = detect_capabilities(&mock);
    assert!(caps.cgroup_v2);
    assert!(caps.memory_controller);
    assert!(!caps.pids_controller);
    assert!(!caps.cpu_controller);
    let reason = caps.unavailable_reason.unwrap_or_default();
    assert!(reason.contains("pids"));
    assert!(reason.contains("cpu"));
}

#[test]
fn test_cgroup_no_delegation_prohibits_active_mode() {
    let mock = MockCgroupFs::new();
    let current = Path::new("user.slice/user-1000.slice/user@1000.service");
    mock.set_file_content(&current.join("cgroup.controllers"), "memory pids cpu");
    mock.set_file_content(&current.join("cgroup.subtree_control"), "memory pids cpu");
    *mock.fail_create_dir.lock().unwrap() = true;

    let caps = detect_capabilities(&mock);
    assert!(caps.cgroup_v2);
    assert!(!caps.delegated_writable);
    let reason = caps.unavailable_reason.unwrap_or_default();
    assert!(reason.contains("not writable / delegated"));
}

#[test]
fn test_limit_serialization_and_creation() -> Result<()> {
    let mock = Arc::new(MockCgroupFs::new());
    let current = Path::new("user.slice/user-1000.slice/user@1000.service");
    mock.set_file_content(&current.join("cgroup.controllers"), "memory pids cpu");
    mock.set_file_content(&current.join("cgroup.subtree_control"), "memory pids cpu");

    let caps = detect_capabilities(mock.as_ref());
    assert!(caps.delegated_writable);

    let limits = CgroupLimits {
        memory_max_bytes: 2_u64 * 1024 * 1024 * 1024,
        pids_max: 256,
        cpu_quota_us: Some(150_000),
        cpu_period_us: 100_000,
        memory_swap_max_bytes: Some(0),
        memory_high_bytes: Some(1800_u64 * 1024 * 1024),
    };

    let guard = CgroupGuard::create(mock.clone(), &caps, &limits, "test-run")?;
    let child_rel = guard.rel_path();

    assert_eq!(
        mock.read_file(&child_rel.join("memory.max"))?,
        (2_u64 * 1024 * 1024 * 1024).to_string()
    );
    assert_eq!(mock.read_file(&child_rel.join("pids.max"))?, "256");
    assert_eq!(mock.read_file(&child_rel.join("cpu.max"))?, "150000 100000");
    assert_eq!(mock.read_file(&child_rel.join("memory.swap.max"))?, "0");
    assert_eq!(
        mock.read_file(&child_rel.join("memory.high"))?,
        (1800_u64 * 1024 * 1024).to_string()
    );
    Ok(())
}

#[test]
fn test_telemetry_event_parsing() -> Result<()> {
    let mock = Arc::new(MockCgroupFs::new());
    let current = Path::new("user.slice/user-1000.slice/user@1000.service");
    mock.set_file_content(&current.join("cgroup.controllers"), "memory pids cpu");
    mock.set_file_content(&current.join("cgroup.subtree_control"), "memory pids cpu");

    let caps = detect_capabilities(mock.as_ref());
    let limits = CgroupLimits::default();
    let guard = CgroupGuard::create(mock.clone(), &caps, &limits, "parse-test")?;
    let child_rel = guard.rel_path();

    mock.set_file_content(&child_rel.join("memory.current"), "524288000\n");
    mock.set_file_content(&child_rel.join("memory.peak"), "1073741824\n");
    mock.set_file_content(
        &child_rel.join("memory.events"),
        "low 0\nhigh 12\nmax 5\noom 2\noom_kill 1\n",
    );
    mock.set_file_content(&child_rel.join("pids.current"), "42\n");
    mock.set_file_content(&child_rel.join("pids.events"), "max 7\n");
    mock.set_file_content(&child_rel.join("cpu.stat"), "usage_usec 123456\n");

    let telemetry = guard.collect_telemetry();
    assert!(telemetry.enabled);
    assert_eq!(telemetry.memory_peak_bytes, Some(1073741824));
    assert_eq!(telemetry.oom_events, 2);
    assert_eq!(telemetry.oom_kill_events, 1);
    assert_eq!(telemetry.pids_current, Some(42));
    assert_eq!(telemetry.pids_events_max, 7);
    assert_eq!(telemetry.cpu_quota_us, Some(100_000));
    assert_eq!(telemetry.cpu_period_us, Some(100_000));
    assert_eq!(telemetry.cpu_usage_us, Some(123_456));
    Ok(())
}

#[test]
fn test_hostile_cgroup_nonce_sanitization() {
    assert_eq!(
        sanitize_cgroup_nonce("../../../etc/passwd"),
        "_________etc_passwd"
    );
    assert_eq!(sanitize_cgroup_nonce("valid-name_123"), "valid-name_123");
    assert_eq!(sanitize_cgroup_nonce(""), "sandbox-run");
}
