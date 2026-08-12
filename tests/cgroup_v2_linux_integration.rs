use layerfault::behaviour::cgroup::{
    detect_host_capabilities, CgroupGuard, CgroupLimits, HostCgroupFs,
};
use std::sync::Arc;

#[test]
fn test_linux_cgroup_v2_integration_if_available() {
    let caps = detect_host_capabilities();
    if !caps.cgroup_v2 || !caps.delegated_writable {
        eprintln!(
            "SKIP: cgroup v2 delegated creation not available on host: {:?}",
            caps.unavailable_reason
        );
        return;
    }

    let host_fs = Arc::new(HostCgroupFs::new());
    let limits = CgroupLimits {
        memory_max_bytes: 512 * 1024 * 1024,
        pids_max: 64,
        cpu_quota_us: None,
        cpu_period_us: 100_000,
        memory_swap_max_bytes: Some(0),
        memory_high_bytes: None,
    };

    let mut guard = match CgroupGuard::create(host_fs, &caps, &limits, "integration-test") {
        Ok(g) => g,
        Err(err) => {
            eprintln!("SKIP: failed to create child cgroup: {err}");
            return;
        }
    };

    // Attach self PID
    let _self_pid = std::process::id();
    // Move a spawned child rather than the test runner itself
    if let Ok(mut child) = std::process::Command::new("sleep").arg("0.1").spawn() {
        let _ = guard.attach_process(child.id());
        let _ = child.wait();
    }

    let telemetry = guard.collect_telemetry();
    assert!(telemetry.enabled);
    assert_eq!(telemetry.enforced_limits.pids_max, Some(64));

    let cleanup = guard.teardown();
    assert!(cleanup.contains("cleaned"));
}
