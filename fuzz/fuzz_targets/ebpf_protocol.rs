#![no_main]
use layerfault::behaviour::ebpf_telemetry::{decode_frames, ScopeToken};
use layerfault::behaviour::sandbox::SandboxTelemetry;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let scope = ScopeToken {
        run_token: "fuzz-run".to_owned(),
        cgroup_path: None,
        root_pid: None,
        pid_namespace_inode: None,
    };
    let mut telemetry = SandboxTelemetry::default();
    // The decoder must never panic, hang, or allocate unboundedly on
    // arbitrary attacker-controlled bytes, regardless of what garbage
    // framing/JSON the input contains.
    let _ = decode_frames(std::io::Cursor::new(data), &scope, &mut telemetry);
});
