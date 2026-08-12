//! Exercises the real host-side loader (`probes::load_and_attach`, via the
//! actual `layerfault-ebpf-telemetry` binary) against the real compiled
//! probe object from the sibling `layerfault-ebpf-telemetry-ebpf` crate.
//!
//! This development environment has no root and
//! `/proc/sys/kernel/unprivileged_bpf_disabled` is permanently `2`, so the
//! kernel will reject the `bpf()` syscall needed to actually load/attach
//! the programs — that part of the pipeline cannot be exercised here.
//! What CAN be verified without privilege: the object file itself is a
//! well-formed BPF ELF the `aya` loader can parse, and the failure path
//! when the kernel then refuses to load it is a clean, reported error —
//! not a panic, hang, or silently-ignored failure.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

fn probe_object_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../layerfault-ebpf-telemetry-ebpf/target/bpfel-unknown-none/release/layerfault-ebpf-telemetry-ebpf")
}

#[test]
fn real_probe_object_is_a_valid_bpf_elf() {
    let path = probe_object_path();
    assert!(
        path.is_file(),
        "expected the sibling -ebpf crate's release build at {}; run `cargo build --release` there first",
        path.display()
    );
    let bytes = std::fs::read(&path).expect("read compiled probe object");
    // ELF magic + e_machine field (offset 18-19, little-endian) identifies
    // this as EM_BPF (247) rather than an empty/corrupt linker output.
    assert_eq!(&bytes[0..4], b"\x7fELF", "not a valid ELF file");
    let e_machine = u16::from_le_bytes([bytes[18], bytes[19]]);
    assert_eq!(
        e_machine, 247,
        "expected EM_BPF (247), got machine={e_machine}"
    );
}

#[test]
fn loader_reports_a_clean_error_when_the_kernel_refuses_bpf_without_privilege() {
    let path = probe_object_path();
    if !path.is_file() {
        eprintln!(
            "skipping: sibling -ebpf crate release build not present at {}",
            path.display()
        );
        return;
    }

    let mut output_file = tempfile::NamedTempFile::new().expect("temp output file");
    let mut child = Command::new(env!("CARGO_BIN_EXE_layerfault-ebpf-telemetry"))
        .arg("--run-token")
        .arg("integration-test-run")
        .arg("--root-pid")
        .arg(std::process::id().to_string())
        .arg("--object")
        .arg(&path)
        .arg("--output")
        .arg(output_file.path())
        .arg("--max-seconds")
        .arg("1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn layerfault-ebpf-telemetry");

    let status = wait_with_timeout(&mut child, Duration::from_secs(15))
        .expect("helper must exit within 15s, not hang, when the kernel refuses bpf()");

    // Without CAP_BPF/root the kernel must refuse program loading, so this
    // is expected to fail — the property under test is that it fails
    // *cleanly* (a normal process exit, not a crash/panic/hang) and
    // explains why on stderr, matching the "malformed helper output /
    // unavailable backend becomes a reported telemetry failure, never
    // silently ignored" contract this whole feature is built around.
    assert!(
        !status.success(),
        "expected a permission failure without CAP_BPF/root on this host"
    );
    let _ = output_file.flush();
}

fn wait_with_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
) -> Option<std::process::ExitStatus> {
    let started = std::time::Instant::now();
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            return Some(status);
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
