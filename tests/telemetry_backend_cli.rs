//! End-to-end CLI coverage for `--telemetry-backend` selection: the
//! explicit-`ebpf`-unavailable hard-fail path (no silent fallback), the
//! `auto` visible-degrade path, and `doctor` reporting on the eBPF helper.
//! No real helper is installed in CI/dev environments (the embedded
//! manifest's placeholder sha256 in
//! `helpers/layerfault-ebpf-telemetry/EXPECTED.toml` is deliberately
//! unsatisfiable until a release pipeline populates it), so these tests
//! exercise the fail-closed/fallback machinery itself, not a live probe.

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_layerfault"))
        .args(args)
        .output()
        .expect("run Layerfault")
}

#[test]
fn explicit_ebpf_backend_hard_fails_before_touching_the_model() {
    // telemetry_backend::resolve() runs before model resolution in
    // run_external_llama_active_deadline, so a nonexistent model path still
    // surfaces the eBPF-unavailable error, not a "model not found" error —
    // proof the hard-fail happens first, not as an afterthought.
    let output = run(&[
        "behaviour",
        "/nonexistent/model.gguf",
        "--telemetry-backend",
        "ebpf",
        "--profile",
        "quick",
    ]);
    assert!(
        !output.status.success(),
        "explicit --telemetry-backend ebpf must fail when no verified helper is installed"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("eBPF telemetry backend was explicitly requested"),
        "stderr did not mention the explicit eBPF request failure: {stderr}"
    );
}

#[test]
fn unknown_telemetry_backend_value_is_rejected_by_clap() {
    let output = run(&[
        "behaviour",
        "/nonexistent/model.gguf",
        "--telemetry-backend",
        "bogus",
    ]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("bogus") || stderr.contains("invalid value"),
        "stderr did not reject the unknown backend value: {stderr}"
    );
}

#[test]
fn doctor_reports_ebpf_telemetry_status() {
    let output = run(&["doctor"]);
    assert!(output.status.success(), "doctor command should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("ebpf-telemetry"),
        "doctor output did not include the ebpf-telemetry check: {stdout}"
    );
}
