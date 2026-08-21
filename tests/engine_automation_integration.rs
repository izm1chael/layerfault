//! Integration tests for automated scanning and harness execution requirements:
//! 1. Behavioural preflight command (`layerfault behaviour preflight`)
//! 2. Machine-readable reason codes for `NOT_RUN`
//! 3. Structured progress events (JSONL progress)
//! 4. Caller-controlled research deadlines (`--timeout-seconds`)
//! 5. Profile metadata (`layerfault behaviour profiles --json` & capabilities)
//! 6. Active execution host readiness report (`active_analysis` in capabilities)

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_layerfault"))
        .args(args)
        .output()
        .expect("run Layerfault")
}

#[test]
fn capabilities_json_exposes_active_analysis_and_behaviour_profiles() {
    let output = run(&["capabilities", "--json"]);
    assert!(output.status.success(), "capabilities --json must succeed");
    let val: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse capabilities json");

    // 1. active_analysis object verification
    let active = val
        .get("active_analysis")
        .expect("must contain active_analysis object");
    assert!(
        active.get("bwrap").is_some(),
        "missing bwrap in active_analysis"
    );
    assert!(
        active.get("user_namespaces").is_some(),
        "missing user_namespaces in active_analysis"
    );
    assert!(
        active.get("cgroup_v2").is_some(),
        "missing cgroup_v2 in active_analysis"
    );
    assert!(
        active.get("cgroup_delegated").is_some(),
        "missing cgroup_delegated in active_analysis"
    );
    assert!(
        active.get("strace").is_some(),
        "missing strace in active_analysis"
    );
    assert!(
        active.get("ebpf").is_some(),
        "missing ebpf in active_analysis"
    );
    assert!(
        active.get("kvm").is_some(),
        "missing kvm in active_analysis"
    );
    assert!(
        active.get("recommended_memory_budget_bytes").is_some(),
        "missing recommended_memory_budget_bytes in active_analysis"
    );

    // 2. behaviour_profiles map verification
    let profiles = val
        .get("behaviour_profiles")
        .expect("must contain behaviour_profiles");
    assert!(profiles.get("quick").is_some(), "missing quick profile");
    assert!(
        profiles.get("standard").is_some(),
        "missing standard profile"
    );
    assert!(profiles.get("deep").is_some(), "missing deep profile");
    assert!(
        profiles.get("research").is_some(),
        "missing research profile"
    );

    let standard = &profiles["standard"];
    assert_eq!(standard["max_prompts"], 64);
    assert_eq!(standard["repeat_count"], 1);
    assert_eq!(standard["max_tokens"], 512);
}

#[test]
fn behaviour_profiles_subcommand_outputs_metadata() {
    let output = run(&["behaviour", "profiles", "--json"]);
    assert!(
        output.status.success(),
        "behaviour profiles --json must succeed"
    );
    let val: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse behaviour profiles json");

    assert!(val.get("standard").is_some());
    assert_eq!(val["standard"]["name"], "standard");
    assert_eq!(val["standard"]["max_prompts"], 64);
    assert_eq!(val["standard"]["repeat_count"], 1);
    assert_eq!(val["quick"]["max_prompts"], 8);
    assert_eq!(val["deep"]["max_prompts"], 256);
    assert_eq!(val["research"]["max_prompts"], 1000);
}

#[test]
fn behaviour_preflight_on_missing_model_returns_machine_readable_not_run() {
    let output = run(&[
        "behaviour",
        "preflight",
        "/nonexistent/model.gguf",
        "--runtime",
        "llama-cpp",
        "--profile",
        "standard",
        "--json",
    ]);
    let val: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse preflight json response");

    assert_eq!(val["state"], "NOT_RUN");
    assert!(val.get("reason_code").is_some());
    assert!(val["reason_code"].is_string());
    let reason_code = val["reason_code"].as_str().unwrap();
    assert!(
        reason_code == "RUNTIME_UNAVAILABLE"
            || reason_code == "PREREQUISITE_UNAVAILABLE"
            || reason_code == "INSUFFICIENT_MEMORY"
            || reason_code == "STATIC_BLOCKED",
        "unexpected reason_code: {reason_code}"
    );
    assert_eq!(val["profile"]["name"], "standard");
    assert_eq!(val["profile"]["prompts"], 64);
    assert_eq!(val["profile"]["repeats"], 1);
}

#[test]
fn behaviour_json_error_returns_structured_not_run_reason_code() {
    let output = run(&[
        "behaviour",
        "/nonexistent/missing_model_for_test.gguf",
        "--runtime",
        "llama-cpp",
        "--profile",
        "standard",
        "--json",
    ]);
    let val: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse behaviour json response");

    assert_eq!(val["state"], "NOT_RUN");
    assert!(val.get("reason_code").is_some());
    assert!(val["reason_code"].is_string());
    assert!(val.get("available_budget_bytes").is_some());
}

#[test]
fn research_subcommands_accept_timeout_seconds_argument() {
    // Backdoor
    let out = run(&[
        "research",
        "backdoor",
        "/tmp/fake.gguf",
        "--timeout-seconds",
        "45",
        "--help",
    ]);
    assert!(out.status.success());

    // TriggerHunt
    let out = run(&[
        "research",
        "trigger-hunt",
        "--model",
        "/tmp/fake.gguf",
        "--timeout-seconds",
        "45",
        "--help",
    ]);
    assert!(out.status.success());

    // ActivationDiff
    let out = run(&[
        "research",
        "activation-diff",
        "/tmp/base.safetensors",
        "/tmp/derived.safetensors",
        "--tokenizer",
        "/tmp/tok.json",
        "--timeout-seconds",
        "45",
        "--help",
    ]);
    assert!(out.status.success());
}
