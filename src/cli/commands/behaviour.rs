use super::super::{BehaviourArgs, CompareBehaviourArgs};
use anyhow::{anyhow, bail, Result};
use layerfault::json_stream::write_stdout_json;
use std::path::Path;

use layerfault::decision::SecurityDecision;

/// A structured `BehaviourReport` for the case where behaviour never
/// actually executed (static admission blocked it, the runner/sandbox was
/// unavailable, it failed to start, or it timed out before producing a
/// result). `--json` callers must still get a valid, parseable document on
/// stdout describing why, not an empty stream with the reason only on
/// stderr as plain text.
/// `anyhow::Error`'s `Display` (and thus `.to_string()`) only prints the
/// outermost `.context(...)` message, not the chain of causes underneath it
/// — e.g. a `.context("persistent llama-server probe failed")` wrapping the
/// real HTTP/IO error renders as just that generic wrapper text, with the
/// actual underlying failure silently dropped. Join the full chain so a
/// JSON `NOT_RUN` reason is actually diagnostic.
fn error_reason_with_chain(error: &anyhow::Error) -> String {
    let causes: Vec<String> = error.chain().skip(1).map(ToString::to_string).collect();
    if causes.is_empty() {
        error.to_string()
    } else {
        format!("{error} ({})", causes.join("; "))
    }
}

fn not_run_behaviour_report(
    model_path: &Path,
    limits: &layerfault::behaviour::BehaviourLimits,
    reason: &str,
) -> layerfault::behaviour::BehaviourReport {
    layerfault::behaviour::BehaviourReport {
        schema_version: "1.0".to_owned(),
        model_identity: String::new(),
        model_path: model_path.display().to_string(),
        runtime: layerfault::behaviour::RuntimeIdentity {
            backend: "not-run".to_owned(),
            executable: String::new(),
            executable_sha256: String::new(),
            version: None,
            sandbox: Default::default(),
            closure: None,
        },
        probe_suite_id: String::new(),
        probe_suite_version: 0,
        seed: 0,
        limits: limits.clone(),
        executions: Vec::new(),
        dynamic_observations: Default::default(),
        state: layerfault::transformation::BehaviourState::NotRun,
        findings: vec![format!("LF-BEHAV-NOT-RUN: {reason}")],
        boundary: format!(
            "Behavioural execution did not occur: {reason}. This is not evidence the model is safe or unsafe; it means no dynamic observation was made."
        ),
    }
}

/// The differential-comparison counterpart of `not_run_behaviour_report`,
/// for `compare-behaviour --json` when the comparison never ran.
fn not_run_differential_report(
    base_path: &Path,
    derived_path: &Path,
    limits: &layerfault::behaviour::BehaviourLimits,
    reason: &str,
) -> layerfault::behaviour::DifferentialReport {
    layerfault::behaviour::DifferentialReport {
        schema_version: "1.0".to_owned(),
        base: not_run_behaviour_report(base_path, limits, reason),
        derived: not_run_behaviour_report(derived_path, limits, reason),
        rows: Vec::new(),
        state: layerfault::transformation::DifferentialBehaviourState::NotRun,
        findings: vec![format!("LF-BEHAV-DIFF-NOT-RUN: {reason}")],
    }
}
pub(crate) fn run_behaviour(args: BehaviourArgs) -> Result<()> {
    let closure_level = layerfault::behaviour::closure::ClosureLevel::parse(&args.closure_level)?;
    if let Some(replay_path) = args.replay.as_deref() {
        let replay = layerfault::behaviour::load_replay(replay_path)?;
        let active = layerfault::behaviour::ActiveExecutionOptions {
            sandbox_kind: args.sandbox,
            microvm_config: layerfault::behaviour::microvm::MicrovmConfig::from_env_and_args(
                args.microvm_image.clone(),
                args.microvm_image_hash.clone(),
            ),
            allow_static_blocked: args.allow_static_blocked,
            execute_custom_code: args.execute_custom_code,
            closure_level: replay.closure_level,
            require_cgroup: require_cgroup_from_env_or_arg(args.require_cgroup),
            telemetry_backend: args.telemetry_backend,
        };
        let mut report = match args.runtime.as_str() {
            "llama-cpp" => layerfault::behaviour::run_external_llama_active(
                Path::new(&replay.model_path),
                Some(Path::new(&replay.runtime_path)),
                replay.probe_suite_path.as_deref().map(Path::new),
                replay.seed,
                replay.limits.clone(),
                active,
            )?,
            "transformers" | "transformers-python" => {
                layerfault::behaviour::python::run_transformers(
                    Path::new(&replay.model_path),
                    None,
                    Some(Path::new(&replay.runtime_path)),
                    replay.probe_suite_path.as_deref().map(Path::new),
                    replay.seed,
                    replay.limits.clone(),
                    active,
                )?
            }
            other => bail!("unsupported behaviour replay runtime '{other}'"),
        };

        let current_closure_id = report.runtime.closure.as_ref().map(|c| &c.closure_id);
        let expected_closure_id = &replay.runtime_closure_id;

        let drifted = match (expected_closure_id.is_empty(), current_closure_id) {
            (false, Some(curr)) => curr != expected_closure_id,
            _ => report.runtime.executable_sha256 != replay.runtime_sha256,
        };

        if drifted {
            report.findings.push(format!(
                "RUNTIME_ENVIRONMENT_CHANGED: replay execution under changed software runtime closure (expected '{}', got '{}')",
                if !expected_closure_id.is_empty() { expected_closure_id } else { &replay.runtime_sha256 },
                current_closure_id.map(|s| s.as_str()).unwrap_or(&report.runtime.executable_sha256)
            ));
        }

        return emit_behaviour(&report, args.json);
    }
    let limits = resolve_behaviour_limits(&args)?;
    let active = layerfault::behaviour::ActiveExecutionOptions {
        sandbox_kind: args.sandbox,
        microvm_config: layerfault::behaviour::microvm::MicrovmConfig::from_env_and_args(
            args.microvm_image.clone(),
            args.microvm_image_hash.clone(),
        ),
        allow_static_blocked: args.allow_static_blocked,
        execute_custom_code: args.execute_custom_code,
        closure_level,
        require_cgroup: require_cgroup_from_env_or_arg(args.require_cgroup),
        telemetry_backend: args.telemetry_backend,
    };
    let report_limits = limits.clone();
    let result: Result<layerfault::behaviour::BehaviourReport> = match args.runtime.as_str() {
        "llama-cpp" => {
            if args.execute_custom_code {
                bail!("--execute-custom-code is only supported by --runtime transformers");
            }
            layerfault::behaviour::run_external_llama_active(
                &args.model,
                args.runtime_path.as_deref(),
                args.probe_suite.as_deref(),
                args.seed,
                limits,
                active,
            )
        }
        "transformers" | "transformers-python" => layerfault::behaviour::python::run_transformers(
            &args.model,
            args.base.as_deref(),
            args.runtime_path.as_deref(),
            args.probe_suite.as_deref(),
            args.seed,
            limits,
            active,
        ),
        "embedded" => {
            if args.allow_static_blocked || args.execute_custom_code {
                bail!("--allow-static-blocked/--execute-custom-code require an external strong-sandbox runtime, not --runtime embedded");
            }
            let tokenizer = args.tokenizer.as_deref().ok_or_else(|| {
                anyhow!("--runtime embedded requires --tokenizer /path/to/tokenizer.json")
            })?;
            layerfault::behaviour::run_embedded(
                &args.model,
                tokenizer,
                args.probe_suite.as_deref(),
                args.seed,
                limits,
            )
        }
        other => {
            bail!("unsupported behaviour runtime '{other}'; supported values: llama-cpp, transformers, embedded")
        }
    };
    // Under --json, a runtime-execution failure (static admission block,
    // unavailable sandbox/runner, startup/timeout error) must still produce
    // a structured, machine-readable result on stdout, not an empty stream
    // with the reason only on stderr as plain text. Non-JSON invocations
    // keep the normal error path — propagate via `?` so the message lands
    // on stderr and the process exits non-zero, matching every other
    // Layerfault CLI error.
    let mut report = match result {
        Ok(report) => report,
        Err(error) if args.json => {
            return emit_behaviour(
                &not_run_behaviour_report(
                    &args.model,
                    &report_limits,
                    &error_reason_with_chain(&error),
                ),
                args.json,
            );
        }
        Err(error) => return Err(error),
    };
    apply_watch_strings(&mut report, &args.watch_string);
    if let Some(path) = args.run_manifest_out.as_deref() {
        let manifest = layerfault::behaviour::replay_manifest(&report, args.probe_suite.as_deref());
        layerfault::paths::write_private(path, &serde_json::to_vec_pretty(&manifest)?)?;
    }
    emit_behaviour(&report, args.json)
}

pub(crate) fn resolve_behaviour_limits(
    args: &BehaviourArgs,
) -> Result<layerfault::behaviour::BehaviourLimits> {
    Ok(
        layerfault::behaviour::BehaviourLimits::for_profile(&args.profile)?.clamp(
            args.max_prompts.unwrap_or(usize::MAX),
            args.max_turns.unwrap_or(usize::MAX),
            args.max_tokens.map(|v| v as u64).unwrap_or(u64::MAX),
            args.timeout_seconds.unwrap_or(u64::MAX),
            args.max_mutations.unwrap_or(usize::MAX),
            args.repeat_count.unwrap_or(usize::MAX),
        ),
    )
}

pub(crate) fn run_compare_behaviour(args: CompareBehaviourArgs) -> Result<()> {
    let defaults = layerfault::behaviour::BehaviourLimits::for_profile(&args.profile)?;
    let limits = defaults.clamp(
        args.max_prompts.unwrap_or(usize::MAX),
        args.max_turns.unwrap_or(usize::MAX),
        args.max_tokens.map(|v| v as u64).unwrap_or(u64::MAX),
        args.timeout_seconds.unwrap_or(u64::MAX),
        usize::MAX,
        usize::MAX,
    );
    let closure_level = layerfault::behaviour::closure::ClosureLevel::parse(&args.closure_level)?;
    let active = layerfault::behaviour::ActiveExecutionOptions {
        sandbox_kind: args.sandbox,
        microvm_config: layerfault::behaviour::microvm::MicrovmConfig::from_env_and_args(
            args.microvm_image.clone(),
            args.microvm_image_hash.clone(),
        ),
        allow_static_blocked: args.allow_static_blocked,
        execute_custom_code: args.execute_custom_code,
        closure_level,
        require_cgroup: args.require_cgroup,
        telemetry_backend: args.telemetry_backend,
    };
    let report_limits = limits.clone();
    let result: Result<layerfault::behaviour::DifferentialReport> = match args.runtime.as_str() {
        "llama-cpp" => {
            if args.execute_custom_code {
                bail!("--execute-custom-code is only supported by --runtime transformers");
            }
            layerfault::behaviour::compare_external_llama_active(
                &args.base,
                &args.derived,
                args.runtime_path.as_deref(),
                args.probe_suite.as_deref(),
                args.seed,
                limits,
                active,
            )
        }
        "transformers" | "transformers-python" => {
            layerfault::behaviour::python::compare_transformers(
                &args.base,
                &args.derived,
                args.runtime_path.as_deref(),
                args.probe_suite.as_deref(),
                args.seed,
                limits,
                active,
            )
        }
        "embedded" => {
            if args.allow_static_blocked || args.execute_custom_code {
                bail!("--allow-static-blocked/--execute-custom-code require an external strong-sandbox runtime, not --runtime embedded");
            }
            let tokenizer = args.tokenizer.as_deref().ok_or_else(|| {
                anyhow!("--runtime embedded requires --tokenizer /path/to/tokenizer.json")
            })?;
            layerfault::behaviour::compare_embedded(
                &args.base,
                &args.derived,
                tokenizer,
                args.probe_suite.as_deref(),
                args.seed,
                limits,
            )
        }
        other => {
            bail!("unsupported behaviour runtime '{other}'; supported values: llama-cpp, transformers, embedded")
        }
    };
    // Same contract as `run_behaviour`: under --json, a comparison that
    // never executed (static admission block, unavailable runtime,
    // startup/timeout error) must still emit a structured document. A
    // non-JSON invocation keeps the normal stderr error path.
    let report = match result {
        Ok(report) => report,
        Err(error) if args.json => not_run_differential_report(
            &args.base,
            &args.derived,
            &report_limits,
            &error_reason_with_chain(&error),
        ),
        Err(error) => return Err(error),
    };
    emit_differential(&report, args.json)
}
fn emit_differential(
    report: &layerfault::behaviour::DifferentialReport,
    json_output: bool,
) -> Result<()> {
    if json_output {
        write_stdout_json(report, true)?;
    } else {
        println!(
            "DIFFERENTIAL BEHAVIOUR\n{:?}\n\n{} comparison row(s)",
            report.state,
            report.rows.len()
        );
        for row in report.rows.iter().filter(|r| {
            !matches!(
                r.classification,
                layerfault::transformation::DifferentialBehaviourState::Expected
            )
        }) {
            println!("{}: {:?}", row.probe_id, row.classification);
        }
    }
    let decision = SecurityDecision::from_differential_behaviour_state(report.state);
    let code = decision.exit_code();
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}
fn emit_behaviour(
    report: &layerfault::behaviour::BehaviourReport,
    json_output: bool,
) -> Result<()> {
    if json_output {
        write_stdout_json(report, true)?;
    } else {
        println!(
            "BEHAVIOURAL SECURITY\n{:?}\n\n{} probe execution(s)",
            report.state,
            report.executions.len()
        );
        for f in &report.findings {
            println!("{f}");
        }
        let dynamic = &report.dynamic_observations;
        println!(
            "\nDYNAMIC TELEMETRY\nnetwork={} exec={} sensitive_path={} canary={} protected_write_attempt={} unexpected_fs={} trace={}",
            dynamic.network_attempts,
            dynamic.process_exec_attempts,
            dynamic.sensitive_path_accesses,
            dynamic.canary_accesses,
            dynamic.filesystem_write_attempts,
            dynamic.unexpected_filesystem_mutations,
            if dynamic.trace_available { "AVAILABLE" } else { "UNAVAILABLE" }
        );
        println!("\n{}", report.boundary);
    }
    let decision = SecurityDecision::from_behaviour_state(report.state);
    let code = decision.exit_code();
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}
fn apply_watch_strings(report: &mut layerfault::behaviour::BehaviourReport, watch: &[String]) {
    for value in watch.iter().filter(|v| !v.is_empty()).take(128) {
        if report
            .executions
            .iter()
            .any(|e| e.response_excerpt.contains(value))
        {
            report.findings.push("LF-BEHAV-TARGETED-CONTENT".to_owned());
            report.state = match report.state {
                layerfault::transformation::BehaviourState::HighRisk => {
                    layerfault::transformation::BehaviourState::HighRisk
                }
                _ => layerfault::transformation::BehaviourState::Suspicious,
            };
        }
    }
    report.findings.sort();
    report.findings.dedup();
}

pub(super) fn require_cgroup_from_env_or_arg(arg: bool) -> bool {
    arg || std::env::var("LAYERFAULT_BEHAVIOUR_REQUIRE_CGROUP")
        .is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_reason_with_chain_includes_underlying_causes() {
        let base = anyhow::anyhow!("connection reset by peer");
        let wrapped = base.context("persistent llama-server probe failed");
        let reason = error_reason_with_chain(&wrapped);
        assert!(reason.contains("persistent llama-server probe failed"));
        assert!(
            reason.contains("connection reset by peer"),
            "reason must surface the real underlying cause, not just the wrapper message: {reason}"
        );
    }

    #[test]
    fn error_reason_with_chain_handles_no_causes() {
        let error = anyhow::anyhow!("llama.cpp runtime was not found on PATH");
        let reason = error_reason_with_chain(&error);
        assert_eq!(reason, "llama.cpp runtime was not found on PATH");
    }
}
