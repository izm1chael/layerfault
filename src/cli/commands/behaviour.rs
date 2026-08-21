use super::super::{
    args::BehaviourCommand, BehaviourArgs, BehaviourPreflightArgs, CompareBehaviourArgs, OutputArgs,
};
use anyhow::{anyhow, bail, Result};
use layerfault::json_stream::write_stdout_json;
use std::path::{Path, PathBuf};
use std::time::Instant;

use layerfault::decision::SecurityDecision;

/// Standardised machine-readable reason codes for unexecuted behavioural runs.
pub(crate) fn classify_not_run_reason(error_message: &str) -> &'static str {
    let lower = error_message.to_ascii_lowercase();
    if lower.contains("exceeds safe host budget")
        || lower.contains("estimated runtime memory")
        || lower.contains("insufficient memory")
        || lower.contains("out of memory")
    {
        "INSUFFICIENT_MEMORY"
    } else if lower.contains("static check failed")
        || lower.contains("static admission blocked")
        || lower.contains("blocked by policy")
        || lower.contains("lf-static-")
        || lower.contains("static_blocked")
        || lower.contains("static admission")
    {
        "STATIC_BLOCKED"
    } else if lower.contains("cgroup") {
        "CGROUP_UNAVAILABLE"
    } else if lower.contains("bubblewrap")
        || lower.contains("bwrap")
        || lower.contains("user namespace")
        || lower.contains("sandbox")
        || lower.contains("microvm")
    {
        "SANDBOX_UNAVAILABLE"
    } else if lower.contains("unsupported behaviour runtime")
        || lower.contains("unsupported behaviour replay runtime")
        || lower.contains("unsupported runtime")
        || lower.contains("unsupported active trigger hunt runtime")
    {
        "UNSUPPORTED_RUNTIME"
    } else if lower.contains("not found on path")
        || lower.contains("not found")
        || lower.contains("executable was not found")
        || lower.contains("runtime was not found")
        || lower.contains("managed python runtime not found")
    {
        "RUNTIME_UNAVAILABLE"
    } else if lower.contains("timeout") || lower.contains("timed out") || lower.contains("deadline")
    {
        "TIME_BUDGET_EXCEEDED"
    } else if lower.contains("stalled") || lower.contains("stall") {
        "STALLED"
    } else {
        "PREREQUISITE_UNAVAILABLE"
    }
}

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
    let reason_code = classify_not_run_reason(reason).to_owned();
    let budget = layerfault::behaviour::configured_memory_budget_bytes();
    let estimated =
        layerfault::behaviour::estimate_active_target_memory("dummy", model_path, None).ok();

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
        reason_code: Some(reason_code),
        detail: Some(reason.to_owned()),
        estimated_memory_bytes: estimated,
        available_budget_bytes: Some(budget),
        safe_memory_budget_bytes: Some(budget),
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
    let reason_code = classify_not_run_reason(reason).to_owned();
    let budget = layerfault::behaviour::configured_memory_budget_bytes();
    let estimated = layerfault::behaviour::estimate_active_target_memory(
        "dummy",
        derived_path,
        Some(base_path),
    )
    .ok();

    layerfault::behaviour::DifferentialReport {
        schema_version: "1.0".to_owned(),
        base: not_run_behaviour_report(base_path, limits, reason),
        derived: not_run_behaviour_report(derived_path, limits, reason),
        rows: Vec::new(),
        state: layerfault::transformation::DifferentialBehaviourState::NotRun,
        reason_code: Some(reason_code),
        detail: Some(reason.to_owned()),
        estimated_memory_bytes: estimated,
        available_budget_bytes: Some(budget),
        safe_memory_budget_bytes: Some(budget),
        findings: vec![format!("LF-BEHAV-DIFF-NOT-RUN: {reason}")],
    }
}

pub(crate) fn run_behaviour_profiles(args: OutputArgs) -> Result<()> {
    let profiles = layerfault::behaviour::BehaviourLimits::all_profiles();
    if args.json {
        write_stdout_json(&profiles, true)?;
    } else {
        println!("BEHAVIOURAL PROFILES\n");
        for (name, meta) in &profiles {
            println!(
                "  {:<12} max_prompts={:<4} repeat_count={:<2} max_tokens={:<4} timeout_seconds={:<3}",
                name, meta.max_prompts, meta.repeat_count, meta.max_tokens, meta.timeout_seconds
            );
        }
    }
    Ok(())
}

fn emit_preflight(
    result: &layerfault::behaviour::BehaviourPreflightResult,
    json: bool,
) -> Result<()> {
    if json {
        write_stdout_json(result, true)?;
    } else {
        println!("BEHAVIOURAL PREFLIGHT: {}", result.state);
        if let Some(code) = &result.reason_code {
            println!("  reason_code: {code}");
        }
        if let Some(detail) = &result.detail {
            println!("  detail: {detail}");
        }
        if let Some(est) = result.estimated_memory_bytes {
            println!(
                "  estimated_memory: {}",
                layerfault::doctor::human_bytes(est)
            );
        }
        if let Some(safe) = result.safe_memory_budget_bytes {
            println!(
                "  safe_memory_budget: {}",
                layerfault::doctor::human_bytes(safe)
            );
        }
        if let Some(load) = result.model_load_ms {
            println!("  model_load_ms: {load} ms");
        }
        if let Some(pilot) = result.pilot_execution_ms {
            println!("  pilot_execution_ms: {pilot} ms");
        }
        if let Some(tps) = result.tokens_per_second {
            println!("  tokens_per_second: {tps:.1} tps");
        }
    }
    Ok(())
}

pub(crate) fn run_behaviour_preflight(args: BehaviourPreflightArgs) -> Result<()> {
    let limits = layerfault::behaviour::BehaviourLimits::for_profile(&args.profile)?;
    let safe_budget = layerfault::behaviour::configured_memory_budget_bytes();
    let estimated_memory = layerfault::behaviour::estimate_active_target_memory(
        &args.runtime,
        &args.model,
        args.base.as_deref(),
    )
    .ok();
    let profile_info = layerfault::behaviour::BehaviourPreflightProfile {
        name: args.profile.clone(),
        prompts: limits.max_prompts,
        repeats: limits.repeat_count,
    };

    if let Some(est) = estimated_memory {
        if est > safe_budget {
            let res = layerfault::behaviour::BehaviourPreflightResult {
                state: "NOT_RUN".to_owned(),
                reason_code: Some("INSUFFICIENT_MEMORY".to_owned()),
                detail: Some(format!(
                    "active analysis skipped: estimated runtime memory {:.1} GiB exceeds safe host budget {:.1} GiB",
                    est as f64 / 1073741824.0,
                    safe_budget as f64 / 1073741824.0
                )),
                estimated_memory_bytes: Some(est),
                safe_memory_budget_bytes: Some(safe_budget),
                available_budget_bytes: Some(safe_budget),
                model_load_ms: None,
                pilot_execution_ms: None,
                tokens_per_second: None,
                profile: profile_info,
            };
            return emit_preflight(&res, args.json);
        }
    }

    if let Err(err) = layerfault::behaviour::static_admit(&args.model, args.allow_static_blocked) {
        let res = layerfault::behaviour::BehaviourPreflightResult {
            state: "NOT_RUN".to_owned(),
            reason_code: Some("STATIC_BLOCKED".to_owned()),
            detail: Some(format!("static admission blocked: {err}")),
            estimated_memory_bytes: estimated_memory,
            safe_memory_budget_bytes: Some(safe_budget),
            available_budget_bytes: Some(safe_budget),
            model_load_ms: None,
            pilot_execution_ms: None,
            tokens_per_second: None,
            profile: profile_info,
        };
        return emit_preflight(&res, args.json);
    }

    let executable = match args.runtime.as_str() {
        "llama-cpp" => match args.runtime_path.as_deref() {
            Some(path) => Some(path.to_path_buf()),
            None => layerfault::sources::find_executable("llama-server")
                .or_else(|| layerfault::sources::find_executable("llama-cli"))
                .or_else(|| layerfault::sources::find_executable("main")),
        },
        "transformers" | "transformers-python" => match args.runtime_path.as_deref() {
            Some(path) => Some(path.to_path_buf()),
            None => layerfault::sources::find_executable("python3")
                .or_else(|| layerfault::sources::find_executable("python")),
        },
        "embedded" => Some(PathBuf::from("embedded")),
        _ => None,
    };
    if executable.is_none() {
        let res = layerfault::behaviour::BehaviourPreflightResult {
            state: "NOT_RUN".to_owned(),
            reason_code: Some(
                if args.runtime != "llama-cpp"
                    && args.runtime != "transformers"
                    && args.runtime != "transformers-python"
                    && args.runtime != "embedded"
                {
                    "UNSUPPORTED_RUNTIME".to_owned()
                } else {
                    "RUNTIME_UNAVAILABLE".to_owned()
                },
            ),
            detail: Some(format!("runtime '{}' is unavailable", args.runtime)),
            estimated_memory_bytes: estimated_memory,
            safe_memory_budget_bytes: Some(safe_budget),
            available_budget_bytes: Some(safe_budget),
            model_load_ms: None,
            pilot_execution_ms: None,
            tokens_per_second: None,
            profile: profile_info,
        };
        return emit_preflight(&res, args.json);
    }

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
        require_cgroup: require_cgroup_from_env_or_arg(args.require_cgroup),
        telemetry_backend: args.telemetry_backend,
    };

    let backend = layerfault::behaviour::sandbox::get_backend(
        active.sandbox_kind,
        active.microvm_config.clone(),
    );
    if let Err(err) = backend.require_execution_stack(active.clone()) {
        let res = layerfault::behaviour::BehaviourPreflightResult {
            state: "NOT_RUN".to_owned(),
            reason_code: Some("SANDBOX_UNAVAILABLE".to_owned()),
            detail: Some(err.to_string()),
            estimated_memory_bytes: estimated_memory,
            safe_memory_budget_bytes: Some(safe_budget),
            available_budget_bytes: Some(safe_budget),
            model_load_ms: None,
            pilot_execution_ms: None,
            tokens_per_second: None,
            profile: profile_info,
        };
        return emit_preflight(&res, args.json);
    }

    let pilot_start = Instant::now();
    let pilot_limits = layerfault::behaviour::BehaviourLimits {
        max_prompts: 1,
        max_turns: 1,
        max_tokens: 32,
        max_output_bytes: 32 * 1024,
        timeout_seconds: args.timeout_seconds.unwrap_or(60),
        max_mutations: 0,
        repeat_count: 1,
    };

    let report_result = match args.runtime.as_str() {
        "llama-cpp" => {
            if args.execute_custom_code {
                bail!("--execute-custom-code is only supported by --runtime transformers");
            }
            layerfault::behaviour::run_external_llama_active(
                &args.model,
                args.runtime_path.as_deref(),
                None,
                0,
                pilot_limits,
                active,
            )
        }
        "transformers" | "transformers-python" => layerfault::behaviour::python::run_transformers(
            &args.model,
            args.base.as_deref(),
            args.runtime_path.as_deref(),
            None,
            0,
            pilot_limits,
            active,
        ),
        "embedded" => {
            let tokenizer = args.tokenizer.as_deref().ok_or_else(|| {
                anyhow!("--runtime embedded requires --tokenizer /path/to/tokenizer.json")
            })?;
            layerfault::behaviour::run_embedded(&args.model, tokenizer, None, 0, pilot_limits)
        }
        other => bail!("unsupported behaviour runtime '{other}'"),
    };

    match report_result {
        Ok(rep) => {
            let total_ms = pilot_start.elapsed().as_millis() as u64;
            let probe_dur = rep.executions.first().map(|e| e.duration_ms).unwrap_or(0);
            let model_load_ms = total_ms.saturating_sub(probe_dur);
            let pilot_execution_ms = probe_dur.max(1);
            let words = rep
                .executions
                .first()
                .map(|e| e.response_excerpt.split_whitespace().count())
                .unwrap_or(1);
            let estimated_tokens = (words as f64 * 1.33).max(1.0);
            let tokens_per_second =
                ((estimated_tokens / (pilot_execution_ms as f64 / 1000.0).max(0.001)) * 10.0)
                    .round()
                    / 10.0;
            let res = layerfault::behaviour::BehaviourPreflightResult {
                state: "RUNNABLE".to_owned(),
                reason_code: None,
                detail: None,
                estimated_memory_bytes: estimated_memory,
                safe_memory_budget_bytes: Some(safe_budget),
                available_budget_bytes: Some(safe_budget),
                model_load_ms: Some(model_load_ms),
                pilot_execution_ms: Some(pilot_execution_ms),
                tokens_per_second: Some(tokens_per_second),
                profile: profile_info,
            };
            emit_preflight(&res, args.json)
        }
        Err(err) => {
            let reason = error_reason_with_chain(&err);
            let reason_code = classify_not_run_reason(&reason).to_owned();
            let res = layerfault::behaviour::BehaviourPreflightResult {
                state: "NOT_RUN".to_owned(),
                reason_code: Some(reason_code),
                detail: Some(reason),
                estimated_memory_bytes: estimated_memory,
                safe_memory_budget_bytes: Some(safe_budget),
                available_budget_bytes: Some(safe_budget),
                model_load_ms: None,
                pilot_execution_ms: None,
                tokens_per_second: None,
                profile: profile_info,
            };
            emit_preflight(&res, args.json)
        }
    }
}

pub(crate) fn run_behaviour(args: BehaviourArgs) -> Result<()> {
    if let Some(cmd) = args.command {
        return match cmd {
            BehaviourCommand::Preflight(preflight_args) => run_behaviour_preflight(preflight_args),
            BehaviourCommand::Profiles(output_args) => run_behaviour_profiles(output_args),
        };
    }
    let model = args
        .model
        .as_ref()
        .ok_or_else(|| anyhow!("model path is required"))?;
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
                model,
                args.runtime_path.as_deref(),
                args.probe_suite.as_deref(),
                args.seed,
                limits,
                active,
            )
        }
        "transformers" | "transformers-python" => layerfault::behaviour::python::run_transformers(
            model,
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
                model,
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
                &not_run_behaviour_report(model, &report_limits, &error_reason_with_chain(&error)),
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
