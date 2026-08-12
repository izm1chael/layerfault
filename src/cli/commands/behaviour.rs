use super::super::{BehaviourArgs, CompareBehaviourArgs};
use anyhow::{anyhow, bail, Result};
use layerfault::json_stream::write_stdout_json;
use std::path::Path;

use layerfault::decision::SecurityDecision;
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
    };
    let mut report = match args.runtime.as_str() {
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
            )?
        }
        "transformers" | "transformers-python" => layerfault::behaviour::python::run_transformers(
            &args.model,
            args.base.as_deref(),
            args.runtime_path.as_deref(),
            args.probe_suite.as_deref(),
            args.seed,
            limits,
            active,
        )?,
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
            )?
        }
        other => {
            bail!("unsupported behaviour runtime '{other}'; supported values: llama-cpp, transformers, embedded")
        }
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
    };
    let report = match args.runtime.as_str() {
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
            )?
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
            )?
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
            )?
        }
        other => {
            bail!("unsupported behaviour runtime '{other}'; supported values: llama-cpp, transformers, embedded")
        }
    };
    if args.json {
        write_stdout_json(&report, true)?;
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
