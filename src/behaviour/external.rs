use super::*;
pub fn run_external_llama(
    model: &Path,
    runtime_path: Option<&Path>,
    suite_path: Option<&Path>,
    seed: u64,
    limits: BehaviourLimits,
) -> Result<BehaviourReport> {
    run_external_llama_active(
        model,
        runtime_path,
        suite_path,
        seed,
        limits,
        ActiveExecutionOptions::default(),
    )
}

pub fn run_external_llama_active(
    model: &Path,
    runtime_path: Option<&Path>,
    suite_path: Option<&Path>,
    seed: u64,
    limits: BehaviourLimits,
    active: ActiveExecutionOptions,
) -> Result<BehaviourReport> {
    let deadline = CommandDeadline::new(limits.timeout_seconds);
    run_external_llama_active_deadline(
        model,
        runtime_path,
        suite_path,
        seed,
        limits,
        active,
        &deadline,
        "model",
    )
}

#[allow(clippy::too_many_arguments)]
fn run_external_llama_active_deadline(
    model: &Path,
    runtime_path: Option<&Path>,
    suite_path: Option<&Path>,
    seed: u64,
    limits: BehaviourLimits,
    active: ActiveExecutionOptions,
    deadline: &CommandDeadline,
    phase_label: &str,
) -> Result<BehaviourReport> {
    let heartbeat = ProgressHeartbeat::start(phase_label);
    heartbeat.update(format!("phase={phase_label} static-admission"));
    if active.execute_custom_code {
        bail!("custom Hugging Face loader execution is only supported by the Transformers backend");
    }
    let telemetry_resolution = telemetry_backend::resolve(active.telemetry_backend)?;
    let backend = sandbox::get_backend(active.sandbox_kind, active.microvm_config.clone());
    backend.require_execution_stack(active.clone())?;
    static_admit(model, active.allow_static_blocked)?;
    if deadline.expired() {
        bail!("behaviour command hard total timeout expired during static admission");
    }
    let model = resolve_gguf(model)?;
    let model_identity = crate::modelmeta::build_snapshot(&model)?.identity.canonical;
    let staged_model = crate::binding::stage_verified(&model, &model_identity)?;
    let suite = probes::expand_mutations(probes::load_suite(suite_path)?, limits.max_mutations);
    let executable = match runtime_path {
        Some(path) => path.to_path_buf(),
        None => crate::sources::find_executable("llama-server")
            .or_else(|| crate::sources::find_executable("llama-cli"))
            .or_else(|| crate::sources::find_executable("main"))
            .ok_or_else(|| anyhow::anyhow!("llama.cpp runtime was not found on PATH"))?,
    };
    let runtime = runtime::RuntimeAdapter::new(executable, &limits, &active)?;
    let identity = runtime.identity_with_closure(active.closure_level);
    let canary_a = synthetic_canary(&model_identity, seed, "A");
    let canary_b = synthetic_canary(&model_identity, seed, "B");
    heartbeat.update(format!("phase={phase_label} model-loading"));
    staged_model.revalidate()?;
    let mut session = runtime.open(
        staged_model.path(),
        &[&canary_a, &canary_b],
        deadline.remaining(),
    )?;
    heartbeat.update(format!("phase={phase_label} model-loaded"));
    let planned = suite
        .probes
        .iter()
        .take(limits.max_prompts)
        .map(|probe| probe.repeat.max(1).min(limits.repeat_count.max(1)))
        .sum::<usize>();
    let mut probe_index = 0usize;
    let mut executions = Vec::new();
    'probes: for probe in suite.probes.iter().take(limits.max_prompts) {
        let repeat = probe.repeat.max(1).min(limits.repeat_count.max(1));
        for repeat_index in 0..repeat {
            if deadline.expired() {
                bail!("behaviour command hard total timeout expired before probe execution");
            }
            probe_index = probe_index.saturating_add(1);
            heartbeat.update(format!(
                "phase={phase_label} probe={probe_index}/{planned} id={}",
                probe.id
            ));
            let system = probes::render(&probe.system, &canary_a, &canary_b);
            let prompt = probes::render(&probe.prompt, &canary_a, &canary_b);
            let combined = format!("<system>\n{system}\n</system>\n<user>\n{prompt}\n</user>");
            let result = session.infer(
                &combined,
                seed.saturating_add(repeat_index as u64),
                limits.max_tokens,
                deadline.remaining(),
            )?;
            let evaluation = evaluate::evaluate_runtime(
                &probe.category,
                &result.stdout,
                &result.stderr,
                &[&canary_a, &canary_b],
                &result.telemetry,
            );
            let timed_out = result.timed_out;
            executions.push(ProbeExecution {
                probe_id: probe.id.clone(),
                category: probe.category.clone(),
                comparison_group: probe.comparison_group.clone(),
                comparison_role: probe.comparison_role.clone(),
                expected_boundary: probe.expected_boundary.clone(),
                prompt_sha256: sha256(combined.as_bytes()),
                response_sha256: sha256(result.stdout.as_bytes()),
                response_excerpt: bounded_excerpt(&result.stdout, 4096),
                duration_ms: result.duration_ms,
                exit_code: result.exit_code,
                timed_out,
                telemetry: result.telemetry,
                evaluation,
            });
            if timed_out {
                break 'probes;
            }
        }
    }
    heartbeat.update(format!("phase={phase_label} teardown"));
    let _ = session.close()?;
    heartbeat.update(format!(
        "phase={phase_label} complete elapsed={}s",
        deadline.elapsed_seconds()
    ));
    for execution in &mut executions {
        execution.telemetry.backend_degraded = telemetry_resolution.degraded.clone();
    }
    finalize_report(
        model_identity,
        model.display().to_string(),
        identity,
        suite,
        seed,
        limits,
        executions,
    )
}

pub fn compare_external_llama(
    base: &Path,
    derived: &Path,
    runtime_path: Option<&Path>,
    suite_path: Option<&Path>,
    seed: u64,
    limits: BehaviourLimits,
) -> Result<DifferentialReport> {
    compare_external_llama_active(
        base,
        derived,
        runtime_path,
        suite_path,
        seed,
        limits,
        ActiveExecutionOptions::default(),
    )
}

pub fn compare_external_llama_active(
    base: &Path,
    derived: &Path,
    runtime_path: Option<&Path>,
    suite_path: Option<&Path>,
    seed: u64,
    limits: BehaviourLimits,
    active: ActiveExecutionOptions,
) -> Result<DifferentialReport> {
    let deadline = CommandDeadline::new(limits.timeout_seconds);
    let base_report = run_external_llama_active_deadline(
        base,
        runtime_path,
        suite_path,
        seed,
        limits.clone(),
        active.clone(),
        &deadline,
        "base",
    )?;
    if deadline.expired() {
        bail!("behaviour comparison hard total timeout expired after base model");
    }
    let derived_report = run_external_llama_active_deadline(
        derived,
        runtime_path,
        suite_path,
        seed,
        limits,
        active,
        &deadline,
        "derived",
    )?;
    compare_reports(base_report, derived_report)
}
