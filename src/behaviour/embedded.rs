use super::*;
/// Run the same bounded probe framework using Layerfault's embedded Rust/Candle
/// backend. The operator must supply a local tokenizer.json; this function does
/// not download it.
pub fn run_embedded(
    model: &Path,
    tokenizer: &Path,
    suite_path: Option<&Path>,
    seed: u64,
    limits: BehaviourLimits,
) -> Result<BehaviourReport> {
    static_admit(model, false)?;
    let model = resolve_gguf(model)?;
    let model_identity = crate::modelmeta::build_snapshot(&model)?.identity.canonical;
    let suite = probes::expand_mutations(probes::load_suite(suite_path)?, limits.max_mutations);
    let canary_a = synthetic_canary(&model_identity, seed, "A");
    let canary_b = synthetic_canary(&model_identity, seed, "B");
    let mut executions = Vec::new();
    let mut embedded_identity: Option<crate::embedded::EmbeddedIdentity> = None;

    for probe in suite.probes.iter().take(limits.max_prompts) {
        let repeat = probe.repeat.max(1).min(limits.repeat_count.max(1));
        for _repeat_index in 0..repeat {
            let system = probes::render(&probe.system, &canary_a, &canary_b);
            let prompt = probes::render(&probe.prompt, &canary_a, &canary_b);
            let combined = format!("<system>\n{system}\n</system>\n<user>\n{prompt}\n</user>");
            let result = crate::embedded::run(
                &model,
                tokenizer,
                &combined,
                usize::try_from(limits.max_tokens).unwrap_or(4096),
                limits.timeout_seconds,
            )?;
            if result.output.len() > limits.max_output_bytes {
                bail!("embedded response exceeded the selected behaviour output cap");
            }
            embedded_identity.get_or_insert_with(|| result.identity.clone());
            let evaluation =
                evaluate::evaluate(&probe.category, &result.output, &[&canary_a, &canary_b]);
            executions.push(ProbeExecution {
                probe_id: probe.id.clone(),
                category: probe.category.clone(),
                comparison_group: probe.comparison_group.clone(),
                comparison_role: probe.comparison_role.clone(),
                expected_boundary: probe.expected_boundary.clone(),
                prompt_sha256: sha256(combined.as_bytes()),
                response_sha256: result.output_sha256.clone(),
                response_excerpt: bounded_excerpt(&result.output, 4096),
                duration_ms: result.duration_ms,
                exit_code: Some(0),
                timed_out: false,
                telemetry: sandbox::SandboxTelemetry::default(),
                evaluation,
            });
        }
    }
    let embedded_identity =
        embedded_identity.ok_or_else(|| anyhow::anyhow!("no embedded probes executed"))?;
    let runtime = RuntimeIdentity {
        backend: embedded_identity.backend,
        executable: "embedded".to_owned(),
        executable_sha256: format!("crate:candelabra:{}", embedded_identity.version),
        version: Some(embedded_identity.version),
        sandbox: sandbox::SandboxCapabilities {
            workspace_isolated: true,
            home_isolated: true,
            environment_scrubbed: true,
            network_isolation: true,
            network_mechanism: Some("in-process-no-network-api".to_owned()),
            host_files_hidden: false,
            real_tools_disabled: true,
            process_namespace_isolated: false,
            ipc_namespace_isolated: false,
            uts_namespace_isolated: false,
            capabilities_dropped: false,
            resource_limits: false,
            address_space_limit_bytes: None,
            seccomp_filter: false,
            syscall_trace: false,
            syscall_trace_mechanism: None,
            ..sandbox::SandboxCapabilities::default()
        },
        closure: None,
    };
    finalize_report(
        model_identity,
        model.display().to_string(),
        runtime,
        suite,
        seed,
        limits,
        executions,
    )
}

pub fn compare_embedded(
    base: &Path,
    derived: &Path,
    tokenizer: &Path,
    suite_path: Option<&Path>,
    seed: u64,
    limits: BehaviourLimits,
) -> Result<DifferentialReport> {
    let base_report = run_embedded(base, tokenizer, suite_path, seed, limits.clone())?;
    let derived_report = run_embedded(derived, tokenizer, suite_path, seed, limits)?;
    compare_reports(base_report, derived_report)
}

pub(crate) fn finalize_report(
    model_identity: String,
    model_path: String,
    runtime: RuntimeIdentity,
    suite: probes::ProbeSuite,
    seed: u64,
    limits: BehaviourLimits,
    executions: Vec<ProbeExecution>,
) -> Result<BehaviourReport> {
    let mut findings: Vec<String> = executions
        .iter()
        .flat_map(|value| value.evaluation.rule_ids.clone())
        .collect();
    findings.sort();
    findings.dedup();
    let high = executions
        .iter()
        .any(|value| value.evaluation.risk == evaluate::Risk::High);
    let suspicious = executions.iter().any(|value| {
        matches!(
            value.evaluation.risk,
            evaluate::Risk::Medium | evaluate::Risk::High
        ) && value
            .evaluation
            .rule_ids
            .iter()
            .any(|rule| rule != "LF-BEHAV-RUNTIME-FAILURE")
    });
    let meaningful_probe_completed = executions.iter().any(|value| {
        value.category != "runtime_side_effects" && value.exit_code == Some(0) && !value.timed_out
    });
    let dynamic_observations = summarize_dynamic_observations(&executions);
    Ok(BehaviourReport {
        schema_version: "1.1".to_owned(),
        model_identity,
        model_path,
        runtime,
        probe_suite_id: suite.id,
        probe_suite_version: suite.version,
        seed,
        limits,
        executions,
        dynamic_observations,
        state: if high {
            // Proven high-risk side effects are not erased by a later model or
            // tokenizer failure that prevents a normal inference response.
            crate::transformation::BehaviourState::HighRisk
        } else if suspicious {
            crate::transformation::BehaviourState::Suspicious
        } else if !meaningful_probe_completed {
            crate::transformation::BehaviourState::NotRun
        } else {
            crate::transformation::BehaviourState::NoSuspiciousObserved
        },
        findings,
        boundary: "No suspicious behaviour observed means only that no suspicious behaviour was observed under the executed probe suite; it does not prove absence of hidden triggers or backdoors.".to_owned(),
    })
}

pub(crate) fn summarize_dynamic_observations(
    executions: &[ProbeExecution],
) -> DynamicObservationSummary {
    let mut summary = DynamicObservationSummary::default();
    for execution in executions {
        let telemetry = &execution.telemetry;
        if telemetry.trace_available || !telemetry.filesystem_mutations.is_empty() {
            summary.executions_with_telemetry = summary.executions_with_telemetry.saturating_add(1);
        }
        summary.filesystem_write_attempts = summary
            .filesystem_write_attempts
            .saturating_add(telemetry.filesystem_write_attempts.len());
        summary.network_attempts = summary
            .network_attempts
            .saturating_add(telemetry.network_attempts.len());
        summary.process_exec_attempts = summary
            .process_exec_attempts
            .saturating_add(telemetry.process_exec_attempts.len());
        summary.sensitive_path_accesses = summary
            .sensitive_path_accesses
            .saturating_add(telemetry.sensitive_path_accesses.len());
        summary.canary_accesses = summary
            .canary_accesses
            .saturating_add(telemetry.canary_accesses.len());
        summary.unexpected_filesystem_mutations =
            summary.unexpected_filesystem_mutations.saturating_add(
                telemetry
                    .filesystem_mutations
                    .iter()
                    .filter(|value| !value.expected_runtime_artifact)
                    .count(),
            );
        summary.trace_available |= telemetry.trace_available;
    }
    summary
}
