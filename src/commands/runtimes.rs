use crate::*;

pub(crate) fn run_guarded(args: RunArgs) -> Result<()> {
    match SourceKind::parse(&args.source)? {
        SourceKind::Ollama => run_guarded_ollama(args),
        SourceKind::LmStudio => run_guarded_lmstudio(args),
        SourceKind::LlamaCpp | SourceKind::File => run_guarded_llama(args, false),
        other => Err(anyhow!(
            "Guarded run is not supported for source '{}'",
            other.as_str()
        )),
    }
}

pub(crate) fn run_guarded_ollama(args: RunArgs) -> Result<()> {
    let prepared = prepare(&args.common)?;
    let base_dir = app::resolve_base_dir(args.common.ollama_dir.as_deref())?;
    let options = scan_options(&args.common, &prepared, false);
    let reports = app::scan_selected(&base_dir, Some(&args.model), &options)?;
    report::emit_evaluated_table(&reports);
    enforce_ollama_gate(&reports, &args)?;

    let runtime = commands::security::runtime_evaluation_for_binary(
        advisory::RuntimeKind::Ollama,
        &args.runtime_security,
        Some("ollama"),
    )?;
    commands::security::enforce_runtime_evaluation(&runtime)?;

    let before = commands::ollama::manifest_fingerprint(&base_dir, &args.model)?;
    let quiet_options = scan_options(&args.common, &prepared, true);
    let revalidated_reports = app::scan_selected(&base_dir, Some(&args.model), &quiet_options)?;
    let scanner_code = app::scanner_exit_code(&revalidated_reports);
    let policy_code = app::policy_exit_code(&revalidated_reports);
    let after = commands::ollama::manifest_fingerprint(&base_dir, &args.model)?;
    if before != after || matches!(scanner_code, 2 | 3) {
        eprintln!("Layerfault blocked inference because the Ollama artifact set changed or failed integrity during the final pre-launch revalidation.");
        std::process::exit(if scanner_code == 2 { 2 } else { 3 });
    }
    if policy_code == 4 && args.override_reason.is_none() {
        eprintln!("Layerfault policy changed to BLOCK during the final pre-launch revalidation.");
        std::process::exit(4);
    }
    let binding = binding::revalidated(
        args.model.clone(),
        Some(after.clone()),
        "Ollama model manifest and every referenced descriptor were revalidated immediately before launch. Ollama opens its own store paths, so execution binding remains revalidation-based rather than file-descriptor-bound.",
    );
    commands::security::print_binding(&binding);
    commands::security::maybe_write_evidence(
        &args.evidence,
        &prepared,
        &args.model,
        "ollama",
        Some(&after),
        Some(&runtime),
        Some(&binding),
        run_decision(&reports, args.override_reason.as_deref()),
        serde_json::json!({"initial": reports, "pre_launch_revalidation": revalidated_reports}),
    )?;

    // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
    let mut process =
        // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
        crate::safeio::command_for_executable(std::path::Path::new(&runtime.runtime.executable))?;
    let status = process
        .arg("run")
        .arg(&args.model)
        .args(&args.runtime_args)
        .status()
        .with_context(|| format!("Unable to execute '{} run'", runtime.runtime.executable))?;
    std::process::exit(status.code().unwrap_or(1));
}

pub(crate) fn run_guarded_lmstudio(args: RunArgs) -> Result<()> {
    let prepared = prepare(&args.common)?;
    let artifacts = sources::discover_lmstudio()?;
    let item = find_source_artifact(&artifacts, &args.model)?;
    let result = admission::inspect_and_evaluate(
        &item.path,
        &item.identity,
        SourceKind::LmStudio,
        &prepared.policy,
        item.architecture.as_deref(),
        item.quantization.as_deref(),
        None,
    )?;
    emit_admission(&result, false)?;
    enforce_artifact_gate(
        &result,
        args.override_reason.as_deref(),
        args.override_log.as_deref(),
    )?;

    let runtime = commands::security::runtime_evaluation_for_binary(
        advisory::RuntimeKind::LmStudio,
        &args.runtime_security,
        Some("lms"),
    )?;
    commands::security::enforce_runtime_evaluation(&runtime)?;
    let second = artifact::inspect(&item.path, ArtifactScanMode::Full)?;
    let expected = result
        .report
        .sha256
        .as_deref()
        .ok_or_else(|| anyhow!("LM Studio admission did not produce an artifact digest"))?;
    if second.sha256.as_deref() != Some(expected) || second.blocking() {
        eprintln!("Layerfault blocked LM Studio load because the selected artifact changed or failed the final pre-launch validation.");
        std::process::exit(3);
    }
    let binding = binding::revalidated(
        item.path.display().to_string(),
        second.sha256.clone(),
        "The LM Studio model artifact was rehashed immediately before lms load. LM Studio selects the model by runtime key, so Layerfault cannot bind its open file descriptor to the runtime process.",
    );
    commands::security::print_binding(&binding);
    commands::security::maybe_write_evidence(
        &args.evidence,
        &prepared,
        &item.identity,
        "lmstudio",
        second.sha256.as_deref(),
        Some(&runtime),
        Some(&binding),
        artifact_run_decision(&result, args.override_reason.as_deref()),
        serde_json::to_value(&result)?,
    )?;
    std::process::exit(sources::run_lmstudio_load_with(
        Path::new(&runtime.runtime.executable),
        &args.model,
        &args.runtime_args,
    )?);
}

pub(crate) fn run_guarded_llama(args: RunArgs, _serve: bool) -> Result<()> {
    let prepared = prepare(&args.common)?;
    let path = PathBuf::from(&args.model);
    let result = admission::inspect_and_evaluate(
        &path,
        &args.model,
        SourceKind::LlamaCpp,
        &prepared.policy,
        None,
        None,
        None,
    )?;
    emit_admission(&result, false)?;
    enforce_artifact_gate(
        &result,
        args.override_reason.as_deref(),
        args.override_log.as_deref(),
    )?;
    let runtime = commands::security::runtime_evaluation_for_binary(
        advisory::RuntimeKind::LlamaCpp,
        &args.runtime_security,
        Some("llama-cli"),
    )?;
    commands::security::enforce_runtime_evaluation(&runtime)?;
    let digest = result
        .report
        .sha256
        .as_deref()
        .ok_or_else(|| anyhow!("llama.cpp admission did not produce an artifact digest"))?;
    let staged = binding::stage_verified(&path, digest)?;
    commands::security::print_binding(&staged.record);
    commands::security::maybe_write_evidence(
        &args.evidence,
        &prepared,
        &args.model,
        "llama-cpp",
        Some(digest),
        Some(&runtime),
        Some(&staged.record),
        artifact_run_decision(&result, args.override_reason.as_deref()),
        serde_json::to_value(&result)?,
    )?;
    let code = sources::run_llama_with(
        Path::new(&runtime.runtime.executable),
        staged.path(),
        &args.runtime_args,
    )?;
    staged.cleanup()?;
    std::process::exit(code);
}

pub(crate) fn run_import(args: ImportArgs) -> Result<()> {
    let source = SourceKind::parse(&args.source)?;
    if source != SourceKind::LmStudio {
        return Err(anyhow!(
            "Guarded import currently supports only --source lmstudio"
        ));
    }
    let prepared = prepare(&args.common)?;
    let identity = args.path.display().to_string();
    let result = admission::inspect_and_evaluate(
        &args.path,
        &identity,
        SourceKind::LmStudio,
        &prepared.policy,
        None,
        None,
        None,
    )?;
    emit_admission(&result, false)?;
    let code = admission::exit_code(std::slice::from_ref(&result));
    if matches!(code, 2..=4) {
        eprintln!("Layerfault blocked import; the runtime was not modified.");
        std::process::exit(code);
    }
    let runtime = commands::security::runtime_evaluation_for_binary(
        advisory::RuntimeKind::LmStudio,
        &args.runtime_security,
        Some("lms"),
    )?;
    commands::security::enforce_runtime_evaluation(&runtime)?;
    let digest = result
        .report
        .sha256
        .as_deref()
        .ok_or_else(|| anyhow!("Import admission did not produce an artifact digest"))?;
    let staged = binding::stage_verified(&args.path, digest)?;
    commands::security::print_binding(&staged.record);
    commands::security::maybe_write_evidence(
        &args.evidence,
        &prepared,
        &identity,
        "lmstudio-import",
        Some(digest),
        Some(&runtime),
        Some(&staged.record),
        "ALLOW",
        serde_json::to_value(&result)?,
    )?;
    let runtime_code = sources::run_lmstudio_import_with(
        Path::new(&runtime.runtime.executable),
        staged.path(),
        args.execute,
        &args.runtime_args,
    )?;
    staged.cleanup()?;
    std::process::exit(runtime_code);
}

pub(crate) fn run_serve(args: ServeArgs) -> Result<()> {
    let prepared = prepare(&args.common)?;
    let identity = args.path.display().to_string();
    let result = admission::inspect_and_evaluate(
        &args.path,
        &identity,
        SourceKind::LlamaCpp,
        &prepared.policy,
        None,
        None,
        None,
    )?;
    emit_admission(&result, false)?;
    let code = admission::exit_code(std::slice::from_ref(&result));
    if matches!(code, 2..=4) {
        eprintln!("Layerfault blocked llama-server startup.");
        std::process::exit(code);
    }
    let runtime = commands::security::runtime_evaluation_for_binary(
        advisory::RuntimeKind::LlamaCpp,
        &args.runtime_security,
        Some("llama-server"),
    )?;
    commands::security::enforce_runtime_evaluation(&runtime)?;
    let digest = result
        .report
        .sha256
        .as_deref()
        .ok_or_else(|| anyhow!("llama-server admission did not produce an artifact digest"))?;
    let staged = binding::stage_verified(&args.path, digest)?;
    commands::security::print_binding(&staged.record);
    commands::security::maybe_write_evidence(
        &args.evidence,
        &prepared,
        &identity,
        "llama-cpp-server",
        Some(digest),
        Some(&runtime),
        Some(&staged.record),
        "ALLOW",
        serde_json::to_value(&result)?,
    )?;
    let runtime_code = sources::run_llama_with(
        Path::new(&runtime.runtime.executable),
        staged.path(),
        &args.runtime_args,
    )?;
    staged.cleanup()?;
    std::process::exit(runtime_code);
}

pub(crate) fn enforce_ollama_gate(reports: &[app::EvaluatedReport], args: &RunArgs) -> Result<()> {
    let gate = app::policy_exit_code(reports);
    if matches!(gate, 2 | 3) {
        eprintln!("Layerfault blocked inference; scanner/provenance failures are not overridable.");
        std::process::exit(gate);
    }
    if gate == 4 {
        let Some(reason) = args.override_reason.as_deref() else {
            eprintln!("Layerfault policy blocked inference; use --override-reason only for an intentional, audited local-policy exception.");
            std::process::exit(4);
        };
        let first = reports
            .first()
            .ok_or_else(|| anyhow!("No model report available for override audit"))?;
        record_override(
            &first.report.model_name,
            reason,
            first.policy.profile,
            first.trust_state,
            app::scanner_exit_code(reports),
            args.override_log.as_deref(),
        )?;
    }
    Ok(())
}

pub(crate) fn enforce_artifact_gate(
    result: &ArtifactAdmission,
    reason: Option<&str>,
    log: Option<&Path>,
) -> Result<()> {
    let code = admission::exit_code(std::slice::from_ref(result));
    if matches!(code, 2 | 3) {
        eprintln!("Layerfault blocked execution; scanner/provenance failures are not overridable.");
        std::process::exit(code);
    }
    if code == 4 {
        let Some(reason) = reason else {
            eprintln!("Layerfault policy blocked execution; use --override-reason only for an intentional policy exception.");
            std::process::exit(4);
        };
        record_override(
            &result.identity,
            reason,
            result.policy.profile,
            result.trust_state,
            artifact_report_exit(&result.report),
            log,
        )?;
    }
    Ok(())
}

pub(crate) fn find_source_artifact<'a>(
    artifacts: &'a [sources::SourceArtifact],
    selector: &str,
) -> Result<&'a sources::SourceArtifact> {
    let exact = artifacts
        .iter()
        .filter(|item| item.identity == selector)
        .collect::<Vec<_>>();
    if exact.len() == 1 {
        return Ok(exact[0]);
    }
    let matches = artifacts
        .iter()
        .filter(|item| item.identity.contains(selector) || item.display_path.contains(selector))
        .collect::<Vec<_>>();
    if matches.len() == 1 {
        return Ok(matches[0]);
    }
    if matches.is_empty() {
        Err(anyhow!("No local source artifact matched '{selector}'"))
    } else {
        Err(anyhow!(
            "Source selector '{selector}' is ambiguous; use the exact model key/path"
        ))
    }
}

fn run_decision(reports: &[app::EvaluatedReport], override_reason: Option<&str>) -> &'static str {
    let code = app::policy_exit_code(reports);
    if code == 4 && override_reason.is_some() {
        "OVERRIDE_ALLOW"
    } else if code == 1 {
        "WARN"
    } else {
        "ALLOW"
    }
}

fn artifact_run_decision(
    result: &ArtifactAdmission,
    override_reason: Option<&str>,
) -> &'static str {
    let code = admission::exit_code(std::slice::from_ref(result));
    if result.policy.action == policy::PolicyAction::Block && override_reason.is_some() {
        "OVERRIDE_ALLOW"
    } else if code == 1 {
        "WARN"
    } else {
        "ALLOW"
    }
}
