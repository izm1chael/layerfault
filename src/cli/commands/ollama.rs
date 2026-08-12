use super::super::*;

pub(crate) fn run_scan(args: ScanArgs) -> Result<()> {
    let prepared = prepare(&args.common)?;
    let base_dir = app::resolve_base_dir(args.common.ollama_dir.as_deref())?;
    let options = scan_options(
        &args.common,
        &prepared,
        args.json || args.sarif || args.jsonl,
    );
    let reports = app::scan_selected(&base_dir, args.model.as_deref(), &options)?;
    if args.json {
        report::emit_evaluated_json(&reports)?;
    } else if args.sarif {
        report::emit_evaluated_sarif(&reports)?;
    } else if args.jsonl {
        layerfault::jsonl::emit_evaluated_jsonl(&reports)?;
    } else {
        report::emit_evaluated_table(&reports);
    }
    std::process::exit(app::policy_exit_code(&reports));
}

pub(crate) fn run_verify(args: VerifyArgs) -> Result<()> {
    let prepared = prepare(&args.common)?;
    let base_dir = app::resolve_base_dir(args.common.ollama_dir.as_deref())?;
    let options = scan_options(&args.common, &prepared, args.json);
    let reports = app::scan_selected(&base_dir, Some(&args.model), &options)?;
    let subject_fingerprint = manifest_fingerprint(&base_dir, &args.model).ok();
    commands::security::maybe_write_evidence(
        &args.evidence,
        &prepared,
        &args.model,
        "ollama",
        subject_fingerprint.as_deref(),
        None,
        None,
        None,
        &decision_label(app::policy_exit_code(&reports)),
        serde_json::to_value(&reports)?,
    )?;
    if args.json {
        report::emit_evaluated_json(&reports)?;
    } else {
        report::emit_evaluated_table(&reports);
    }
    std::process::exit(app::policy_exit_code(&reports));
}

pub(crate) fn manifest_fingerprint(base_dir: &Path, model: &str) -> Result<String> {
    let model_ref = manifest::find_model(base_dir, model)?;
    Ok(manifest::load_model(&model_ref)?.digest)
}

pub(crate) fn decision_label(code: i32) -> String {
    match code {
        0 => "ALLOW",
        1 => "WARN",
        _ => "BLOCK",
    }
    .to_owned()
}
