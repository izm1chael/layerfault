use crate::*;

pub(crate) fn run_inspect(args: InspectArgs) -> Result<()> {
    if args.path.is_dir() {
        let result = package::inspect(&args.path)?;
        if args.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&package_json_report(&result))?
            );
        } else {
            print_package_report(&result);
        }
        std::process::exit(package_report_exit(&result, None));
    }

    let mode = if args.structure_only {
        ArtifactScanMode::StructureOnly
    } else {
        ArtifactScanMode::Full
    };
    let result = artifact::inspect(&args.path, mode)?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&artifact_json_report(&result))?
        );
    } else {
        print_artifact_report(&result);
    }
    std::process::exit(artifact_report_exit(&result));
}

pub(crate) fn run_verify_file(args: VerifyFileArgs) -> Result<()> {
    let prepared = prepare(&args.common)?;
    let source = SourceKind::parse(&args.source)?;
    let identity = args
        .identity
        .clone()
        .unwrap_or_else(|| args.path.display().to_string());
    let sigstore = sigstore_request(
        args.sigstore_bundle.as_deref(),
        args.certificate_identity.as_deref(),
        args.certificate_issuer.as_deref(),
    )?;
    let result = admission::inspect_and_evaluate(
        &args.path,
        &identity,
        source,
        &prepared.policy,
        args.architecture.as_deref(),
        args.quantization.as_deref(),
        sigstore,
    )?;
    let decision = format!("{:?}", result.policy.action).to_ascii_uppercase();
    commands::security::maybe_write_evidence(
        &args.evidence,
        &prepared,
        &identity,
        source.as_str(),
        result.report.sha256.as_deref(),
        None,
        None,
        &decision,
        serde_json::to_value(&result)?,
    )?;
    emit_admission(&result, args.json)?;
    std::process::exit(admission::exit_code(&[result]));
}

pub(crate) fn run_scan_dir(args: ScanDirArgs) -> Result<()> {
    let mode = if args.structure_only {
        ArtifactScanMode::StructureOnly
    } else {
        ArtifactScanMode::Full
    };
    let reports = artifact::inspect_dir(&args.path, args.recursive, mode)?;
    if args.json {
        let output = reports.iter().map(artifact_json_report).collect::<Vec<_>>();
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        for report in &reports {
            print_artifact_report(report);
        }
    }
    let code = reports.iter().map(artifact_report_exit).max().unwrap_or(0);
    std::process::exit(code);
}

pub(crate) fn run_fingerprint(args: FingerprintArgs) -> Result<()> {
    let report = package::inspect(&args.path)?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "path": report.root,
                "package_fingerprint": report.fingerprint,
                "files": report.files.len(),
                "bytes": report.total_bytes,
                "blocking": report.blocking()
            }))?
        );
    } else {
        println!("{}", report.fingerprint);
        println!(
            "files={} bytes={} blocking={}",
            report.files.len(),
            report.total_bytes,
            report.blocking()
        );
    }
    Ok(())
}

pub(crate) fn run_verify_package(args: VerifyPackageArgs) -> Result<()> {
    let prepared = prepare(&args.common)?;
    let report = package::inspect(&args.path)?;
    let context = policy::PolicyContext {
        source: Some("directory".to_owned()),
        format: Some("model-package".to_owned()),
        model_size: Some(report.total_bytes),
        now_unix: layerfault::paths::now_unix(),
        ..policy::PolicyContext::default()
    };
    let decision = prepared.policy.evaluate_with_context(
        &report.fingerprint,
        &report.findings,
        provenance::TrustState::Unsigned,
        &context,
    );
    let output = serde_json::json!({
        "package": package_json_report(&report),
        "trust_state": provenance::TrustState::Unsigned,
        "policy": &decision
    });
    commands::security::maybe_write_evidence(
        &args.evidence,
        &prepared,
        &report.fingerprint,
        "directory",
        Some(&report.fingerprint),
        None,
        None,
        &format!("{:?}", decision.action).to_ascii_uppercase(),
        output.clone(),
    )?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        print_package_report(&report);
        println!("Policy: {:?}", decision.action);
        for reason in &decision.reasons {
            println!("  {reason}");
        }
    }
    std::process::exit(package_report_exit(&report, Some(&decision)));
}

pub(crate) fn run_pipeline(args: PipelineArgs) -> Result<()> {
    let prepared = prepare(&args.common)?;
    if args.path.is_dir() {
        let report = package::inspect(&args.path)?;
        let context = policy::PolicyContext {
            source: Some("directory".to_owned()),
            format: Some("model-package".to_owned()),
            model_size: Some(report.total_bytes),
            now_unix: layerfault::paths::now_unix(),
            ..policy::PolicyContext::default()
        };
        let decision = prepared.policy.evaluate_with_context(
            &report.fingerprint,
            &report.findings,
            provenance::TrustState::LocallyVerified,
            &context,
        );
        let exit = package_report_exit(&report, Some(&decision));
        let output = pipeline_json(
            &report.root,
            Some(&report.fingerprint),
            &report.findings,
            &decision,
            exit,
        );
        commands::security::maybe_write_evidence(
            &args.evidence,
            &prepared,
            &report.fingerprint,
            "directory",
            Some(&report.fingerprint),
            None,
            None,
            &pipeline_decision(exit),
            output.clone(),
        )?;
        emit_pipeline(
            &args,
            &report.root,
            &report.fingerprint,
            &report.findings,
            &decision,
            exit,
            output,
        )?;
        std::process::exit(exit);
    }

    let report = artifact::inspect(&args.path, ArtifactScanMode::Full)?;
    let identity = report
        .sha256
        .clone()
        .unwrap_or_else(|| args.path.display().to_string());
    let source = SourceKind::parse("file")?;
    let context = policy::PolicyContext {
        source: Some(source.as_str().to_owned()),
        format: Some(report.format.as_str().to_owned()),
        model_size: Some(report.size),
        now_unix: layerfault::paths::now_unix(),
        ..policy::PolicyContext::default()
    };
    let decision = prepared.policy.evaluate_with_context(
        &identity,
        &report.results,
        provenance::TrustState::LocallyVerified,
        &context,
    );
    let scanner_exit = artifact_report_exit(&report);
    let exit = if scanner_exit != 0 {
        scanner_exit
    } else {
        match decision.action {
            policy::PolicyAction::Block => 4,
            policy::PolicyAction::Warn => 1,
            policy::PolicyAction::Allow => 0,
        }
    };
    let output = pipeline_json(
        &report.path,
        Some(&identity),
        &report.results,
        &decision,
        exit,
    );
    commands::security::maybe_write_evidence(
        &args.evidence,
        &prepared,
        &identity,
        source.as_str(),
        report.sha256.as_deref(),
        None,
        None,
        &pipeline_decision(exit),
        output.clone(),
    )?;
    emit_pipeline(
        &args,
        &report.path,
        &identity,
        &report.results,
        &decision,
        exit,
        output,
    )?;
    std::process::exit(exit);
}

fn pipeline_json(
    target: &str,
    identity: Option<&str>,
    findings: &[layerfault::scanner::LayerScanResult],
    decision: &policy::PolicyDecision,
    exit: i32,
) -> serde_json::Value {
    let blocking = findings
        .iter()
        .filter(|finding| finding.status == layerfault::scanner::ScanStatus::Fail)
        .count();
    let warnings = findings
        .iter()
        .filter(|finding| finding.status == layerfault::scanner::ScanStatus::Warn)
        .count();
    let informational = findings
        .iter()
        .filter(|finding| finding.status == layerfault::scanner::ScanStatus::Pass)
        .count();
    let primary = findings
        .iter()
        .filter(|finding| finding.status != layerfault::scanner::ScanStatus::Pass)
        .min_by_key(|finding| (pipeline_priority(finding), policy::rule_id(finding)))
        .map(|finding| {
            let mut value = report::enriched_finding(finding);
            if let Some(object) = value.as_object_mut() {
                object.insert("detail".to_owned(), serde_json::json!(finding.detail));
            }
            value
        });
    serde_json::json!({
        "schema_version": "1.0",
        "tool_version": env!("CARGO_PKG_VERSION"),
        "target": target,
        "identity": identity,
        "decision": pipeline_decision(exit),
        "exit_code": exit,
        "policy": decision,
        "summary": {
            "blocking": blocking,
            "warnings": warnings,
            "informational": informational,
            "primary_risk": primary.as_ref().and_then(|value| value.get("risk"))
        },
        "findings": findings.iter().map(report::enriched_finding).collect::<Vec<_>>()
    })
}

fn emit_pipeline(
    args: &PipelineArgs,
    target: &str,
    identity: &str,
    findings: &[layerfault::scanner::LayerScanResult],
    decision: &policy::PolicyDecision,
    exit: i32,
    output: serde_json::Value,
) -> Result<()> {
    if args.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else if args.sarif {
        report::emit_sarif(&[report::ModelReport {
            model_name: target.to_owned(),
            results: findings.to_vec(),
        }])?;
    } else if args.summary {
        let blocking = findings
            .iter()
            .filter(|f| f.status == layerfault::scanner::ScanStatus::Fail)
            .count();
        let warnings = findings
            .iter()
            .filter(|f| f.status == layerfault::scanner::ScanStatus::Warn)
            .count();
        println!("{}  {}", pipeline_decision(exit), target);
        println!("{} blocking finding(s)", blocking);
        println!("{} warning(s)", warnings);
        for finding in findings
            .iter()
            .filter(|f| f.status != layerfault::scanner::ScanStatus::Pass)
        {
            let rule = policy::rule_id(finding);
            let risk = explain::risk_lookup(&rule);
            println!(
                "{}  {}",
                if f_status(finding) == "BLOCK" {
                    "BLOCK"
                } else {
                    "WARN"
                },
                risk.title
            );
            println!("  {}\n  Risk: {}", rule, risk.risk);
        }
        println!("Recommendation: {}", primary_action(findings));
    } else {
        println!("Layerfault admission result: {}\n", pipeline_decision(exit));
        println!("Target: {target}");
        println!("Identity: {identity}");
        if let Some(finding) = findings
            .iter()
            .filter(|finding| finding.status != layerfault::scanner::ScanStatus::Pass)
            .min_by_key(|finding| (pipeline_priority(finding), policy::rule_id(finding)))
        {
            let rule = policy::rule_id(finding);
            let risk = explain::risk_lookup(&rule);
            println!("\nPrimary concern\n---------------\n{}", risk.title);
            println!(
                "\nFinding\n-------\n{}\n{:?} confidence\n{}",
                rule,
                finding.confidence,
                risk.categories.join(" / ")
            );
            println!("\nWhy this matters\n----------------\n{}", risk.risk);
            println!(
                "\nPotential impact\n----------------\n- {}",
                risk.potential_impact.join("\n- ")
            );
            println!(
                "\nRecommended action\n------------------\n- {}",
                risk.recommended_actions.join("\n- ")
            );
            if let Some(detail) = &finding.detail {
                println!("\nEvidence\n--------\n{detail}");
            }
        } else {
            println!("\nNo blocking or warning findings were detected by the configured admission checks.");
        }
        println!("\nDecision\n--------\n{}", pipeline_decision(exit));
        println!("\nBoundary\n--------\nThis result covers configured artifact, package, integrity, provenance, trust, compatibility, and policy checks. It does not prove learned behavior is benign or free from hidden semantic backdoors.");
        println!("\nPolicy: {:?}", decision.action);
    }
    Ok(())
}

fn pipeline_decision(exit: i32) -> String {
    match exit {
        0 => "PASS".to_owned(),
        1 => "WARN".to_owned(),
        _ => "BLOCK".to_owned(),
    }
}

fn f_status(finding: &layerfault::scanner::LayerScanResult) -> &'static str {
    if finding.status == layerfault::scanner::ScanStatus::Fail {
        "BLOCK"
    } else {
        "WARN"
    }
}

fn primary_action(findings: &[layerfault::scanner::LayerScanResult]) -> String {
    findings
        .iter()
        .filter(|finding| finding.status != layerfault::scanner::ScanStatus::Pass)
        .min_by_key(|finding| (pipeline_priority(finding), policy::rule_id(finding)))
        .map(|finding| {
            explain::risk_lookup(&policy::rule_id(finding))
                .recommended_actions
                .join(" ")
        })
        .unwrap_or_else(|| "No action is required for the configured checks.".to_owned())
}

fn pipeline_priority(finding: &layerfault::scanner::LayerScanResult) -> u8 {
    match policy::rule_id(finding).as_str() {
        id if id.starts_with("LF-PACKAGE-RACE") || id.starts_with("LF-PROV-") => 0,
        "T15-STRUCT" | "LF-SAFE-STRUCT" | "LF-SAFE-INDEX-INVALID" => 1,
        "LF-SERIALIZATION-UNSAFE" | "LF-CODE-IMPORT-SIDE-EFFECT" => 3,
        "LF-CODE-AUTO-MAP" | "LF-CODE-REMOTE-TRUST" | "LF-PACKAGE-CODE" => 4,
        "LF-CODE-NETWORK" | "LF-CODE-OS-SYSTEM" | "LF-CODE-SUBPROCESS" => 5,
        _ => 8,
    }
}

fn print_package_report(report: &package::PackageReport) {
    println!("Package: {}", report.root);
    println!("Identity: {}", report.fingerprint);
    println!(
        "Files: {}  Bytes: {}",
        report.files.len(),
        report.total_bytes
    );
    print_actionable_findings(&report.findings);
}

fn package_report_exit(
    report: &package::PackageReport,
    decision: Option<&policy::PolicyDecision>,
) -> i32 {
    let mut warn = false;
    for finding in &report.findings {
        match finding.status {
            layerfault::scanner::ScanStatus::Fail
                if finding.finding_class == layerfault::scanner::FindingClass::Integrity =>
            {
                return 2
            }
            layerfault::scanner::ScanStatus::Fail => return 3,
            layerfault::scanner::ScanStatus::Warn => warn = true,
            layerfault::scanner::ScanStatus::Pass => {}
        }
    }
    if decision.is_some_and(|value| value.action == policy::PolicyAction::Block) {
        return 4;
    }
    if decision.is_some_and(|value| value.action == policy::PolicyAction::Warn) || warn {
        1
    } else {
        0
    }
}
