use crate::*;

pub(crate) fn run_inspect(args: InspectArgs) -> Result<()> {
    if args.path.is_dir() {
        let result = package::inspect(&args.path)?;
        if args.json {
            println!("{}", serde_json::to_string_pretty(&result)?);
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
        println!("{}", serde_json::to_string_pretty(&result)?);
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
        println!("{}", serde_json::to_string_pretty(&reports)?);
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
    if report.blocking() {
        std::process::exit(3);
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
        "package": &report,
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

fn print_package_report(report: &package::PackageReport) {
    println!("Package: {}", report.root);
    println!("Identity: {}", report.fingerprint);
    println!(
        "Files: {}  Bytes: {}",
        report.files.len(),
        report.total_bytes
    );
    for finding in &report.findings {
        if finding.status != layerfault::scanner::ScanStatus::Pass {
            println!(
                "  {:?} {:?} - {}",
                finding.status,
                finding.finding_class,
                finding.detail.as_deref().unwrap_or("")
            );
        }
    }
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
