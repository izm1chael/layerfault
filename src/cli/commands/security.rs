use super::super::*;

pub(crate) fn run_advisories(args: AdvisoryArgs) -> Result<()> {
    match args.command {
        AdvisoryCommand::List { json } => {
            let db = advisory::builtin_database()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&db)?);
            } else {
                println!(
                    "Runtime advisories (catalog generated {}):",
                    db.generated_unix
                );
                for item in db.advisories {
                    println!(
                        "{}  {:<9} {:?}  fixed={}  {}",
                        item.id, item.runtime, item.severity, item.matcher.fixed, item.title
                    );
                }
            }
        }
        AdvisoryCommand::Check {
            runtime,
            security,
            json,
        } => {
            let kind = advisory::RuntimeKind::parse(&runtime)?;
            let evaluation = runtime_evaluation(kind, &security)?;
            emit_runtime_evaluation(&evaluation, json)?;
            if evaluation.blocking {
                std::process::exit(3);
            }
            if evaluation
                .findings
                .iter()
                .any(|f| f.status == layerfault::scanner::ScanStatus::Warn)
            {
                std::process::exit(1);
            }
        }
        AdvisoryCommand::Verify {
            database,
            signature,
            public_key,
        } => {
            let digest = advisory::verify_external_database(&database, &signature, &public_key)?;
            println!("Verified signed advisory database: {digest}");
        }
    }
    Ok(())
}

pub(crate) fn run_evidence(args: EvidenceArgs) -> Result<()> {
    match args.command {
        EvidenceCommand::Verify {
            path,
            trust_store,
            json,
        } => {
            let store = TrustStore::load(trust_store.as_deref())?;
            let result = evidence::verify(&path, Some(&store))?;
            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!(
                    "Signature: {}",
                    if result.valid_signature {
                        "VALID"
                    } else {
                        "INVALID"
                    }
                );
                println!("Key: {}", result.key_fingerprint);
                println!("Trusted: {}", result.trusted);
                println!("Authorized for subject: {}", result.authorized_for_subject);
                println!("{}", result.detail);
            }
            if !result.valid_signature {
                std::process::exit(3);
            }
            if !(result.trusted && result.authorized_for_subject) {
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

pub(crate) fn runtime_evaluation(
    kind: advisory::RuntimeKind,
    security: &RuntimeSecurityArgs,
) -> Result<advisory::RuntimeEvaluation> {
    runtime_evaluation_for_binary(kind, security, None)
}

pub(crate) fn runtime_evaluation_for_binary(
    kind: advisory::RuntimeKind,
    security: &RuntimeSecurityArgs,
    executable_name: Option<&str>,
) -> Result<advisory::RuntimeEvaluation> {
    let (database, bytes) =
        if let Some(database) = security.advisory_db.as_deref() {
            let signature = security.advisory_signature.as_deref().ok_or_else(|| {
                anyhow!("External advisory database requires --advisory-signature")
            })?;
            let public_key = security.advisory_public_key.as_deref().ok_or_else(|| {
                anyhow!("External advisory database requires --advisory-public-key")
            })?;
            let (database, bytes, _) =
                advisory::load_verified_external_database(database, signature, public_key)?;
            (database, bytes)
        } else {
            advisory::load_database(None)?
        };
    if let Some(path) = security.runtime_path.as_deref() {
        let runtime = advisory::detect_runtime_executable(kind, path)?;
        return Ok(advisory::evaluate_info(runtime, &database, &bytes));
    }
    match executable_name {
        Some(name) => advisory::evaluate_named(kind, name, &database, &bytes),
        None => {
            let runtime = advisory::detect_runtime(kind)?;
            Ok(advisory::evaluate_info(runtime, &database, &bytes))
        }
    }
}

pub(crate) fn enforce_runtime_evaluation(evaluation: &advisory::RuntimeEvaluation) -> Result<()> {
    emit_runtime_evaluation(evaluation, false)?;
    if evaluation.blocking {
        eprintln!("Layerfault blocked runtime launch because the installed runtime matches a high/critical offline security advisory.");
        std::process::exit(3);
    }
    Ok(())
}

pub(crate) fn emit_runtime_evaluation(
    evaluation: &advisory::RuntimeEvaluation,
    json: bool,
) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(evaluation)?);
        return Ok(());
    }
    println!(
        "Runtime: {}  version={}  advisory-db={}",
        evaluation.runtime.runtime.as_str(),
        evaluation
            .runtime
            .parsed_version
            .as_deref()
            .unwrap_or("unparsed"),
        evaluation.database_sha256
    );
    for finding in &evaluation.findings {
        println!(
            "  {:?} - {}",
            finding.status,
            finding
                .detail
                .as_deref()
                .unwrap_or("runtime advisory finding")
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn maybe_write_evidence(
    args: &EvidenceWriteArgs,
    prepared: &Prepared,
    subject: &str,
    source: &str,
    fingerprint: Option<&str>,
    merkle_identity: Option<&str>,
    runtime: Option<&advisory::RuntimeEvaluation>,
    binding: Option<&binding::BindingRecord>,
    decision: &str,
    details: serde_json::Value,
) -> Result<Option<PathBuf>> {
    let (Some(output), Some(key)) = (args.evidence_out.as_deref(), args.evidence_key.as_deref())
    else {
        return Ok(None);
    };
    let envelope = evidence::create_signed(
        evidence::EvidenceContext {
            subject,
            source,
            subject_fingerprint: fingerprint,
            merkle_identity,
            policy: &prepared.policy,
            trust_store: &prepared.trust_store,
            runtime,
            binding,
            decision,
            details,
        },
        key,
    )?;
    evidence::write_signed(output, &envelope)?;
    eprintln!("Signed Layerfault evidence: {}", output.display());
    Ok(Some(output.to_path_buf()))
}

pub(crate) fn print_binding(record: &binding::BindingRecord) {
    println!("Execution binding: {:?} - {}", record.kind, record.detail);
}
