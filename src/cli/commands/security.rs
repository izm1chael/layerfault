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
        EvidenceCommand::Admit {
            target,
            runtime,
            private_key,
            output,
            policy: profile,
            policy_file,
            trust_store,
        } => {
            if target.is_dir() {
                return Err(anyhow!("evidence admit currently requires a concrete artifact file; package receipts should bind the final admitted artifact/package workflow"));
            }
            let profile = PolicyProfile::parse(&profile)?;
            let policy_doc = match policy_file.as_deref() {
                Some(path) => PolicyDocument::load(path)?,
                None => PolicyDocument::builtin(profile),
            };
            let effective = policy_doc.effective();
            let trust = TrustStore::load(trust_store.as_deref())?;
            let snapshot = layerfault::modelmeta::build_snapshot(&target)?;
            let identity = snapshot
                .identity
                .artifact_sha256
                .clone()
                .unwrap_or_else(|| snapshot.identity.canonical.clone());
            let admission = admission::inspect_and_evaluate(
                &target,
                &identity,
                SourceKind::File,
                &effective,
                snapshot.architecture.architecture.as_deref(),
                None,
                None,
            )?;
            let layered = layerfault::model::identity::build(
                &target,
                None,
                &snapshot,
                None,
                None,
                None,
                &Default::default(),
            )?;
            let kind = layerfault::runtime_security::RuntimeKind::parse(&runtime)?;
            let posture = layerfault::runtime_security::audit_kind(kind).into_iter().next()
                .ok_or_else(|| anyhow!("runtime '{}' was not discovered; receipt creation requires observed runtime identity", kind.as_str()))?;
            let subject = layerfault::finding_evidence::EvidenceSubject::identity(
                &identity,
                "application/vnd.layerfault.model+json",
            )
            .with_sha256(snapshot.identity.artifact_sha256.clone());
            let mut model_context =
                layerfault::runtime_security::ModelSecurityContext::from_artifact_report(
                    subject,
                    Some(snapshot.format.clone()),
                    snapshot.architecture.architecture.clone(),
                    &admission.report.results,
                    layerfault::coverage::Coverage::complete(1, admission.report.size),
                );
            model_context.merge_snapshot(&snapshot);
            let pack = layerfault::intelligence::builtin_pack()?;
            let exploitability =
                layerfault::runtime_security::assess_from_pack(&posture, &model_context, &pack);
            let compatibility = layerfault::runtime_security::assess_compatibility(
                &posture,
                &model_context,
                &exploitability,
            );
            let receipt = admission::build_receipt(
                &admission,
                Some(&layered),
                Some(&posture),
                Some(&compatibility),
                &exploitability,
                None,
                None,
            )?;
            let envelope = evidence::create_signed(
                evidence::EvidenceContext {
                    subject: &identity,
                    source: "local-admission",
                    subject_fingerprint: admission.report.sha256.as_deref(),
                    merkle_identity: layered.package.as_ref().map(|v| v.value.as_str()),
                    policy: &effective,
                    trust_store: &trust,
                    runtime: None,
                    binding: None,
                    intelligence_sha256: None,
                    security_passport_sha256: None,
                    admission_receipt: Some(&receipt),
                    decision: "ALLOW",
                    details: serde_json::json!({"runtime": posture, "compatibility": compatibility, "exploitability": exploitability}),
                },
                &private_key,
            )?;
            evidence::write_signed(&output, &envelope)?;
            println!("{}", output.display());
        }
        EvidenceCommand::Gate {
            receipt,
            target,
            runtime,
            trust_store,
            accept_stale_receipt,
            override_reason,
            json,
        } => {
            let trust = TrustStore::load(trust_store.as_deref())?;
            let mut result = admission::verify_for_execution(
                &receipt,
                &trust,
                &target,
                runtime.as_deref(),
                None,
                None,
            )?;
            if accept_stale_receipt && !result.allowed {
                let reason = override_reason
                    .as_deref()
                    .ok_or_else(|| anyhow!("--accept-stale-receipt requires --override-reason"))?;
                if reason.trim().len() < 8 {
                    return Err(anyhow!("--override-reason must be at least 8 characters"));
                }
                // Staleness may waive ruleset/intelligence/passport freshness only. Artifact/runtime identity,
                // signature, trust, authorization and ALLOW decision remain mandatory and cannot be bypassed.
                if result.evidence_valid
                    && result.evidence_trusted
                    && result.artifact_match
                    && result.runtime_match
                {
                    let only_stale = result.reasons.iter().all(|r| {
                        r.contains("ruleset digest")
                            || r.contains("security intelligence digest")
                            || r.contains("security passport digest")
                    });
                    if only_stale {
                        result.allowed = true;
                        layerfault::policy::record_policy_override(
                            &layerfault::policy::OverrideRecord {
                                version: 1,
                                created_unix: layerfault::paths::now_unix(),
                                model: target.display().to_string(),
                                reason: reason.to_owned(),
                                profile: PolicyProfile::Workstation,
                                trust_state: layerfault::provenance::TrustState::Trusted,
                                scanner_exit_code: 0,
                            },
                            None,
                        )?;
                    }
                }
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!(
                    "Execution gate: {}",
                    if result.allowed { "ALLOW" } else { "BLOCK" }
                );
                for reason in &result.reasons {
                    println!("- {reason}");
                }
            }
            if !result.allowed {
                std::process::exit(3);
            }
        }
        EvidenceCommand::Predicate { receipt, output } => {
            let envelope = evidence::load(&receipt)?;
            let statement = serde_json::json!({
                "_type": "https://in-toto.io/Statement/v1",
                "subject": [{"name": envelope.payload.subject, "digest": {"sha256": envelope.payload.subject_fingerprint.clone().unwrap_or_default().trim_start_matches("sha256:")}}],
                "predicateType": "https://layerfault.dev/attestation/admission/v1",
                "predicate": {"evidence": envelope}
            });
            layerfault::paths::write_private(&output, &serde_json::to_vec_pretty(&statement)?)?;
            println!("{}", output.display());
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
            intelligence_sha256: None,
            security_passport_sha256: None,
            admission_receipt: None,
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
