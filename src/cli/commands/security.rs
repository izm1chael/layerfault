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
            json,
        } => {
            let digest = advisory::verify_external_database(&database, &signature, &public_key)?;
            if json {
                println!("{}", serde_json::json!({"ok": true, "sha256": digest}));
            } else {
                println!("Verified signed advisory database: {digest}");
            }
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
            runtime_config,
            composition_manifest,
            agent_config,
            agent_name,
            provenance_chain,
            passport,
            intelligence_pack,
            intelligence_signature,
            intelligence_public_key,
            private_key,
            output,
            policy: profile,
            policy_file,
            trust_store,
            json,
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
            let mut observed =
                super::execution_context::observe(super::execution_context::ObservationRequest {
                    composition_manifest: composition_manifest.as_deref(),
                    runtime_config: runtime_config.as_deref(),
                    agent_config: agent_config.as_deref(),
                    agent_name: &agent_name,
                    provenance_chain: provenance_chain.as_deref(),
                    passport: passport.as_deref(),
                    trust_store: &trust,
                })?;
            let snapshot = layerfault::modelmeta::build_snapshot(&target)?;
            let identity = snapshot
                .identity
                .artifact_sha256
                .clone()
                .unwrap_or_else(|| snapshot.identity.canonical.clone());
            let mut admission = admission::inspect_and_evaluate(
                &target,
                &identity,
                SourceKind::File,
                &effective,
                snapshot.architecture.architecture.as_deref(),
                None,
                None,
            )?;
            admission.report.results.extend(observed.findings.clone());
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
            let posture = layerfault::runtime_security::audit_kind(kind)
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("runtime '{}' was not discovered; receipt creation requires observed runtime identity", kind.as_str()))?;
            if observed.runtime_configuration_identity.is_none() {
                observed.runtime_configuration_identity = Some(
                    layerfault::runtime_security::configuration_identity(&posture.configuration)?,
                );
            }
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
            let pack = super::domains::load_cli_intelligence(
                intelligence_pack.as_deref(),
                intelligence_signature.as_deref(),
                intelligence_public_key.as_deref(),
            )?;
            let intelligence_sha256 = layerfault::intelligence::pack_identity(&pack)?;
            let now = layerfault::paths::now_unix();
            let mut intelligence_subjects = layerfault::intelligence::IntelligenceSubjects {
                models: vec![identity.clone()],
                passports: observed.passport_sha256.iter().cloned().collect(),
                runtime_releases: Vec::new(),
                signers: admission.signer_fingerprints.clone(),
                adapters: observed.adapter_identities.clone(),
                builders: observed.builder_identities.clone(),
            };
            if let Some(digest) = posture.installation.executable_sha256.clone() {
                intelligence_subjects.runtime_releases.push(digest);
            }
            if let Some(version) = posture.installation.parsed_version.as_deref() {
                intelligence_subjects
                    .runtime_releases
                    .push(format!("{}@{version}", kind.as_str()));
            }
            let intelligence_findings =
                layerfault::intelligence::assess_subjects(&pack, now, &intelligence_subjects);
            admission.report.results.extend(intelligence_findings);
            let exploitability =
                layerfault::runtime_security::assess_from_pack(&posture, &model_context, &pack);
            let compatibility = layerfault::runtime_security::assess_compatibility(
                &posture,
                &model_context,
                &exploitability,
            );

            let evidence_complete = !admission.report.results.iter().any(|finding| {
                matches!(
                    finding.evidence_state,
                    Some(layerfault::finding_evidence::EvidenceState::Partial)
                        | Some(layerfault::finding_evidence::EvidenceState::Unavailable)
                )
            });
            let mut policy_context = layerfault::policy::PolicyContext {
                architecture: snapshot.architecture.architecture.clone(),
                runtime_compatibility: Some(compatibility.state),
                coverage_complete: Some(evidence_complete),
                intelligence_age_days: Some(now.saturating_sub(pack.generated_unix) / 86_400),
                intelligence_verified: Some(true),
                runtime_exploitability_blocking: Some(exploitability.iter().any(|item| {
                    item.state
                        == layerfault::runtime_security::ExploitabilityState::PreconditionsMet
                })),
                admission_receipt_present: Some(true),
                layered_identity_complete: Some(
                    layered.completeness == layerfault::assurance::AnalysisCompleteness::Complete,
                ),
                evidence_fresh: Some(true),
                ..layerfault::policy::PolicyContext::default()
            };
            observed.apply_policy_context(&mut policy_context);
            admission::reevaluate_with_context(&mut admission, &effective, policy_context);

            let mut receipt = admission::build_receipt(
                &admission,
                Some(&layered),
                Some(&posture),
                Some(&compatibility),
                &exploitability,
                Some(&intelligence_sha256),
                observed.passport_sha256.as_deref(),
            )?;
            admission::bind_execution_context(&mut receipt, &observed.binding())?;
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
                    intelligence_sha256: Some(&intelligence_sha256),
                    security_passport_sha256: observed.passport_sha256.as_deref(),
                    admission_receipt: Some(&receipt),
                    decision: "ALLOW",
                    details: serde_json::json!({
                        "runtime": posture,
                        "compatibility": compatibility,
                        "exploitability": exploitability,
                        "composition_identity": observed.composition_identity,
                        "agent_identity": observed.agent_identity,
                        "capability_graph_identity": observed.capability_graph_identity,
                    }),
                },
                &private_key,
            )?;
            evidence::write_signed(&output, &envelope)?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({"ok": true, "output": output.display().to_string()})
                );
            } else {
                println!("{}", output.display());
            }
        }
        EvidenceCommand::Gate {
            receipt,
            target,
            runtime,
            runtime_config,
            composition_manifest,
            agent_config,
            agent_name,
            passport,
            intelligence_pack,
            intelligence_signature,
            intelligence_public_key,
            trust_store,
            accept_stale_receipt,
            override_reason,
            json,
        } => {
            let trust = TrustStore::load(trust_store.as_deref())?;
            let receipt_envelope = evidence::load(&receipt)?;
            let mut observed =
                super::execution_context::observe(super::execution_context::ObservationRequest {
                    composition_manifest: composition_manifest.as_deref(),
                    runtime_config: runtime_config.as_deref(),
                    agent_config: agent_config.as_deref(),
                    agent_name: &agent_name,
                    provenance_chain: None,
                    passport: passport.as_deref(),
                    trust_store: &trust,
                })?;

            if observed.runtime_configuration_identity.is_none() {
                if let Some(runtime_path) = runtime.as_deref() {
                    if let Some(expected) = receipt_envelope
                        .payload
                        .admission_receipt
                        .as_ref()
                        .and_then(|value| value.runtime.as_ref())
                    {
                        if let Ok(kind) =
                            layerfault::runtime_security::RuntimeKind::parse(&expected.kind)
                        {
                            let current_digest = layerfault::safeio::sha256_path(runtime_path)?;
                            if let Some(posture) = layerfault::runtime_security::audit_kind(kind)
                                .into_iter()
                                .find(|posture| {
                                    posture
                                        .installation
                                        .executable_sha256
                                        .as_deref()
                                        .is_some_and(|digest| {
                                            digest.eq_ignore_ascii_case(&current_digest)
                                        })
                                })
                            {
                                observed.runtime_configuration_identity =
                                    Some(layerfault::runtime_security::configuration_identity(
                                        &posture.configuration,
                                    )?);
                            }
                        }
                    }
                }
            }

            let pack = super::domains::load_cli_intelligence(
                intelligence_pack.as_deref(),
                intelligence_signature.as_deref(),
                intelligence_public_key.as_deref(),
            )?;
            let intelligence_sha256 = layerfault::intelligence::pack_identity(&pack)?;
            let mut intelligence_subjects = layerfault::intelligence::IntelligenceSubjects {
                models: vec![layerfault::safeio::sha256_path(&target)?],
                passports: observed.passport_sha256.iter().cloned().collect(),
                runtime_releases: Vec::new(),
                signers: vec![receipt_envelope.key_fingerprint.clone()],
                adapters: observed.adapter_identities.clone(),
                builders: observed.builder_identities.clone(),
            };
            if let Some(runtime_path) = runtime.as_deref() {
                intelligence_subjects
                    .runtime_releases
                    .push(layerfault::safeio::sha256_path(runtime_path)?);
            }
            let intelligence_findings = layerfault::intelligence::assess_subjects(
                &pack,
                layerfault::paths::now_unix(),
                &intelligence_subjects,
            );
            let intelligence_blocking = intelligence_findings
                .iter()
                .any(|finding| finding.status == layerfault::scanner::ScanStatus::Fail);
            let expectation = observed.expectation();
            let mut result = admission::verify_for_execution_context(
                &receipt,
                &trust,
                &target,
                runtime.as_deref(),
                Some(&intelligence_sha256),
                observed.passport_sha256.as_deref(),
                &expectation,
            )?;
            if accept_stale_receipt && !result.allowed {
                let reason = override_reason
                    .as_deref()
                    .ok_or_else(|| anyhow!("--accept-stale-receipt requires --override-reason"))?;
                if reason.trim().len() < 8 {
                    return Err(anyhow!("--override-reason must be at least 8 characters"));
                }
                // Freshness overrides cannot waive artifact, runtime, composition,
                // agent, capability, signature, trust or authorization identity checks.
                if result.evidence_valid
                    && result.evidence_trusted
                    && result.artifact_match
                    && result.runtime_match
                    && result.composition_match != Some(false)
                    && result.runtime_configuration_match != Some(false)
                    && result.agent_match != Some(false)
                    && result.capability_graph_match != Some(false)
                    && result.mcp_servers_match != Some(false)
                    && !intelligence_blocking
                {
                    let only_stale = result.reasons.iter().all(|reason| {
                        reason.contains("ruleset digest")
                            || reason.contains("security intelligence digest")
                            || reason.contains("security passport digest")
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
            for finding in &intelligence_findings {
                let rule = finding.rule_id.as_deref().unwrap_or("INTELLIGENCE");
                let detail = finding
                    .detail
                    .as_deref()
                    .unwrap_or("current security intelligence applies to this execution context");
                result.reasons.push(format!("{rule}: {detail}"));
            }
            result.reasons.sort();
            result.reasons.dedup();
            if intelligence_blocking {
                result.allowed = false;
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
        EvidenceCommand::Predicate {
            receipt,
            output,
            json,
        } => {
            let envelope = evidence::load(&receipt)?;
            let statement = serde_json::json!({
                "_type": "https://in-toto.io/Statement/v1",
                "subject": [{"name": envelope.payload.subject, "digest": {"sha256": envelope.payload.subject_fingerprint.clone().unwrap_or_default().trim_start_matches("sha256:")}}],
                "predicateType": "https://layerfault.dev/attestation/admission/v1",
                "predicate": {"evidence": envelope}
            });
            layerfault::paths::write_private(&output, &serde_json::to_vec_pretty(&statement)?)?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({"ok": true, "output": output.display().to_string()})
                );
            } else {
                println!("{}", output.display());
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
