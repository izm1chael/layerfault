use super::super::{DriftArgs, ModelsArgs, ModelsCommand};
use anyhow::{anyhow, Result};
use layerfault::json_stream::write_stdout_json;
use std::io::Read;
use std::path::Path;
pub(crate) fn run_models(args: ModelsArgs) -> Result<()> {
    let mut store = layerfault::observations::ObservationStore::load()?;
    match args.command {
        ModelsCommand::Remember {
            model,
            name,
            publisher,
            revision,
            trust_label,
            json: emit_json,
        } => {
            let snapshot = layerfault::modelmeta::build_snapshot(&model)?;
            let (key, observation) =
                store.remember(&snapshot, name, publisher, revision, trust_label)?;
            let key = key.to_owned();
            let observation = observation.clone();
            store.save()?;
            if emit_json {
                #[derive(serde::Serialize)]
                struct Remembered<'a> {
                    record: &'a str,
                    observation: &'a layerfault::observations::StoredObservation,
                }
                write_stdout_json(
                    &Remembered {
                        record: &key,
                        observation: &observation,
                    },
                    true,
                )?;
            } else {
                println!("Remembered {} as {}", observation.id, key);
            }
        }
        ModelsCommand::List { json: emit_json } => {
            if emit_json {
                write_stdout_json(&store, true)?;
            } else {
                for record in &store.records {
                    println!(
                        "{}\t{}\t{} observation(s)",
                        record.key,
                        record.name.as_deref().unwrap_or("<unnamed>"),
                        record.observations.len()
                    );
                }
            }
        }
        ModelsCommand::Show {
            id,
            json: emit_json,
        } => {
            let record = store
                .record(&id)
                .ok_or_else(|| anyhow!("model record/observation '{id}' was not found"))?;
            if emit_json {
                write_stdout_json(record, true)?;
            } else if let Some(last) = record.observations.last() {
                println!(
                    "{}\nidentity: {}\nobserved: {}\nformat: {}",
                    record.name.as_deref().unwrap_or(&record.key),
                    last.identity.canonical,
                    last.observed_unix,
                    last.format
                );
            }
        }
        ModelsCommand::History {
            id,
            json: emit_json,
        } => {
            let record = store
                .record(&id)
                .ok_or_else(|| anyhow!("model record/observation '{id}' was not found"))?;
            if emit_json {
                write_stdout_json(&record.observations, true)?;
            } else {
                for obs in &record.observations {
                    println!(
                        "{}\t{}\t{}",
                        obs.observed_unix, obs.id, obs.identity.canonical
                    );
                }
            }
        }
        ModelsCommand::Forget {
            id,
            json: emit_json,
        } => {
            let removed = store.forget(&id);
            if removed {
                store.save()?;
            }
            if emit_json {
                #[derive(serde::Serialize)]
                struct Forgotten<'a> {
                    forgotten: &'a str,
                    removed: bool,
                }
                write_stdout_json(
                    &Forgotten {
                        forgotten: &id,
                        removed,
                    },
                    false,
                )?;
            } else {
                println!("{} {}", if removed { "Forgot" } else { "Not found" }, id);
            }
        }
        ModelsCommand::Identity {
            target,
            weights,
            json: emit_json,
        } => {
            let identity = layered_identity(&target, weights)?;
            if emit_json {
                write_stdout_json(&identity, true)?;
            } else {
                print_identity(&identity);
            }
        }
        ModelsCommand::IdentityCompare {
            left,
            right,
            weights,
            json: emit_json,
        } => {
            let left_identity = layered_identity(&left, weights)?;
            let right_identity = layered_identity(&right, weights)?;
            let comparison = layerfault::model::identity::compare(&left_identity, &right_identity);
            if emit_json {
                write_stdout_json(&comparison, true)?;
            } else {
                println!("IDENTITY COMPARISON\n{:?}", comparison.overall);
            }
        }
        ModelsCommand::Carve {
            target,
            profile,
            json: emit_json,
        } => {
            let profile = match profile.to_ascii_lowercase().as_str() {
                "standard" => layerfault::model::forensics::ForensicsProfile::Standard,
                "research" => layerfault::model::forensics::ForensicsProfile::Research,
                other => {
                    return Err(anyhow!(
                        "unknown carve profile '{other}'; use standard or research"
                    ))
                }
            };
            if target.is_dir() {
                return Err(anyhow!(
                    "models carve requires a model artifact file, not a directory"
                ));
            }
            let mut file = layerfault::safeio::open_readonly_nofollow(&target)?;
            let mut prefix = [0u8; 8];
            let n = file.read(&mut prefix)?;
            let format = layerfault::formats::ArtifactFormat::detect(&target, &prefix[..n]);
            let report = layerfault::model::forensics::inspect(&target, format, profile)?;
            if emit_json {
                write_stdout_json(&report, true)?;
            } else {
                println!(
                    "MODEL FORENSICS\n{}\n{} region(s), {} carved signature(s), {} finding(s)",
                    report.artifact_sha256,
                    report.regions.len(),
                    report.carved.len(),
                    report.findings.len()
                );
                println!(
                    "No content was extracted; carving reports offsets and bounded evidence only."
                );
            }
        }
        ModelsCommand::Passport {
            target,
            parent,
            composition_manifest,
            agent_config,
            agent_name,
            provenance_chain,
            behaviour_report,
            trust_store,
            runtimes,
            format,
            output,
        } => {
            let passport = build_passport(
                &target,
                PassportBuildOptions {
                    parent: parent.as_deref(),
                    composition_manifest: composition_manifest.as_deref(),
                    agent_config: agent_config.as_deref(),
                    agent_name: &agent_name,
                    provenance_chain: provenance_chain.as_deref(),
                    behaviour_report: behaviour_report.as_deref(),
                    trust_store: trust_store.as_deref(),
                    runtimes: &runtimes,
                },
            )?;
            let value = match format.to_ascii_lowercase().as_str() {
                "native" => serde_json::to_value(&passport)?,
                "cyclonedx" => layerfault::inventory::cyclonedx_security_passport(&passport),
                "spdx" => layerfault::inventory::spdx_ai_3_0_1(&passport),
                other => {
                    return Err(anyhow!(
                        "unknown passport format '{other}'; use native, cyclonedx, or spdx"
                    ))
                }
            };
            let bytes = serde_json::to_vec_pretty(&value)?;
            if let Some(path) = output {
                layerfault::paths::write_private(&path, &bytes)?;
                println!("{}", path.display());
            } else {
                println!("{}", String::from_utf8_lossy(&bytes));
            }
        }
    }
    Ok(())
}

pub(crate) fn run_drift(args: DriftArgs) -> Result<()> {
    let snapshot = layerfault::modelmeta::build_snapshot(&args.model)?;
    let store = layerfault::observations::ObservationStore::load()?;
    let prior = if let Some(selector) = args.against.as_deref() {
        store.record(selector).and_then(|r| r.observations.last())
    } else if args.previous {
        store.previous_for_snapshot(&snapshot)
    } else {
        None
    }
    .ok_or_else(|| anyhow!("no matching prior observation was selected"))?;
    let report = layerfault::observations::drift(prior, &snapshot);
    if args.json {
        write_stdout_json(&report, true)?;
    } else {
        println!(
            "DRIFT\n{}\n\n{} material change(s)",
            if report.material {
                "CHANGED"
            } else {
                "UNCHANGED"
            },
            report.changes.len()
        );
        for change in report.changes {
            println!("{}: {}", change.component, change.state);
        }
    }
    Ok(())
}

fn layered_identity(
    path: &Path,
    weights: bool,
) -> Result<layerfault::model::identity::LayeredModelIdentity> {
    let snapshot = layerfault::modelmeta::build_snapshot(path)?;
    let package = if path.is_dir() {
        Some(layerfault::package::inspect(path)?)
    } else {
        None
    };
    layerfault::model::identity::build(
        path,
        package.as_ref(),
        &snapshot,
        None,
        None,
        None,
        &layerfault::model::identity::IdentityBuildOptions {
            include_weight_sample: weights,
            include_behavioural: false,
        },
    )
}

fn print_identity(identity: &layerfault::model::identity::LayeredModelIdentity) {
    println!("LAYERED MODEL IDENTITY\n{}", identity.subject);
    for (name, value) in [
        ("byte", identity.byte.as_ref()),
        ("package", identity.package.as_ref()),
        ("structural", identity.structural.as_ref()),
        ("tokenizer", identity.tokenizer.as_ref()),
        ("weight-sample", identity.weight_sample.as_ref()),
    ] {
        if let Some(value) = value {
            println!("{name}\t{}\t{:?}", value.value, value.strength);
        }
    }
    println!("completeness\t{:?}", identity.completeness);
}

struct PassportBuildOptions<'a> {
    parent: Option<&'a Path>,
    composition_manifest: Option<&'a Path>,
    agent_config: Option<&'a Path>,
    agent_name: &'a str,
    provenance_chain: Option<&'a Path>,
    behaviour_report: Option<&'a Path>,
    trust_store: Option<&'a Path>,
    runtimes: &'a [String],
}

fn build_passport(
    path: &Path,
    options: PassportBuildOptions<'_>,
) -> Result<layerfault::inventory::ModelSecurityPassport> {
    let snapshot = layerfault::modelmeta::build_snapshot(path)?;
    let identity = layered_identity(path, false)?;
    let (mut findings, coverage) = if path.is_dir() {
        let report = layerfault::package::inspect(path)?;
        (report.findings, report.coverage)
    } else {
        let report = layerfault::formats::artifact::inspect(
            path,
            layerfault::formats::artifact::ArtifactScanMode::Full,
        )?;
        let bytes = report.size;
        (
            report.results,
            layerfault::coverage::Coverage::complete(1, bytes),
        )
    };
    let trust = layerfault::trust::TrustStore::load(options.trust_store)?;
    let observed =
        super::execution_context::observe(super::execution_context::ObservationRequest {
            composition_manifest: options.composition_manifest,
            runtime_config: None,
            agent_config: options.agent_config,
            agent_name: options.agent_name,
            provenance_chain: options.provenance_chain,
            passport: None,
            trust_store: &trust,
        })?;
    findings.extend(observed.findings.clone());

    let subject_identity = snapshot
        .identity
        .artifact_sha256
        .clone()
        .unwrap_or_else(|| snapshot.identity.canonical.clone());
    let subject = layerfault::finding_evidence::EvidenceSubject::identity(
        &subject_identity,
        "application/vnd.layerfault.model+json",
    )
    .with_sha256(snapshot.identity.artifact_sha256.clone());
    let mut context = layerfault::runtime_security::ModelSecurityContext::from_artifact_report(
        subject,
        Some(snapshot.format.clone()),
        snapshot.architecture.architecture.clone(),
        &findings,
        coverage.clone(),
    );
    context.merge_snapshot(&snapshot);
    let pack = layerfault::intelligence::builtin_pack()?;
    let intelligence_sha256 = layerfault::intelligence::pack_identity(&pack)?;
    let mut runtime = Vec::new();
    let mut runtime_release_subjects = Vec::new();
    let mut runtime_completeness = if options.runtimes.is_empty() {
        layerfault::assurance::AnalysisCompleteness::Unknown
    } else {
        layerfault::assurance::AnalysisCompleteness::Complete
    };
    for raw in options.runtimes {
        let kind = layerfault::runtime_security::RuntimeKind::parse(raw)?;
        let postures = layerfault::runtime_security::audit_kind(kind);
        if postures.is_empty() {
            runtime_completeness = layerfault::assurance::AnalysisCompleteness::Partial;
        }
        for posture in postures {
            if let Some(digest) = posture.installation.executable_sha256.clone() {
                runtime_release_subjects.push(digest);
            }
            if let Some(version) = posture.installation.parsed_version.as_deref() {
                runtime_release_subjects.push(format!("{}@{version}", kind.as_str()));
            }
            if !posture.coverage.complete {
                runtime_completeness = layerfault::assurance::AnalysisCompleteness::Partial;
            }
            let exploit = layerfault::runtime_security::assess_from_pack(&posture, &context, &pack);
            let compat =
                layerfault::runtime_security::assess_compatibility(&posture, &context, &exploit);
            runtime.push(layerfault::inventory::PassportRuntimeAssessment {
                runtime: kind.as_str().into(),
                version: posture.installation.parsed_version.clone(),
                executable_sha256: posture.installation.executable_sha256.clone(),
                compatibility: format!("{:?}", compat.state),
                exploitability: exploit
                    .iter()
                    .map(|assessment| format!("{}:{:?}", assessment.advisory_id, assessment.state))
                    .collect(),
                posture_findings: posture
                    .findings
                    .iter()
                    .filter_map(|finding| finding.rule_id.clone())
                    .collect(),
            });
        }
    }

    runtime_release_subjects.sort();
    runtime_release_subjects.dedup();
    let intelligence_subjects = layerfault::intelligence::IntelligenceSubjects {
        models: vec![subject_identity.clone()],
        passports: Vec::new(),
        runtime_releases: runtime_release_subjects,
        signers: Vec::new(),
        adapters: observed.adapter_identities.clone(),
        builders: observed.builder_identities.clone(),
    };
    findings.extend(layerfault::intelligence::assess_subjects(
        &pack,
        layerfault::paths::now_unix(),
        &intelligence_subjects,
    ));

    let behavioural = options
        .behaviour_report
        .map(load_behaviour_summary)
        .transpose()?;
    let mut limitations = Vec::new();
    if options.parent.is_some() {
        limitations.push("parent was supplied to passport generation; explicit lineage relation verification requires `layerfault lineage verify` and is not inferred".into());
    }
    if options.composition_manifest.is_none() {
        limitations.push(
            "executable composition was not supplied; composition completeness is unknown".into(),
        );
    }
    if options.agent_config.is_none() {
        limitations.push(
            "agent/MCP/tool configuration was not supplied; capability exposure is unknown".into(),
        );
    }
    if options.provenance_chain.is_none() {
        limitations.push("signed transformation provenance was not supplied".into());
    }
    if options.behaviour_report.is_none() {
        limitations.push("behavioural evidence was not supplied".into());
    }

    let mut domains = std::collections::BTreeMap::new();
    domains.insert(
        "static_model".to_owned(),
        if coverage.complete {
            layerfault::assurance::AnalysisCompleteness::Complete
        } else {
            layerfault::assurance::AnalysisCompleteness::Partial
        },
    );
    domains.insert(
        "tokenizer".to_owned(),
        if snapshot.tokenizer_security_digest.is_some() {
            layerfault::assurance::AnalysisCompleteness::Complete
        } else {
            layerfault::assurance::AnalysisCompleteness::Unknown
        },
    );
    domains.insert(
        "composition".to_owned(),
        observed
            .composition_summary
            .as_ref()
            .map(|summary| summary.completeness)
            .unwrap_or(layerfault::assurance::AnalysisCompleteness::Unknown),
    );
    domains.insert(
        "adapters".to_owned(),
        match observed.adapters_independently_scanned {
            Some(true) => layerfault::assurance::AnalysisCompleteness::Complete,
            Some(false) => layerfault::assurance::AnalysisCompleteness::Partial,
            None => layerfault::assurance::AnalysisCompleteness::Unknown,
        },
    );
    domains.insert("runtime".to_owned(), runtime_completeness);
    domains.insert(
        "agent".to_owned(),
        observed
            .agent_summary
            .as_ref()
            .map(|summary| summary.completeness)
            .unwrap_or(layerfault::assurance::AnalysisCompleteness::Unknown),
    );
    domains.insert(
        "provenance".to_owned(),
        match observed.provenance_verified {
            Some(true) => layerfault::assurance::AnalysisCompleteness::Complete,
            Some(false) => layerfault::assurance::AnalysisCompleteness::Partial,
            None => layerfault::assurance::AnalysisCompleteness::Unknown,
        },
    );
    domains.insert(
        "behavioural".to_owned(),
        behavioural
            .as_ref()
            .map(|summary| summary.completeness)
            .unwrap_or(layerfault::assurance::AnalysisCompleteness::Unknown),
    );

    layerfault::inventory::build_passport(layerfault::inventory::PassportInputs {
        generated_unix: layerfault::paths::now_unix(),
        scanner_revision: layerfault::explain::scanner_revision().into(),
        ruleset_sha256: layerfault::explain::ruleset_sha256().into(),
        intelligence_sha256: Some(intelligence_sha256),
        intelligence_epoch: Some(layerfault::intelligence::epoch(&pack)),
        subject: layerfault::inventory::PassportSubject {
            name: path
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or("model")
                .into(),
            format: snapshot.format.clone(),
            size: if path.is_file() {
                Some(std::fs::metadata(path)?.len())
            } else {
                None
            },
        },
        identity,
        source: None,
        lineage: None,
        composition: observed.composition_summary,
        agent: observed.agent_summary,
        provenance: observed.provenance_summary,
        behavioural,
        completeness: Some(layerfault::inventory::PassportCompleteness { domains }),
        tokenizer: Some(layerfault::inventory::PassportTokenizerSummary {
            digest: snapshot.tokenizer_security_digest.clone(),
            finding_count: snapshot.tokenizer_security_finding_count,
            chat_template_sha256: snapshot
                .template
                .as_ref()
                .and_then(|template| template.exact_hash.clone()),
        }),
        runtime,
        findings,
        mapping_pack: Some(pack),
        coverage,
        policy: None,
        evidence_digest: None,
        limitations,
    })
}

fn load_behaviour_summary(path: &Path) -> Result<layerfault::inventory::PassportBehaviourSummary> {
    const MAX_BEHAVIOUR_REPORT_BYTES: u64 = 64 * 1024 * 1024;
    let file = layerfault::safeio::open_readonly_nofollow(path)?;
    let bytes = layerfault::safeio::read_all_from_file(&file, MAX_BEHAVIOUR_REPORT_BYTES)?;
    let report: layerfault::behaviour::BehaviourReport =
        serde_json::from_slice(&bytes).map_err(|error| {
            anyhow!(
                "behaviour report '{}' is invalid JSON: {error}",
                path.display()
            )
        })?;
    let mut limitations = Vec::new();
    let completeness = if report.executions.is_empty() {
        limitations.push("behaviour report contains no probe executions".to_owned());
        layerfault::assurance::AnalysisCompleteness::Unknown
    } else if report
        .executions
        .iter()
        .any(|execution| execution.timed_out)
        || !report.dynamic_observations.trace_available
    {
        if report
            .executions
            .iter()
            .any(|execution| execution.timed_out)
        {
            limitations.push("one or more behavioural trials timed out".to_owned());
        }
        if !report.dynamic_observations.trace_available {
            limitations.push("sandbox telemetry trace was unavailable".to_owned());
        }
        layerfault::assurance::AnalysisCompleteness::Partial
    } else {
        layerfault::assurance::AnalysisCompleteness::Complete
    };
    Ok(layerfault::inventory::PassportBehaviourSummary {
        suite_id: report.probe_suite_id,
        suite_version: report.probe_suite_version.to_string(),
        trial_count: report.executions.len() as u64,
        state: format!("{:?}", report.state),
        completeness,
        limitations,
    })
}
