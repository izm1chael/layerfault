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
            runtimes,
            format,
            output,
        } => {
            let passport = build_passport(&target, parent.as_deref(), &runtimes)?;
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

fn build_passport(
    path: &Path,
    parent: Option<&Path>,
    runtimes: &[String],
) -> Result<layerfault::inventory::ModelSecurityPassport> {
    let snapshot = layerfault::modelmeta::build_snapshot(path)?;
    let identity = layered_identity(path, false)?;
    let (findings, coverage) = if path.is_dir() {
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
    let mut runtime = Vec::new();
    for raw in runtimes {
        let kind = layerfault::runtime_security::RuntimeKind::parse(raw)?;
        for posture in layerfault::runtime_security::audit_kind(kind) {
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
                    .map(|a| format!("{}:{:?}", a.advisory_id, a.state))
                    .collect(),
                posture_findings: posture
                    .findings
                    .iter()
                    .filter_map(|f| f.rule_id.clone())
                    .collect(),
            });
        }
    }
    let mut limitations = Vec::new();
    if parent.is_some() {
        limitations.push("parent was supplied to passport generation; explicit lineage relation verification requires `layerfault lineage verify` and is not inferred".into());
    }
    layerfault::inventory::build_passport(layerfault::inventory::PassportInputs {
        generated_unix: layerfault::paths::now_unix(),
        scanner_revision: layerfault::explain::scanner_revision().into(),
        ruleset_sha256: layerfault::explain::ruleset_sha256().into(),
        intelligence_sha256: None,
        subject: layerfault::inventory::PassportSubject {
            name: path
                .file_name()
                .and_then(|v| v.to_str())
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
        tokenizer: Some(layerfault::inventory::PassportTokenizerSummary {
            digest: snapshot.tokenizer_security_digest.clone(),
            finding_count: snapshot.tokenizer_security_finding_count,
            chat_template_sha256: snapshot
                .template
                .as_ref()
                .and_then(|t| t.exact_hash.clone()),
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
