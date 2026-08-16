use super::super::{ResearchArgs, ResearchCommand};
use anyhow::{anyhow, bail, Result};
use layerfault::json_stream::write_stdout_json;
use layerfault::research::{CandidateSource, TriggerCandidate};

fn tag(text: String, source: CandidateSource, rationale: &str) -> TriggerCandidate {
    TriggerCandidate {
        text,
        source,
        rationale: rationale.to_owned(),
    }
}

fn tag_all(values: Vec<String>, source: CandidateSource, rationale: &str) -> Vec<TriggerCandidate> {
    values
        .into_iter()
        .map(|value| tag(value, source, rationale))
        .collect()
}
pub(crate) fn run_research(args: ResearchArgs) -> Result<()> {
    match args.command {
        ResearchCommand::TriggerSearch {
            model,
            base,
            runtime,
            runtime_path,
            tokenizer,
            alphabet,
            min_length,
            max_length,
            max_candidates,
            prefix,
            suffix,
            seed,
            timeout_seconds,
            json: emit_json,
        } => {
            let space = layerfault::research::trigger_space_from_strings(
                alphabet,
                min_length,
                max_length,
                max_candidates,
                prefix,
                suffix,
                true,
            )?;
            let candidates = tag_all(
                layerfault::research::enumerate(&space)?,
                CandidateSource::ExhaustiveEnumeration,
                "exhaustive enumeration over the configured alphabet",
            );
            let report = match runtime.as_str() {
                "llama-cpp" => layerfault::research::search_external(
                    &model,
                    base.as_deref(),
                    runtime_path.as_deref(),
                    &candidates,
                    seed,
                    timeout_seconds,
                )?,
                "embedded" => {
                    let tokenizer = tokenizer
                        .as_deref()
                        .ok_or_else(|| anyhow!("embedded trigger search requires --tokenizer"))?;
                    layerfault::research::search_embedded(
                        &model,
                        base.as_deref(),
                        tokenizer,
                        &candidates,
                        seed,
                        timeout_seconds,
                    )?
                }
                other => bail!("unsupported research runtime '{other}'"),
            };
            emit_research(&report, emit_json)?;
        }
        ResearchCommand::Backdoor {
            model,
            base,
            runtime,
            runtime_path,
            tokenizer,
            seed,
            json: emit_json,
        } => {
            let seed_literals = vec![
                "RFC-79".to_owned(),
                "CWE-79".to_owned(),
                "NIST-79".to_owned(),
                "ISO-79".to_owned(),
                "LF_TRIGGER_ALPHA".to_owned(),
                "\u{200b}LF_TRIGGER_ALPHA".to_owned(),
                "TEZfVFJJR0dFUl9BTFBIQQ==".to_owned(),
            ];
            let mut rare = Vec::new();
            if let Some(path) = tokenizer.as_deref() {
                if let Ok(mut r) = layerfault::research::tail_vocab_candidates(path) {
                    r.truncate(512);
                    rare = r;
                }
            }
            let beam_seeds: Vec<String> = seed_literals
                .iter()
                .chain(rare.iter())
                .take(16)
                .cloned()
                .collect();
            let beam = layerfault::research::beam_candidates(
                &beam_seeds,
                &[
                    "-".into(),
                    "_".into(),
                    "79".into(),
                    "RFC".into(),
                    "CVE".into(),
                ],
                32,
                2,
                2048,
            )?;
            let mut candidates = layerfault::research::build_candidates(
                &seed_literals,
                None,
                None,
                &rare,
                Some(&layerfault::research::BeamOptions { candidates: beam }),
            )?;
            candidates.truncate(4096);
            let report = match runtime.as_str() {
                "llama-cpp" => layerfault::research::search_external(
                    &model,
                    base.as_deref(),
                    runtime_path.as_deref(),
                    &candidates,
                    seed,
                    120,
                )?,
                "embedded" => {
                    let tokenizer = tokenizer.as_deref().ok_or_else(|| {
                        anyhow!("embedded backdoor research requires --tokenizer")
                    })?;
                    layerfault::research::search_embedded(
                        &model,
                        base.as_deref(),
                        tokenizer,
                        &candidates,
                        seed,
                        120,
                    )?
                }
                other => bail!("unsupported research runtime '{other}'"),
            };
            emit_research(&report, emit_json)?;
        }
        ResearchCommand::ActivationDiff {
            base,
            derived,
            tokenizer,
            json: emit_json,
        } => {
            let comparison = layerfault::lineage::compare_paths(&base, &derived, None, None)?;
            let weight = if base
                .extension()
                .and_then(|v| v.to_str())
                .is_some_and(|v| v.eq_ignore_ascii_case("safetensors"))
                && derived
                    .extension()
                    .and_then(|v| v.to_str())
                    .is_some_and(|v| v.eq_ignore_ascii_case("safetensors"))
            {
                layerfault::weights::compare_safetensors(&base, &derived, 100_000).ok()
            } else {
                None
            };
            let behaviour = layerfault::behaviour::compare_embedded(
                &base,
                &derived,
                &tokenizer,
                None,
                0,
                layerfault::behaviour::BehaviourLimits::for_profile("standard")?,
            )
            .ok();
            #[derive(serde::Serialize)]
            struct ActivationCapture {
                state: &'static str,
                detail: &'static str,
            }
            #[derive(serde::Serialize)]
            struct ActivationDiffReport {
                schema_version: &'static str,
                lineage: layerfault::lineage::ComparisonReport,
                weight_deltas: Option<Vec<layerfault::weights::TensorDeltaStatistics>>,
                embedded_differential: Option<layerfault::behaviour::DifferentialReport>,
                activation_capture: ActivationCapture,
                boundary: &'static str,
            }
            let report = ActivationDiffReport {
                schema_version: "1.0",
                lineage: comparison,
                weight_deltas: weight,
                embedded_differential: behaviour,
                activation_capture: ActivationCapture {
                    state: "SUPPORTED_WITH_CAPABILITY_LIMIT",
                    detail: "The current embedded candelabra backend does not expose arbitrary hidden-state tensors through its public API. Layerfault records weight and identical-backend behavioural differentials without fabricating activation evidence.",
                },
                boundary: "Absence of captured hidden-state anomalies is not evidence that no hidden trigger exists.",
            };
            if emit_json {
                write_stdout_json(&report, true)?;
            } else {
                println!("ACTIVATION / EMBEDDED DIFFERENTIAL\nCapability-limited hidden-state capture; weight and same-backend behavioural evidence were collected where supported.");
            }
        }
        ResearchCommand::Campaign { json: emit_json } => {
            let store = layerfault::observations::ObservationStore::load()?;
            let report = layerfault::research::campaign(&store);
            if emit_json {
                write_stdout_json(&report, true)?;
            } else {
                println!("MODEL CAMPAIGN CORRELATION\n{} observation(s), {} shared component correlation(s)",report.records_examined,report.shared_component_hashes.len());
            }
        }
        ResearchCommand::BackdoorStatic {
            model,
            parent,
            dataset,
            adapter,
            profile,
            json: emit_json,
        } => {
            let profile = match profile.to_ascii_lowercase().as_str() {
                "standard" => layerfault::model::forensics::BackdoorProfile::Standard,
                "research" => layerfault::model::forensics::BackdoorProfile::Research,
                other => bail!("unknown backdoor profile '{other}'; use standard or research"),
            };
            let subject = layerfault::safeio::sha256_path(&model)
                .unwrap_or_else(|_| model.display().to_string());
            let reference = parent
                .as_ref()
                .map(|p| layerfault::safeio::sha256_path(p))
                .transpose()?;
            let mut delta_masses = Vec::new();
            if let Some(parent) = parent.as_deref() {
                let safetensors = |p: &std::path::Path| {
                    p.extension()
                        .and_then(|v| v.to_str())
                        .is_some_and(|v| v.eq_ignore_ascii_case("safetensors"))
                };
                if safetensors(parent) && safetensors(&model) {
                    if let Ok(stats) =
                        layerfault::weights::compare_safetensors(parent, &model, 100_000)
                    {
                        delta_masses = stats
                            .into_iter()
                            .map(|s| layerfault::model::forensics::TensorDeltaMass {
                                tensor: s.tensor,
                                absolute_delta: s.l1_delta,
                            })
                            .collect();
                    }
                }
            }
            // Dataset poisoning remains a separate typed report today; do not fabricate scanner findings from it.
            // Running the review here still validates/parses the supplied dataset and keeps the evidence boundary explicit.
            if let Some(path) = dataset.as_deref() {
                let _ = layerfault::dataset::poisoning_review(path)?;
            }
            let dataset_findings = Vec::new();
            let adapter_findings = adapter
                .as_deref()
                .and_then(|p| layerfault::package::inspect(p).ok())
                .map(|r| r.findings)
                .unwrap_or_default();
            let report = layerfault::model::forensics::analyze_backdoor_static(
                layerfault::model::forensics::BackdoorStaticInput {
                    subject,
                    reference,
                    profile,
                    tensor_anomalies: Vec::new(),
                    embedding_candidates: Vec::new(),
                    ordinary_embedding_norms: Vec::new(),
                    delta_masses,
                    nonfinite: Vec::new(),
                    dataset_findings,
                    adapter_findings,
                },
            );
            if emit_json {
                write_stdout_json(&report, true)?;
            } else {
                println!(
                    "STATIC BACKDOOR FORENSICS\n{} finding(s)\ncompleteness={:?}",
                    report.findings.len(),
                    report.completeness
                );
                for limitation in &report.limitations {
                    println!("LIMITATION: {limitation}");
                }
                println!("Static statistical indicators are probabilistic evidence and do not establish malicious intent.");
            }
        }
        ResearchCommand::TriggerHunt {
            model,
            parent,
            runtime,
            candidates: operator_candidates,
            from_tokenizer,
            beam_width,
            beam_rounds,
            profile,
            json: emit_json,
        } => {
            if profile != "standard" && profile != "research" {
                bail!(
                    "unknown trigger-hunt profile '{}'; use standard or research",
                    profile
                );
            }
            let tokenizer_path = if model.is_dir() {
                ["tokenizer.json", "tokenizer.model"]
                    .into_iter()
                    .map(|name| model.join(name))
                    .find(|p| p.is_file())
            } else {
                None
            };
            let mut rare = Vec::new();
            if from_tokenizer {
                let tokenizer = tokenizer_path.as_deref().ok_or_else(|| anyhow!("--from-tokenizer requires a discoverable tokenizer.json/tokenizer.model in the model package"))?;
                let mut r = layerfault::research::tail_vocab_candidates(tokenizer)?;
                r.truncate(if profile == "research" { 4096 } else { 512 });
                rare = r;
            }
            let beam = if beam_rounds > 0 && !(operator_candidates.is_empty() && rare.is_empty()) {
                let seeds: Vec<String> = operator_candidates
                    .iter()
                    .chain(rare.iter())
                    .take(16)
                    .cloned()
                    .collect();
                let additions = [
                    "-".into(),
                    "_".into(),
                    "RFC".into(),
                    "CVE".into(),
                    "79".into(),
                ];
                layerfault::research::beam_candidates(
                    &seeds,
                    &additions,
                    beam_width.max(1),
                    beam_rounds,
                    if profile == "research" { 8192 } else { 2048 },
                )?
            } else {
                Vec::new()
            };
            let candidates = layerfault::research::build_candidates(
                &operator_candidates,
                None,
                None,
                &rare,
                (!beam.is_empty())
                    .then_some(layerfault::research::BeamOptions { candidates: beam })
                    .as_ref(),
            )?;
            let cap = if profile == "research" {
                100_000
            } else {
                10_000
            };
            if candidates.len() > cap {
                bail!(
                    "trigger candidate count {} exceeds {} profile cap {}",
                    candidates.len(),
                    profile,
                    cap
                );
            }
            if candidates.is_empty() {
                bail!("trigger hunt requires at least one --candidate or --from-tokenizer");
            }
            let mut report = match runtime.as_deref() {
                Some("llama-cpp") => layerfault::research::search_external(&model, parent.as_deref(), None, &candidates, 0, 120)?,
                Some(other) => bail!("active trigger hunt runtime '{}' is not available through the current guarded behavioural backend; use llama-cpp or omit --runtime for embedded analysis", other),
                None => {
                    let tokenizer = tokenizer_path.as_deref().ok_or_else(|| anyhow!("embedded trigger hunt is unavailable for this target; supply --runtime llama-cpp"))?;
                    layerfault::research::search_embedded(&model, parent.as_deref(), tokenizer, &candidates, 0, 120)?
                }
            };
            report.boundary = layerfault::model::research::HUNT_BOUNDARY.into();
            if emit_json {
                write_stdout_json(&report, true)?;
            } else {
                println!(
                    "TRIGGER HUNT\n{} candidate(s) executed\n{} suspicious transition(s)\n\n{}",
                    report.executed,
                    report.suspicious.len(),
                    report.boundary
                );
            }
        }
    }
    Ok(())
}

fn emit_research(
    report: &layerfault::research::TriggerSearchResult,
    json_output: bool,
) -> Result<()> {
    if json_output {
        write_stdout_json(report, true)?;
    } else {
        println!("TRIGGER / BACKDOOR RESEARCH\n{} candidate(s) executed\n{} suspicious transition(s)\n\n{}",report.executed,report.suspicious.len(),report.boundary);
        for hit in report.suspicious.iter().take(100) {
            println!(
                "{}: {} {:?}",
                hit.candidate_display, hit.classification, hit.rule_ids
            );
        }
    }
    Ok(())
}
