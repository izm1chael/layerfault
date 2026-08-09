use crate::{
    BehaviourArgs, CompareArgs, CompareBehaviourArgs, DriftArgs, LineageArgs, LineageCommand,
    ModelsArgs, ModelsCommand, ReviewArgs,
};
use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use std::path::Path;

use layerfault::decision::SecurityDecision;

fn claim(value: Option<&str>) -> Result<Option<layerfault::transformation::TransformationType>> {
    value
        .map(layerfault::transformation::TransformationType::parse)
        .transpose()
}

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
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({"record":key,"observation":observation}))?
                );
            } else {
                println!("Remembered {} as {}", observation.id, key);
            }
        }
        ModelsCommand::List { json: emit_json } => {
            if emit_json {
                println!("{}", serde_json::to_string_pretty(&store)?);
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
                println!("{}", serde_json::to_string_pretty(record)?);
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
                println!("{}", serde_json::to_string_pretty(&record.observations)?);
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
                println!("{}", json!({"forgotten":id,"removed":removed}));
            } else {
                println!("{} {}", if removed { "Forgot" } else { "Not found" }, id);
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
        println!("{}", serde_json::to_string_pretty(&report)?);
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

pub(crate) fn run_lineage(args: LineageArgs) -> Result<()> {
    match args.command {
        LineageCommand::VerifyChain {
            chain,
            json: emit_json,
        } => {
            let trust = layerfault::trust::TrustStore::load(None)?;
            let report = layerfault::transformation::verify_chain(&chain, &trust)?;
            if emit_json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "LINEAGE CHAIN\n{:?}\n\n{} link(s) verified",
                    report.state,
                    report.links.len()
                );
            }
        }
    }
    Ok(())
}

pub(crate) fn run_compare(args: CompareArgs) -> Result<()> {
    let parsed_claim = claim(args.claim.as_deref())?;
    let manifest = args
        .transformation_manifest
        .as_deref()
        .map(layerfault::transformation::load_manifest)
        .transpose()?;
    let mut comparison = layerfault::lineage::compare_paths(
        &args.base,
        &args.derived,
        parsed_claim,
        manifest.as_ref(),
    )?;
    let comparison_seed = format!(
        "{}\0{}",
        comparison.base.identity.canonical, comparison.derived.identity.canonical
    );
    let weight_analysis = weight_analysis(&args.base, &args.derived, "quick", &comparison_seed);
    let lora_analysis =
        if args.derived.is_dir() && args.derived.join("adapter_config.json").is_file() {
            Some(layerfault::lora::inspect_adapter(
                &args.derived,
                Some(&comparison.base),
            )?)
        } else {
            None
        };
    let lora_merge = if matches!(
        parsed_claim,
        Some(layerfault::transformation::TransformationType::LoraMerge)
    ) {
        args.adapter
            .as_deref()
            .map(|adapter| layerfault::lora::verify_merge(&args.base, adapter, &args.derived))
            .transpose()?
    } else {
        None
    };
    let quantization = if args.reproduce_quantization {
        let quantizer = args
            .quantizer
            .as_deref()
            .ok_or_else(|| anyhow!("--reproduce-quantization requires --quantizer"))?;
        let quant = args
            .quantization
            .as_deref()
            .ok_or_else(|| anyhow!("--reproduce-quantization requires --quantization"))?;
        Some(layerfault::quantization::reproduce(
            &args.base,
            &args.derived,
            quantizer,
            quant,
            300,
        )?)
    } else {
        None
    };
    if quantization
        .as_ref()
        .is_some_and(|v| v.status == "VERIFIED")
        && comparison.lineage == layerfault::transformation::LineageState::Consistent
    {
        comparison.lineage = layerfault::transformation::LineageState::Verified;
    }
    let final_decision = if comparison.lineage
        == layerfault::transformation::LineageState::Contradicted
        || lora_merge
            .as_ref()
            .is_some_and(|v| v.state == "CONTRADICTED")
    {
        SecurityDecision::Block
    } else if comparison.findings.is_empty()
        && lora_merge.as_ref().is_none_or(|v| v.state == "VERIFIED")
    {
        SecurityDecision::Pass
    } else {
        SecurityDecision::Warn
    };
    let result = json!({"schema_version":"1.0","comparison":&comparison,"weight_analysis":weight_analysis,"lora":lora_analysis,"lora_merge_verification":lora_merge,"quantization_reproducibility":quantization,"final_decision":final_decision});
    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!(
            "LINEAGE / DERIVATION COMPARISON\n{:?}\n\nFINAL {}",
            comparison.lineage, final_decision
        );
        for finding in &comparison.findings {
            println!("{}: {}", finding.rule_id, finding.title);
        }
    }
    let code = final_decision.exit_code();
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

pub(crate) fn run_behaviour(args: BehaviourArgs) -> Result<()> {
    if let Some(replay_path) = args.replay.as_deref() {
        if args.runtime != "llama-cpp" {
            bail!("behaviour replay currently records external llama.cpp runtime identity; use --runtime llama-cpp");
        }
        let replay = layerfault::behaviour::load_replay(replay_path)?;
        let report = layerfault::behaviour::run_external_llama(
            Path::new(&replay.model_path),
            Some(Path::new(&replay.runtime_path)),
            replay.probe_suite_path.as_deref().map(Path::new),
            replay.seed,
            replay.limits,
        )?;
        if report.runtime.executable_sha256 != replay.runtime_sha256 {
            bail!(
                "replay runtime fingerprint changed: expected {}, got {}",
                replay.runtime_sha256,
                report.runtime.executable_sha256
            );
        }
        return emit_behaviour(&report, args.json);
    }
    let defaults = layerfault::behaviour::BehaviourLimits::for_profile(&args.profile)?;
    let limits = defaults.clamp(
        args.max_prompts.unwrap_or(usize::MAX),
        args.max_turns.unwrap_or(usize::MAX),
        args.max_tokens.map(|v| v as u64).unwrap_or(u64::MAX),
        args.timeout_seconds.unwrap_or(u64::MAX),
        args.max_mutations.unwrap_or(usize::MAX),
        args.repeat_count.unwrap_or(usize::MAX),
    );
    let active = layerfault::behaviour::ActiveExecutionOptions {
        allow_static_blocked: args.allow_static_blocked,
        execute_custom_code: args.execute_custom_code,
    };
    let mut report = match args.runtime.as_str() {
        "llama-cpp" => {
            if args.execute_custom_code {
                bail!("--execute-custom-code is only supported by --runtime transformers");
            }
            layerfault::behaviour::run_external_llama_active(
                &args.model,
                args.runtime_path.as_deref(),
                args.probe_suite.as_deref(),
                args.seed,
                limits,
                active,
            )?
        }
        "transformers" | "transformers-python" => layerfault::behaviour::python::run_transformers(
            &args.model,
            args.base.as_deref(),
            args.runtime_path.as_deref(),
            args.probe_suite.as_deref(),
            args.seed,
            limits,
            active,
        )?,
        "embedded" => {
            if args.allow_static_blocked || args.execute_custom_code {
                bail!("--allow-static-blocked/--execute-custom-code require an external strong-sandbox runtime, not --runtime embedded");
            }
            let tokenizer = args.tokenizer.as_deref().ok_or_else(|| {
                anyhow!("--runtime embedded requires --tokenizer /path/to/tokenizer.json")
            })?;
            layerfault::behaviour::run_embedded(
                &args.model,
                tokenizer,
                args.probe_suite.as_deref(),
                args.seed,
                limits,
            )?
        }
        other => {
            bail!("unsupported behaviour runtime '{other}'; supported values: llama-cpp, transformers, embedded")
        }
    };
    apply_watch_strings(&mut report, &args.watch_string);
    if let Some(path) = args.run_manifest_out.as_deref() {
        if args.runtime != "llama-cpp" {
            bail!("--run-manifest-out replay format currently requires --runtime llama-cpp");
        }
        let manifest = layerfault::behaviour::replay_manifest(&report, args.probe_suite.as_deref());
        layerfault::paths::write_private(path, &serde_json::to_vec_pretty(&manifest)?)?;
    }
    emit_behaviour(&report, args.json)
}

pub(crate) fn run_compare_behaviour(args: CompareBehaviourArgs) -> Result<()> {
    let defaults = layerfault::behaviour::BehaviourLimits::for_profile(&args.profile)?;
    let limits = defaults.clamp(
        args.max_prompts.unwrap_or(usize::MAX),
        args.max_turns.unwrap_or(usize::MAX),
        args.max_tokens.map(|v| v as u64).unwrap_or(u64::MAX),
        args.timeout_seconds.unwrap_or(u64::MAX),
        usize::MAX,
        usize::MAX,
    );
    let active = layerfault::behaviour::ActiveExecutionOptions {
        allow_static_blocked: args.allow_static_blocked,
        execute_custom_code: args.execute_custom_code,
    };
    let report = match args.runtime.as_str() {
        "llama-cpp" => {
            if args.execute_custom_code {
                bail!("--execute-custom-code is only supported by --runtime transformers");
            }
            layerfault::behaviour::compare_external_llama_active(
                &args.base,
                &args.derived,
                args.runtime_path.as_deref(),
                args.probe_suite.as_deref(),
                args.seed,
                limits,
                active,
            )?
        }
        "transformers" | "transformers-python" => {
            layerfault::behaviour::python::compare_transformers(
                &args.base,
                &args.derived,
                args.runtime_path.as_deref(),
                args.probe_suite.as_deref(),
                args.seed,
                limits,
                active,
            )?
        }
        "embedded" => {
            if args.allow_static_blocked || args.execute_custom_code {
                bail!("--allow-static-blocked/--execute-custom-code require an external strong-sandbox runtime, not --runtime embedded");
            }
            let tokenizer = args.tokenizer.as_deref().ok_or_else(|| {
                anyhow!("--runtime embedded requires --tokenizer /path/to/tokenizer.json")
            })?;
            layerfault::behaviour::compare_embedded(
                &args.base,
                &args.derived,
                tokenizer,
                args.probe_suite.as_deref(),
                args.seed,
                limits,
            )?
        }
        other => {
            bail!("unsupported behaviour runtime '{other}'; supported values: llama-cpp, transformers, embedded")
        }
    };
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "DIFFERENTIAL BEHAVIOUR\n{:?}\n\n{} comparison row(s)",
            report.state,
            report.rows.len()
        );
        for row in report.rows.iter().filter(|r| {
            !matches!(
                r.classification,
                layerfault::transformation::DifferentialBehaviourState::Expected
            )
        }) {
            println!("{}: {:?}", row.probe_id, row.classification);
        }
    }
    let decision = SecurityDecision::from_differential_behaviour_state(report.state);
    let code = decision.exit_code();
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

pub(crate) fn run_review(args: ReviewArgs) -> Result<()> {
    // Validate explicit CLI relationships before admission. These are operator
    // configuration errors rather than secondary-analysis failures.
    let parsed_claim = claim(args.claim.as_deref())?;
    if args.reproduce_quantization {
        if args.base.is_none() {
            bail!("quantization reproduction requires --base");
        }
        if args.quantizer.is_none() {
            bail!("quantization reproduction requires --quantizer");
        }
        if args.quantization.is_none() {
            bail!("quantization reproduction requires --quantization");
        }
    }
    if args.evidence_out.is_some() != args.evidence_key.is_some() {
        bail!("--evidence-out and --evidence-key must be supplied together");
    }
    // Treat an unknown review profile as an operator/configuration error, not
    // as a supplementary security-domain failure.
    let _ = layerfault::weights::WeightAnalysisOptions::for_review_profile(
        &args.profile,
        "profile-validation",
    )?;

    // Static admission is intentionally first. Once it establishes BLOCK no
    // optional/supplementary analysis is allowed to downgrade that decision or
    // prevent a structured review report from being emitted.
    let (static_value, static_block, static_warn, admitted_package) = scan_target(&args.model)?;
    let mut decision = if static_block {
        SecurityDecision::Block
    } else if static_warn {
        SecurityDecision::Warn
    } else {
        SecurityDecision::Pass
    };

    let manifest_result = args
        .transformation_manifest
        .as_deref()
        .map(layerfault::transformation::load_manifest)
        .transpose();
    let (manifest, manifest_domain) = match manifest_result {
        Ok(value) => {
            let domain = value
                .as_ref()
                .map(domain_available)
                .unwrap_or_else(|| domain_not_run("no transformation manifest supplied"));
            (value, domain)
        }
        Err(error) => {
            decision.raise(SecurityDecision::Warn);
            (None, domain_failed(error.to_string()))
        }
    };

    let snapshot_result = if let Some(report) = admitted_package.as_ref() {
        layerfault::modelmeta::snapshot_package_from_report(&args.model, report)
    } else {
        layerfault::modelmeta::build_snapshot(&args.model)
    };
    let (snapshot, snapshot_domain) = match snapshot_result {
        Ok(value) => {
            let domain = domain_available(&value);
            (Some(value), domain)
        }
        Err(error) => {
            decision.raise(SecurityDecision::Warn);
            (None, domain_failed(error.to_string()))
        }
    };

    let (base_snapshot, base_snapshot_domain) = if let Some(base) = args.base.as_deref() {
        match layerfault::modelmeta::build_snapshot(base) {
            Ok(value) => {
                let domain = domain_available(&value);
                (Some(value), domain)
            }
            Err(error) => {
                decision.raise(SecurityDecision::Warn);
                (None, domain_failed(error.to_string()))
            }
        }
    } else {
        (None, domain_not_run("no base model supplied"))
    };

    let (comparison, lineage_domain) = match (base_snapshot.as_ref(), snapshot.as_ref()) {
        (Some(base), Some(derived)) => {
            let report = layerfault::lineage::compare_snapshots(
                base.clone(),
                derived.clone(),
                parsed_claim,
                manifest.as_ref(),
            );
            if report.lineage == layerfault::transformation::LineageState::Contradicted {
                decision.raise(SecurityDecision::Block);
            } else if !report.findings.is_empty() {
                decision.raise(SecurityDecision::Warn);
            }
            let domain = domain_available(&report);
            (Some(report), domain)
        }
        (None, _) if args.base.is_some() => (
            None,
            domain_unavailable(
                "base model snapshot was unavailable; lineage comparison was not attempted",
            ),
        ),
        (_, None) if args.base.is_some() => (
            None,
            domain_unavailable(
                "target model snapshot was unavailable; lineage comparison was not attempted",
            ),
        ),
        _ => (None, domain_not_run("no base model supplied")),
    };

    let (_lora, lora_domain) =
        if args.model.is_dir() && args.model.join("adapter_config.json").is_file() {
            match layerfault::lora::inspect_adapter(&args.model, base_snapshot.as_ref()) {
                Ok(report) => {
                    if !report.findings.is_empty() {
                        decision.raise(SecurityDecision::Warn);
                    }
                    let domain = domain_available(&report);
                    (Some(report), domain)
                }
                Err(error) => {
                    decision.raise(SecurityDecision::Warn);
                    (None, domain_failed(error.to_string()))
                }
            }
        } else {
            (
                None,
                domain_not_run("target is not a detected LoRA adapter package"),
            )
        };

    let (_lora_merge, lora_merge_domain) = if matches!(
        parsed_claim,
        Some(layerfault::transformation::TransformationType::LoraMerge)
    ) {
        match (args.base.as_deref(), args.adapter.as_deref()) {
            (Some(base), Some(adapter)) => {
                match layerfault::lora::verify_merge(base, adapter, &args.model) {
                    Ok(report) => {
                        if report.state == "CONTRADICTED" {
                            decision.raise(SecurityDecision::Block);
                        } else if report.state != "VERIFIED" {
                            decision.raise(SecurityDecision::Warn);
                        }
                        let domain = domain_available(&report);
                        (Some(report), domain)
                    }
                    Err(error) => {
                        decision.raise(SecurityDecision::Warn);
                        (None, domain_failed(error.to_string()))
                    }
                }
            }
            _ => {
                decision.raise(SecurityDecision::Warn);
                (
                    None,
                    domain_unavailable(
                        "lora-merge verification requires both --base and --adapter",
                    ),
                )
            }
        }
    } else {
        (None, domain_not_run("no lora-merge claim supplied"))
    };

    let target_weight_seed = snapshot
        .as_ref()
        .map(|value| value.identity.canonical.clone())
        .unwrap_or_else(|| review_subject(&args.model, &static_value, None));
    let weight = match args.base.as_deref() {
        Some(base) => {
            let base_weight_seed = base_snapshot
                .as_ref()
                .map(|value| value.identity.canonical.as_str())
                .unwrap_or("base-snapshot-unavailable");
            let seed = format!("{}\0{}", base_weight_seed, target_weight_seed);
            weight_analysis(base, &args.model, &args.profile, &seed)
        }
        None => single_weight_analysis(&args.model, &args.profile, &target_weight_seed),
    };
    if domain_state(&weight) == Some("FAILED") {
        decision.raise(SecurityDecision::Warn);
    }

    let (_quant, quant_domain) = if args.reproduce_quantization {
        match layerfault::quantization::reproduce(
            args.base.as_deref().expect("validated --base"),
            &args.model,
            args.quantizer.as_deref().expect("validated --quantizer"),
            args.quantization
                .as_deref()
                .expect("validated --quantization"),
            300,
        ) {
            Ok(report) => {
                if report.status != "VERIFIED" {
                    decision.raise(SecurityDecision::Warn);
                }
                let domain = domain_available(&report);
                (Some(report), domain)
            }
            Err(error) => {
                decision.raise(SecurityDecision::Warn);
                (None, domain_failed(error.to_string()))
            }
        }
    } else {
        (
            None,
            domain_not_run("quantization reproduction was not requested"),
        )
    };

    let active_execution = layerfault::behaviour::ActiveExecutionOptions {
        allow_static_blocked: args.allow_static_blocked,
        execute_custom_code: args.execute_custom_code,
    };
    let (behavior, behaviour_domain) = if static_block && !args.allow_static_blocked {
        (None, domain_not_run("static admission blocked the model"))
    } else if args.profile.eq_ignore_ascii_case("quick") {
        (None, domain_not_run("quick profile does not run inference"))
    } else {
        let result = layerfault::behaviour::BehaviourLimits::for_profile(&args.profile)
                .and_then(|limits| match args.runtime.as_str() {
                    "llama-cpp" => {
                        if args.execute_custom_code {
                            Err(anyhow!("--execute-custom-code is only supported by --runtime transformers"))
                        } else {
                            layerfault::behaviour::run_external_llama_active(
                        &args.model,
                        args.runtime_path.as_deref(),
                        args.probe_suite.as_deref(),
                        0,
                        limits,
                        active_execution,
                    )
                        }
                    },
                    "transformers" | "transformers-python" => layerfault::behaviour::python::run_transformers(
                        &args.model,
                        args.base.as_deref(),
                        args.runtime_path.as_deref(),
                        args.probe_suite.as_deref(),
                        0,
                        limits,
                        active_execution,
                    ),
                    "embedded" => {
                        if args.allow_static_blocked || args.execute_custom_code {
                            Err(anyhow!("--allow-static-blocked/--execute-custom-code require an external strong-sandbox runtime"))
                        } else {
                            match args.tokenizer.as_deref() {
                        Some(tokenizer) => layerfault::behaviour::run_embedded(
                            &args.model,
                            tokenizer,
                            args.probe_suite.as_deref(),
                            0,
                            limits,
                        ),
                        None => Err(anyhow!("--runtime embedded requires --tokenizer")),
                            }
                        }
                    },
                    other => Err(anyhow!("unsupported behaviour runtime '{other}'; supported: llama-cpp, transformers, embedded")),
                });
        match result {
            Ok(report) => {
                decision.raise(SecurityDecision::from_behaviour_state(report.state));
                let domain = domain_available(&report);
                (Some(report), domain)
            }
            Err(error) => {
                decision.raise(SecurityDecision::Warn);
                (None, domain_failed(error.to_string()))
            }
        }
    };

    let (_differential, differential_domain) = if static_block && !args.allow_static_blocked {
        (None, domain_not_run("static admission blocked the model"))
    } else if args.profile.eq_ignore_ascii_case("quick") {
        (None, domain_not_run("quick profile does not run inference"))
    } else if let Some(base) = args.base.as_deref() {
        match behavior.as_ref().cloned() {
            None => (
                None,
                domain_not_run(
                    "target behavioural report unavailable, so differential behaviour was not run",
                ),
            ),
            Some(derived_report) => {
                let result = layerfault::behaviour::BehaviourLimits::for_profile(&args.profile)
                        .and_then(|limits| {
                            let base_report = match args.runtime.as_str() {
                                "llama-cpp" => {
                                    if args.execute_custom_code {
                                        return Err(anyhow!("--execute-custom-code is only supported by --runtime transformers"));
                                    }
                                    layerfault::behaviour::run_external_llama_active(
                                        base,
                                        args.runtime_path.as_deref(),
                                        args.probe_suite.as_deref(),
                                        0,
                                        limits,
                                        active_execution,
                                    )?
                                }
                                "transformers" | "transformers-python" => {
                                    layerfault::behaviour::python::run_transformers(
                                        base,
                                        None,
                                        args.runtime_path.as_deref(),
                                        args.probe_suite.as_deref(),
                                        0,
                                        limits,
                                        active_execution,
                                    )?
                                }
                                "embedded" => {
                                    if args.allow_static_blocked || args.execute_custom_code {
                                        return Err(anyhow!("--allow-static-blocked/--execute-custom-code require an external strong-sandbox runtime"));
                                    }
                                    let tokenizer = args
                                        .tokenizer
                                        .as_deref()
                                        .ok_or_else(|| anyhow!("--runtime embedded requires --tokenizer"))?;
                                    layerfault::behaviour::run_embedded(
                                        base,
                                        tokenizer,
                                        args.probe_suite.as_deref(),
                                        0,
                                        limits,
                                    )?
                                }
                                other => {
                                    return Err(anyhow!("unsupported behaviour runtime '{other}'; supported: llama-cpp, transformers, embedded"));
                                }
                            };
                            layerfault::behaviour::compare_reports(base_report, derived_report)
                        });
                match result {
                    Ok(report) => {
                        decision.raise(SecurityDecision::from_differential_behaviour_state(
                            report.state,
                        ));
                        let domain = domain_available(&report);
                        (Some(report), domain)
                    }
                    Err(error) => {
                        decision.raise(SecurityDecision::Warn);
                        (None, domain_failed(error.to_string()))
                    }
                }
            }
        }
    } else {
        (None, domain_not_run("no base model supplied"))
    };

    let (_judge_result, judge_domain) = if args.judge == "disabled" {
        (None, domain_not_run("advisory judge disabled"))
    } else if behavior.is_none() {
        (
            None,
            domain_not_run("behavioural report unavailable, so judge was not invoked"),
        )
    } else {
        match review_judge(&args, &behavior) {
            Ok(Some(report)) => {
                let domain = domain_available(&report);
                (Some(report), domain)
            }
            Ok(None) => (
                None,
                domain_unavailable("no behavioural execution was available to judge"),
            ),
            Err(error) => {
                decision.raise(SecurityDecision::Warn);
                (None, domain_failed(error.to_string()))
            }
        }
    };

    let (_drift, drift_domain) = if args.compare_previous {
        if let Some(snapshot) = snapshot.as_ref() {
            match layerfault::observations::ObservationStore::load() {
                Ok(store) => match store.previous_for_snapshot(snapshot) {
                    Some(prior) => {
                        let report = layerfault::observations::drift(prior, snapshot);
                        let domain = domain_available(&report);
                        (Some(report), domain)
                    }
                    None => (
                        None,
                        domain_unavailable("no prior observation matched this model"),
                    ),
                },
                Err(error) => {
                    decision.raise(SecurityDecision::Warn);
                    (None, domain_failed(error.to_string()))
                }
            }
        } else {
            (
                None,
                domain_unavailable("target snapshot unavailable; drift could not be computed"),
            )
        }
    } else {
        (None, domain_not_run("--compare-previous was not requested"))
    };

    let observation_domain = if args.record_observation {
        if let Some(snapshot) = snapshot.as_ref() {
            match layerfault::observations::ObservationStore::load().and_then(|mut store| {
                let _ = store.remember(snapshot, None, None, None, None)?;
                store.save().map(|_| ())
            }) {
                Ok(()) => json!({"state":"AVAILABLE","recorded":true}),
                Err(error) => {
                    decision.raise(SecurityDecision::Warn);
                    domain_failed(error.to_string())
                }
            }
        } else {
            decision.raise(SecurityDecision::Warn);
            domain_unavailable("target snapshot unavailable; observation could not be recorded")
        }
    } else {
        domain_not_run("--record-observation was not requested")
    };

    let target_value = snapshot
        .as_ref()
        .and_then(|value| serde_json::to_value(value).ok())
        .unwrap_or_else(|| json!({"path":args.model,"snapshot_state":"UNAVAILABLE"}));
    let static_domain = domain_available(&static_value);
    let result = json!({
        "schema_version":"1.1",
        "review_profile":args.profile,
        "target":target_value,
        "domains":{
            "static_admission":static_domain,
            "metadata_snapshot":snapshot_domain,
            "base_snapshot":base_snapshot_domain,
            "transformation_manifest":manifest_domain,
            "lineage":lineage_domain,
            "weight_analysis":weight,
            "lora":lora_domain,
            "lora_merge_verification":lora_merge_domain,
            "quantization_reproducibility":quant_domain,
            "behavioural_security":behaviour_domain,
            "differential_behaviour":differential_domain,
            "judge":judge_domain,
            "drift":drift_domain,
            "observation_recording":observation_domain
        },
        "final_decision":decision,
        "boundary":"Layerfault reports evidence from the checks performed. FAILED and UNAVAILABLE domains are explicit coverage limitations. Behavioural testing cannot prove that no unknown hidden trigger or backdoor exists."
    });

    if let (Some(out), Some(key)) = (args.evidence_out.as_deref(), args.evidence_key.as_deref()) {
        let policy = layerfault::policy::PolicyDocument::builtin(
            layerfault::policy::PolicyProfile::Workstation,
        )
        .effective();
        let trust = layerfault::trust::TrustStore::load(None)?;
        let subject = review_subject(&args.model, &static_value, snapshot.as_ref());
        let envelope = layerfault::evidence::create_signed(
            layerfault::evidence::EvidenceContext {
                subject: &subject,
                source: "local-review",
                subject_fingerprint: Some(&subject),
                policy: &policy,
                trust_store: &trust,
                runtime: None,
                binding: None,
                decision: decision.as_str(),
                details: result.clone(),
            },
            key,
        )?;
        layerfault::evidence::write_signed(out, &envelope)?;
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        let lineage = comparison
            .as_ref()
            .map(|value| format!("{:?}", value.lineage).to_ascii_uppercase())
            .unwrap_or_else(|| {
                domain_state(&lineage_domain)
                    .unwrap_or("NOT_RUN")
                    .to_owned()
            });
        let behaviour = behavior
            .as_ref()
            .map(|value| format!("{:?}", value.state).to_ascii_uppercase())
            .unwrap_or_else(|| {
                domain_state(&behaviour_domain)
                    .unwrap_or("NOT_RUN")
                    .to_owned()
            });
        println!(
            "LAYERFAULT MODEL SECURITY REVIEW\n\nSTATIC ADMISSION\n{}\n\nLINEAGE\n{}\n\nBEHAVIOUR\n{}\n\nFINAL\n{}",
            if static_block { "BLOCK" } else if static_warn { "WARN" } else { "PASS" },
            lineage,
            behaviour,
            decision
        );
    }

    let code = decision.exit_code();
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

fn domain_available<T: serde::Serialize>(report: &T) -> Value {
    json!({"state":"AVAILABLE","report":report,"reason":Value::Null})
}

fn domain_not_run(reason: impl Into<String>) -> Value {
    let reason = reason.into();
    json!({"state":"NOT_RUN","report":Value::Null,"reason":reason,"not_run_reason":reason})
}

fn domain_unavailable(reason: impl Into<String>) -> Value {
    json!({"state":"UNAVAILABLE","report":Value::Null,"reason":reason.into()})
}

fn domain_failed(reason: impl Into<String>) -> Value {
    json!({"state":"FAILED","report":Value::Null,"reason":reason.into()})
}

fn domain_state(value: &Value) -> Option<&str> {
    value.get("state").and_then(Value::as_str)
}

fn review_subject(
    model: &Path,
    static_value: &Value,
    snapshot: Option<&layerfault::modelmeta::ModelSnapshot>,
) -> String {
    if let Some(snapshot) = snapshot {
        return snapshot.identity.canonical.clone();
    }
    for pointer in ["/fingerprint", "/sha256", "/compound_identity"] {
        if let Some(value) = static_value.pointer(pointer).and_then(Value::as_str) {
            return value.to_owned();
        }
    }
    model.display().to_string()
}

fn review_judge(
    args: &ReviewArgs,
    behavior: &Option<layerfault::behaviour::BehaviourReport>,
) -> Result<Option<layerfault::judge::JudgeResult>> {
    if args.judge == "disabled" {
        return Ok(None);
    }
    let Some(report) = behavior.as_ref() else {
        return Ok(None);
    };
    let execution = report
        .executions
        .iter()
        .find(|e| !e.evaluation.rule_ids.is_empty())
        .or_else(|| report.executions.first());
    let Some(execution) = execution else {
        return Ok(None);
    };
    let input = layerfault::judge::JudgeInput {
        probe_id: execution.probe_id.clone(),
        category: execution.category.clone(),
        prompt_excerpt: execution.prompt_sha256.clone(),
        response_excerpt: execution.response_excerpt.clone(),
        base_response_excerpt: None,
        local_rule_ids: execution.evaluation.rule_ids.clone(),
        local_classification: format!("{:?}", execution.evaluation.risk).to_ascii_uppercase(),
    };
    match args.judge.as_str() {
        "local" => Ok(Some(layerfault::judge::local(&input))),
        "openai-compatible" => {
            let endpoint = args
                .judge_endpoint
                .as_deref()
                .ok_or_else(|| anyhow!("--judge openai-compatible requires --judge-endpoint"))?;
            let model = args
                .judge_model
                .as_deref()
                .ok_or_else(|| anyhow!("--judge openai-compatible requires --judge-model"))?;
            let key = layerfault::paths::secret_from_env(&args.judge_api_key_env)?;
            Ok(Some(layerfault::judge::cloud_openai_compatible(
                endpoint,
                model,
                key.as_deref(),
                args.allow_cloud_judge,
                &input,
            )?))
        }
        other => {
            bail!("unsupported judge '{other}'; supported: disabled, local, openai-compatible")
        }
    }
}

fn scan_target(
    path: &Path,
) -> Result<(
    Value,
    bool,
    bool,
    Option<layerfault::package::PackageReport>,
)> {
    if path.is_dir() {
        let report = layerfault::package::inspect(path)?;
        let semantic = SecurityDecision::from_findings(&report.findings);
        let block = semantic == SecurityDecision::Block;
        let warn = semantic == SecurityDecision::Warn;
        let value = serde_json::to_value(&report)?;
        Ok((value, block, warn, Some(report)))
    } else {
        let report = layerfault::formats::artifact::inspect(
            path,
            layerfault::formats::artifact::ArtifactScanMode::Full,
        )?;
        let semantic = SecurityDecision::from_findings(&report.results);
        let block = semantic == SecurityDecision::Block;
        let warn = semantic == SecurityDecision::Warn;
        Ok((serde_json::to_value(report)?, block, warn, None))
    }
}

fn weight_analysis(base: &Path, derived: &Path, profile: &str, seed_material: &str) -> Value {
    let base_set = layerfault::weights::discover_safetensors_weight_set(base);
    let derived_set = layerfault::weights::discover_safetensors_weight_set(derived);
    match (base_set, derived_set) {
        (Ok(Some(_)), Ok(Some(_))) => {
            let options = match layerfault::weights::WeightAnalysisOptions::for_review_profile(
                profile,
                seed_material,
            ) {
                Ok(value) => value,
                Err(error) => {
                    return json!({
                        "state":"FAILED",
                        "report":Value::Null,
                        "reason":error.to_string()
                    });
                }
            };
            match layerfault::weights::compare_safetensors_targets_with_options(
                base, derived, &options,
            ) {
                Ok(report) => json!({"state":"AVAILABLE","report":report}),
                Err(error) => json!({
                    "state":"FAILED",
                    "report":Value::Null,
                    "reason":error.to_string()
                }),
            }
        }
        (Err(error), _) | (_, Err(error)) => {
            json!({"state":"FAILED","report":Value::Null,"reason":error.to_string()})
        }
        _ => json!({
            "state":"UNAVAILABLE",
            "report":Value::Null,
            "reason":"numeric differential requires compatible Safetensors weights in both targets; structural tensor comparison remains available in lineage output"
        }),
    }
}

fn single_weight_analysis(path: &Path, profile: &str, seed_material: &str) -> Value {
    match layerfault::weights::discover_safetensors_weight_set(path) {
        Ok(Some(_)) => {
            let options = match layerfault::weights::WeightAnalysisOptions::for_review_profile(
                profile,
                seed_material,
            ) {
                Ok(value) => value,
                Err(error) => {
                    return json!({
                        "state":"FAILED",
                        "report":Value::Null,
                        "reason":error.to_string()
                    });
                }
            };
            match layerfault::weights::safetensors_statistics_for_target_with_options(
                path, &options,
            ) {
                Ok(report) => json!({"state":"AVAILABLE","report":report}),
                Err(error) => json!({
                    "state":"FAILED",
                    "report":Value::Null,
                    "reason":error.to_string()
                }),
            }
        }
        Ok(None) => json!({
            "state":"UNAVAILABLE",
            "report":Value::Null,
            "reason":"numeric statistics are not interpreted from compressed/quantized bytes without a correct dtype decoder"
        }),
        Err(error) => json!({"state":"FAILED","report":Value::Null,"reason":error.to_string()}),
    }
}

fn emit_behaviour(
    report: &layerfault::behaviour::BehaviourReport,
    json_output: bool,
) -> Result<()> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else {
        println!(
            "BEHAVIOURAL SECURITY\n{:?}\n\n{} probe execution(s)",
            report.state,
            report.executions.len()
        );
        for f in &report.findings {
            println!("{f}");
        }
        let dynamic = &report.dynamic_observations;
        println!(
            "\nDYNAMIC TELEMETRY\nnetwork={} exec={} sensitive_path={} canary={} protected_write_attempt={} unexpected_fs={} trace={}",
            dynamic.network_attempts,
            dynamic.process_exec_attempts,
            dynamic.sensitive_path_accesses,
            dynamic.canary_accesses,
            dynamic.filesystem_write_attempts,
            dynamic.unexpected_filesystem_mutations,
            if dynamic.trace_available { "AVAILABLE" } else { "UNAVAILABLE" }
        );
        println!("\n{}", report.boundary);
    }
    let decision = SecurityDecision::from_behaviour_state(report.state);
    let code = decision.exit_code();
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}
fn apply_watch_strings(report: &mut layerfault::behaviour::BehaviourReport, watch: &[String]) {
    for value in watch.iter().filter(|v| !v.is_empty()).take(128) {
        if report
            .executions
            .iter()
            .any(|e| e.response_excerpt.contains(value))
        {
            report.findings.push("LF-BEHAV-TARGETED-CONTENT".to_owned());
            report.state = match report.state {
                layerfault::transformation::BehaviourState::HighRisk => {
                    layerfault::transformation::BehaviourState::HighRisk
                }
                _ => layerfault::transformation::BehaviourState::Suspicious,
            };
        }
    }
    report.findings.sort();
    report.findings.dedup();
}
