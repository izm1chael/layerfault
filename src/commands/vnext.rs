use crate::{
    BehaviourArgs, CompareArgs, CompareBehaviourArgs, DriftArgs, LineageArgs, LineageCommand,
    ModelsArgs, ModelsCommand, ReviewArgs,
};
use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use std::path::Path;

fn claim(value: Option<&str>) -> Result<Option<layerfault::transformation::TransformationType>> {
    value
        .map(layerfault::transformation::TransformationType::parse)
        .transpose()
}

fn security_decision_exit_code(decision: &str) -> i32 {
    match decision {
        "PASS" => 0,
        "WARN" => 1,
        "BLOCK" => 3,
        _ => 1,
    }
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
    let weight_analysis = weight_analysis(&args.base, &args.derived);
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
        "BLOCK"
    } else if comparison.findings.is_empty()
        && lora_merge.as_ref().is_none_or(|v| v.state == "VERIFIED")
    {
        "PASS"
    } else {
        "WARN"
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
    let mut report = match args.runtime.as_str() {
        "llama-cpp" => layerfault::behaviour::run_external_llama(
            &args.model,
            args.runtime_path.as_deref(),
            args.probe_suite.as_deref(),
            args.seed,
            limits,
        )?,
        "embedded" => {
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
            bail!("unsupported behaviour runtime '{other}'; supported values: llama-cpp, embedded")
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
    let report = match args.runtime.as_str() {
        "llama-cpp" => layerfault::behaviour::compare_external_llama(
            &args.base,
            &args.derived,
            args.runtime_path.as_deref(),
            args.probe_suite.as_deref(),
            args.seed,
            limits,
        )?,
        "embedded" => {
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
            bail!("unsupported behaviour runtime '{other}'; supported values: llama-cpp, embedded")
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
    Ok(())
}

pub(crate) fn run_review(args: ReviewArgs) -> Result<()> {
    let snapshot = layerfault::modelmeta::build_snapshot(&args.model)?;
    let (static_value, static_block, static_warn) = scan_target(&args.model)?;
    let parsed_claim = claim(args.claim.as_deref())?;
    let manifest = args
        .transformation_manifest
        .as_deref()
        .map(layerfault::transformation::load_manifest)
        .transpose()?;
    let comparison = match args.base.as_deref() {
        Some(base) => Some(layerfault::lineage::compare_paths(
            base,
            &args.model,
            parsed_claim,
            manifest.as_ref(),
        )?),
        None => None,
    };
    let lora = if args.model.is_dir() && args.model.join("adapter_config.json").is_file() {
        Some(layerfault::lora::inspect_adapter(
            &args.model,
            comparison.as_ref().map(|v| &v.base),
        )?)
    } else {
        None
    };
    let lora_merge = if matches!(
        parsed_claim,
        Some(layerfault::transformation::TransformationType::LoraMerge)
    ) {
        match (args.base.as_deref(), args.adapter.as_deref()) {
            (Some(base), Some(adapter)) => {
                Some(layerfault::lora::verify_merge(base, adapter, &args.model)?)
            }
            _ => None,
        }
    } else {
        None
    };
    let weight = match args.base.as_deref() {
        Some(base) => weight_analysis(base, &args.model),
        None => single_weight_analysis(&args.model),
    };
    let quant = if args.reproduce_quantization {
        let base = args
            .base
            .as_deref()
            .ok_or_else(|| anyhow!("quantization reproduction requires --base"))?;
        let tool = args
            .quantizer
            .as_deref()
            .ok_or_else(|| anyhow!("quantization reproduction requires --quantizer"))?;
        let q = args
            .quantization
            .as_deref()
            .ok_or_else(|| anyhow!("quantization reproduction requires --quantization"))?;
        Some(layerfault::quantization::reproduce(
            base,
            &args.model,
            tool,
            q,
            300,
        )?)
    } else {
        None
    };
    let (behavior, behaviour_not_run_reason) = if static_block {
        (None, Some("static admission blocked the model".to_owned()))
    } else if args.profile.eq_ignore_ascii_case("quick") {
        (
            None,
            Some("quick profile does not run inference".to_owned()),
        )
    } else {
        let limits = layerfault::behaviour::BehaviourLimits::for_profile(&args.profile)?;
        let result = match args.runtime.as_str() {
            "llama-cpp" => layerfault::behaviour::run_external_llama(
                &args.model,
                args.runtime_path.as_deref(),
                args.probe_suite.as_deref(),
                0,
                limits,
            ),
            "embedded" => match args.tokenizer.as_deref() {
                Some(tokenizer) => layerfault::behaviour::run_embedded(
                    &args.model,
                    tokenizer,
                    args.probe_suite.as_deref(),
                    0,
                    limits,
                ),
                None => Err(anyhow!("--runtime embedded requires --tokenizer")),
            },
            other => Err(anyhow!("unsupported behaviour runtime '{other}'")),
        };
        match result {
            Ok(report) => (Some(report), None),
            Err(error) => (None, Some(error.to_string())),
        }
    };
    let (differential, differential_not_run_reason) =
        if static_block || args.profile.eq_ignore_ascii_case("quick") {
            (None, behaviour_not_run_reason.clone())
        } else if let Some(base) = args.base.as_deref() {
            let limits = layerfault::behaviour::BehaviourLimits::for_profile(&args.profile)?;
            let result = match args.runtime.as_str() {
                "llama-cpp" => layerfault::behaviour::compare_external_llama(
                    base,
                    &args.model,
                    args.runtime_path.as_deref(),
                    args.probe_suite.as_deref(),
                    0,
                    limits,
                ),
                "embedded" => match args.tokenizer.as_deref() {
                    Some(tokenizer) => layerfault::behaviour::compare_embedded(
                        base,
                        &args.model,
                        tokenizer,
                        args.probe_suite.as_deref(),
                        0,
                        limits,
                    ),
                    None => Err(anyhow!("--runtime embedded requires --tokenizer")),
                },
                other => Err(anyhow!("unsupported behaviour runtime '{other}'")),
            };
            match result {
                Ok(report) => (Some(report), None),
                Err(error) => (None, Some(error.to_string())),
            }
        } else {
            (None, Some("no base model supplied".to_owned()))
        };
    let judge_result = review_judge(&args, &behavior)?;
    let drift = if args.compare_previous {
        let store = layerfault::observations::ObservationStore::load()?;
        store
            .previous_for_snapshot(&snapshot)
            .map(|prior| layerfault::observations::drift(prior, &snapshot))
    } else {
        None
    };
    if args.record_observation {
        let mut store = layerfault::observations::ObservationStore::load()?;
        let _ = store.remember(&snapshot, None, None, None, None)?;
        store.save()?;
    }
    let mut decision = if static_block {
        "BLOCK"
    } else if static_warn {
        "WARN"
    } else {
        "PASS"
    };
    if comparison
        .as_ref()
        .is_some_and(|v| v.lineage == layerfault::transformation::LineageState::Contradicted)
    {
        decision = "BLOCK";
    }
    if lora_merge
        .as_ref()
        .is_some_and(|v| v.state == "CONTRADICTED")
    {
        decision = "BLOCK";
    }
    if behavior.as_ref().is_some_and(|v| {
        matches!(
            v.state,
            layerfault::transformation::BehaviourState::HighRisk
        )
    }) {
        decision = "BLOCK";
    } else if decision == "PASS"
        && behavior.as_ref().is_some_and(|v| {
            matches!(
                v.state,
                layerfault::transformation::BehaviourState::Suspicious
            )
        })
    {
        decision = "WARN";
    }
    if differential.as_ref().is_some_and(|v| {
        matches!(
            v.state,
            layerfault::transformation::DifferentialBehaviourState::SecurityRegression
                | layerfault::transformation::DifferentialBehaviourState::SuspiciousTrigger
                | layerfault::transformation::DifferentialBehaviourState::HighRiskBehaviour
        )
    }) {
        decision = "BLOCK";
    }
    let result = json!({
        "schema_version":"1.0","review_profile":args.profile,"target":snapshot,
        "domains":{"static_admission":static_value,"lineage":comparison,"weight_analysis":weight,"lora":lora,"lora_merge_verification":lora_merge,"quantization_reproducibility":quant,"behavioural_security":{"report":behavior,"not_run_reason":behaviour_not_run_reason},"differential_behaviour":{"report":differential,"not_run_reason":differential_not_run_reason},"judge":judge_result,"drift":drift},
        "final_decision":decision,
        "boundary":"Layerfault reports evidence from the checks performed. Behavioural testing cannot prove that no unknown hidden trigger or backdoor exists."
    });
    if let (Some(out), Some(key)) = (args.evidence_out.as_deref(), args.evidence_key.as_deref()) {
        let policy = layerfault::policy::PolicyDocument::builtin(
            layerfault::policy::PolicyProfile::Workstation,
        )
        .effective();
        let trust = layerfault::trust::TrustStore::load(None)?;
        let subject = result["target"]["identity"]["canonical"]
            .as_str()
            .unwrap_or("local-model");
        let envelope = layerfault::evidence::create_signed(
            layerfault::evidence::EvidenceContext {
                subject,
                source: "local-review",
                subject_fingerprint: Some(subject),
                policy: &policy,
                trust_store: &trust,
                runtime: None,
                binding: None,
                decision,
                details: result.clone(),
            },
            key,
        )?;
        layerfault::evidence::write_signed(out, &envelope)?;
    } else if args.evidence_out.is_some() || args.evidence_key.is_some() {
        bail!("--evidence-out and --evidence-key must be supplied together");
    }
    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("LAYERFAULT MODEL SECURITY REVIEW\n\nSTATIC ADMISSION\n{}\n\nLINEAGE\n{}\n\nBEHAVIOUR\n{}\n\nFINAL\n{}",if static_block{"BLOCK"}else if static_warn{"WARN"}else{"PASS"},result["domains"]["lineage"].get("lineage").and_then(Value::as_str).unwrap_or("UNVERIFIED"),result["domains"]["behavioural_security"]["report"].get("state").and_then(Value::as_str).unwrap_or("NOT_RUN"),decision);
    }
    let code = security_decision_exit_code(decision);
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
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

fn scan_target(path: &Path) -> Result<(Value, bool, bool)> {
    if path.is_dir() {
        let report = layerfault::package::inspect(path)?;
        let warn = report
            .findings
            .iter()
            .any(|v| v.status == layerfault::scanner::ScanStatus::Warn);
        let block = report.blocking();
        Ok((serde_json::to_value(report)?, block, warn))
    } else {
        let report = layerfault::formats::artifact::inspect(
            path,
            layerfault::formats::artifact::ArtifactScanMode::Full,
        )?;
        let warn = report
            .results
            .iter()
            .any(|v| v.status == layerfault::scanner::ScanStatus::Warn);
        let block = report.blocking();
        Ok((serde_json::to_value(report)?, block, warn))
    }
}

fn weight_analysis(base: &Path, derived: &Path) -> Value {
    if base.is_file()
        && derived.is_file()
        && base
            .extension()
            .and_then(|v| v.to_str())
            .is_some_and(|v| v.eq_ignore_ascii_case("safetensors"))
        && derived
            .extension()
            .and_then(|v| v.to_str())
            .is_some_and(|v| v.eq_ignore_ascii_case("safetensors"))
    {
        match layerfault::weights::compare_safetensors(base, derived, 100_000) {
            Ok(v) => json!({"state":"AVAILABLE","tensor_deltas":v}),
            Err(e) => json!({"state":"UNAVAILABLE","reason":e.to_string()}),
        }
    } else {
        json!({"state":"UNAVAILABLE","reason":"numeric differential currently requires compatible standalone Safetensors; structural tensor comparison remains available in lineage output"})
    }
}
fn single_weight_analysis(path: &Path) -> Value {
    if path.is_file()
        && path
            .extension()
            .and_then(|v| v.to_str())
            .is_some_and(|v| v.eq_ignore_ascii_case("safetensors"))
    {
        match layerfault::weights::safetensors_statistics(path, 100_000) {
            Ok(v) => json!({"state":"AVAILABLE","tensors":v}),
            Err(e) => json!({"state":"UNAVAILABLE","reason":e.to_string()}),
        }
    } else {
        json!({"state":"UNAVAILABLE","reason":"numeric statistics are not interpreted from compressed/quantized bytes without a correct dtype decoder"})
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
        println!("\n{}", report.boundary);
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
