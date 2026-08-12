use super::super::{CompareArgs, LineageArgs, LineageCommand};
use anyhow::{anyhow, Result};
use layerfault::json_stream::write_stdout_json;
use serde_json::{json, Value};
use std::path::Path;

use layerfault::decision::SecurityDecision;
pub(super) fn claim(
    value: Option<&str>,
) -> Result<Option<layerfault::transformation::TransformationType>> {
    value
        .map(layerfault::transformation::TransformationType::parse)
        .transpose()
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
                write_stdout_json(&report, true)?;
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
    #[derive(serde::Serialize)]
    struct CompareReport<'a> {
        schema_version: &'static str,
        comparison: &'a layerfault::lineage::ComparisonReport,
        // `weight_analysis` genuinely varies in underlying report shape at
        // runtime (numeric differential vs. unavailable/failed reasons), so
        // it stays a `Value` here rather than forcing a single static type.
        weight_analysis: Value,
        lora: Option<layerfault::lora::LoraReport>,
        lora_merge_verification: Option<layerfault::lora::LoraMergeVerification>,
        quantization_reproducibility: Option<layerfault::quantization::QuantizationReproduction>,
        final_decision: SecurityDecision,
    }
    let result = CompareReport {
        schema_version: "1.0",
        comparison: &comparison,
        weight_analysis,
        lora: lora_analysis,
        lora_merge_verification: lora_merge,
        quantization_reproducibility: quantization,
        final_decision,
    };
    if args.json {
        write_stdout_json(&result, true)?;
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

pub(super) fn weight_analysis(
    base: &Path,
    derived: &Path,
    profile: &str,
    seed_material: &str,
) -> Value {
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

pub(super) fn single_weight_analysis(path: &Path, profile: &str, seed_material: &str) -> Value {
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
