use super::super::{CompositionArgs, CompositionCommand};
use anyhow::Result;
use layerfault::finding_evidence::EvidenceSubject;
use layerfault::json_stream::write_stdout_json;

pub(crate) fn run_composition(args: CompositionArgs) -> Result<()> {
    match args.command {
        CompositionCommand::Inspect { manifest, json } => {
            let composition = layerfault::model::composition::resolve_manifest(&manifest)?;
            let mut assessment = layerfault::model::composition::assess(composition)?;
            let subject = EvidenceSubject::identity(
                &assessment.identity.value,
                "application/vnd.layerfault.model-composition+json",
            );
            for adapter in &assessment.composition.adapters {
                let Some(source) = adapter.source.as_deref() else {
                    continue;
                };
                let path = std::path::Path::new(source);
                if !path.exists() || !path.is_dir() {
                    continue;
                }
                let inspected = layerfault::model::composition::inspect_adapter(
                    path,
                    adapter.declared_base.as_deref(),
                )?;
                assessment
                    .findings
                    .extend(layerfault::model::composition::adapter_findings(
                        &inspected, &subject,
                    ));
            }
            if json {
                write_stdout_json(&assessment, true)?;
            } else {
                println!("Composition: {}", assessment.identity.value);
                println!("Components: {}", assessment.identity.component_count);
                println!("Adapters: {}", assessment.composition.adapters.len());
                println!("Completeness: {:?}", assessment.identity.completeness);
                for finding in &assessment.findings {
                    println!(
                        "{}\t{:?}\t{}",
                        finding.rule_id.as_deref().unwrap_or("UNREGISTERED"),
                        finding.status,
                        finding.detail.as_deref().unwrap_or("")
                    );
                }
                for limitation in &assessment.composition.limitations {
                    println!("Limitation: {limitation}");
                }
            }
        }
        CompositionCommand::Adapter {
            adapter,
            expected_base,
            json,
        } => {
            let assessment = layerfault::model::composition::inspect_adapter(
                &adapter,
                expected_base.as_deref(),
            )?;
            if json {
                write_stdout_json(&assessment, true)?;
            } else {
                println!("Adapter: {}", assessment.component.name);
                println!("Identity: {}", assessment.component.identity);
                println!("Base relationship: {:?}", assessment.base_relation);
                println!("Declared targets: {}", assessment.target_modules.len());
                println!("Observed targets: {}", assessment.observed_modules.len());
                if !assessment.unexpected_modules.is_empty() {
                    println!("Unexpected targets:");
                    for module in &assessment.unexpected_modules {
                        println!("- {module}");
                    }
                }
            }
        }
        CompositionCommand::VerifyMerge {
            base,
            adapter,
            merged,
            json,
        } => {
            let assessment =
                layerfault::model::composition::verify_lora_merge(&base, &adapter, &merged)?;
            if json {
                write_stdout_json(&assessment, true)?;
            } else {
                println!("Merge verification: {:?}", assessment.state);
                println!("Verified tensors: {}", assessment.verified_tensors);
                println!("Unsupported tensors: {}", assessment.unsupported_tensors);
                println!(
                    "Changed non-target tensors: {}",
                    assessment.changed_non_target_tensors
                );
                println!("{}", assessment.detail);
            }
        }
        CompositionCommand::Init { output } => {
            layerfault::model::composition::write_example(&output)?;
            println!("{}", output.display());
        }
    }
    Ok(())
}
