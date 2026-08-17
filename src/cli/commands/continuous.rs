use super::super::{ContinuousArgs, ContinuousCommand};
use anyhow::{bail, Result};
use layerfault::continuous::{ObservationInputs, TrustState};
use layerfault::json_stream::write_stdout_json;
use std::path::PathBuf;
use std::time::Duration;

pub(crate) fn run_continuous(args: ContinuousArgs) -> Result<()> {
    match args.command {
        ContinuousCommand::Snapshot {
            output,
            state,
            model_artifact,
            composition_manifest,
            agent_config,
            agent_name,
            runtime_binary,
            runtime_config,
            policy_file,
            intelligence_pack,
            provenance_chain,
            passport,
            receipt,
            behavioural_report,
            behaviour_affecting_environment,
            platform_environment,
            json,
        } => {
            let inputs = observation_inputs(
                parse_state(&state)?,
                model_artifact,
                composition_manifest,
                agent_config,
                agent_name,
                runtime_binary,
                runtime_config,
                policy_file,
                intelligence_pack,
                provenance_chain,
                passport,
                receipt,
                behavioural_report,
                behaviour_affecting_environment,
                platform_environment,
            );
            let snapshot = layerfault::continuous::observe(&inputs)?;
            layerfault::continuous::save_snapshot(&output, &snapshot)?;
            if json {
                write_stdout_json(&snapshot, true)?;
            } else {
                println!("Execution snapshot: {}", output.display());
                println!("State: {:?}", snapshot.state);
                println!(
                    "Identity: {}",
                    layerfault::continuous::snapshot_identity(&snapshot)?
                );
                println!("Bound components: {}", snapshot.identities.len());
                println!("Evidence records: {}", snapshot.evidence.len());
            }
        }
        ContinuousCommand::Diff {
            previous,
            current,
            output,
            journal,
            head_anchor,
            entity,
            json,
        } => {
            let before = layerfault::continuous::load_snapshot(&previous)?;
            let after = layerfault::continuous::load_snapshot(&current)?;
            let evaluation = evaluate_change(&entity, &before, after)?;
            if let Some(path) = output.as_deref() {
                layerfault::continuous::save_snapshot(path, &evaluation.snapshot)?;
            }
            if let (Some(path), Some(event)) = (journal.as_deref(), evaluation.event.as_ref()) {
                layerfault::continuous::append_event(path, event)?;
                if let Some(anchor_path) = head_anchor.as_deref() {
                    let records = layerfault::continuous::load_events(path)?;
                    layerfault::continuous::write_head_anchor(anchor_path, &records)?;
                }
            }
            if json {
                write_stdout_json(&evaluation, true)?;
            } else {
                print_evaluation(&evaluation);
                if let Some(path) = output.as_deref() {
                    println!("Updated snapshot: {}", path.display());
                }
            }
        }
        ContinuousCommand::Watch {
            state_path,
            journal,
            head_anchor,
            entity,
            state,
            interval,
            model_artifact,
            composition_manifest,
            agent_config,
            agent_name,
            runtime_binary,
            runtime_config,
            policy_file,
            intelligence_pack,
            provenance_chain,
            passport,
            receipt,
            behavioural_report,
            behaviour_affecting_environment,
            platform_environment,
            jsonl,
        } => {
            if interval < 30 {
                bail!("continuous watch interval must be at least 30 seconds");
            }
            let initial_state = parse_state(&state)?;
            let mut inputs = observation_inputs(
                initial_state,
                model_artifact,
                composition_manifest,
                agent_config,
                agent_name,
                runtime_binary,
                runtime_config,
                policy_file,
                intelligence_pack,
                provenance_chain,
                passport,
                receipt,
                behavioural_report,
                behaviour_affecting_environment,
                platform_environment,
            );
            let mut previous = if state_path.exists() {
                layerfault::continuous::load_snapshot(&state_path)?
            } else {
                let snapshot = layerfault::continuous::observe(&inputs)?;
                layerfault::continuous::save_snapshot(&state_path, &snapshot)?;
                snapshot
            };
            if !jsonl {
                println!("Watching security-relevant execution state for {entity}");
                println!("State: {}", state_path.display());
                println!("Journal: {}", journal.display());
            }
            loop {
                std::thread::sleep(Duration::from_secs(interval));
                inputs.state = previous.state;
                let current = layerfault::continuous::observe(&inputs)?;
                let evaluation = evaluate_change(&entity, &previous, current)?;
                if evaluation.plan.changed_components.is_empty() {
                    previous = evaluation.snapshot;
                    continue;
                }
                layerfault::continuous::save_snapshot(&state_path, &evaluation.snapshot)?;
                if let Some(event) = evaluation.event.as_ref() {
                    layerfault::continuous::append_event(&journal, event)?;
                    if let Some(anchor_path) = head_anchor.as_deref() {
                        let records = layerfault::continuous::load_events(&journal)?;
                        layerfault::continuous::write_head_anchor(anchor_path, &records)?;
                    }
                }
                if jsonl {
                    println!("{}", serde_json::to_string(&evaluation)?);
                } else {
                    print_evaluation(&evaluation);
                }
                previous = evaluation.snapshot;
            }
        }
        ContinuousCommand::Journal {
            journal,
            verify,
            head_anchor,
            json,
        } => {
            let records = layerfault::continuous::load_events(&journal)?;
            if verify {
                let head = match head_anchor.as_deref() {
                    Some(path) => layerfault::continuous::load_head_anchor(path)?,
                    None => None,
                };
                let result = layerfault::continuous::verify_chain(&records, head.as_ref())?;
                if json {
                    write_stdout_json(&result, true)?;
                } else {
                    print_chain_verification(&result);
                }
                if !matches!(result, layerfault::continuous::ChainVerification::Intact) {
                    std::process::exit(1);
                }
            } else if json {
                write_stdout_json(&records, true)?;
            } else if records.is_empty() {
                println!("Trust journal is empty.");
            } else {
                for record in records {
                    println!(
                        "{}\t{}\t{}\t{:?}->{:?}\t{}",
                        record.sequence,
                        record.event.timestamp_unix,
                        record.event.entity,
                        record.event.previous_state,
                        record.event.new_state,
                        record.event.cause
                    );
                }
            }
        }
    }
    Ok(())
}

#[derive(serde::Serialize)]
struct ChangeEvaluation {
    plan: layerfault::continuous::InvalidationPlan,
    state: TrustState,
    action: layerfault::continuous::ReassessmentAction,
    findings: Vec<layerfault::scanner::LayerScanResult>,
    event: Option<layerfault::continuous::TrustEvent>,
    snapshot: layerfault::continuous::ExecutionSnapshot,
}

fn print_chain_verification(result: &layerfault::continuous::ChainVerification) {
    use layerfault::continuous::ChainVerification;
    match result {
        ChainVerification::Intact => println!("Journal chain: intact"),
        ChainVerification::Broken {
            at_sequence,
            reason,
        } => {
            println!("Journal chain: BROKEN at sequence {at_sequence}: {reason}");
        }
        ChainVerification::TruncationSuspected {
            anchored_sequence,
            tail_sequence,
        } => {
            println!(
                "Journal chain: TRUNCATION SUSPECTED — anchor expects tail sequence {anchored_sequence}, journal ends at {}",
                tail_sequence
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none (empty journal)".to_owned())
            );
        }
    }
}

fn evaluate_change(
    entity: &str,
    before: &layerfault::continuous::ExecutionSnapshot,
    mut after: layerfault::continuous::ExecutionSnapshot,
) -> Result<ChangeEvaluation> {
    let plan = layerfault::continuous::invalidation_plan(before, &after);
    let reason = if plan.changed_components.is_empty() {
        "no security-relevant execution components changed".to_owned()
    } else {
        format!(
            "security-relevant execution components changed: {}",
            plan.changed_components
                .iter()
                .map(|component| format!("{component:?}"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    layerfault::continuous::apply_invalidation(&mut after, &plan, &reason);
    let new_state = layerfault::continuous::state_after_invalidation(before.state, &plan);
    let action = layerfault::continuous::reassessment_action(&plan);
    let findings = layerfault::continuous::drift_findings(entity, &plan, before.state);
    let event = if new_state != before.state || !plan.changed_components.is_empty() {
        let mut event = layerfault::continuous::transition(
            entity,
            before.state,
            new_state,
            &reason,
            Some(&plan),
        )?;
        event.finding_ids = findings
            .iter()
            .filter_map(|finding| finding.finding_id.clone())
            .collect();
        event.rule_ids = findings
            .iter()
            .filter_map(|finding| finding.rule_id.clone())
            .collect();
        Some(event)
    } else {
        None
    };
    after.state = new_state;
    Ok(ChangeEvaluation {
        plan,
        state: new_state,
        action,
        findings,
        event,
        snapshot: after,
    })
}

fn print_evaluation(evaluation: &ChangeEvaluation) {
    println!(
        "Changed components: {}",
        evaluation.plan.changed_components.len()
    );
    println!(
        "Invalidated evidence: {}",
        evaluation.plan.invalidated_domains.len()
    );
    println!("Trust state: {:?}", evaluation.state);
    println!("Reassessment action: {:?}", evaluation.action);
    for component in &evaluation.plan.changed_components {
        println!("- changed: {component:?}");
    }
    for domain in &evaluation.plan.invalidated_domains {
        println!("- stale: {domain:?}");
    }
}

#[allow(clippy::too_many_arguments)]
fn observation_inputs(
    state: TrustState,
    model_artifact: Option<PathBuf>,
    composition_manifest: Option<PathBuf>,
    agent_config: Option<PathBuf>,
    agent_name: String,
    runtime_binary: Option<PathBuf>,
    runtime_config: Option<PathBuf>,
    policy_file: Option<PathBuf>,
    intelligence_pack: Option<PathBuf>,
    provenance_chain: Option<PathBuf>,
    passport: Option<PathBuf>,
    receipt: Option<PathBuf>,
    behavioural_report: Option<PathBuf>,
    behaviour_affecting_environment: Option<PathBuf>,
    platform_environment: Option<PathBuf>,
) -> ObservationInputs {
    ObservationInputs {
        state,
        model_artifact,
        composition_manifest,
        agent_config,
        agent_name,
        runtime_binary,
        runtime_config,
        policy_file,
        intelligence_pack,
        provenance_chain,
        passport,
        receipt,
        behavioural_report,
        behaviour_affecting_environment,
        platform_environment,
    }
}

fn parse_state(value: &str) -> Result<TrustState> {
    match value.to_ascii_lowercase().replace(['_', '-'], "").as_str() {
        "unknown" => Ok(TrustState::Unknown),
        "scanning" => Ok(TrustState::Scanning),
        "approved" => Ok(TrustState::Approved),
        "conditionallyapproved" | "conditional" => Ok(TrustState::ConditionallyApproved),
        "reviewrequired" | "review" => Ok(TrustState::ReviewRequired),
        "blocked" => Ok(TrustState::Blocked),
        "quarantined" => Ok(TrustState::Quarantined),
        "expired" => Ok(TrustState::Expired),
        other => bail!("unsupported trust state '{other}'"),
    }
}
