use super::super::{
    IntelligenceArgs, IntelligenceCommand, InventoryArgs, InventoryCommand, RuntimeArgs,
    RuntimeCommand,
};
use anyhow::{anyhow, bail, Context, Result};
use layerfault::json_stream::write_stdout_json;
use layerfault::runtime_security::{ModelSecurityContext, RuntimeKind};
use std::path::Path;
use std::time::Duration;

pub(crate) fn run_intelligence(args: IntelligenceArgs) -> Result<()> {
    match args.command {
        IntelligenceCommand::Show { pack, json } => {
            let pack = match pack {
                Some(path) => layerfault::intelligence::load_pack(&path)?.0,
                None => layerfault::intelligence::builtin_pack()?,
            };
            if json {
                write_stdout_json(&pack, true)?;
            } else {
                let freshness =
                    layerfault::intelligence::freshness(&pack, layerfault::paths::now_unix());
                println!(
                    "Intelligence pack v{} sequence={} generated={} freshness={:?}",
                    pack.version, pack.sequence, pack.generated_unix, freshness
                );
                println!(
                    "{} runtime advisories, {} pickle gadgets, {} declarative edges, {} known identities, {} framework mappings",
                    pack.runtime_advisories.len(),
                    pack.pickle_gadgets.len(),
                    pack.declarative_edges.len(),
                    pack.known_identities.len(),
                    pack.threat_mappings.len()
                );
            }
        }
        IntelligenceCommand::Verify {
            pack,
            signature,
            public_key,
            allow_rollback,
            json,
        } => {
            let verified = layerfault::intelligence::load_verified(&pack, &signature, &public_key)?;
            layerfault::intelligence::enforce_no_rollback(&verified, allow_rollback)?;
            layerfault::intelligence::record_accepted(&verified)?;
            if json {
                write_stdout_json(&verified, true)?;
            } else {
                println!("Verified intelligence pack: {}", verified.sha256);
                println!("Signer: {}", verified.signer_sha256);
                println!("Sequence: {}", verified.pack.sequence);
            }
        }
        IntelligenceCommand::Export {
            pack,
            signature,
            public_key,
            output,
        } => {
            layerfault::intelligence::export_bundle(&pack, &signature, &public_key, &output)?;
            println!("{}", output.display());
        }
        IntelligenceCommand::Import {
            bundle,
            pack_output,
            signature_output,
            public_key_output,
            allow_rollback,
        } => {
            let verified = layerfault::intelligence::verify_bundle(&bundle)?;
            layerfault::intelligence::enforce_no_rollback(&verified, allow_rollback)?;
            let imported = layerfault::intelligence::import_bundle(
                &bundle,
                &pack_output,
                &signature_output,
                &public_key_output,
            )?;
            layerfault::intelligence::record_accepted(&imported)?;
            println!("Imported intelligence pack: {}", imported.sha256);
            println!("Pack: {}", pack_output.display());
            println!("Signature: {}", signature_output.display());
            println!("Public key: {}", public_key_output.display());
        }
        IntelligenceCommand::VerifyBundle { bundle, json } => {
            let verified = layerfault::intelligence::verify_bundle(&bundle)?;
            if json {
                write_stdout_json(&verified, true)?;
            } else {
                println!("Verified offline intelligence bundle: {}", verified.sha256);
                println!("Signer: {}", verified.signer_sha256);
                println!("Epoch: {}", layerfault::intelligence::epoch(&verified.pack));
            }
        }
    }
    Ok(())
}

pub(crate) fn run_runtime(args: RuntimeArgs) -> Result<()> {
    match args.command {
        RuntimeCommand::List { runtime, json } => {
            let kind = runtime.as_deref().map(RuntimeKind::parse).transpose()?;
            let mut rows = layerfault::runtime_security::discover_installed();
            if let Some(kind) = kind {
                rows.retain(|r| r.runtime == kind);
            }
            if json {
                write_stdout_json(&rows, true)?;
            } else if rows.is_empty() {
                println!("No matching local AI runtime installation was discovered.");
            } else {
                for row in rows {
                    println!(
                        "{}\t{}\t{}",
                        row.runtime.as_str(),
                        row.parsed_version.as_deref().unwrap_or("unknown"),
                        row.executable.as_deref().unwrap_or("<package-only>")
                    );
                }
            }
        }
        RuntimeCommand::Audit { runtime, json } => {
            let rows = match runtime.as_deref() {
                Some(value) => layerfault::runtime_security::audit_kind(RuntimeKind::parse(value)?),
                None => layerfault::runtime_security::audit_all(),
            };
            if json {
                write_stdout_json(&rows, true)?;
            } else if rows.is_empty() {
                println!("No matching local AI runtime was discovered.");
            } else {
                for row in rows {
                    println!(
                        "{}\tversion={}\texposure={:?}\tauth={:?}\ttls={:?}\tfindings={}",
                        row.installation.runtime.as_str(),
                        row.installation
                            .parsed_version
                            .as_deref()
                            .unwrap_or("unknown"),
                        row.configuration.network_exposure,
                        row.configuration.authentication,
                        row.configuration.tls,
                        row.findings.len()
                    );
                }
            }
        }
        RuntimeCommand::Assess {
            runtime,
            model,
            intelligence_pack,
            intelligence_signature,
            intelligence_public_key,
            json,
        } => {
            let kind = RuntimeKind::parse(&runtime)?;
            let pack = load_cli_intelligence(
                intelligence_pack.as_deref(),
                intelligence_signature.as_deref(),
                intelligence_public_key.as_deref(),
            )?;
            let context = context_for_model(&model)?;
            let runtimes = layerfault::runtime_security::audit_kind(kind);
            if runtimes.is_empty() {
                bail!(
                    "runtime '{}' was not discovered on this host",
                    kind.as_str()
                );
            }
            #[derive(serde::Serialize)]
            struct Assessment {
                runtime: layerfault::runtime_security::RuntimePosture,
                exploitability: Vec<layerfault::runtime_security::AdvisoryApplicability>,
                compatibility: layerfault::runtime_security::ModelRuntimeCompatibility,
            }
            let rows = runtimes
                .into_iter()
                .map(|posture| {
                    let exploitability =
                        layerfault::runtime_security::assess_from_pack(&posture, &context, &pack);
                    let compatibility = layerfault::runtime_security::assess_compatibility(
                        &posture,
                        &context,
                        &exploitability,
                    );
                    Assessment {
                        runtime: posture,
                        exploitability,
                        compatibility,
                    }
                })
                .collect::<Vec<_>>();
            if json {
                write_stdout_json(&rows, true)?;
            } else {
                for row in rows {
                    println!(
                        "{}\t{:?}\t{} contextual advisory assessment(s)",
                        row.runtime.installation.runtime.as_str(),
                        row.compatibility.state,
                        row.exploitability.len()
                    );
                }
            }
        }
        RuntimeCommand::Matrix {
            model,
            runtimes,
            json,
        } => {
            let context = context_for_model(&model)?;
            let pack = layerfault::intelligence::builtin_pack()?;
            let selected = if runtimes.is_empty() {
                layerfault::runtime_security::audit_all()
            } else {
                let kinds = runtimes
                    .iter()
                    .map(|v| RuntimeKind::parse(v))
                    .collect::<Result<Vec<_>>>()?;
                let mut out = Vec::new();
                for kind in kinds {
                    out.extend(layerfault::runtime_security::audit_kind(kind));
                }
                out
            };
            let rows = layerfault::runtime_security::matrix(&selected, &context, &pack);
            if json {
                write_stdout_json(&rows, true)?;
            } else if rows.is_empty() {
                println!("No matching local AI runtime was discovered.");
            } else {
                for row in rows {
                    println!(
                        "{}\t{:?}\t{} condition(s)",
                        row.runtime.runtime.as_str(),
                        row.state,
                        row.conditions.len()
                    );
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn run_inventory(args: InventoryArgs) -> Result<()> {
    match args.command {
        InventoryCommand::Snapshot {
            state,
            runtime_aware,
            directories,
            json,
        } => {
            let options = inventory_options(directories);
            let snapshot = layerfault::inventory::snapshot(&options)?;
            let state_path = state.unwrap_or(layerfault::inventory::default_state_path()?);
            layerfault::inventory::save_state(&state_path, &snapshot)?;
            if runtime_aware {
                let _ = layerfault::runtime_security::audit_all();
            }
            if json {
                write_stdout_json(&snapshot, true)?;
            } else {
                println!(
                    "Inventory snapshot: {} entries -> {}",
                    snapshot.entries.len(),
                    state_path.display()
                );
            }
        }
        InventoryCommand::Diff {
            previous,
            current,
            scan,
            json,
        } => {
            let before = layerfault::inventory::load_state(&previous)?;
            let after = if let Some(path) = current {
                layerfault::inventory::load_state(&path)?
            } else if scan {
                layerfault::inventory::snapshot(&layerfault::inventory::InventoryOptions::default())?
            } else {
                bail!("inventory diff requires --current PATH or --scan");
            };
            let delta = layerfault::inventory::diff_states(&before, &after);
            if json {
                write_stdout_json(&delta, true)?;
            } else {
                println!(
                    "Inventory delta: +{} -{} ~{} approval_changes={}",
                    delta.added.len(),
                    delta.removed.len(),
                    delta.modified.len(),
                    delta.approval_changes.len()
                );
            }
        }
        InventoryCommand::Approve {
            state,
            identity,
            receipt,
            trust_store,
        } => {
            let mut inventory = layerfault::inventory::load_state(&state)?;
            let entry = inventory
                .entries
                .iter_mut()
                .find(|e| {
                    e.key == identity
                        || e.identity == identity
                        || e.byte_sha256.as_deref() == Some(identity.as_str())
                })
                .ok_or_else(|| anyhow!("inventory identity '{}' was not found", identity))?;
            let trust = layerfault::trust::TrustStore::load(trust_store.as_deref())?;
            layerfault::inventory::apply_receipt(entry, &receipt, &trust)?;
            inventory.updated_unix = layerfault::paths::now_unix();
            layerfault::inventory::save_state(&state, &inventory)?;
            println!("Approved {} using {}", identity, receipt.display());
        }
        InventoryCommand::Watch {
            state,
            interval,
            runtime_aware,
            verbose,
            directories,
            jsonl,
        } => {
            let options = inventory_options(directories);
            let state_path = state.unwrap_or(layerfault::inventory::default_state_path()?);
            if interval < 30 {
                bail!("inventory watch interval must be at least 30 seconds");
            }
            if runtime_aware {
                let _ = layerfault::runtime_security::audit_all();
            }
            let initial = layerfault::inventory::snapshot(&options)?;
            layerfault::inventory::save_state(&state_path, &initial)?;
            if verbose {
                eprintln!(
                    "Watching {} inventory entries; state={}",
                    initial.entries.len(),
                    state_path.display()
                );
            }
            layerfault::inventory::watch(
                &options,
                Duration::from_secs(interval),
                |current, delta| {
                    layerfault::inventory::save_state(&state_path, current)?;
                    if jsonl {
                        println!("{}", serde_json::to_string(delta)?);
                    } else if verbose
                        || !delta.added.is_empty()
                        || !delta.removed.is_empty()
                        || !delta.modified.is_empty()
                        || !delta.approval_changes.is_empty()
                    {
                        println!(
                            "Inventory delta: +{} -{} ~{} approval_changes={}",
                            delta.added.len(),
                            delta.removed.len(),
                            delta.modified.len(),
                            delta.approval_changes.len()
                        );
                    }
                    Ok(true)
                },
            )?;
        }
    }
    Ok(())
}

fn inventory_options(
    directories: Vec<std::path::PathBuf>,
) -> layerfault::inventory::InventoryOptions {
    layerfault::inventory::InventoryOptions {
        directories,
        ..Default::default()
    }
}

pub(super) fn load_cli_intelligence(
    pack: Option<&Path>,
    signature: Option<&Path>,
    public_key: Option<&Path>,
) -> Result<layerfault::intelligence::IntelligencePack> {
    match pack {
        None => {
            if signature.is_some() || public_key.is_some() {
                bail!("intelligence signature/public key require --intelligence-pack");
            }
            layerfault::intelligence::builtin_pack()
        }
        Some(path) => {
            let signature = signature.ok_or_else(|| {
                anyhow!("external intelligence pack requires --intelligence-signature")
            })?;
            let public_key = public_key.ok_or_else(|| {
                anyhow!("external intelligence pack requires --intelligence-public-key")
            })?;
            let verified = layerfault::intelligence::load_verified(path, signature, public_key)?;
            layerfault::intelligence::enforce_no_rollback(&verified, false)?;
            Ok(verified.pack)
        }
    }
}

fn context_for_model(path: &Path) -> Result<ModelSecurityContext> {
    let snapshot = layerfault::modelmeta::build_snapshot(path).with_context(|| {
        format!(
            "unable to build model security context for '{}'",
            path.display()
        )
    })?;
    let identity = snapshot
        .identity
        .artifact_sha256
        .clone()
        .unwrap_or_else(|| snapshot.identity.canonical.clone());
    let subject = layerfault::finding_evidence::EvidenceSubject::identity(
        &identity,
        "application/vnd.layerfault.model+json",
    )
    .with_sha256(snapshot.identity.artifact_sha256.clone());
    let mut context = ModelSecurityContext::from_artifact_report(
        subject,
        Some(snapshot.format.clone()),
        snapshot.architecture.architecture.clone(),
        &[],
        layerfault::coverage::Coverage::complete(1, 0),
    );
    context.merge_snapshot(&snapshot);
    Ok(context)
}
