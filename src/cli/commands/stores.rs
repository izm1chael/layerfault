use super::super::*;

pub(crate) fn run_audit(args: AuditArgs) -> Result<()> {
    match args.source.to_ascii_lowercase().as_str() {
        "ollama" => run_ollama_audit(args),
        "hf-cache" | "huggingface" => run_external_audit(args, false, true),
        "lmstudio" | "lm-studio" | "lms" => run_external_audit(args, true, false),
        "all" => run_all_audit(args),
        other => Err(anyhow!(
            "Unknown audit source '{other}'. Use ollama, lmstudio, hf-cache, or all"
        )),
    }
}

pub(crate) fn run_ollama_audit(args: AuditArgs) -> Result<()> {
    let base_dir = app::resolve_base_dir(args.common.ollama_dir.as_deref())?;
    let store_audit = audit::audit_store(&base_dir)?;
    let need_reports = args.deep || args.mlbom.is_some();
    let deep_reports = if need_reports {
        let prepared = prepare(&args.common)?;
        let options = scan_options(&args.common, &prepared, true);
        Some(app::scan_selected(&base_dir, None, &options)?)
    } else {
        None
    };
    if let Some(path) = args.mlbom.as_deref() {
        let entries = inventory::ollama_entries(&base_dir, deep_reports.as_deref().unwrap_or(&[]));
        write_json(path, &inventory::cyclonedx_mlbom(&entries))?;
    }
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "schema_version":"1.0", "store":&store_audit,
                "inventory":deep_reports.as_ref().map(|reports| report::inventory_value(reports))
            }))?
        );
    } else {
        print_store_audit(&store_audit);
        if let Some(reports) = &deep_reports {
            println!("\nDeep security inventory:");
            report::emit_inventory_table(reports);
        }
        if let Some(path) = args.mlbom {
            println!("ML-BOM written to {}", path.display());
        }
    }
    exit_for_store_audit(&store_audit, deep_reports.as_deref());
}

pub(crate) fn run_external_audit(args: AuditArgs, lmstudio: bool, hf: bool) -> Result<()> {
    let artifacts =
        inventory::discover_non_ollama(lmstudio, hf, &args.directories, args.hf_cache.as_deref());
    let entries = inventory::scan_artifacts(&artifacts, !args.deep && args.mlbom.is_none());
    let hf_audits = if hf {
        sources::audit_hf_cache(args.hf_cache.as_deref())?
    } else {
        Vec::new()
    };
    if let Some(path) = args.mlbom.as_deref() {
        write_json(path, &inventory::cyclonedx_mlbom(&entries))?;
    }
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(
                &serde_json::json!({"entries":entries,"hf_cache":hf_audits})
            )?
        );
    } else {
        print_inventory_entries(&entries);
        for repo in &hf_audits {
            let package_blocking = repo
                .package_findings
                .iter()
                .filter(|f| f.status == layerfault::scanner::ScanStatus::Fail)
                .count();
            let package_warnings = repo
                .package_findings
                .iter()
                .filter(|f| f.status == layerfault::scanner::ScanStatus::Warn)
                .count();
            println!("HF {} snapshots={} orphaned_blobs={} invalid_links={} missing_refs={} package_failures={} package_warnings={}", repo.repository, repo.snapshots.len(), repo.orphaned_blobs.len(), repo.invalid_links.len(), repo.missing_ref_snapshots.len(), package_blocking, package_warnings);
        }
    }
    let blocking = entries.iter().any(|entry| entry.blocking)
        || hf_audits.iter().any(|repo| {
            !repo.invalid_links.is_empty()
                || !repo.missing_ref_snapshots.is_empty()
                || repo
                    .package_findings
                    .iter()
                    .any(|f| f.status == layerfault::scanner::ScanStatus::Fail)
        });
    if blocking {
        std::process::exit(3);
    }
    if hf_audits.iter().any(|repo| {
        !repo.orphaned_blobs.is_empty()
            || !repo.detached_snapshots.is_empty()
            || repo
                .package_findings
                .iter()
                .any(|f| f.status == layerfault::scanner::ScanStatus::Warn)
    }) {
        std::process::exit(1);
    }
    Ok(())
}

pub(crate) fn run_all_audit(args: AuditArgs) -> Result<()> {
    let mut entries = Vec::new();
    let mut ollama_store = None;
    let mut ollama_reports = None;
    if let Ok(base_dir) = app::resolve_base_dir(args.common.ollama_dir.as_deref()) {
        if let Ok(store) = audit::audit_store(&base_dir) {
            let prepared = prepare(&args.common)?;
            let options = scan_options(&args.common, &prepared, true);
            let reports = app::scan_selected(&base_dir, None, &options)?;
            entries.extend(inventory::ollama_entries(&base_dir, &reports));
            ollama_store = Some(store);
            ollama_reports = Some(reports);
        }
    }
    let external =
        inventory::discover_non_ollama(true, true, &args.directories, args.hf_cache.as_deref());
    entries.extend(inventory::scan_artifacts(
        &external,
        !args.deep && args.mlbom.is_none(),
    ));
    let hf_audits = sources::audit_hf_cache(args.hf_cache.as_deref()).unwrap_or_default();
    if let Some(path) = args.mlbom.as_deref() {
        write_json(path, &inventory::cyclonedx_mlbom(&entries))?;
    }
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "schema_version":"1.0", "inventory":entries, "ollama_store":ollama_store, "hf_cache":hf_audits
            }))?
        );
    } else {
        print_inventory_entries(&entries);
        if let Some(path) = args.mlbom {
            println!("ML-BOM written to {}", path.display());
        }
    }
    if entries.iter().any(|entry| entry.blocking) {
        std::process::exit(3);
    }
    if hf_audits.iter().any(|repo| {
        !repo.invalid_links.is_empty()
            || !repo.missing_ref_snapshots.is_empty()
            || repo
                .package_findings
                .iter()
                .any(|f| f.status == layerfault::scanner::ScanStatus::Fail)
    }) {
        std::process::exit(3);
    }
    if let Some(store) = &ollama_store {
        if store.invalid_model_count > 0
            || !store.missing_blobs.is_empty()
            || !store.invalid_manifest_paths.is_empty()
        {
            std::process::exit(3);
        }
    }
    if ollama_reports
        .as_deref()
        .is_some_and(|reports| app::policy_exit_code(reports) == 4)
    {
        std::process::exit(4);
    }
    Ok(())
}

pub(crate) fn run_baseline(args: BaselineArgs) -> Result<()> {
    match args.command {
        BaselineCommand::Create {
            name,
            output,
            ollama_dir,
        } => {
            let base_dir = app::resolve_base_dir(ollama_dir.as_deref())?;
            baseline_preflight(&base_dir)?;
            let value = Baseline::capture(&base_dir)?;
            let path = output.unwrap_or(Baseline::default_path(&name)?);
            value.save(&path)?;
            println!(
                "Baseline '{}' captured {} model(s) at {}",
                name,
                value.models.len(),
                path.display()
            );
        }
        BaselineCommand::Verify {
            name,
            baseline: path,
            ollama_dir,
            require_signature,
            trust_store,
            json,
        } => {
            let base_dir = app::resolve_base_dir(ollama_dir.as_deref())?;
            let path = path.unwrap_or(Baseline::default_path(&name)?);
            let saved = Baseline::load(&path)?;
            let preflight = baseline_scan(&base_dir)?;
            let result = saved.verify(&base_dir, &path)?;
            let signature =
                baseline::verify_signature(&path, &TrustStore::load(trust_store.as_deref())?)?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &serde_json::json!({"drift":result,"signature":signature})
                    )?
                );
            } else {
                print_baseline_verification(&result);
                println!("Signature: {}", signature.detail);
            }
            if require_signature && !signature.trusted {
                std::process::exit(3);
            }
            if !result.matches {
                std::process::exit(5);
            }
            let code = app::scanner_exit_code(&preflight);
            if matches!(code, 2 | 3) {
                std::process::exit(code);
            }
        }
        BaselineCommand::Diff {
            name,
            baseline: path,
            ollama_dir,
            json,
        } => {
            let base_dir = app::resolve_base_dir(ollama_dir.as_deref())?;
            let path = path.unwrap_or(Baseline::default_path(&name)?);
            let result = Baseline::load(&path)?.verify(&base_dir, &path)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                print_baseline_verification(&result);
            }
            if !result.matches {
                std::process::exit(5);
            }
        }
        BaselineCommand::Update {
            name,
            baseline: path,
            ollama_dir,
            reason,
            sign_with,
        } => {
            let base_dir = app::resolve_base_dir(ollama_dir.as_deref())?;
            baseline_preflight(&base_dir)?;
            let path = path.unwrap_or(Baseline::default_path(&name)?);
            let previous = Baseline::load(&path)?;
            let next = Baseline::updated(&base_dir, &previous, reason)?;
            next.save(&path)?;
            let old_sig = baseline::signature_path(&path);
            if old_sig.exists() {
                fs::remove_file(&old_sig).with_context(|| {
                    format!(
                        "Unable to remove stale baseline signature '{}'",
                        old_sig.display()
                    )
                })?;
            }
            if let Some(key) = sign_with {
                baseline::sign(&path, &key)?;
            }
            println!("Baseline '{}' updated at {}", name, path.display());
        }
        BaselineCommand::Sign {
            name,
            baseline: path,
            private_key,
        } => {
            let path = path.unwrap_or(Baseline::default_path(&name)?);
            Baseline::load(&path)?;
            let signature = baseline::sign(&path, &private_key)?;
            println!(
                "Signed baseline {} with {}",
                path.display(),
                signature.key_fingerprint
            );
        }
        BaselineCommand::VerifySignature {
            name,
            baseline: path,
            trust_store,
            json,
        } => {
            let path = path.unwrap_or(Baseline::default_path(&name)?);
            let result =
                baseline::verify_signature(&path, &TrustStore::load(trust_store.as_deref())?)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("{}", result.detail);
            }
            if !result.trusted {
                std::process::exit(3);
            }
        }
    }
    Ok(())
}

pub(crate) fn run_quarantine(args: QuarantineArgs) -> Result<()> {
    match args.command {
        QuarantineCommand::Put {
            model,
            ollama_dir,
            reason,
            no_scan,
        } => {
            let base_dir = app::resolve_base_dir(ollama_dir.as_deref())?;
            let mut evidence = quarantine::QuarantineEvidence {
                reason: Some(reason.unwrap_or_else(|| "Operator quarantine request".to_owned())),
                ..Default::default()
            };
            if !no_scan {
                let common = ScanCommon {
                    ollama_dir: Some(base_dir.clone()),
                    ..ScanCommon::default()
                };
                let prepared = prepare(&common)?;
                let options = scan_options(&common, &prepared, true);
                let reports = app::scan_selected(&base_dir, Some(&model), &options)?;
                let first = reports
                    .first()
                    .ok_or_else(|| anyhow!("Model scan returned no report"))?;
                evidence.scanner_exit_code = Some(app::scanner_exit_code(&reports));
                evidence.trust_state = Some(format!("{:?}", first.trust_state));
                evidence.policy_action = Some(format!("{:?}", first.policy.action));
                evidence.finding_ids = first
                    .report
                    .results
                    .iter()
                    .filter(|r| r.status != layerfault::scanner::ScanStatus::Pass)
                    .map(policy::rule_id)
                    .collect();
                evidence.finding_ids.sort();
                evidence.finding_ids.dedup();
            }
            let record = quarantine::quarantine_model_with_evidence(&base_dir, &model, evidence)?;
            println!(
                "Quarantined {} as {} ({} exclusive blobs moved; {} shared blobs retained)",
                record.model,
                record.id,
                record.moved_blob_digests.len(),
                record.shared_blob_digests.len()
            );
        }
        QuarantineCommand::List { ollama_dir, json } => {
            let base_dir = app::resolve_base_dir(ollama_dir.as_deref())?;
            let records = quarantine::list(&base_dir)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&records)?);
            } else if records.is_empty() {
                println!("No quarantined models.");
            } else {
                for record in records {
                    println!(
                        "{}  {}  {}",
                        record.id, record.model, record.manifest_digest
                    );
                }
            }
        }
        QuarantineCommand::Inspect {
            id,
            ollama_dir,
            json,
        } => {
            let base_dir = app::resolve_base_dir(ollama_dir.as_deref())?;
            let record = quarantine::load_record(&base_dir, &id)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&record)?);
            } else {
                println!("{}\nModel: {}\nManifest: {}\nCreated: {}\nExclusive blobs: {}\nShared blobs: {}\nReason: {}",
                record.id, record.model, record.manifest_digest, record.created_unix,
                record.moved_blob_digests.len(), record.shared_blob_digests.len(), record.evidence.reason.as_deref().unwrap_or("-"));
            }
        }
        QuarantineCommand::Export {
            id,
            ollama_dir,
            output,
            include_blobs,
            sign_with,
        } => {
            let base_dir = app::resolve_base_dir(ollama_dir.as_deref())?;
            let exported = quarantine::export_evidence(
                &base_dir,
                &id,
                &output,
                include_blobs,
                sign_with.as_deref(),
            )?;
            println!(
                "Exported quarantine {} to {} ({} files, {} bytes, signed={})",
                exported.quarantine_id,
                exported.output,
                exported.files,
                exported.bytes,
                exported.signed
            );
        }
        QuarantineCommand::Purge {
            id,
            ollama_dir,
            yes,
        } => {
            if !yes {
                return Err(anyhow!("Purging quarantine is destructive; rerun with --yes after exporting evidence if required"));
            }
            let base_dir = app::resolve_base_dir(ollama_dir.as_deref())?;
            let record = quarantine::purge(&base_dir, &id)?;
            println!("Purged quarantine {} ({})", record.id, record.model);
        }
        QuarantineCommand::Restore {
            id,
            ollama_dir,
            force,
        } => {
            let base_dir = app::resolve_base_dir(ollama_dir.as_deref())?;
            let record = quarantine::restore(&base_dir, &id, force)?;
            println!("Restored {} from quarantine {}", record.model, record.id);
        }
    }
    Ok(())
}

pub(crate) fn run_gc(args: GcArgs) -> Result<()> {
    if matches!(args.target, GcTarget::Blobs | GcTarget::All) {
        run_blob_gc(&args)?;
    }
    if matches!(args.target, GcTarget::ContentCache | GcTarget::All) {
        run_content_cache_gc(&args)?;
    }
    if matches!(args.target, GcTarget::ObjectCache | GcTarget::All) {
        run_object_cache_gc(&args)?;
    }
    Ok(())
}

fn run_blob_gc(args: &GcArgs) -> Result<()> {
    let base_dir = app::resolve_base_dir(args.ollama_dir.as_deref())?;
    let plan = gc::plan(&base_dir)?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&plan)?);
    } else {
        println!("GC candidates: {}", plan.candidates.len());
        println!("Recoverable bytes: {}", plan.recoverable_bytes);
        println!(
            "Protected baseline orphans: {}",
            plan.protected_orphans.len()
        );
        for entry in &plan.candidates {
            println!("ORPHAN {}  {} bytes", entry.digest, entry.bytes);
        }
    }
    if args.execute {
        let deleted = gc::execute(&base_dir, &plan)?;
        println!("Deleted {deleted} bytes of demonstrably unreferenced Ollama blobs");
    }
    Ok(())
}

fn run_content_cache_gc(args: &GcArgs) -> Result<()> {
    let plan = content_cache::gc::plan()?;
    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "total_entries": plan.total_entries,
                "total_bytes": plan.total_bytes,
                "evict_candidates": plan.evict.len(),
                "bytes_reclaimable": plan.bytes_reclaimed,
            })
        );
    } else {
        println!("Content cache entries: {}", plan.total_entries);
        println!("Content cache bytes: {}", plan.total_bytes);
        println!(
            "Eviction candidates: {} ({} bytes reclaimable)",
            plan.evict.len(),
            plan.bytes_reclaimed
        );
    }
    if args.execute {
        let removed = content_cache::gc::execute(&plan)?;
        println!("Removed {removed} content-cache records");
    }
    Ok(())
}

fn run_object_cache_gc(args: &GcArgs) -> Result<()> {
    let plan = layerfault::object_cache::gc::plan()?;
    if args.json {
        println!(
            "{}",
            serde_json::json!({
                "total_entries": plan.total_entries,
                "total_bytes": plan.total_bytes,
                "free_disk_bytes": plan.free_disk_bytes,
                "evict_candidates": plan.candidates.len(),
                "bytes_reclaimable": plan.bytes_to_reclaim,
                "stale_part_files": plan.stale_part_files.len(),
            })
        );
    } else {
        println!("Object cache entries: {}", plan.total_entries);
        println!("Object cache bytes: {}", plan.total_bytes);
        println!(
            "Eviction candidates: {} ({} bytes reclaimable)",
            plan.candidates.len(),
            plan.bytes_to_reclaim
        );
        if !plan.stale_part_files.is_empty() {
            println!(
                "Stale .layerfault-part files: {}",
                plan.stale_part_files.len()
            );
        }
    }
    if args.execute {
        let removed = layerfault::object_cache::gc::execute(&plan)?;
        println!("Removed {removed} bytes of object-cache records");
    }
    Ok(())
}

pub(crate) fn baseline_preflight(base_dir: &Path) -> Result<()> {
    let reports = baseline_scan(base_dir)?;
    let code = app::scanner_exit_code(&reports);
    if matches!(code, 2 | 3) {
        return Err(anyhow!(
            "Refusing to capture a known-good baseline while blocking scanner findings exist"
        ));
    }
    Ok(())
}

pub(crate) fn baseline_scan(base_dir: &Path) -> Result<Vec<app::EvaluatedReport>> {
    let common = ScanCommon {
        ollama_dir: Some(base_dir.to_path_buf()),
        ..ScanCommon::default()
    };
    let prepared = prepare(&common)?;
    let options = scan_options(&common, &prepared, true);
    app::scan_selected(base_dir, None, &options)
}

pub(crate) fn print_baseline_verification(result: &baseline::BaselineVerification) {
    if result.matches {
        println!(
            "Baseline matches: {} unchanged model(s)",
            result.unchanged_models
        );
    } else {
        println!("Baseline drift detected.");
        for model in &result.added_models {
            println!("  ADDED {model}");
        }
        for model in &result.removed_models {
            println!("  REMOVED {model}");
        }
        for model in &result.changed_models {
            println!(
                "  CHANGED {} {} -> {}",
                model.model, model.previous_manifest_digest, model.current_manifest_digest
            );
            for digest in &model.added_descriptors {
                println!("    + layer {digest}");
            }
            for digest in &model.removed_descriptors {
                println!("    - layer {digest}");
            }
            for signer in &model.added_attestation_fingerprints {
                println!("    + signer {signer}");
            }
            for signer in &model.removed_attestation_fingerprints {
                println!("    - signer {signer}");
            }
        }
    }
}
