use anyhow::Result;
use layerfault::admission::ArtifactAdmission;
use layerfault::app;
use layerfault::formats::artifact;
use layerfault::sources::SourceKind;
use layerfault::{audit, explain, inventory, json_stream, package, policy, provenance, report};
use std::collections::BTreeMap;
use std::path::Path;

pub(crate) fn emit_admission(result: &ArtifactAdmission, json: bool) -> Result<()> {
    if json {
        json_stream::write_stdout_json(&admission_json(result), true)?;
    } else {
        print_artifact_report(&result.report);
        println!(
            "Trust: {:?} ({} trusted signature(s))",
            result.trust_state, result.trusted_signatures
        );
        println!("Policy: {:?}", result.policy.action);
        for reason in &result.policy.reasons {
            println!("  {reason}");
        }
    }
    Ok(())
}

pub(crate) fn print_artifact_report(result: &artifact::ArtifactReport) {
    println!(
        "{}  format={}  bytes={}  sha256={}",
        result.path,
        result.format.as_str(),
        result.size,
        result.sha256.as_deref().unwrap_or("not-computed")
    );
    if let Some(identity) = &result.compound_identity {
        println!("  compound_identity={identity}");
    }
    print_actionable_findings(&result.results);
}

fn is_empty_slice<T>(items: &&[T]) -> bool {
    items.is_empty()
}

/// Typed mirror of [`artifact::ArtifactReport`] with `results` replaced by a
/// streamed, enriched projection instead of a `serde_json::Value` array
/// built by re-serializing the whole report and then overwriting one field.
#[derive(serde::Serialize)]
pub(crate) struct ArtifactJsonReport<'a, S: serde::Serialize> {
    path: &'a str,
    name: &'a str,
    format: &'a layerfault::formats::ArtifactFormat,
    size: u64,
    sha256: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    compound_identity: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cache: Option<&'a artifact::ArtifactCacheInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metrics: Option<&'a layerfault::scanner::ScanMetrics>,
    results: S,
    #[serde(skip_serializing_if = "is_empty_slice")]
    budget: &'a [layerfault::budget::BudgetUsage],
}

pub(crate) fn artifact_json_report(
    result: &artifact::ArtifactReport,
) -> ArtifactJsonReport<'_, impl serde::Serialize + '_> {
    ArtifactJsonReport {
        path: &result.path,
        name: &result.name,
        format: &result.format,
        size: result.size,
        sha256: result.sha256.as_deref(),
        compound_identity: result.compound_identity.as_deref(),
        cache: result.cache.as_ref(),
        metrics: result.metrics.as_ref(),
        results: json_stream::stream_seq(&result.results, report::enriched_finding_ref),
        budget: &result.budget,
    }
}

/// Typed mirror of [`package::PackageReport`] with `findings` streamed the
/// same way.
#[derive(serde::Serialize)]
pub(crate) struct PackageJsonReport<'a, S: serde::Serialize> {
    root: &'a str,
    fingerprint: &'a str,
    merkle_identity: &'a str,
    files: &'a [package::PackageEntry],
    #[serde(skip_serializing_if = "is_empty_slice")]
    merkle_manifest: &'a [package::PackageMerkleLeaf],
    total_bytes: u64,
    findings: S,
    #[serde(skip_serializing_if = "is_empty_slice")]
    correlations: &'a [layerfault::finding_evidence::FindingCorrelation],
    coverage: &'a layerfault::coverage::Coverage,
    #[serde(skip_serializing_if = "Option::is_none")]
    metrics: Option<&'a layerfault::scanner::ScanMetrics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    incremental_diagnostics: Option<&'a layerfault::incremental::IncrementalDiagnostics>,
}

pub(crate) fn package_json_report(
    result: &package::PackageReport,
) -> PackageJsonReport<'_, impl serde::Serialize + '_> {
    PackageJsonReport {
        root: &result.root,
        fingerprint: &result.fingerprint,
        merkle_identity: &result.merkle_identity,
        files: &result.files,
        merkle_manifest: &result.merkle_manifest,
        total_bytes: result.total_bytes,
        findings: json_stream::stream_seq(&result.findings, report::enriched_finding_ref),
        correlations: &result.correlations,
        coverage: &result.coverage,
        metrics: result.metrics.as_ref(),
        incremental_diagnostics: result.incremental_diagnostics.as_ref(),
    }
}

#[derive(serde::Serialize)]
struct AdmissionJsonReport<'a, S: serde::Serialize> {
    identity: &'a str,
    source: &'a SourceKind,
    report: ArtifactJsonReport<'a, S>,
    trust_state: provenance::TrustState,
    trusted_signatures: usize,
    signer_fingerprints: &'a [String],
    policy: &'a policy::PolicyDecision,
}

fn admission_json(
    result: &ArtifactAdmission,
) -> AdmissionJsonReport<'_, impl serde::Serialize + '_> {
    AdmissionJsonReport {
        identity: &result.identity,
        source: &result.source,
        report: artifact_json_report(&result.report),
        trust_state: result.trust_state,
        trusted_signatures: result.trusted_signatures,
        signer_fingerprints: &result.signer_fingerprints,
        policy: &result.policy,
    }
}

pub(crate) fn print_actionable_findings(findings: &[layerfault::scanner::LayerScanResult]) {
    let mut grouped = BTreeMap::<
        String,
        (
            layerfault::scanner::ScanStatus,
            usize,
            String,
            String,
            Vec<String>,
        ),
    >::new();
    for finding in findings {
        if finding.status == layerfault::scanner::ScanStatus::Pass {
            continue;
        }
        let rule = policy::rule_id(finding);
        let risk = explain::risk_lookup(&rule);
        let entry = grouped.entry(rule).or_insert_with(|| {
            (
                finding.status,
                0,
                risk.title.clone(),
                risk.risk.clone(),
                Vec::new(),
            )
        });
        entry.1 += 1;
        if let Some(detail) = &finding.detail {
            if entry.4.len() < 4 && !entry.4.iter().any(|value| value == detail) {
                entry.4.push(detail.clone());
            }
        }
        if finding.status == layerfault::scanner::ScanStatus::Fail {
            entry.0 = finding.status;
        }
    }
    for (rule, (status, count, title, risk, details)) in grouped {
        println!(
            "  {} {}{}",
            match status {
                layerfault::scanner::ScanStatus::Fail => "BLOCK",
                layerfault::scanner::ScanStatus::Warn => "WARN",
                layerfault::scanner::ScanStatus::Pass => "PASS",
            },
            title,
            if count > 1 {
                format!(" ({} findings)", count)
            } else {
                String::new()
            }
        );
        println!("    Finding: {rule}");
        for detail in details {
            println!("    - {detail}");
        }
        println!("    Risk: {risk}");
        let explanation = explain::risk_lookup(&rule);
        println!("    Action: {}", explanation.recommended_actions.join(" "));
    }
}

pub(crate) fn artifact_report_exit(result: &artifact::ArtifactReport) -> i32 {
    let scanner =
        layerfault::decision::SecurityDecision::scanner_finding_exit_code(result.results.iter());
    layerfault::decision::SecurityDecision::combine_scanner_and_policy_exit_code(
        scanner, false, false,
    )
}

pub(crate) fn print_store_audit(store: &audit::StoreAudit) {
    println!("Models: {}", store.model_count);
    println!("Invalid models: {}", store.invalid_model_count);
    println!("Blob files: {}", store.blob_file_count);
    println!("Referenced blobs: {}", store.referenced_blob_count);
    println!("Orphaned blobs: {}", store.orphaned_blobs.len());
    println!("Missing blobs: {}", store.missing_blobs.len());
    println!("Shared blobs: {}", store.shared_blobs.len());
    println!(
        "Partial/temp files: {}",
        store.partial_or_temporary_files.len()
    );
    println!(
        "Invalid manifest paths: {}",
        store.invalid_manifest_paths.len()
    );
}

pub(crate) fn exit_for_store_audit(
    store: &audit::StoreAudit,
    reports: Option<&[app::EvaluatedReport]>,
) -> ! {
    if store.invalid_model_count > 0
        || !store.missing_blobs.is_empty()
        || !store.invalid_manifest_paths.is_empty()
    {
        std::process::exit(3);
    }
    let deep_code = reports.map(app::policy_exit_code).unwrap_or(0);
    if matches!(deep_code, 2..=4) {
        std::process::exit(deep_code);
    }
    if deep_code == 1
        || !store.orphaned_blobs.is_empty()
        || !store.partial_or_temporary_files.is_empty()
    {
        std::process::exit(1);
    }
    std::process::exit(0);
}

pub(crate) fn print_inventory_entries(entries: &[inventory::InventoryEntry]) {
    println!("SOURCE      FORMAT              BLOCK  BYTES        IDENTITY");
    for entry in entries {
        println!(
            "{:<11} {:<19} {:<6} {:<12} {}",
            entry.source.as_str(),
            entry.format.as_str(),
            entry.blocking,
            entry.size,
            entry.identity
        );
    }
}

pub(crate) fn write_json(path: &Path, value: &serde_json::Value) -> Result<()> {
    layerfault::paths::write_private(path, &serde_json::to_vec_pretty(value)?)
}

pub(crate) fn top_level_json_diff(
    left: &serde_json::Value,
    right: &serde_json::Value,
) -> serde_json::Value {
    let mut changed = serde_json::Map::new();
    let left_obj = left.as_object();
    let right_obj = right.as_object();
    let mut keys = std::collections::BTreeSet::new();
    if let Some(object) = left_obj {
        keys.extend(object.keys().cloned());
    }
    if let Some(object) = right_obj {
        keys.extend(object.keys().cloned());
    }
    for key in keys {
        let a = left_obj.and_then(|object| object.get(&key));
        let b = right_obj.and_then(|object| object.get(&key));
        if a != b {
            changed.insert(key, serde_json::json!({"left":a,"right":b}));
        }
    }
    serde_json::Value::Object(changed)
}
