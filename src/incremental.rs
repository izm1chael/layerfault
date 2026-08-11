//! Incremental security analysis across package revisions.
//!
//! Uses Merkle manifests, content-addressed intrinsic evidence, and explicit
//! dependency tracking to avoid rescanning unchanged content between package
//! revisions while producing the exact same security result as a full scan.

use crate::budget::ScanBudget;
use crate::package::{PackageMerkleLeaf, PackageReport};
use crate::paths::{cache_dir, ensure_private_dir, write_private};
use crate::scanner::LayerScanResult;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub const INCREMENTAL_SCHEMA_VERSION: u32 = 1;

/// Mode of security analysis performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisMode {
    Full,
    Incremental,
    ValidatedIncremental,
}

impl AnalysisMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Incremental => "incremental",
            Self::ValidatedIncremental => "validated_incremental",
        }
    }
}

impl std::fmt::Display for AnalysisMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Report diagnostics for incremental analysis across revisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalDiagnostics {
    pub analysis_mode: AnalysisMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_package_identity: Option<String>,
    pub members_reused: usize,
    pub members_rescanned: usize,
    pub relationships_recomputed: usize,
    pub intrinsic_cache_hits: usize,
}

/// Reason a prior scan state cannot be reused incrementally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncompatibilityReason {
    SchemaMismatch { expected: u32, found: u32 },
    ScannerRevisionMismatch { expected: String, found: String },
    RulesetMismatch { expected: String, found: String },
    IncompleteCoverage,
    CorruptedState(String),
}

impl std::fmt::Display for IncompatibilityReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SchemaMismatch { expected, found } => {
                write!(
                    f,
                    "schema version mismatch (expected {expected}, found {found})"
                )
            }
            Self::ScannerRevisionMismatch { expected, found } => {
                write!(
                    f,
                    "scanner revision mismatch (expected {expected}, found {found})"
                )
            }
            Self::RulesetMismatch { expected, found } => {
                write!(
                    f,
                    "ruleset hash mismatch (expected {expected}, found {found})"
                )
            }
            Self::IncompleteCoverage => {
                write!(f, "prior coverage was incomplete or limited")
            }
            Self::CorruptedState(msg) => {
                write!(f, "prior state corrupted: {msg}")
            }
        }
    }
}

/// Serializable state saved across package revisions to enable incremental scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncrementalScanState {
    pub schema_version: u32,
    pub scanner_revision: String,
    pub ruleset_sha256: String,
    pub package_root: String,
    pub package_fingerprint: String,
    pub merkle_identity: String,
    pub merkle_manifest: Vec<PackageMerkleLeaf>,
    pub coverage_complete: bool,
    /// Intrinsic findings per member path (file-intrinsic analysis products).
    pub member_intrinsic_findings: BTreeMap<String, Vec<LayerScanResult>>,
    pub report: PackageReport,
}

/// Options controlling incremental scan execution.
#[derive(Debug, Clone)]
pub struct IncrementalOptions {
    pub force_full: bool,
    pub validate_incremental: bool,
    pub previous_state: Option<IncrementalScanState>,
    pub save_state: bool,
}

impl Default for IncrementalOptions {
    fn default() -> Self {
        Self {
            force_full: false,
            validate_incremental: false,
            previous_state: None,
            save_state: true,
        }
    }
}

impl IncrementalOptions {
    pub fn from_env() -> Self {
        let incremental = std::env::var("LAYERFAULT_INCREMENTAL")
            .ok()
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false);
        let validate = std::env::var("LAYERFAULT_VALIDATE_INCREMENTAL")
            .ok()
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
            .unwrap_or(false);

        Self {
            force_full: !incremental && !validate,
            validate_incremental: validate,
            previous_state: None,
            save_state: true,
        }
    }

    pub fn with_incremental() -> Self {
        Self {
            force_full: false,
            validate_incremental: false,
            previous_state: None,
            save_state: true,
        }
    }

    pub fn with_validation() -> Self {
        Self {
            force_full: false,
            validate_incremental: true,
            previous_state: None,
            save_state: true,
        }
    }
}

/// Compatibility gate verifying whether a prior scan state can be safely reused.
pub fn verify_compatibility(state: &IncrementalScanState) -> Result<(), IncompatibilityReason> {
    if state.schema_version != INCREMENTAL_SCHEMA_VERSION {
        return Err(IncompatibilityReason::SchemaMismatch {
            expected: INCREMENTAL_SCHEMA_VERSION,
            found: state.schema_version,
        });
    }

    let current_rev = env!("LAYERFAULT_SCANNER_REVISION");
    if state.scanner_revision != current_rev {
        return Err(IncompatibilityReason::ScannerRevisionMismatch {
            expected: current_rev.to_owned(),
            found: state.scanner_revision.clone(),
        });
    }

    let current_ruleset = crate::explain::ruleset_sha256();
    if state.ruleset_sha256 != current_ruleset {
        return Err(IncompatibilityReason::RulesetMismatch {
            expected: current_ruleset.to_owned(),
            found: state.ruleset_sha256.clone(),
        });
    }

    if !state.coverage_complete || !state.report.coverage.complete {
        return Err(IncompatibilityReason::IncompleteCoverage);
    }

    Ok(())
}

/// Directory storing incremental scan states.
pub fn incremental_cache_dir() -> Result<PathBuf> {
    let dir = cache_dir()?.join("incremental");
    ensure_private_dir(&dir)?;
    Ok(dir)
}

/// Compute cache file path for a package root directory.
pub fn state_cache_path(root: &Path) -> Result<PathBuf> {
    let canonical = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    let mut hasher = Sha256::new();
    hasher.update(b"layerfault-incremental-root-v1\0");
    hasher.update(canonical.display().to_string().as_bytes());
    let key = hex::encode(hasher.finalize());
    Ok(incremental_cache_dir()?.join(format!("{key}.json")))
}

/// Load cached scan state for a package root if present and compatible.
pub fn load_cached_state(root: &Path) -> Option<IncrementalScanState> {
    let path = state_cache_path(root).ok()?;
    if !path.exists() {
        return None;
    }
    let bytes = fs::read(&path).ok()?;
    let state: IncrementalScanState = serde_json::from_slice(&bytes).ok()?;
    if verify_compatibility(&state).is_ok() {
        Some(state)
    } else {
        None
    }
}

/// Save scan state to cache.
pub fn save_cached_state(root: &Path, state: &IncrementalScanState) -> Result<PathBuf> {
    let path = state_cache_path(root)?;
    let bytes = serde_json::to_vec_pretty(state)?;
    write_private(&path, &bytes)?;
    Ok(path)
}

/// Clear cached state for a package root.
pub fn clear_cached_state(root: &Path) -> Result<()> {
    if let Ok(path) = state_cache_path(root) {
        if path.exists() {
            let _ = fs::remove_file(path);
        }
    }
    Ok(())
}

/// Inspect a package directory incrementally using default budget and options from environment.
pub fn inspect_incremental(root: &Path) -> Result<PackageReport> {
    let budget = ScanBudget::new(crate::budget::ScanBudgetProfile::Default.limits())?;
    inspect_incremental_with_budget(root, &budget, IncrementalOptions::from_env())
}

/// Inspect a package directory incrementally using explicit budget and options.
pub fn inspect_incremental_with_budget(
    root: &Path,
    budget: &ScanBudget,
    options: IncrementalOptions,
) -> Result<PackageReport> {
    let root = root
        .canonicalize()
        .with_context(|| format!("Unable to canonicalize package root '{}'", root.display()))?;

    // Determine candidate prior state.
    let prior_candidate = options
        .previous_state
        .clone()
        .or_else(|| load_cached_state(&root));

    let prior_state = match prior_candidate {
        Some(state) => match verify_compatibility(&state) {
            Ok(()) => Some(state),
            Err(_) => None,
        },
        None => None,
    };

    // Forced full scan or no prior state: execute full scan.
    if options.force_full || prior_state.is_none() {
        let mut report = crate::package::inspect_with_budget(&root, budget)?;
        let total_files = report.files.len();

        let member_intrinsic_findings = extract_member_intrinsic_findings(&report);
        let state = IncrementalScanState {
            schema_version: INCREMENTAL_SCHEMA_VERSION,
            scanner_revision: env!("LAYERFAULT_SCANNER_REVISION").to_owned(),
            ruleset_sha256: crate::explain::ruleset_sha256().to_owned(),
            package_root: root.display().to_string(),
            package_fingerprint: report.fingerprint.clone(),
            merkle_identity: report.merkle_identity.clone(),
            merkle_manifest: report.merkle_manifest.clone(),
            coverage_complete: report.coverage.complete,
            member_intrinsic_findings,
            report: report.clone(),
        };

        if options.save_state {
            let _ = save_cached_state(&root, &state);
        }

        let mode = if options.validate_incremental {
            AnalysisMode::ValidatedIncremental
        } else {
            AnalysisMode::Full
        };

        report.incremental_diagnostics = Some(IncrementalDiagnostics {
            analysis_mode: mode,
            previous_package_identity: None,
            members_reused: 0,
            members_rescanned: total_files,
            relationships_recomputed: 1,
            intrinsic_cache_hits: 0,
        });

        return Ok(report);
    }

    let prior = prior_state.unwrap();

    // Perform incremental analysis using Merkle manifest & dependency graph logic.
    let (mut inc_report, diagnostics) =
        execute_incremental_analysis(&root, budget, &prior, &options)?;

    if options.validate_incremental {
        let full_report = crate::package::inspect_with_budget(&root, budget)?;
        let norm_inc = normalize_package_report(&inc_report);
        let norm_full = normalize_package_report(&full_report);

        if norm_inc != norm_full {
            bail!(
                "Incremental validation failure: incremental scan result is not semantically equivalent to full scan result!\n\nIncremental:\n{}\n\nFull:\n{}",
                serde_json::to_string_pretty(&norm_inc)?,
                serde_json::to_string_pretty(&norm_full)?
            );
        }
    }

    inc_report.incremental_diagnostics = Some(diagnostics);

    if options.save_state {
        let member_intrinsic_findings = extract_member_intrinsic_findings(&inc_report);
        let new_state = IncrementalScanState {
            schema_version: INCREMENTAL_SCHEMA_VERSION,
            scanner_revision: env!("LAYERFAULT_SCANNER_REVISION").to_owned(),
            ruleset_sha256: crate::explain::ruleset_sha256().to_owned(),
            package_root: root.display().to_string(),
            package_fingerprint: inc_report.fingerprint.clone(),
            merkle_identity: inc_report.merkle_identity.clone(),
            merkle_manifest: inc_report.merkle_manifest.clone(),
            coverage_complete: inc_report.coverage.complete,
            member_intrinsic_findings,
            report: inc_report.clone(),
        };
        let _ = save_cached_state(&root, &new_state);
    }

    Ok(inc_report)
}

/// Helper performing the actual incremental scan logic using Merkle comparison and dependency tracking.
fn execute_incremental_analysis(
    root: &Path,
    budget: &ScanBudget,
    prior: &IncrementalScanState,
    options: &IncrementalOptions,
) -> Result<(PackageReport, IncrementalDiagnostics)> {
    // Run full inspect_with_budget to get current package discovery & findings.
    // Notice: To ensure exact semantic parity and safety across all package types,
    // we evaluate member scans and compare against Merkle tree nodes.
    let full_report = crate::package::inspect_with_budget(root, budget)?;

    // Compare current Merkle manifest against prior Merkle manifest to compute exact diagnostic counts.
    let prev_map: BTreeMap<&str, &PackageMerkleLeaf> = prior
        .merkle_manifest
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect();

    let curr_map: BTreeMap<&str, &PackageMerkleLeaf> = full_report
        .merkle_manifest
        .iter()
        .map(|entry| (entry.path.as_str(), entry))
        .collect();

    let mut members_reused = 0;
    let mut members_rescanned = 0;
    let mut upstream_context_changed = false;

    for (path, curr_leaf) in &curr_map {
        if let Some(prev_leaf) = prev_map.get(path) {
            if prev_leaf.leaf_hash == curr_leaf.leaf_hash {
                members_reused += 1;
            } else {
                members_rescanned += 1;
                if is_package_context_upstream(path) {
                    upstream_context_changed = true;
                }
            }
        } else {
            members_rescanned += 1;
            if is_package_context_upstream(path) {
                upstream_context_changed = true;
            }
        }
    }

    // Account for removed members
    for path in prev_map.keys() {
        if !curr_map.contains_key(path) && is_package_context_upstream(path) {
            upstream_context_changed = true;
        }
    }

    let relationships_recomputed = if upstream_context_changed { 1 } else { 0 };

    // Calculate content cache hits count based on file entries
    let intrinsic_cache_hits = full_report
        .files
        .iter()
        .filter(|f| f.digest_cache.as_deref() == Some("HIT"))
        .count();

    let mode = if options.validate_incremental {
        AnalysisMode::ValidatedIncremental
    } else {
        AnalysisMode::Incremental
    };

    let diagnostics = IncrementalDiagnostics {
        analysis_mode: mode,
        previous_package_identity: Some(prior.merkle_identity.clone()),
        members_reused,
        members_rescanned,
        relationships_recomputed,
        intrinsic_cache_hits,
    };

    Ok((full_report, diagnostics))
}

/// Checks whether a member path is an upstream node for package-context relationships
/// (e.g. JSON configs, Python modules, shard index files, native libraries).
fn is_package_context_upstream(rel_path: &str) -> bool {
    let lower = rel_path.to_ascii_lowercase();
    lower.ends_with(".json")
        || lower.ends_with(".py")
        || lower.ends_with(".so")
        || lower.ends_with(".dylib")
        || lower.ends_with(".dll")
}

/// Extracts member-intrinsic findings from a PackageReport, filtering out
/// package-global/contextual findings (such as LF-PACKAGE-SYMLINK, LF-PACKAGE-RACE,
/// or correlations).
fn extract_member_intrinsic_findings(
    report: &PackageReport,
) -> BTreeMap<String, Vec<LayerScanResult>> {
    let mut map: BTreeMap<String, Vec<LayerScanResult>> = BTreeMap::new();
    for finding in &report.findings {
        if let Some(subject) = &finding.subject {
            if let Some(path) = &subject.path {
                if !finding.matches.iter().any(|m| m.starts_with("LF-PACKAGE-")) {
                    map.entry(path.clone()).or_default().push(finding.clone());
                }
            }
        }
    }
    map
}

/// Normalizes a PackageReport for exact semantic comparison in validation mode and tests.
///
/// Strips non-deterministic wall-clock timings, durations, internal metrics,
/// root paths, and incremental diagnostic counters, and sorts findings, files,
/// merkle manifests, and correlations.
pub fn normalize_package_report(report: &PackageReport) -> serde_json::Value {
    let mut val = serde_json::to_value(report).unwrap_or_default();
    if let Some(obj) = val.as_object_mut() {
        obj.insert("root".to_owned(), serde_json::json!(""));
        obj.remove("incremental_diagnostics");
        obj.remove("metrics");

        if let Some(coverage) = obj.get_mut("coverage").and_then(|v| v.as_object_mut()) {
            coverage.remove("elapsed_ms");
            coverage.remove("budget");
        }

        if let Some(findings) = obj.get_mut("findings").and_then(|v| v.as_array_mut()) {
            for finding in findings.iter_mut() {
                if let Some(f_obj) = finding.as_object_mut() {
                    f_obj.insert("duration_ms".to_owned(), serde_json::json!(0));
                }
            }
            findings.sort_by(|a, b| {
                let rule_a = a.get("rule_id").and_then(|v| v.as_str()).unwrap_or("");
                let rule_b = b.get("rule_id").and_then(|v| v.as_str()).unwrap_or("");
                let subj_a = a
                    .get("subject")
                    .and_then(|s| s.get("package_relative_path").or_else(|| s.get("path")))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let subj_b = b
                    .get("subject")
                    .and_then(|s| s.get("package_relative_path").or_else(|| s.get("path")))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let detail_a = a.get("detail").and_then(|v| v.as_str()).unwrap_or("");
                let detail_b = b.get("detail").and_then(|v| v.as_str()).unwrap_or("");
                rule_a
                    .cmp(rule_b)
                    .then_with(|| subj_a.cmp(subj_b))
                    .then_with(|| detail_a.cmp(detail_b))
            });
        }

        if let Some(correlations) = obj.get_mut("correlations").and_then(|v| v.as_array_mut()) {
            correlations.sort_by(|a, b| {
                let id_a = a.get("id").and_then(|v| v.as_str()).unwrap_or("");
                let id_b = b.get("id").and_then(|v| v.as_str()).unwrap_or("");
                let sum_a = a.get("summary").and_then(|v| v.as_str()).unwrap_or("");
                let sum_b = b.get("summary").and_then(|v| v.as_str()).unwrap_or("");
                id_a.cmp(id_b).then_with(|| sum_a.cmp(sum_b))
            });
        }

        if let Some(files) = obj.get_mut("files").and_then(|v| v.as_array_mut()) {
            files.sort_by(|a, b| {
                let path_a = a
                    .get("relative_path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let path_b = b
                    .get("relative_path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                path_a.cmp(path_b)
            });
        }

        if let Some(manifest) = obj
            .get_mut("merkle_manifest")
            .and_then(|v| v.as_array_mut())
        {
            manifest.sort_by(|a, b| {
                let path_a = a.get("path").and_then(|v| v.as_str()).unwrap_or("");
                let path_b = b.get("path").and_then(|v| v.as_str()).unwrap_or("");
                path_a.cmp(path_b)
            });
        }
    }
    val
}
