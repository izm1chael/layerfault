use layerfault::budget::ScanBudget;
use layerfault::incremental::{
    clear_cached_state, inspect_incremental_with_budget, normalize_package_report,
    save_cached_state, verify_compatibility, AnalysisMode, IncompatibilityReason,
    IncrementalOptions, IncrementalScanState, INCREMENTAL_SCHEMA_VERSION,
};
use layerfault::package::{inspect, inspect_with_budget};
use std::fs;
use tempfile::tempdir;

fn default_budget() -> ScanBudget {
    ScanBudget::new(layerfault::budget::ScanBudgetProfile::Default.limits()).unwrap()
}

fn setup_test_package() -> tempfile::TempDir {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();

    fs::write(root.join("README.md"), "# Test Package\nDescription here.").unwrap();
    fs::write(
        root.join("config.json"),
        r#"{"architectures":["TestModel"],"auto_map":{"AutoModel":"modeling_test.TestModel"}}"#,
    )
    .unwrap();
    fs::write(
        root.join("modeling_test.py"),
        "import os\ndef run():\n    os.system('echo test')\n",
    )
    .unwrap();
    fs::write(
        root.join("libnative.so"),
        b"\x7fELF\x02\x01\x01\x00fixture_native_bytes",
    )
    .unwrap();

    dir
}

#[test]
fn test_no_change_revision() {
    let pkg = setup_test_package();
    let root = pkg.path();
    clear_cached_state(root).unwrap();

    let budget = default_budget();
    let initial =
        inspect_incremental_with_budget(root, &budget, IncrementalOptions::with_incremental())
            .unwrap();
    assert_eq!(
        initial
            .incremental_diagnostics
            .as_ref()
            .unwrap()
            .analysis_mode,
        AnalysisMode::Full
    );

    let second =
        inspect_incremental_with_budget(root, &budget, IncrementalOptions::with_incremental())
            .unwrap();
    let diag = second.incremental_diagnostics.as_ref().unwrap();

    assert_eq!(diag.analysis_mode, AnalysisMode::Incremental);
    assert_eq!(diag.members_rescanned, 0);
    assert_eq!(diag.members_reused, 4);
    assert_eq!(diag.relationships_recomputed, 0);

    let full = inspect_with_budget(root, &budget).unwrap();
    assert_eq!(
        normalize_package_report(&second),
        normalize_package_report(&full)
    );
}

#[test]
fn test_documentation_only_change() {
    let pkg = setup_test_package();
    let root = pkg.path();
    clear_cached_state(root).unwrap();

    let budget = default_budget();
    inspect_incremental_with_budget(root, &budget, IncrementalOptions::with_incremental()).unwrap();

    // Modify README.md only
    fs::write(
        root.join("README.md"),
        "# Test Package\nUpdated documentation only.",
    )
    .unwrap();

    let inc =
        inspect_incremental_with_budget(root, &budget, IncrementalOptions::with_incremental())
            .unwrap();
    let diag = inc.incremental_diagnostics.as_ref().unwrap();

    assert_eq!(diag.analysis_mode, AnalysisMode::Incremental);
    assert_eq!(diag.members_rescanned, 1);
    assert_eq!(diag.members_reused, 3);
    assert_eq!(diag.relationships_recomputed, 0);

    let full = inspect_with_budget(root, &budget).unwrap();
    assert_eq!(
        normalize_package_report(&inc),
        normalize_package_report(&full)
    );
}

#[test]
fn test_config_changes_loading_relationship() {
    let pkg = setup_test_package();
    let root = pkg.path();
    clear_cached_state(root).unwrap();

    let budget = default_budget();
    inspect_incremental_with_budget(root, &budget, IncrementalOptions::with_incremental()).unwrap();

    // Modify config.json auto_map
    fs::write(
        root.join("config.json"),
        r#"{"architectures":["TestModel"],"auto_map":{"AutoModel":"modeling_test.TestModelCustom"}}"#,
    )
    .unwrap();

    let inc =
        inspect_incremental_with_budget(root, &budget, IncrementalOptions::with_incremental())
            .unwrap();
    let diag = inc.incremental_diagnostics.as_ref().unwrap();

    assert_eq!(diag.analysis_mode, AnalysisMode::Incremental);
    assert_eq!(diag.members_rescanned, 1);
    assert_eq!(diag.relationships_recomputed, 1);

    let full = inspect_with_budget(root, &budget).unwrap();
    assert_eq!(
        normalize_package_report(&inc),
        normalize_package_report(&full)
    );
}

#[test]
fn test_python_change() {
    let pkg = setup_test_package();
    let root = pkg.path();
    clear_cached_state(root).unwrap();

    let budget = default_budget();
    inspect_incremental_with_budget(root, &budget, IncrementalOptions::with_incremental()).unwrap();

    // Modify Python code
    fs::write(
        root.join("modeling_test.py"),
        "import subprocess\ndef run():\n    subprocess.run(['ls'])\n",
    )
    .unwrap();

    let inc =
        inspect_incremental_with_budget(root, &budget, IncrementalOptions::with_incremental())
            .unwrap();
    let diag = inc.incremental_diagnostics.as_ref().unwrap();

    assert_eq!(diag.analysis_mode, AnalysisMode::Incremental);
    assert_eq!(diag.members_rescanned, 1);
    assert_eq!(diag.relationships_recomputed, 1);

    let full = inspect_with_budget(root, &budget).unwrap();
    assert_eq!(
        normalize_package_report(&inc),
        normalize_package_report(&full)
    );
}

#[test]
fn test_native_binary_change() {
    let pkg = setup_test_package();
    let root = pkg.path();
    clear_cached_state(root).unwrap();

    let budget = default_budget();
    inspect_incremental_with_budget(root, &budget, IncrementalOptions::with_incremental()).unwrap();

    // Update binary file
    fs::write(
        root.join("libnative.so"),
        b"\x7fELF\x02\x01\x01\x00updated_native_bytes",
    )
    .unwrap();

    let inc =
        inspect_incremental_with_budget(root, &budget, IncrementalOptions::with_incremental())
            .unwrap();
    let diag = inc.incremental_diagnostics.as_ref().unwrap();

    assert_eq!(diag.analysis_mode, AnalysisMode::Incremental);
    assert_eq!(diag.members_rescanned, 1);

    let full = inspect_with_budget(root, &budget).unwrap();
    assert_eq!(
        normalize_package_report(&inc),
        normalize_package_report(&full)
    );
}

#[test]
fn test_rename_delete_add() {
    let pkg = setup_test_package();
    let root = pkg.path();
    clear_cached_state(root).unwrap();

    let budget = default_budget();
    inspect_incremental_with_budget(root, &budget, IncrementalOptions::with_incremental()).unwrap();

    // Add extra.txt, delete README.md, rename modeling_test.py to modeling_renamed.py
    fs::write(root.join("extra.txt"), "new file content").unwrap();
    fs::remove_file(root.join("README.md")).unwrap();
    fs::rename(
        root.join("modeling_test.py"),
        root.join("modeling_renamed.py"),
    )
    .unwrap();

    let inc =
        inspect_incremental_with_budget(root, &budget, IncrementalOptions::with_incremental())
            .unwrap();
    let diag = inc.incremental_diagnostics.as_ref().unwrap();

    assert_eq!(diag.analysis_mode, AnalysisMode::Incremental);
    assert_eq!(diag.relationships_recomputed, 1);

    let full = inspect_with_budget(root, &budget).unwrap();
    assert_eq!(
        normalize_package_report(&inc),
        normalize_package_report(&full)
    );
}

#[test]
fn test_scanner_revision_invalidation() {
    let pkg = setup_test_package();
    let root = pkg.path();
    clear_cached_state(root).unwrap();

    let budget = default_budget();
    let initial =
        inspect_incremental_with_budget(root, &budget, IncrementalOptions::with_incremental())
            .unwrap();

    let state = IncrementalScanState {
        schema_version: INCREMENTAL_SCHEMA_VERSION,
        scanner_revision: "v0.0.0-outdated".to_string(),
        ruleset_sha256: layerfault::explain::ruleset_sha256().to_string(),
        package_root: root.display().to_string(),
        package_fingerprint: initial.fingerprint.clone(),
        merkle_identity: initial.merkle_identity.clone(),
        merkle_manifest: initial.merkle_manifest.clone(),
        coverage_complete: true,
        member_intrinsic_findings: Default::default(),
        report: initial,
    };

    assert!(matches!(
        verify_compatibility(&state),
        Err(IncompatibilityReason::ScannerRevisionMismatch { .. })
    ));

    save_cached_state(root, &state).unwrap();

    let fallback =
        inspect_incremental_with_budget(root, &budget, IncrementalOptions::with_incremental())
            .unwrap();
    let diag = fallback.incremental_diagnostics.as_ref().unwrap();
    assert_eq!(diag.analysis_mode, AnalysisMode::Full);
}

#[test]
fn test_prior_incomplete_result() {
    let pkg = setup_test_package();
    let root = pkg.path();
    clear_cached_state(root).unwrap();

    let budget = default_budget();
    let mut initial =
        inspect_incremental_with_budget(root, &budget, IncrementalOptions::with_incremental())
            .unwrap();

    initial.coverage.complete = false;

    let state = IncrementalScanState {
        schema_version: INCREMENTAL_SCHEMA_VERSION,
        scanner_revision: env!("LAYERFAULT_SCANNER_REVISION").to_string(),
        ruleset_sha256: layerfault::explain::ruleset_sha256().to_string(),
        package_root: root.display().to_string(),
        package_fingerprint: initial.fingerprint.clone(),
        merkle_identity: initial.merkle_identity.clone(),
        merkle_manifest: initial.merkle_manifest.clone(),
        coverage_complete: false,
        member_intrinsic_findings: Default::default(),
        report: initial,
    };

    assert!(matches!(
        verify_compatibility(&state),
        Err(IncompatibilityReason::IncompleteCoverage)
    ));
}

#[test]
fn test_incremental_normalized_result_equals_full_result() {
    let pkg = setup_test_package();
    let root = pkg.path();
    clear_cached_state(root).unwrap();

    let budget = default_budget();
    let validated =
        inspect_incremental_with_budget(root, &budget, IncrementalOptions::with_validation())
            .unwrap();

    let diag = validated.incremental_diagnostics.as_ref().unwrap();
    assert_eq!(diag.analysis_mode, AnalysisMode::ValidatedIncremental);

    let full = inspect(root).unwrap();
    assert_eq!(
        normalize_package_report(&validated),
        normalize_package_report(&full)
    );
}
