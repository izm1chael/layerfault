use anyhow::Result;
use layerfault::budget::{ScanBudget, ScanBudgetProfile};
use layerfault::incremental::normalize_package_report;
use layerfault::package::inspect_with_scheduler;
use layerfault::scheduler::{AdaptiveScheduler, SchedulerConfig, SchedulerMode};
use std::fs;
use std::io::{Cursor, Write};
use std::path::Path;
use tempfile::tempdir;

fn make_test_scheduler(concurrency: usize) -> AdaptiveScheduler {
    let config = SchedulerConfig::detect(
        Some(concurrency),
        Some(1024),
        Some(256 * 1024 * 1024),
        SchedulerMode::Adaptive,
        ScanBudgetProfile::Default,
    );
    AdaptiveScheduler::new(config)
}

fn create_synthetic_package(root: &Path) -> Result<()> {
    fs::create_dir_all(root.join("sub"))?;
    fs::write(
        root.join("config.json"),
        br#"{"architectures":["FixtureModel"],"auto_map":{"AutoModel":"sub.modeling_custom.CustomModel"}}"#,
    )?;
    fs::write(
        root.join("sub/modeling_custom.py"),
        b"import os\ndef forward(x):\n    os.system('id')\n    return x\n",
    )?;
    fs::write(
        root.join("sub/adapter_config.json"),
        br#"{"peft_type":"LORA","target_modules":["q_proj","v_proj"]}"#,
    )?;
    fs::write(
        root.join("README.md"),
        b"# Test Model Package\nDocumentation.\n",
    )?;
    let mut weights = vec![0u8; 1024];
    weights[0..4].copy_from_slice(b"GGUF");
    fs::write(root.join("model.gguf"), weights)?;
    Ok(())
}

#[test]
fn test_serial_vs_parallel_normalized_output_identical() -> Result<()> {
    let dir = tempdir()?;
    let pkg_dir = dir.path().join("pkg");
    create_synthetic_package(&pkg_dir)?;

    let budget1 = ScanBudget::new(ScanBudgetProfile::Default.limits())?;
    let sched1 = make_test_scheduler(1);
    let report1 = inspect_with_scheduler(&pkg_dir, &budget1, &sched1)?;

    let budget2 = ScanBudget::new(ScanBudgetProfile::Default.limits())?;
    let sched2 = make_test_scheduler(2);
    let report2 = inspect_with_scheduler(&pkg_dir, &budget2, &sched2)?;

    let budget8 = ScanBudget::new(ScanBudgetProfile::Default.limits())?;
    let sched8 = make_test_scheduler(8);
    let report8 = inspect_with_scheduler(&pkg_dir, &budget8, &sched8)?;

    assert_eq!(
        normalize_package_report(&report1),
        normalize_package_report(&report2)
    );
    assert_eq!(
        normalize_package_report(&report1),
        normalize_package_report(&report8)
    );

    Ok(())
}

#[test]
fn test_concurrency_1_2_8_identities() -> Result<()> {
    let dir = tempdir()?;
    let pkg = dir.path().join("identity_pkg");
    fs::create_dir_all(&pkg)?;
    fs::write(pkg.join("a.json"), b"{\"a\":1}")?;
    fs::write(pkg.join("b.py"), b"print('b')")?;
    fs::write(pkg.join("c.txt"), b"text content")?;

    let budget1 = ScanBudget::new(ScanBudgetProfile::Default.limits())?;
    let rep1 = inspect_with_scheduler(&pkg, &budget1, &make_test_scheduler(1))?;

    let budget2 = ScanBudget::new(ScanBudgetProfile::Default.limits())?;
    let rep2 = inspect_with_scheduler(&pkg, &budget2, &make_test_scheduler(2))?;

    let budget8 = ScanBudget::new(ScanBudgetProfile::Default.limits())?;
    let rep8 = inspect_with_scheduler(&pkg, &budget8, &make_test_scheduler(8))?;

    assert_eq!(rep1.fingerprint, rep2.fingerprint);
    assert_eq!(rep2.fingerprint, rep8.fingerprint);
    assert_eq!(rep1.merkle_manifest, rep2.merkle_manifest);
    assert_eq!(rep2.merkle_manifest, rep8.merkle_manifest);
    let ids = |report: &layerfault::package::PackageReport| {
        report
            .findings
            .iter()
            .map(|finding| finding.finding_id.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(ids(&rep1), ids(&rep2));
    assert_eq!(ids(&rep2), ids(&rep8));
    Ok(())
}

#[test]
fn test_one_malformed_member_isolated() -> Result<()> {
    let dir = tempdir()?;
    let pkg = dir.path().join("malformed_pkg");
    fs::create_dir_all(&pkg)?;
    fs::write(pkg.join("valid.json"), b"{\"key\":\"value\"}")?;
    // Write invalid/corrupt archive
    fs::write(pkg.join("corrupt.zip"), b"PK\x03\x04corrupted_zip_bytes")?;
    fs::write(pkg.join("valid.py"), b"x = 42\n")?;

    let budget = ScanBudget::new(ScanBudgetProfile::Default.limits())?;
    let sched = make_test_scheduler(4);
    let report = inspect_with_scheduler(&pkg, &budget, &sched)?;

    assert_eq!(report.files.len(), 3);
    assert!(report
        .findings
        .iter()
        .any(|f| f.matches.iter().any(|m| m.contains("LF-ARCHIVE-MALFORMED"))));
    assert!(!report.coverage.complete);
    assert_eq!(report.coverage.parser_failures, 1);
    assert!(report.findings.iter().any(|f| f
        .subject
        .as_ref()
        .map(|s| s.package_relative_path.as_deref() == Some("valid.py"))
        .unwrap_or(false)));
    Ok(())
}

#[test]
fn test_cancellation_releases_workers() -> Result<()> {
    let dir = tempdir()?;
    let pkg = dir.path().join("cancel_pkg");
    fs::create_dir_all(&pkg)?;
    fs::write(pkg.join("a.json"), b"{}")?;
    fs::write(pkg.join("b.json"), b"{}")?;

    let budget = ScanBudget::new(ScanBudgetProfile::Default.limits())?;
    budget.cancel();
    let sched = make_test_scheduler(4);
    let report = inspect_with_scheduler(&pkg, &budget, &sched)?;

    assert!(!report.coverage.complete);
    assert!(report.coverage.control_interrupted());
    assert_eq!(sched.diagnostics().queued_tasks, 0);
    Ok(())
}

#[test]
fn nested_archives_share_the_package_scheduler_limit() -> Result<()> {
    let dir = tempdir()?;
    let pkg = dir.path().join("nested_pkg");
    fs::create_dir_all(&pkg)?;

    let mut inner_bytes = Cursor::new(Vec::new());
    {
        let mut inner = zip::ZipWriter::new(&mut inner_bytes);
        inner.start_file("payload.py", zip::write::SimpleFileOptions::default())?;
        inner.write_all(b"import subprocess\nsubprocess.run(['id'])\n")?;
        inner.finish()?;
    }
    let outer_file = fs::File::create(pkg.join("outer.zip"))?;
    let mut outer = zip::ZipWriter::new(outer_file);
    outer.start_file("inner.zip", zip::write::SimpleFileOptions::default())?;
    outer.write_all(inner_bytes.get_ref())?;
    outer.finish()?;

    let budget = ScanBudget::new(ScanBudgetProfile::Default.limits())?;
    let scheduler = make_test_scheduler(2);
    let report = inspect_with_scheduler(&pkg, &budget, &scheduler)?;

    assert!(report
        .findings
        .iter()
        .any(|finding| finding.rule_id.as_deref() == Some("LF-CODE-SUBPROCESS")));
    let diagnostics = scheduler.diagnostics();
    assert!(diagnostics.peak_active_workers <= 2);
    assert!(diagnostics.peak_queued_tasks <= 2);
    Ok(())
}

#[test]
fn test_huge_member_count_with_bounded_queue() -> Result<()> {
    let dir = tempdir()?;
    let pkg = dir.path().join("huge_pkg");
    fs::create_dir_all(&pkg)?;

    for i in 0..10_000 {
        fs::write(
            pkg.join(format!("file_{i:04}.json")),
            format!("{{\"index\":{i}}}").as_bytes(),
        )?;
    }

    let budget = ScanBudget::new(ScanBudgetProfile::Default.limits())?;
    let sched = make_test_scheduler(4);
    let report = inspect_with_scheduler(&pkg, &budget, &sched)?;

    assert_eq!(report.files.len(), 10_000);
    let diagnostics = sched.diagnostics();
    assert_eq!(diagnostics.queued_tasks, 0);
    assert!(diagnostics.peak_queued_tasks <= 4);
    assert!(diagnostics.peak_active_workers <= 4);
    Ok(())
}
