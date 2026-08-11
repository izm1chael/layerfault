use layerfault::perf_metrics::{
    record_cache_hit, record_cache_miss, record_full_file_pass, record_logical_bytes,
    record_physical_bytes, record_scheduler_reservation, record_temp_disk_bytes,
    reset_global_counters, BaselineComparison, GateStatus, PerformanceBaseline, PerformanceMetrics,
    PerformanceReport, ThresholdConfig,
};
use layerfault::safeio::open_readonly_nofollow;
use layerfault::scanner::{BinaryStreamObserver, ScanSession, TextStreamObserver};
use std::io::Write;
use std::time::Duration;
use tempfile::tempdir;

#[test]
fn test_performance_metrics_atomic_counters() {
    reset_global_counters();
    record_logical_bytes(2048);
    record_physical_bytes(4096);
    record_full_file_pass();
    record_temp_disk_bytes(1024);
    record_cache_hit();
    record_cache_miss();
    record_scheduler_reservation(8);
    record_scheduler_reservation(4); // lower value should not decrease peak

    let metrics = PerformanceMetrics::snapshot_global_counters(Duration::from_millis(150), 32768);
    assert_eq!(metrics.logical_source_bytes, 2048);
    assert_eq!(metrics.physical_bytes_read, 4096);
    assert_eq!(metrics.full_file_passes, 1);
    assert_eq!(metrics.temp_disk_bytes, 1024);
    assert_eq!(metrics.cache_hits, 1);
    assert_eq!(metrics.cache_misses, 1);
    assert_eq!(metrics.scheduler_peak_reservations, 8);
    assert_eq!(metrics.peak_rss_kib, 32768);
    assert!((metrics.wall_time_ms - 150.0).abs() < 1e-3);
}

#[test]
fn test_baseline_comparison_evaluation() {
    let baseline = PerformanceMetrics {
        wall_time_ms: 200.0,
        cpu_time_ms: 180.0,
        peak_rss_kib: 50000,
        logical_source_bytes: 1000000,
        physical_bytes_read: 1000000,
        full_file_passes: 1,
        temp_disk_bytes: 0,
        cache_hits: 5,
        cache_misses: 1,
        scheduler_peak_reservations: 4,
    };

    // Within default thresholds (<20% wall/rss, 0 pass diff, <25% temp disk)
    let current_pass = PerformanceMetrics {
        wall_time_ms: 220.0, // +10%
        cpu_time_ms: 190.0,
        peak_rss_kib: 52000, // +4%
        logical_source_bytes: 1000000,
        physical_bytes_read: 1000000,
        full_file_passes: 1,
        temp_disk_bytes: 0,
        cache_hits: 5,
        cache_misses: 1,
        scheduler_peak_reservations: 4,
    };

    let thresholds = ThresholdConfig::default();
    let res_pass = BaselineComparison::evaluate(
        "synthetic_pass",
        &current_pass,
        &baseline,
        &thresholds,
        None,
    );
    assert_eq!(res_pass.status, GateStatus::Pass);
    assert!(res_pass.violations.is_empty());

    // Exceeding wall time and RSS limits
    let current_fail = PerformanceMetrics {
        wall_time_ms: 260.0, // +30% (violates 20%)
        cpu_time_ms: 230.0,
        peak_rss_kib: 65000, // +30% (violates 20%)
        logical_source_bytes: 1000000,
        physical_bytes_read: 1000000,
        full_file_passes: 2,   // +1 pass (violates 0)
        temp_disk_bytes: 1024, // +1024 bytes (violates 25%)
        cache_hits: 5,
        cache_misses: 1,
        scheduler_peak_reservations: 4,
    };

    let res_fail = BaselineComparison::evaluate(
        "synthetic_fail",
        &current_fail,
        &baseline,
        &thresholds,
        None,
    );
    assert_eq!(res_fail.status, GateStatus::Fail);
    assert_eq!(res_fail.violations.len(), 4);

    // Exceeding with explicit justification
    let res_override = BaselineComparison::evaluate(
        "synthetic_override",
        &current_fail,
        &baseline,
        &thresholds,
        Some("Justified stronger security parser".to_string()),
    );
    assert_eq!(res_override.status, GateStatus::Warn);
    assert_eq!(res_override.violations.len(), 4);
    assert_eq!(
        res_override.justification.as_deref(),
        Some("Justified stronger security parser")
    );
}

#[test]
fn test_performance_report_serialization() {
    let baseline_metrics = PerformanceMetrics {
        wall_time_ms: 100.0,
        peak_rss_kib: 25000,
        ..Default::default()
    };

    let baseline = PerformanceBaseline {
        scenario: "unit_test_scenario".to_string(),
        metrics: baseline_metrics,
        description: "Unit test scenario description".to_string(),
    };

    let report = PerformanceReport {
        build_revision: "test-rev-123".to_string(),
        host_profile: Default::default(),
        scenarios: std::collections::BTreeMap::from([(
            "unit_test_scenario".to_string(),
            baseline.metrics.clone(),
        )]),
        comparisons: vec![BaselineComparison::evaluate(
            "unit_test_scenario",
            &baseline.metrics,
            &baseline.metrics,
            &ThresholdConfig::default(),
            None,
        )],
    };

    let json_str = serde_json::to_string_pretty(&report).expect("Serialization failed");
    assert!(json_str.contains("test-rev-123"));
    assert!(json_str.contains("unit_test_scenario"));

    let deserialized: PerformanceReport =
        serde_json::from_str(&json_str).expect("Deserialization failed");
    assert_eq!(deserialized, report);
}

#[test]
fn test_single_pass_scan_session_counter_integration() {
    reset_global_counters();
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("counter_test.bin");

    let mut f = std::fs::File::create(&file_path).unwrap();
    f.write_all(b"os.system('id')\n").unwrap();
    f.sync_all().unwrap();

    let file = open_readonly_nofollow(&file_path).unwrap();
    let session = ScanSession::new(&file_path, &file).unwrap();
    let text_obs = Box::new(TextStreamObserver::new("counter_test.bin"));
    let bin_obs = Box::new(BinaryStreamObserver::new());

    let (digest, findings) = session.run("text/plain", vec![text_obs, bin_obs]).unwrap();

    assert!(!digest.is_empty());
    assert!(!findings.is_empty());

    let metrics = PerformanceMetrics::snapshot_global_counters(Duration::from_millis(50), 1024);
    assert_eq!(metrics.full_file_passes, 1);
    assert_eq!(metrics.logical_source_bytes, 16);
    assert!(metrics.physical_bytes_read >= 16);
}
