//! Performance, memory, and I/O metrics tracking, baseline comparisons, and regression gate evaluation.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

/// Atomic global counters for cheap internal primitive instrumentation.
pub static GLOBAL_LOGICAL_SOURCE_BYTES: AtomicU64 = AtomicU64::new(0);
pub static GLOBAL_PHYSICAL_BYTES_READ: AtomicU64 = AtomicU64::new(0);
pub static GLOBAL_FULL_FILE_PASSES: AtomicU64 = AtomicU64::new(0);
pub static GLOBAL_TEMP_DISK_BYTES: AtomicU64 = AtomicU64::new(0);
pub static GLOBAL_CACHE_HITS: AtomicU64 = AtomicU64::new(0);
pub static GLOBAL_CACHE_MISSES: AtomicU64 = AtomicU64::new(0);
pub static GLOBAL_SCHEDULER_PEAK_RESERVATIONS: AtomicUsize = AtomicUsize::new(0);

/// Reset all global instrumentation counters.
pub fn reset_global_counters() {
    GLOBAL_LOGICAL_SOURCE_BYTES.store(0, Ordering::Relaxed);
    GLOBAL_PHYSICAL_BYTES_READ.store(0, Ordering::Relaxed);
    GLOBAL_FULL_FILE_PASSES.store(0, Ordering::Relaxed);
    GLOBAL_TEMP_DISK_BYTES.store(0, Ordering::Relaxed);
    GLOBAL_CACHE_HITS.store(0, Ordering::Relaxed);
    GLOBAL_CACHE_MISSES.store(0, Ordering::Relaxed);
    GLOBAL_SCHEDULER_PEAK_RESERVATIONS.store(0, Ordering::Relaxed);
}

/// Record additional logical source bytes processed.
pub fn record_logical_bytes(bytes: u64) {
    GLOBAL_LOGICAL_SOURCE_BYTES.fetch_add(bytes, Ordering::Relaxed);
}

/// Record additional physical bytes read.
pub fn record_physical_bytes(bytes: u64) {
    GLOBAL_PHYSICAL_BYTES_READ.fetch_add(bytes, Ordering::Relaxed);
}

/// Record a full-file read pass.
pub fn record_full_file_pass() {
    GLOBAL_FULL_FILE_PASSES.fetch_add(1, Ordering::Relaxed);
}

/// Record temporary disk allocation.
pub fn record_temp_disk_bytes(bytes: u64) {
    GLOBAL_TEMP_DISK_BYTES.fetch_add(bytes, Ordering::Relaxed);
}

/// Record a cache hit.
pub fn record_cache_hit() {
    GLOBAL_CACHE_HITS.fetch_add(1, Ordering::Relaxed);
}

/// Record a cache miss.
pub fn record_cache_miss() {
    GLOBAL_CACHE_MISSES.fetch_add(1, Ordering::Relaxed);
}

/// Update peak scheduler reservations if `current` exceeds current stored peak.
pub fn record_scheduler_reservation(current: usize) {
    let mut prev = GLOBAL_SCHEDULER_PEAK_RESERVATIONS.load(Ordering::Relaxed);
    while current > prev {
        match GLOBAL_SCHEDULER_PEAK_RESERVATIONS.compare_exchange_weak(
            prev,
            current,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(actual) => prev = actual,
        }
    }
}

/// Machine-readable performance, memory, and I/O metrics structure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct PerformanceMetrics {
    pub wall_time_ms: f64,
    pub cpu_time_ms: f64,
    pub peak_rss_kib: u64,
    pub logical_source_bytes: u64,
    pub physical_bytes_read: u64,
    pub full_file_passes: u32,
    pub temp_disk_bytes: u64,
    pub cache_hits: u32,
    pub cache_misses: u32,
    pub scheduler_peak_reservations: usize,
}

impl PerformanceMetrics {
    /// Capture current global atomic counters into a `PerformanceMetrics` snapshot.
    pub fn snapshot_global_counters(wall_duration: Duration, peak_rss_kib: u64) -> Self {
        Self {
            wall_time_ms: wall_duration.as_secs_f64() * 1000.0,
            cpu_time_ms: 0.0, // CPU time populated by host runner if available
            peak_rss_kib,
            logical_source_bytes: GLOBAL_LOGICAL_SOURCE_BYTES.load(Ordering::Relaxed),
            physical_bytes_read: GLOBAL_PHYSICAL_BYTES_READ.load(Ordering::Relaxed),
            full_file_passes: GLOBAL_FULL_FILE_PASSES.load(Ordering::Relaxed) as u32,
            temp_disk_bytes: GLOBAL_TEMP_DISK_BYTES.load(Ordering::Relaxed),
            cache_hits: GLOBAL_CACHE_HITS.load(Ordering::Relaxed) as u32,
            cache_misses: GLOBAL_CACHE_MISSES.load(Ordering::Relaxed) as u32,
            scheduler_peak_reservations: GLOBAL_SCHEDULER_PEAK_RESERVATIONS.load(Ordering::Relaxed),
        }
    }
}

/// Information describing the execution environment and host profile.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HostProfile {
    pub os: String,
    pub cpu_count: usize,
    pub memory_total_mb: u64,
    pub profile: String,
}

impl Default for HostProfile {
    fn default() -> Self {
        Self {
            os: std::env::consts::OS.to_string(),
            cpu_count: num_cpus_count(),
            memory_total_mb: 0,
            profile: "workstation".to_string(),
        }
    }
}

fn num_cpus_count() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// Baseline specification for a single performance scenario.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PerformanceBaseline {
    pub scenario: String,
    pub metrics: PerformanceMetrics,
    #[serde(default)]
    pub description: String,
}

/// Threshold limits for performance regression detection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ThresholdConfig {
    /// Maximum allowable percentage increase in wall time (default 20%).
    pub max_wall_regression_pct: f64,
    /// Maximum allowable percentage increase in peak RSS (default 20%).
    pub max_rss_regression_pct: f64,
    /// Maximum allowable increase in full-file pass count (default 0).
    pub max_pass_increase: u32,
    /// Maximum allowable percentage increase in temporary disk bytes (default 25%).
    pub max_temp_disk_regression_pct: f64,
}

impl Default for ThresholdConfig {
    fn default() -> Self {
        Self {
            max_wall_regression_pct: 20.0,
            max_rss_regression_pct: 20.0,
            max_pass_increase: 0,
            max_temp_disk_regression_pct: 25.0,
        }
    }
}

/// Status result of a baseline metric comparison.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GateStatus {
    Pass,
    Warn,
    Fail,
}

/// Evaluation result comparing current execution metrics against a reference baseline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BaselineComparison {
    pub scenario: String,
    pub status: GateStatus,
    pub wall_diff_pct: f64,
    pub rss_diff_pct: f64,
    pub full_file_pass_diff: i64,
    pub temp_disk_diff_pct: f64,
    pub violations: Vec<String>,
    pub justification: Option<String>,
}

impl BaselineComparison {
    /// Evaluate current metrics against a reference baseline using the specified thresholds.
    pub fn evaluate(
        scenario: &str,
        current: &PerformanceMetrics,
        baseline: &PerformanceMetrics,
        thresholds: &ThresholdConfig,
        justification: Option<String>,
    ) -> Self {
        let wall_diff_pct = if baseline.wall_time_ms > 0.0 {
            ((current.wall_time_ms - baseline.wall_time_ms) / baseline.wall_time_ms) * 100.0
        } else {
            0.0
        };

        let rss_diff_pct = if baseline.peak_rss_kib > 0 {
            ((current.peak_rss_kib as f64 - baseline.peak_rss_kib as f64)
                / baseline.peak_rss_kib as f64)
                * 100.0
        } else {
            0.0
        };

        let full_file_pass_diff =
            current.full_file_passes as i64 - baseline.full_file_passes as i64;

        let temp_disk_diff_pct = if baseline.temp_disk_bytes > 0 {
            ((current.temp_disk_bytes as f64 - baseline.temp_disk_bytes as f64)
                / baseline.temp_disk_bytes as f64)
                * 100.0
        } else if current.temp_disk_bytes > 0 {
            100.0
        } else {
            0.0
        };

        let mut violations = Vec::new();

        if wall_diff_pct > thresholds.max_wall_regression_pct {
            violations.push(format!(
                "Wall time regression: {:.1}% exceeds threshold {:.1}%",
                wall_diff_pct, thresholds.max_wall_regression_pct
            ));
        }

        if rss_diff_pct > thresholds.max_rss_regression_pct {
            violations.push(format!(
                "Peak RSS regression: {:.1}% exceeds threshold {:.1}%",
                rss_diff_pct, thresholds.max_rss_regression_pct
            ));
        }

        if full_file_pass_diff > thresholds.max_pass_increase as i64 {
            violations.push(format!(
                "Full-file pass increase: +{} pass(es) exceeds limit +{}",
                full_file_pass_diff, thresholds.max_pass_increase
            ));
        }

        if temp_disk_diff_pct > thresholds.max_temp_disk_regression_pct {
            violations.push(format!(
                "Temp disk regression: {:.1}% exceeds threshold {:.1}%",
                temp_disk_diff_pct, thresholds.max_temp_disk_regression_pct
            ));
        }

        let status = if violations.is_empty() {
            GateStatus::Pass
        } else if justification.is_some() {
            GateStatus::Warn
        } else {
            GateStatus::Fail
        };

        Self {
            scenario: scenario.to_string(),
            status,
            wall_diff_pct,
            rss_diff_pct,
            full_file_pass_diff,
            temp_disk_diff_pct,
            violations,
            justification,
        }
    }
}

/// Complete machine-readable benchmark report document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PerformanceReport {
    pub build_revision: String,
    pub host_profile: HostProfile,
    pub scenarios: BTreeMap<String, PerformanceMetrics>,
    pub comparisons: Vec<BaselineComparison>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter_recording() {
        reset_global_counters();
        record_logical_bytes(1024);
        record_physical_bytes(2048);
        record_full_file_pass();
        record_temp_disk_bytes(512);
        record_cache_hit();
        record_cache_miss();
        record_scheduler_reservation(4);
        record_scheduler_reservation(2);

        let metrics =
            PerformanceMetrics::snapshot_global_counters(Duration::from_millis(100), 4096);
        assert_eq!(metrics.logical_source_bytes, 1024);
        assert_eq!(metrics.physical_bytes_read, 2048);
        assert_eq!(metrics.full_file_passes, 1);
        assert_eq!(metrics.temp_disk_bytes, 512);
        assert_eq!(metrics.cache_hits, 1);
        assert_eq!(metrics.cache_misses, 1);
        assert_eq!(metrics.scheduler_peak_reservations, 4);
    }

    #[test]
    fn test_baseline_comparison_pass() {
        let baseline = PerformanceMetrics {
            wall_time_ms: 100.0,
            cpu_time_ms: 90.0,
            peak_rss_kib: 10000,
            logical_source_bytes: 100000,
            physical_bytes_read: 100000,
            full_file_passes: 1,
            temp_disk_bytes: 0,
            cache_hits: 10,
            cache_misses: 2,
            scheduler_peak_reservations: 4,
        };

        let current = PerformanceMetrics {
            wall_time_ms: 105.0, // 5% increase (within 20%)
            cpu_time_ms: 95.0,
            peak_rss_kib: 10500, // 5% increase (within 20%)
            logical_source_bytes: 100000,
            physical_bytes_read: 100000,
            full_file_passes: 1,
            temp_disk_bytes: 0,
            cache_hits: 10,
            cache_misses: 2,
            scheduler_peak_reservations: 4,
        };

        let thresholds = ThresholdConfig::default();
        let eval =
            BaselineComparison::evaluate("test_pass", &current, &baseline, &thresholds, None);
        assert_eq!(eval.status, GateStatus::Pass);
        assert!(eval.violations.is_empty());
    }

    #[test]
    fn test_baseline_comparison_failure_and_justification() {
        let baseline = PerformanceMetrics {
            wall_time_ms: 100.0,
            peak_rss_kib: 10000,
            full_file_passes: 1,
            temp_disk_bytes: 100,
            ..Default::default()
        };

        let current = PerformanceMetrics {
            wall_time_ms: 130.0, // 30% increase (exceeds 20%)
            peak_rss_kib: 10000,
            full_file_passes: 2, // +1 pass (exceeds 0)
            temp_disk_bytes: 100,
            ..Default::default()
        };

        let thresholds = ThresholdConfig::default();
        let eval_fail =
            BaselineComparison::evaluate("test_fail", &current, &baseline, &thresholds, None);
        assert_eq!(eval_fail.status, GateStatus::Fail);
        assert_eq!(eval_fail.violations.len(), 2);

        let eval_override = BaselineComparison::evaluate(
            "test_warn",
            &current,
            &baseline,
            &thresholds,
            Some("Justified stronger security parser".to_string()),
        );
        assert_eq!(eval_override.status, GateStatus::Warn);
        assert_eq!(eval_override.violations.len(), 2);
        assert_eq!(
            eval_override.justification.as_deref(),
            Some("Justified stronger security parser")
        );
    }
}
