//! Resource-aware adaptive scanner scheduler.
//!
//! Replaces fixed job-count concurrency as the sole resource-control mechanism
//! with a scheduler aware of CPU, memory, I/O, temporary disk, decompression,
//! and task type.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::budget::{BudgetDimension, BudgetFailure, BudgetPermit, ScanBudget, ScanBudgetProfile};

/// Coarse-grained task cost classification for admission control heuristics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaskClass {
    SmallCpu,
    SmallIo,
    LargeSequentialIo,
    RandomIoParser,
    ArchiveDecompression,
    AstParse,
    NativeParse,
    PackageCorrelation,
    ActiveAnalysis,
}

impl TaskClass {
    pub const ALL: [Self; 9] = [
        Self::SmallCpu,
        Self::SmallIo,
        Self::LargeSequentialIo,
        Self::RandomIoParser,
        Self::ArchiveDecompression,
        Self::AstParse,
        Self::NativeParse,
        Self::PackageCorrelation,
        Self::ActiveAnalysis,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SmallCpu => "small_cpu",
            Self::SmallIo => "small_io",
            Self::LargeSequentialIo => "large_sequential_io",
            Self::RandomIoParser => "random_io_parser",
            Self::ArchiveDecompression => "archive_decompression",
            Self::AstParse => "ast_parse",
            Self::NativeParse => "native_parse",
            Self::PackageCorrelation => "package_correlation",
            Self::ActiveAnalysis => "active_analysis",
        }
    }
}

/// Estimated resource cost of a task used for admission control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskCost {
    pub cpu_units: u32,
    pub memory_reservation: u64,
    pub io_reservation: u64,
    pub temp_disk_reservation: u64,
    pub class: TaskClass,
}

impl TaskCost {
    pub fn small_cpu() -> Self {
        Self {
            cpu_units: 1,
            memory_reservation: 1024 * 1024,
            io_reservation: 0,
            temp_disk_reservation: 0,
            class: TaskClass::SmallCpu,
        }
    }

    pub fn small_io(size: u64) -> Self {
        Self {
            cpu_units: 1,
            memory_reservation: (size.saturating_mul(2)).max(1024 * 1024),
            io_reservation: size,
            temp_disk_reservation: 0,
            class: TaskClass::SmallIo,
        }
    }

    pub fn large_sequential_io(_size: u64, buffer_size: u64) -> Self {
        let streaming_window = buffer_size.max(4 * 1024 * 1024);
        Self {
            cpu_units: 1,
            memory_reservation: streaming_window,
            io_reservation: streaming_window,
            temp_disk_reservation: 0,
            class: TaskClass::LargeSequentialIo,
        }
    }

    pub fn random_io_parser(size: u64) -> Self {
        Self {
            cpu_units: 1,
            memory_reservation: (size.saturating_mul(2)).max(2 * 1024 * 1024),
            io_reservation: size.min(16 * 1024 * 1024),
            temp_disk_reservation: 0,
            class: TaskClass::RandomIoParser,
        }
    }

    pub fn archive_decompression(uncompressed_estimate: u64) -> Self {
        Self {
            cpu_units: 1,
            memory_reservation: (uncompressed_estimate.saturating_mul(2)).max(8 * 1024 * 1024),
            io_reservation: uncompressed_estimate,
            temp_disk_reservation: uncompressed_estimate,
            class: TaskClass::ArchiveDecompression,
        }
    }

    pub fn ast_parse(source_len: u64) -> Self {
        Self {
            cpu_units: 1,
            memory_reservation: (source_len.saturating_mul(10)).max(4 * 1024 * 1024),
            io_reservation: 0,
            temp_disk_reservation: 0,
            class: TaskClass::AstParse,
        }
    }

    pub fn native_parse(size: u64) -> Self {
        Self {
            cpu_units: 1,
            memory_reservation: (size.saturating_mul(4)).max(8 * 1024 * 1024),
            io_reservation: size,
            temp_disk_reservation: 0,
            class: TaskClass::NativeParse,
        }
    }

    pub fn package_correlation() -> Self {
        Self {
            cpu_units: 1,
            memory_reservation: 16 * 1024 * 1024,
            io_reservation: 0,
            temp_disk_reservation: 0,
            class: TaskClass::PackageCorrelation,
        }
    }

    pub fn active_analysis(memory_bytes: u64) -> Self {
        Self {
            cpu_units: 1,
            memory_reservation: memory_bytes.max(32 * 1024 * 1024),
            io_reservation: 0,
            temp_disk_reservation: 0,
            class: TaskClass::ActiveAnalysis,
        }
    }
}

/// Concurrency scheduler mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SchedulerMode {
    #[default]
    Adaptive,
    Fixed,
}

impl SchedulerMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Adaptive => "adaptive",
            Self::Fixed => "fixed",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "adaptive" => Ok(Self::Adaptive),
            "fixed" => Ok(Self::Fixed),
            other => Err(anyhow!(
                "Unknown scheduler mode '{other}'; expected 'adaptive' or 'fixed'"
            )),
        }
    }
}

/// Dynamic or configured limits for scheduler admission.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchedulerConfig {
    pub mode: SchedulerMode,
    pub max_workers: usize,
    pub max_memory_bytes: u64,
    pub max_inflight_bytes: u64,
    pub max_decompression_workers: usize,
    pub max_active_analysis_jobs: usize,
    pub max_temp_disk_bytes: u64,
}

impl SchedulerConfig {
    /// Detect host defaults given optional user overrides.
    pub fn detect(
        jobs_override: Option<usize>,
        max_memory_mib_override: Option<u64>,
        max_inflight_bytes_override: Option<u64>,
        mode: SchedulerMode,
        profile: ScanBudgetProfile,
    ) -> Self {
        let logical_cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        let max_workers = jobs_override.unwrap_or(logical_cpus).clamp(1, 64);

        let limits = profile.limits();

        let default_memory = match profile {
            ScanBudgetProfile::Constrained => 256 * 1024 * 1024,
            ScanBudgetProfile::Default => 1024 * 1024 * 1024,
            ScanBudgetProfile::Deep => 2 * 1024 * 1024 * 1024,
            ScanBudgetProfile::Research => 8 * 1024 * 1024 * 1024,
        };

        let max_memory_bytes = max_memory_mib_override
            .map(|mib| mib.saturating_mul(1024 * 1024))
            .unwrap_or_else(|| limits.scheduled_memory_bytes.min(default_memory));

        let default_inflight = match profile {
            ScanBudgetProfile::Constrained => 256 * 1024 * 1024,
            _ => 512 * 1024 * 1024,
        };

        let max_inflight_bytes = max_inflight_bytes_override.unwrap_or(default_inflight);

        let max_decompression_workers = (max_workers / 2).max(1);

        let max_active_analysis_jobs =
            if profile == ScanBudgetProfile::Constrained || max_workers <= 4 {
                1
            } else {
                (max_workers / 4).max(1)
            };

        let max_temp_disk_bytes = limits.temporary_disk_bytes;

        Self {
            mode,
            max_workers,
            max_memory_bytes,
            max_inflight_bytes,
            max_decompression_workers,
            max_active_analysis_jobs,
            max_temp_disk_bytes,
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchedulerDiagnostics {
    pub queued_tasks: usize,
    pub peak_queued_tasks: usize,
    pub peak_active_workers: usize,
    pub active_by_class: BTreeMap<String, usize>,
    pub peak_reserved_memory: u64,
    pub peak_inflight_bytes: u64,
    pub permit_wait_time_ms: u64,
}

#[derive(Debug, Default)]
struct SchedulerCounters {
    active_workers: usize,
    active_memory_bytes: u64,
    active_inflight_bytes: u64,
    active_decompression_workers: usize,
    active_active_analysis_jobs: usize,
    active_temp_disk_bytes: u64,
    active_by_class: BTreeMap<TaskClass, usize>,
    queued_tasks: usize,
    peak_queued_tasks: usize,
    peak_active_workers: usize,
    peak_reserved_memory: u64,
    peak_inflight_bytes: u64,
    permit_wait_time_ms: u64,
}

struct SchedulerInner {
    config: SchedulerConfig,
    state: Mutex<SchedulerCounters>,
    condvar: Condvar,
}

/// Adaptive concurrency scheduler.
#[derive(Clone)]
pub struct AdaptiveScheduler {
    inner: Arc<SchedulerInner>,
}

impl AdaptiveScheduler {
    pub fn new(config: SchedulerConfig) -> Self {
        Self {
            inner: Arc::new(SchedulerInner {
                config,
                state: Mutex::new(SchedulerCounters::default()),
                condvar: Condvar::new(),
            }),
        }
    }

    pub fn config(&self) -> &SchedulerConfig {
        &self.inner.config
    }

    /// Acquire a permit for a task specified by `TaskCost` and governed by `ScanBudget`.
    pub fn acquire(
        &self,
        cost: TaskCost,
        budget: &ScanBudget,
    ) -> Result<SchedulerPermit, BudgetFailure> {
        budget.check()?;
        if cost.memory_reservation > self.inner.config.max_memory_bytes
            || (cost.class == TaskClass::LargeSequentialIo
                && cost.io_reservation > self.inner.config.max_inflight_bytes)
            || cost.temp_disk_reservation > self.inner.config.max_temp_disk_bytes
            || (cost.cpu_units as usize) > self.inner.config.max_workers
        {
            return Err(BudgetFailure::Overflow);
        }
        let start_wait = Instant::now();

        let mut state = self.inner.state.lock().unwrap();
        state.queued_tasks += 1;
        state.peak_queued_tasks = state.peak_queued_tasks.max(state.queued_tasks);

        loop {
            if let Err(err) = budget.check() {
                state.queued_tasks = state.queued_tasks.saturating_sub(1);
                self.inner.condvar.notify_all();
                return Err(err);
            }

            let can_admit = match self.inner.config.mode {
                SchedulerMode::Fixed => {
                    let next_workers = state.active_workers.saturating_add(cost.cpu_units as usize);
                    next_workers <= self.inner.config.max_workers
                }
                SchedulerMode::Adaptive => {
                    let next_workers = state.active_workers.saturating_add(cost.cpu_units as usize);
                    let next_mem = state
                        .active_memory_bytes
                        .saturating_add(cost.memory_reservation);
                    let next_inflight = if cost.class == TaskClass::LargeSequentialIo {
                        state
                            .active_inflight_bytes
                            .saturating_add(cost.io_reservation)
                    } else {
                        state.active_inflight_bytes
                    };
                    let next_decomp = if cost.class == TaskClass::ArchiveDecompression {
                        state.active_decompression_workers + 1
                    } else {
                        state.active_decompression_workers
                    };
                    let next_active = if cost.class == TaskClass::ActiveAnalysis {
                        state.active_active_analysis_jobs + 1
                    } else {
                        state.active_active_analysis_jobs
                    };
                    let next_temp = state
                        .active_temp_disk_bytes
                        .saturating_add(cost.temp_disk_reservation);

                    next_workers <= self.inner.config.max_workers
                        && next_mem <= self.inner.config.max_memory_bytes
                        && next_inflight <= self.inner.config.max_inflight_bytes
                        && next_decomp <= self.inner.config.max_decompression_workers
                        && next_active <= self.inner.config.max_active_analysis_jobs
                        && next_temp <= self.inner.config.max_temp_disk_bytes
                }
            };

            if can_admit {
                let budget_permit = if cost.memory_reservation > 0 {
                    match budget.reserve(
                        BudgetDimension::ScheduledMemoryBytes,
                        cost.memory_reservation,
                        cost.class.as_str(),
                    ) {
                        Ok(p) => Some(p),
                        Err(err) => {
                            state.queued_tasks = state.queued_tasks.saturating_sub(1);
                            self.inner.condvar.notify_all();
                            return Err(err);
                        }
                    }
                } else {
                    None
                };

                state.queued_tasks = state.queued_tasks.saturating_sub(1);
                state.active_workers = state.active_workers.saturating_add(cost.cpu_units as usize);
                state.peak_active_workers = state.peak_active_workers.max(state.active_workers);
                state.active_memory_bytes = state
                    .active_memory_bytes
                    .saturating_add(cost.memory_reservation);
                if cost.class == TaskClass::LargeSequentialIo {
                    state.active_inflight_bytes = state
                        .active_inflight_bytes
                        .saturating_add(cost.io_reservation);
                }
                if cost.class == TaskClass::ArchiveDecompression {
                    state.active_decompression_workers += 1;
                }
                if cost.class == TaskClass::ActiveAnalysis {
                    state.active_active_analysis_jobs += 1;
                }
                state.active_temp_disk_bytes = state
                    .active_temp_disk_bytes
                    .saturating_add(cost.temp_disk_reservation);
                *state.active_by_class.entry(cost.class).or_insert(0) += 1;

                if state.active_memory_bytes > state.peak_reserved_memory {
                    state.peak_reserved_memory = state.active_memory_bytes;
                }
                if state.active_inflight_bytes > state.peak_inflight_bytes {
                    state.peak_inflight_bytes = state.active_inflight_bytes;
                }
                let wait_ms = start_wait.elapsed().as_millis() as u64;
                state.permit_wait_time_ms = state.permit_wait_time_ms.saturating_add(wait_ms);

                crate::perf_metrics::record_scheduler_reservation(state.active_workers);

                return Ok(SchedulerPermit {
                    inner: Arc::clone(&self.inner),
                    cost,
                    _budget_permit: budget_permit,
                });
            }

            let (next_state, wait_result) = self
                .inner
                .condvar
                .wait_timeout(state, Duration::from_millis(50))
                .unwrap();
            state = next_state;
            if wait_result.timed_out() {
                if let Err(err) = budget.check() {
                    state.queued_tasks = state.queued_tasks.saturating_sub(1);
                    self.inner.condvar.notify_all();
                    return Err(err);
                }
            }
        }
    }

    /// Diagnostic snapshot of current scheduler metrics.
    pub fn diagnostics(&self) -> SchedulerDiagnostics {
        let state = self.inner.state.lock().unwrap();
        let mut active_by_class = BTreeMap::new();
        for (class, count) in &state.active_by_class {
            if *count > 0 {
                active_by_class.insert(class.as_str().to_owned(), *count);
            }
        }
        SchedulerDiagnostics {
            queued_tasks: state.queued_tasks,
            peak_queued_tasks: state.peak_queued_tasks,
            peak_active_workers: state.peak_active_workers,
            active_by_class,
            peak_reserved_memory: state.peak_reserved_memory,
            peak_inflight_bytes: state.peak_inflight_bytes,
            permit_wait_time_ms: state.permit_wait_time_ms,
        }
    }
}

/// RAII permit representing acquired resource capacity.
/// Releases resources automatically when dropped on any path.
pub struct SchedulerPermit {
    inner: Arc<SchedulerInner>,
    cost: TaskCost,
    _budget_permit: Option<BudgetPermit>,
}

impl Drop for SchedulerPermit {
    fn drop(&mut self) {
        let mut state = self.inner.state.lock().unwrap();
        state.active_workers = state
            .active_workers
            .saturating_sub(self.cost.cpu_units as usize);
        state.active_memory_bytes = state
            .active_memory_bytes
            .saturating_sub(self.cost.memory_reservation);
        if self.cost.class == TaskClass::LargeSequentialIo {
            state.active_inflight_bytes = state
                .active_inflight_bytes
                .saturating_sub(self.cost.io_reservation);
        }
        if self.cost.class == TaskClass::ArchiveDecompression {
            state.active_decompression_workers =
                state.active_decompression_workers.saturating_sub(1);
        }
        if self.cost.class == TaskClass::ActiveAnalysis {
            state.active_active_analysis_jobs = state.active_active_analysis_jobs.saturating_sub(1);
        }
        state.active_temp_disk_bytes = state
            .active_temp_disk_bytes
            .saturating_sub(self.cost.temp_disk_reservation);
        if let Some(count) = state.active_by_class.get_mut(&self.cost.class) {
            *count = count.saturating_sub(1);
        }

        self.inner.condvar.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn scheduler_modes_parse_correctly() {
        assert_eq!(
            SchedulerMode::parse("adaptive").unwrap(),
            SchedulerMode::Adaptive
        );
        assert_eq!(SchedulerMode::parse("fixed").unwrap(), SchedulerMode::Fixed);
        assert!(SchedulerMode::parse("invalid").is_err());
    }

    #[test]
    fn host_defaults_detection() {
        let cfg = SchedulerConfig::detect(
            Some(4),
            Some(512),
            Some(256 * 1024 * 1024),
            SchedulerMode::Adaptive,
            ScanBudgetProfile::Default,
        );
        assert_eq!(cfg.max_workers, 4);
        assert_eq!(cfg.max_memory_bytes, 512 * 1024 * 1024);
        assert_eq!(cfg.max_inflight_bytes, 256 * 1024 * 1024);
    }

    #[test]
    fn permits_released_after_drop() -> Result<()> {
        let budget = ScanBudget::new(ScanBudgetProfile::Constrained.limits())?;
        let config = SchedulerConfig::detect(
            Some(2),
            None,
            None,
            SchedulerMode::Adaptive,
            ScanBudgetProfile::Constrained,
        );
        let scheduler = AdaptiveScheduler::new(config);

        let cost = TaskCost::small_cpu();
        let permit = scheduler.acquire(cost, &budget)?;
        let diag = scheduler.diagnostics();
        assert_eq!(diag.active_by_class.get("small_cpu"), Some(&1));

        drop(permit);
        let diag2 = scheduler.diagnostics();
        assert_eq!(diag2.active_by_class.get("small_cpu"), None);
        Ok(())
    }

    #[test]
    fn memory_cap_prevents_overcommit() -> Result<()> {
        let budget = ScanBudget::new(ScanBudgetProfile::Default.limits())?;
        let mut config = SchedulerConfig::detect(
            Some(4),
            Some(64), // 64 MiB max RAM
            None,
            SchedulerMode::Adaptive,
            ScanBudgetProfile::Default,
        );
        config.max_memory_bytes = 64 * 1024 * 1024;
        let scheduler = AdaptiveScheduler::new(config);

        // First task reserves 40 MiB
        let mut cost1 = TaskCost::small_cpu();
        cost1.memory_reservation = 40 * 1024 * 1024;
        let permit1 = scheduler.acquire(cost1, &budget)?;

        // Second task requests 40 MiB (total 80 MiB > 64 MiB), must block
        let s2 = scheduler.clone();
        let b2 = budget.clone();
        let acquired = Arc::new(AtomicBool::new(false));
        let acq_clone = Arc::clone(&acquired);

        let handle = std::thread::spawn(move || {
            let mut cost2 = TaskCost::small_cpu();
            cost2.memory_reservation = 40 * 1024 * 1024;
            if let Ok(_p) = s2.acquire(cost2, &b2) {
                acq_clone.store(true, Ordering::SeqCst);
            }
        });

        std::thread::sleep(Duration::from_millis(30));
        assert!(!acquired.load(Ordering::SeqCst));

        drop(permit1);
        handle.join().unwrap();
        assert!(acquired.load(Ordering::SeqCst));
        Ok(())
    }

    #[test]
    fn cancellation_wakes_waiting_tasks() -> Result<()> {
        let budget = ScanBudget::new(ScanBudgetProfile::Default.limits())?;
        let mut config = SchedulerConfig::detect(
            Some(1),
            None,
            None,
            SchedulerMode::Fixed,
            ScanBudgetProfile::Default,
        );
        config.max_workers = 1;
        let scheduler = AdaptiveScheduler::new(config);

        let permit1 = scheduler.acquire(TaskCost::small_cpu(), &budget)?;

        let s2 = scheduler.clone();
        let b2 = budget.clone();
        let cancelled = Arc::new(AtomicBool::new(false));
        let can_clone = Arc::clone(&cancelled);

        let handle = std::thread::spawn(move || {
            if let Err(err) = s2.acquire(TaskCost::small_cpu(), &b2) {
                if err == BudgetFailure::Cancelled {
                    can_clone.store(true, Ordering::SeqCst);
                }
            }
        });

        std::thread::sleep(Duration::from_millis(30));
        budget.cancel();
        handle.join().unwrap();
        assert!(cancelled.load(Ordering::SeqCst));
        drop(permit1);
        Ok(())
    }
}
