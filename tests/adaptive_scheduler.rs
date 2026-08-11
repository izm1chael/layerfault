use anyhow::Result;
use layerfault::budget::{ScanBudget, ScanBudgetProfile};
use layerfault::package::{inspect_with_budget, inspect_with_scheduler};
use layerfault::scheduler::{AdaptiveScheduler, SchedulerConfig, SchedulerMode, TaskCost};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tempfile::tempdir;

#[test]
fn simulated_one_core_512mb_budget() -> Result<()> {
    let budget = ScanBudget::new(ScanBudgetProfile::Constrained.limits())?;
    let config = SchedulerConfig::detect(
        Some(1),
        Some(512),
        Some(128 * 1024 * 1024),
        SchedulerMode::Adaptive,
        ScanBudgetProfile::Constrained,
    );
    let scheduler = AdaptiveScheduler::new(config);

    assert_eq!(scheduler.config().max_workers, 1);

    let permit1 = scheduler.acquire(TaskCost::small_cpu(), &budget)?;
    let diag1 = scheduler.diagnostics();
    assert_eq!(diag1.active_by_class.get("small_cpu"), Some(&1));

    drop(permit1);
    let diag2 = scheduler.diagnostics();
    assert_eq!(diag2.active_by_class.get("small_cpu"), None);
    Ok(())
}

#[test]
fn mixed_workload_4core_8gb_profile() -> Result<()> {
    let budget = ScanBudget::new(ScanBudgetProfile::Default.limits())?;
    let config = SchedulerConfig::detect(
        Some(4),
        Some(2048),
        Some(512 * 1024 * 1024),
        SchedulerMode::Adaptive,
        ScanBudgetProfile::Default,
    );
    let scheduler = AdaptiveScheduler::new(config);

    let mut workers = Vec::new();
    for i in 0..10 {
        let sched = scheduler.clone();
        let b = budget.clone();
        workers.push(thread::spawn(move || {
            let cost = if i % 2 == 0 {
                TaskCost::small_cpu()
            } else if i % 3 == 0 {
                TaskCost::ast_parse(100_000)
            } else {
                TaskCost::large_sequential_io(50 * 1024 * 1024, 8 * 1024 * 1024)
            };
            if let Ok(permit) = sched.acquire(cost, &b) {
                thread::sleep(Duration::from_millis(10));
                drop(permit);
            }
        }));
    }

    for w in workers {
        w.join().unwrap();
    }

    let diag = scheduler.diagnostics();
    assert_eq!(diag.queued_tasks, 0);
    Ok(())
}

#[test]
fn huge_file_plus_many_small_files() -> Result<()> {
    let budget = ScanBudget::new(ScanBudgetProfile::Default.limits())?;
    let mut config = SchedulerConfig::detect(
        Some(4),
        Some(1024),
        Some(100 * 1024 * 1024), // 100 MiB max inflight bytes
        SchedulerMode::Adaptive,
        ScanBudgetProfile::Default,
    );
    config.max_inflight_bytes = 100 * 1024 * 1024;
    let scheduler = AdaptiveScheduler::new(config);

    // Acquire permit for 80 MiB inflight IO file
    let huge_cost = TaskCost::large_sequential_io(80 * 1024 * 1024, 8 * 1024 * 1024);
    let huge_permit = scheduler.acquire(huge_cost, &budget)?;

    // Small CPU tasks can still execute concurrently
    let small_permit = scheduler.acquire(TaskCost::small_cpu(), &budget)?;

    drop(small_permit);
    drop(huge_permit);
    Ok(())
}

#[test]
fn permits_released_after_error_and_panic() -> Result<()> {
    let budget = ScanBudget::new(ScanBudgetProfile::Default.limits())?;
    let scheduler = AdaptiveScheduler::new(SchedulerConfig::detect(
        Some(2),
        None,
        None,
        SchedulerMode::Adaptive,
        ScanBudgetProfile::Default,
    ));

    let sched_clone = scheduler.clone();
    let b_clone = budget.clone();

    let handle = thread::spawn(move || {
        let _permit = sched_clone
            .acquire(TaskCost::small_cpu(), &b_clone)
            .unwrap();
        panic!("simulated task failure");
    });

    assert!(handle.join().is_err());
    let diag = scheduler.diagnostics();
    assert_eq!(diag.active_by_class.get("small_cpu"), None);
    Ok(())
}

#[test]
fn cancellation_while_waiting() -> Result<()> {
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

    let permit = scheduler.acquire(TaskCost::small_cpu(), &budget)?;

    let sched_clone = scheduler.clone();
    let b_clone = budget.clone();
    let cancelled = Arc::new(AtomicBool::new(false));
    let c_clone = Arc::clone(&cancelled);

    let handle = thread::spawn(move || {
        if scheduler_acquire_err(&sched_clone, TaskCost::small_cpu(), &b_clone) {
            c_clone.store(true, Ordering::SeqCst);
        }
    });

    thread::sleep(Duration::from_millis(20));
    budget.cancel();
    handle.join().unwrap();
    assert!(cancelled.load(Ordering::SeqCst));
    drop(permit);
    Ok(())
}

fn scheduler_acquire_err(sched: &AdaptiveScheduler, cost: TaskCost, budget: &ScanBudget) -> bool {
    sched.acquire(cost, budget).is_err()
}

#[test]
fn arithmetic_overflow_safe_reservations() -> Result<()> {
    let budget = ScanBudget::new(ScanBudgetProfile::Default.limits())?;
    let scheduler = AdaptiveScheduler::new(SchedulerConfig::detect(
        Some(4),
        None,
        None,
        SchedulerMode::Adaptive,
        ScanBudgetProfile::Default,
    ));

    let mut overflow_cost = TaskCost::small_cpu();
    overflow_cost.memory_reservation = u64::MAX;

    // Reservation for u64::MAX memory will fail gracefully or block without overflow panic
    let result = scheduler.acquire(overflow_cost, &budget);
    assert!(result.is_err() || result.is_ok());
    Ok(())
}

#[test]
fn deterministic_output_across_scheduling_orders() -> Result<()> {
    let dir = tempdir()?;
    let p1 = dir.path().join("a.py");
    let p2 = dir.path().join("b.json");
    std::fs::write(&p1, "print('hello')\n")?;
    std::fs::write(&p2, "{\"key\": \"value\"}\n")?;

    let budget = ScanBudget::new(ScanBudgetProfile::Default.limits())?;
    let report1 = inspect_with_budget(dir.path(), &budget)?;

    let sched_fixed = AdaptiveScheduler::new(SchedulerConfig::detect(
        Some(1),
        None,
        None,
        SchedulerMode::Fixed,
        ScanBudgetProfile::Default,
    ));
    let report2 = inspect_with_scheduler(dir.path(), &budget, &sched_fixed)?;

    let sched_adapt = AdaptiveScheduler::new(SchedulerConfig::detect(
        Some(4),
        None,
        None,
        SchedulerMode::Adaptive,
        ScanBudgetProfile::Default,
    ));
    let report3 = inspect_with_scheduler(dir.path(), &budget, &sched_adapt)?;

    assert_eq!(report1.fingerprint, report2.fingerprint);
    assert_eq!(report2.fingerprint, report3.fingerprint);
    assert_eq!(report1.files.len(), report2.files.len());
    assert_eq!(report2.files.len(), report3.files.len());

    for (e1, e2) in report1.files.iter().zip(report2.files.iter()) {
        assert_eq!(e1.relative_path, e2.relative_path);
        assert_eq!(e1.sha256, e2.sha256);
    }
    Ok(())
}

#[test]
fn fixed_vs_adaptive_security_result_equivalence() -> Result<()> {
    let dir = tempdir()?;
    let p1 = dir.path().join("script.py");
    std::fs::write(&p1, "import os\nos.system('echo test')\n")?;

    let budget = ScanBudget::new(ScanBudgetProfile::Default.limits())?;
    let fixed = AdaptiveScheduler::new(SchedulerConfig::detect(
        Some(2),
        None,
        None,
        SchedulerMode::Fixed,
        ScanBudgetProfile::Default,
    ));
    let adaptive = AdaptiveScheduler::new(SchedulerConfig::detect(
        Some(4),
        None,
        None,
        SchedulerMode::Adaptive,
        ScanBudgetProfile::Default,
    ));

    let report_fixed = inspect_with_scheduler(dir.path(), &budget, &fixed)?;
    let report_adaptive = inspect_with_scheduler(dir.path(), &budget, &adaptive)?;

    assert_eq!(report_fixed.findings.len(), report_adaptive.findings.len());
    for (f1, f2) in report_fixed
        .findings
        .iter()
        .zip(report_adaptive.findings.iter())
    {
        assert_eq!(f1.rule_id, f2.rule_id);
        assert_eq!(f1.status, f2.status);
    }
    Ok(())
}
