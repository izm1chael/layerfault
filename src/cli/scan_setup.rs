use super::args::ScanCommon;
use super::validation::load_verifying_key;
use anyhow::Result;
use ed25519_dalek::VerifyingKey;
use layerfault::app::{self, ScanOptions};
use layerfault::policy::{self, PolicyDocument, PolicyProfile};
use layerfault::trust::TrustStore;
use layerfault::{provenance, ThresholdConfig};
use std::path::Path;

pub(crate) struct Prepared {
    pub(crate) thresholds: ThresholdConfig,
    pub(crate) verifying_key: Option<VerifyingKey>,
    pub(crate) trust_store: TrustStore,
    pub(crate) policy: policy::EffectivePolicy,
    pub(crate) budget: layerfault::budget::ScanBudget,
    pub(crate) scheduler: layerfault::scheduler::AdaptiveScheduler,
}

pub(crate) fn prepare(common: &ScanCommon) -> Result<Prepared> {
    let thresholds = ThresholdConfig {
        max_temperature: common.max_temperature,
        max_ctx: common.max_ctx,
        max_predict: common.max_predict,
    };
    let verifying_key = match common.public_key.as_deref() {
        Some(path) => Some(load_verifying_key(path)?),
        None => None,
    };
    let trust_store = TrustStore::load(common.trust_store.as_deref())?;
    let policy_doc = match common.policy_file.as_deref() {
        Some(path) => PolicyDocument::load(path)?,
        None => PolicyDocument::builtin(PolicyProfile::parse(&common.policy)?),
    };
    policy_doc.validate()?;
    let profile = layerfault::budget::ScanBudgetProfile::parse(&common.budget_profile)?;
    let budget_config = match common.budget_file.as_deref() {
        Some(path) => layerfault::budget::ScanBudgetConfig::load(path)?,
        None => layerfault::budget::ScanBudgetConfig {
            profile,
            limits: None,
        },
    };
    let mut limits = budget_config.limits()?;
    if let Some(timeout_seconds) = common.timeout_seconds {
        limits.wall_clock_ms = timeout_seconds.saturating_mul(1000);
    }
    let budget = layerfault::budget::ScanBudget::new(limits)?;
    arm_ctrlc_cancellation(&budget);

    let mode = layerfault::scheduler::SchedulerMode::parse(&common.scheduler)?;
    let scheduler_config = layerfault::scheduler::SchedulerConfig::detect(
        common.jobs,
        common.max_memory_mib,
        common.max_inflight_bytes,
        mode,
        profile,
    );
    let scheduler = layerfault::scheduler::AdaptiveScheduler::new(scheduler_config);

    Ok(Prepared {
        thresholds,
        verifying_key,
        trust_store,
        policy: policy_doc.effective(),
        budget,
        scheduler,
    })
}

/// Map Ctrl-C (SIGINT) to cooperative cancellation of this invocation's scan
/// budget, so an interactive scan can be interrupted without losing findings
/// already produced. Best-effort: a handler can only be installed once per
/// process, so a failure here (e.g. a second budget created later in the same
/// run) is not fatal — the first-installed handler still cancels its budget's
/// shared inner state via any child scope that was cloned from it.
fn arm_ctrlc_cancellation(budget: &layerfault::budget::ScanBudget) {
    let cancel_budget = budget.clone();
    let _ = ctrlc::set_handler(move || cancel_budget.cancel());
}

pub(crate) fn standalone_budget(
    profile: &str,
    file: Option<&Path>,
    timeout_seconds: Option<u64>,
) -> Result<layerfault::budget::ScanBudget> {
    let config = match file {
        Some(path) => layerfault::budget::ScanBudgetConfig::load(path)?,
        None => layerfault::budget::ScanBudgetConfig {
            profile: layerfault::budget::ScanBudgetProfile::parse(profile)?,
            limits: None,
        },
    };
    let mut limits = config.limits()?;
    if let Some(timeout_seconds) = timeout_seconds {
        limits.wall_clock_ms = timeout_seconds.saturating_mul(1000);
    }
    let budget = layerfault::budget::ScanBudget::new(limits)?;
    arm_ctrlc_cancellation(&budget);
    Ok(budget)
}

pub(crate) fn scan_options<'a>(
    common: &ScanCommon,
    prepared: &'a Prepared,
    quiet: bool,
) -> ScanOptions<'a> {
    ScanOptions {
        thresholds: &prepared.thresholds,
        verifying_key: prepared.verifying_key.as_ref(),
        trust_store: &prepared.trust_store,
        policy: &prepared.policy,
        jobs: common.jobs.unwrap_or_else(app::default_jobs),
        quiet,
        budget: prepared.budget.clone(),
        scheduler: prepared.scheduler.clone(),
    }
}

pub(crate) fn record_override(
    model: &str,
    reason: &str,
    profile: PolicyProfile,
    trust_state: provenance::TrustState,
    scanner_exit_code: i32,
    path: Option<&Path>,
) -> Result<()> {
    let record = policy::OverrideRecord {
        version: 1,
        created_unix: layerfault::paths::now_unix(),
        model: model.to_owned(),
        reason: reason.to_owned(),
        profile,
        trust_state,
        scanner_exit_code,
    };
    let path = policy::record_policy_override(&record, path)?;
    eprintln!("AUDITED POLICY OVERRIDE: {}", path.display());
    Ok(())
}
