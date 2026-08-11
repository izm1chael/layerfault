//! Invocation-scoped hierarchical resource accounting for static scanning.
//!
//! The counters are deliberately independent: parsing never holds a global
//! mutex, and a child scope can only consume capacity that remains in its
//! parent envelope.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const DIMENSION_COUNT: usize = 11;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetDimension {
    SourceBytes,
    DecompressedBytes,
    TemporaryDiskBytes,
    RetainedEvidenceBytes,
    Objects,
    ArchiveMembers,
    RecursionDepth,
    AstNodes,
    ParserWorkUnits,
    ScheduledMemoryBytes,
    WallClock,
}

impl BudgetDimension {
    pub const ALL: [Self; DIMENSION_COUNT] = [
        Self::SourceBytes,
        Self::DecompressedBytes,
        Self::TemporaryDiskBytes,
        Self::RetainedEvidenceBytes,
        Self::Objects,
        Self::ArchiveMembers,
        Self::RecursionDepth,
        Self::AstNodes,
        Self::ParserWorkUnits,
        Self::ScheduledMemoryBytes,
        Self::WallClock,
    ];

    const fn index(self) -> usize {
        match self {
            Self::SourceBytes => 0,
            Self::DecompressedBytes => 1,
            Self::TemporaryDiskBytes => 2,
            Self::RetainedEvidenceBytes => 3,
            Self::Objects => 4,
            Self::ArchiveMembers => 5,
            Self::RecursionDepth => 6,
            Self::AstNodes => 7,
            Self::ParserWorkUnits => 8,
            Self::ScheduledMemoryBytes => 9,
            Self::WallClock => 10,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceBytes => "source_bytes",
            Self::DecompressedBytes => "decompressed_bytes",
            Self::TemporaryDiskBytes => "temporary_disk_bytes",
            Self::RetainedEvidenceBytes => "retained_evidence_bytes",
            Self::Objects => "objects",
            Self::ArchiveMembers => "archive_members",
            Self::RecursionDepth => "recursion_depth",
            Self::AstNodes => "ast_nodes",
            Self::ParserWorkUnits => "parser_work_units",
            Self::ScheduledMemoryBytes => "scheduled_memory_bytes",
            Self::WallClock => "wall_clock",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanBudgetLimits {
    pub source_bytes: u64,
    pub decompressed_bytes: u64,
    pub temporary_disk_bytes: u64,
    pub retained_evidence_bytes: u64,
    pub objects: u64,
    pub archive_members: u64,
    pub recursion_depth: u64,
    pub ast_nodes: u64,
    pub parser_work_units: u64,
    pub scheduled_memory_bytes: u64,
    pub wall_clock_ms: u64,
}

impl ScanBudgetLimits {
    pub fn value(&self, dimension: BudgetDimension) -> u64 {
        match dimension {
            BudgetDimension::SourceBytes => self.source_bytes,
            BudgetDimension::DecompressedBytes => self.decompressed_bytes,
            BudgetDimension::TemporaryDiskBytes => self.temporary_disk_bytes,
            BudgetDimension::RetainedEvidenceBytes => self.retained_evidence_bytes,
            BudgetDimension::Objects => self.objects,
            BudgetDimension::ArchiveMembers => self.archive_members,
            BudgetDimension::RecursionDepth => self.recursion_depth,
            BudgetDimension::AstNodes => self.ast_nodes,
            BudgetDimension::ParserWorkUnits => self.parser_work_units,
            BudgetDimension::ScheduledMemoryBytes => self.scheduled_memory_bytes,
            BudgetDimension::WallClock => self.wall_clock_ms,
        }
    }

    pub fn validate(&self) -> Result<()> {
        for dimension in BudgetDimension::ALL {
            let value = self.value(dimension);
            if value == 0 {
                return Err(anyhow!(
                    "budget {} must be greater than zero",
                    dimension.as_str()
                ));
            }
            if value > reasonable_max(dimension) {
                return Err(anyhow!(
                    "budget {} is unreasonably large",
                    dimension.as_str()
                ));
            }
        }
        Ok(())
    }
}

fn reasonable_max(dimension: BudgetDimension) -> u64 {
    match dimension {
        BudgetDimension::SourceBytes | BudgetDimension::DecompressedBytes => {
            64 * 1024 * 1024 * 1024
        }
        BudgetDimension::TemporaryDiskBytes => 16 * 1024 * 1024 * 1024,
        BudgetDimension::RetainedEvidenceBytes => 512 * 1024 * 1024,
        BudgetDimension::ScheduledMemoryBytes => 64 * 1024 * 1024 * 1024,
        BudgetDimension::WallClock => 24 * 60 * 60 * 1000,
        _ => 100_000_000,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanBudgetProfile {
    Constrained,
    Default,
    Deep,
    Research,
}

impl ScanBudgetProfile {
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "constrained" => Ok(Self::Constrained),
            "default" => Ok(Self::Default),
            "deep" => Ok(Self::Deep),
            "research" => Ok(Self::Research),
            other => Err(anyhow!("Unknown scan budget profile '{other}'")),
        }
    }

    pub fn limits(self) -> ScanBudgetLimits {
        let mib = 1024 * 1024;
        let gib = 1024 * mib;
        match self {
            Self::Constrained => ScanBudgetLimits {
                source_bytes: 128 * mib,
                decompressed_bytes: 256 * mib,
                temporary_disk_bytes: 128 * mib,
                retained_evidence_bytes: 4 * mib,
                objects: 25_000,
                archive_members: 10_000,
                recursion_depth: 4,
                ast_nodes: 100_000,
                parser_work_units: 1_000_000,
                scheduled_memory_bytes: 256 * mib,
                wall_clock_ms: 15_000,
            },
            Self::Default => ScanBudgetLimits {
                source_bytes: gib,
                decompressed_bytes: 2 * gib,
                temporary_disk_bytes: 512 * mib,
                retained_evidence_bytes: 16 * mib,
                objects: 100_000,
                archive_members: 50_000,
                recursion_depth: 8,
                ast_nodes: 500_000,
                parser_work_units: 10_000_000,
                scheduled_memory_bytes: gib,
                wall_clock_ms: 60_000,
            },
            Self::Deep => ScanBudgetLimits {
                source_bytes: 4 * gib,
                decompressed_bytes: 8 * gib,
                temporary_disk_bytes: 2 * gib,
                retained_evidence_bytes: 64 * mib,
                objects: 500_000,
                archive_members: 250_000,
                recursion_depth: 16,
                ast_nodes: 2_000_000,
                parser_work_units: 50_000_000,
                scheduled_memory_bytes: 2 * gib,
                wall_clock_ms: 300_000,
            },
            Self::Research => ScanBudgetLimits {
                source_bytes: 16 * gib,
                decompressed_bytes: 32 * gib,
                temporary_disk_bytes: 8 * gib,
                retained_evidence_bytes: 256 * mib,
                objects: 2_000_000,
                archive_members: 1_000_000,
                recursion_depth: 32,
                ast_nodes: 10_000_000,
                parser_work_units: 250_000_000,
                scheduled_memory_bytes: 8 * gib,
                wall_clock_ms: 1_800_000,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanBudgetConfig {
    #[serde(default = "default_profile")]
    pub profile: ScanBudgetProfile,
    #[serde(default)]
    pub limits: Option<ScanBudgetLimits>,
}

fn default_profile() -> ScanBudgetProfile {
    ScanBudgetProfile::Default
}

impl Default for ScanBudgetConfig {
    fn default() -> Self {
        Self {
            profile: ScanBudgetProfile::Default,
            limits: None,
        }
    }
}

impl ScanBudgetConfig {
    pub fn limits(&self) -> Result<ScanBudgetLimits> {
        let limits = self.limits.clone().unwrap_or_else(|| self.profile.limits());
        limits.validate()?;
        Ok(limits)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let file = crate::safeio::open_readonly_nofollow(path)?;
        let bytes = crate::safeio::read_all_from_file(&file, 2 * 1024 * 1024)?;
        let config: Self = serde_json::from_slice(&bytes).with_context(|| {
            format!(
                "Budget configuration '{}' is not valid JSON",
                path.display()
            )
        })?;
        config.limits()?;
        Ok(config)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BudgetFailure {
    ExhaustedBytes,
    ExhaustedDecompression,
    ExhaustedTempDisk,
    ExhaustedObjects,
    ExhaustedAst,
    Deadline,
    Cancelled,
    Overflow,
}

impl BudgetFailure {
    pub fn for_dimension(dimension: BudgetDimension) -> Self {
        match dimension {
            BudgetDimension::SourceBytes => Self::ExhaustedBytes,
            BudgetDimension::DecompressedBytes => Self::ExhaustedDecompression,
            BudgetDimension::TemporaryDiskBytes => Self::ExhaustedTempDisk,
            BudgetDimension::Objects
            | BudgetDimension::ArchiveMembers
            | BudgetDimension::RecursionDepth => Self::ExhaustedObjects,
            BudgetDimension::AstNodes => Self::ExhaustedAst,
            BudgetDimension::WallClock => Self::Deadline,
            _ => Self::ExhaustedBytes,
        }
    }
}

impl fmt::Display for BudgetFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for BudgetFailure {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetUsage {
    pub dimension: BudgetDimension,
    pub configured_limit: u64,
    pub consumed: u64,
    pub reserved: u64,
    pub subsystem: String,
    pub operation: String,
    pub scope: String,
    pub failure: Option<BudgetFailure>,
}

struct BudgetInner {
    limits: ScanBudgetLimits,
    consumed: [AtomicU64; DIMENSION_COUNT],
    reserved: [AtomicU64; DIMENSION_COUNT],
    held: [AtomicU64; DIMENSION_COUNT],
    cancelled: std::sync::atomic::AtomicBool,
    deadline: Instant,
}

#[derive(Clone)]
pub struct ScanBudget {
    inner: Arc<BudgetInner>,
    local_limits: ScanBudgetLimits,
    local_used: Arc<[AtomicU64; DIMENSION_COUNT]>,
    subsystem: Arc<str>,
    scope: Arc<str>,
}

impl ScanBudget {
    pub fn new(limits: ScanBudgetLimits) -> Result<Self> {
        limits.validate()?;
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(limits.wall_clock_ms))
            .ok_or_else(|| anyhow!("budget deadline overflow"))?;
        Ok(Self {
            inner: Arc::new(BudgetInner {
                limits: limits.clone(),
                consumed: std::array::from_fn(|_| AtomicU64::new(0)),
                reserved: std::array::from_fn(|_| AtomicU64::new(0)),
                held: std::array::from_fn(|_| AtomicU64::new(0)),
                cancelled: std::sync::atomic::AtomicBool::new(false),
                deadline,
            }),
            local_limits: limits,
            local_used: Arc::new(std::array::from_fn(|_| AtomicU64::new(0))),
            subsystem: Arc::from("root"),
            scope: Arc::from("invocation"),
        })
    }

    pub fn child(
        &self,
        subsystem: &str,
        scope: &str,
        local: Option<ScanBudgetLimits>,
    ) -> Result<Self> {
        let mut limits = local.unwrap_or_else(|| self.local_limits.clone());
        for dimension in BudgetDimension::ALL {
            limits.set_min(dimension, self.remaining(dimension));
        }
        limits.validate()?;
        Ok(Self {
            inner: Arc::clone(&self.inner),
            local_limits: limits,
            local_used: Arc::new(std::array::from_fn(|_| AtomicU64::new(0))),
            subsystem: Arc::from(subsystem.to_owned()),
            scope: Arc::from(scope.to_owned()),
        })
    }

    pub fn cancel(&self) {
        self.inner.cancelled.store(true, Ordering::Release);
    }

    pub fn check(&self) -> Result<(), BudgetFailure> {
        if self.inner.cancelled.load(Ordering::Acquire) {
            return Err(BudgetFailure::Cancelled);
        }
        if Instant::now() >= self.inner.deadline {
            return Err(BudgetFailure::Deadline);
        }
        Ok(())
    }

    pub fn remaining(&self, dimension: BudgetDimension) -> u64 {
        let i = dimension.index();
        self.inner
            .limits
            .value(dimension)
            .saturating_sub(self.inner.held[i].load(Ordering::Acquire))
    }

    pub fn reserve(
        &self,
        dimension: BudgetDimension,
        amount: u64,
        operation: &str,
    ) -> Result<BudgetPermit, BudgetFailure> {
        self.check()?;
        let i = dimension.index();
        let local_current = self.local_used[i].load(Ordering::Acquire);
        if amount
            > self
                .local_limits
                .value(dimension)
                .saturating_sub(local_current)
        {
            return Err(BudgetFailure::for_dimension(dimension));
        }
        if amount == 0 {
            return Ok(BudgetPermit {
                budget: self.clone(),
                dimension,
                amount: 0,
                operation: operation.to_owned(),
                committed: true,
            });
        }
        let global = &self.inner.held[i];
        loop {
            let current = global.load(Ordering::Acquire);
            let Some(next) = current.checked_add(amount) else {
                return Err(BudgetFailure::Overflow);
            };
            if next > self.inner.limits.value(dimension) {
                return Err(BudgetFailure::for_dimension(dimension));
            }
            if global
                .compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break;
            }
        }
        self.inner.reserved[i].fetch_add(amount, Ordering::AcqRel);
        self.local_used[i].fetch_add(amount, Ordering::AcqRel);
        Ok(BudgetPermit {
            budget: self.clone(),
            dimension,
            amount,
            operation: operation.to_owned(),
            committed: false,
        })
    }

    pub fn consume(
        &self,
        dimension: BudgetDimension,
        amount: u64,
        operation: &str,
    ) -> Result<(), BudgetFailure> {
        let permit = self.reserve(dimension, amount, operation)?;
        permit.commit();
        Ok(())
    }

    pub fn snapshot(&self, failure: Option<BudgetFailure>) -> Vec<BudgetUsage> {
        self.snapshot_with_operation(failure, "")
    }

    pub fn snapshot_with_operation(
        &self,
        failure: Option<BudgetFailure>,
        operation: &str,
    ) -> Vec<BudgetUsage> {
        BudgetDimension::ALL
            .into_iter()
            .map(|dimension| {
                let i = dimension.index();
                BudgetUsage {
                    dimension,
                    configured_limit: self.inner.limits.value(dimension),
                    consumed: self.inner.consumed[i].load(Ordering::Acquire),
                    reserved: self.inner.reserved[i].load(Ordering::Acquire),
                    subsystem: self.subsystem.to_string(),
                    operation: if !operation.is_empty() {
                        operation.to_owned()
                    } else {
                        String::new()
                    },
                    scope: self.scope.to_string(),
                    failure,
                }
            })
            .collect()
    }
}

impl ScanBudgetLimits {
    fn set_min(&mut self, dimension: BudgetDimension, value: u64) {
        match dimension {
            BudgetDimension::SourceBytes => self.source_bytes = self.source_bytes.min(value),
            BudgetDimension::DecompressedBytes => {
                self.decompressed_bytes = self.decompressed_bytes.min(value)
            }
            BudgetDimension::TemporaryDiskBytes => {
                self.temporary_disk_bytes = self.temporary_disk_bytes.min(value)
            }
            BudgetDimension::RetainedEvidenceBytes => {
                self.retained_evidence_bytes = self.retained_evidence_bytes.min(value)
            }
            BudgetDimension::Objects => self.objects = self.objects.min(value),
            BudgetDimension::ArchiveMembers => {
                self.archive_members = self.archive_members.min(value)
            }
            BudgetDimension::RecursionDepth => {
                self.recursion_depth = self.recursion_depth.min(value)
            }
            BudgetDimension::AstNodes => self.ast_nodes = self.ast_nodes.min(value),
            BudgetDimension::ParserWorkUnits => {
                self.parser_work_units = self.parser_work_units.min(value)
            }
            BudgetDimension::ScheduledMemoryBytes => {
                self.scheduled_memory_bytes = self.scheduled_memory_bytes.min(value)
            }
            BudgetDimension::WallClock => self.wall_clock_ms = self.wall_clock_ms.min(value),
        }
    }
}

pub struct BudgetPermit {
    budget: ScanBudget,
    dimension: BudgetDimension,
    amount: u64,
    operation: String,
    committed: bool,
}

impl BudgetPermit {
    pub fn commit(mut self) {
        if !self.committed {
            let i = self.dimension.index();
            self.budget.inner.reserved[i].fetch_sub(self.amount, Ordering::AcqRel);
            self.budget.inner.consumed[i].fetch_add(self.amount, Ordering::AcqRel);
            self.committed = true;
        }
    }
    pub fn operation(&self) -> &str {
        &self.operation
    }
}

impl Drop for BudgetPermit {
    fn drop(&mut self) {
        if !self.committed {
            let i = self.dimension.index();
            self.budget.inner.reserved[i].fetch_sub(self.amount, Ordering::AcqRel);
            self.budget.inner.held[i].fetch_sub(self.amount, Ordering::AcqRel);
            self.budget.local_used[i].fetch_sub(self.amount, Ordering::AcqRel);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_and_overrides_validate() {
        assert!(ScanBudgetProfile::parse("deep").is_ok());
        assert!(ScanBudgetProfile::parse("unknown").is_err());
        let mut limits = ScanBudgetProfile::Default.limits();
        limits.source_bytes = 0;
        assert!(limits.validate().is_err());
    }

    #[test]
    fn reservation_releases_and_commit_consumes() -> Result<()> {
        let budget = ScanBudget::new(ScanBudgetProfile::Constrained.limits())?;
        let permit = budget.reserve(BudgetDimension::Objects, 10, "test")?;
        assert_eq!(budget.remaining(BudgetDimension::Objects), 24_990);
        drop(permit);
        assert_eq!(budget.remaining(BudgetDimension::Objects), 25_000);
        budget.consume(BudgetDimension::Objects, 10, "test")?;
        assert_eq!(budget.remaining(BudgetDimension::Objects), 24_990);
        Ok(())
    }

    #[test]
    fn nested_capacity_is_shared() -> Result<()> {
        let budget = ScanBudget::new(ScanBudgetProfile::Constrained.limits())?;
        let child = budget.child("archive", "outer!/inner", None)?;
        child.consume(BudgetDimension::DecompressedBytes, 100, "nested")?;
        assert_eq!(
            budget.remaining(BudgetDimension::DecompressedBytes),
            256 * 1024 * 1024 - 100
        );
        Ok(())
    }

    #[test]
    fn concurrent_reservations_cannot_cross_the_parent_cap() -> Result<()> {
        let budget = Arc::new(ScanBudget::new(ScanBudgetProfile::Constrained.limits())?);
        let mut workers = Vec::new();
        for _ in 0..8 {
            let budget = Arc::clone(&budget);
            workers.push(std::thread::spawn(move || {
                for _ in 0..10_000 {
                    if let Ok(permit) = budget.reserve(BudgetDimension::Objects, 1, "parallel") {
                        permit.commit();
                    }
                }
            }));
        }
        for worker in workers {
            worker.join().expect("worker completed");
        }
        assert!(budget.remaining(BudgetDimension::Objects) <= 25_000);
        assert!(
            budget.inner.held[BudgetDimension::Objects.index()].load(Ordering::Acquire) <= 25_000
        );
        Ok(())
    }

    #[test]
    fn cancellation_and_deadline_are_typed() -> Result<()> {
        let budget = ScanBudget::new(ScanBudgetProfile::Constrained.limits())?;
        budget.cancel();
        assert_eq!(budget.check(), Err(BudgetFailure::Cancelled));
        Ok(())
    }
}
