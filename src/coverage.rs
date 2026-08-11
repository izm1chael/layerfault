//! Generalised scan-coverage accounting.
//!
//! A PASS only means something alongside what was actually examined. Layerfault
//! previously expressed coverage three different ways: inline JSON in the hub
//! review paths, a coverage string in weight analysis, and a typed struct in
//! dataset scanning. This module is the shared shape, so incomplete scanning can
//! never be presented as a clean PASS anywhere in the tool.

use crate::finding_evidence::{coverage_gap, EvidenceSubject, FindingEvidence};

/// What a scan actually examined, and what it did not.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Coverage {
    /// False whenever anything relevant was skipped, truncated or failed.
    pub complete: bool,
    #[serde(default)]
    pub files_discovered: u64,
    #[serde(default)]
    pub files_scanned: u64,
    #[serde(default)]
    pub omitted: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub omitted_examples: Vec<String>,
    #[serde(default)]
    pub bytes_scanned: u64,
    #[serde(default)]
    pub parser_failures: u64,
    #[serde(default)]
    pub evidence_limits_reached: bool,
    /// Human-readable explanations for every incompleteness above.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
    /// Additive accounting detail for an invocation budget exhaustion.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub budget: Vec<crate::budget::BudgetUsage>,
    /// "incomplete" once a deadline/cancellation checkpoint has tripped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_state: Option<String>,
    /// "deadline" | "cancelled", set alongside `scan_state`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_reason: Option<String>,
    /// Wall-clock milliseconds from invocation start to completion/interruption.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<u64>,
}

impl Coverage {
    /// A complete scan of `files_scanned` members totalling `bytes_scanned`.
    pub fn complete(files_scanned: u64, bytes_scanned: u64) -> Self {
        Self {
            complete: true,
            files_discovered: files_scanned,
            files_scanned,
            bytes_scanned,
            ..Self::default()
        }
    }

    /// Record that members were deliberately not examined.
    pub fn omit(&mut self, count: u64, reason: &str, examples: &[String]) {
        if count == 0 {
            return;
        }
        self.omitted = self.omitted.saturating_add(count);
        self.complete = false;
        self.note(reason);
        for example in examples.iter().take(8) {
            if !self.omitted_examples.contains(example) {
                self.omitted_examples.push(example.clone());
            }
        }
    }

    /// Record that a parser could not complete.
    pub fn parser_failure(&mut self, reason: &str) {
        self.parser_failures = self.parser_failures.saturating_add(1);
        self.complete = false;
        self.note(reason);
    }

    /// Record that evidence collection hit its bounded limits.
    pub fn evidence_limited(&mut self, reason: &str) {
        self.evidence_limits_reached = true;
        self.complete = false;
        self.note(reason);
    }

    pub fn budget_exhausted(&mut self, usage: crate::budget::BudgetUsage, reason: &str) {
        self.complete = false;
        self.note(reason);
        if !self
            .budget
            .iter()
            .any(|item| item.dimension == usage.dimension && item.scope == usage.scope)
        {
            self.budget.push(usage);
        }
    }

    /// Record that a checkpoint tripped a deadline/cancellation. Unlike other
    /// budget exhaustion, callers use this alongside retaining whatever
    /// findings were already produced, since the scan was interrupted rather
    /// than exceeding a resource cap on the work it attempted.
    pub fn mark_control_interrupted(
        &mut self,
        failure: crate::budget::BudgetFailure,
        usage: crate::budget::BudgetUsage,
    ) {
        let (reason, code) = match failure {
            crate::budget::BudgetFailure::Deadline => ("scan deadline exceeded", "deadline"),
            crate::budget::BudgetFailure::Cancelled => ("scan cancelled", "cancelled"),
            _ => ("scan interrupted", "interrupted"),
        };
        self.complete = false;
        self.note(reason);
        // Upsert rather than the plain insert-if-absent `budget_exhausted`
        // uses: an unconditional per-dimension snapshot (taken with
        // `failure: None`) is commonly recorded on `self.budget` earlier in
        // the same report, and that entry must not shadow this one — a
        // silently-dropped control failure would leave `control_interrupted`
        // seeing no evidence of the interruption at all.
        self.budget
            .retain(|item| !(item.dimension == usage.dimension && item.scope == usage.scope));
        self.budget.push(usage);
        self.scan_state = Some("incomplete".to_owned());
        self.control_reason = Some(code.to_owned());
    }

    /// Record the total wall-clock elapsed time for this invocation.
    pub fn set_elapsed_ms(&mut self, elapsed_ms: u64) {
        self.elapsed_ms = Some(elapsed_ms);
    }

    /// True when this coverage gap was caused by a deadline/cancellation
    /// rather than by an ordinary resource-budget cap or parser limitation.
    /// Used to decide whether an interrupted scan may report PASS/WARN.
    pub fn control_interrupted(&self) -> bool {
        self.budget.iter().any(|item| {
            item.failure
                .is_some_and(crate::budget::BudgetFailure::is_control)
        })
    }

    fn note(&mut self, reason: &str) {
        let reason = reason.to_owned();
        if !self.reasons.contains(&reason) {
            self.reasons.push(reason);
        }
    }

    /// Merge another coverage record into this one.
    pub fn absorb(&mut self, other: &Coverage) {
        self.complete &= other.complete;
        self.files_discovered = self.files_discovered.saturating_add(other.files_discovered);
        self.files_scanned = self.files_scanned.saturating_add(other.files_scanned);
        self.omitted = self.omitted.saturating_add(other.omitted);
        self.bytes_scanned = self.bytes_scanned.saturating_add(other.bytes_scanned);
        self.parser_failures = self.parser_failures.saturating_add(other.parser_failures);
        self.evidence_limits_reached |= other.evidence_limits_reached;
        for usage in &other.budget {
            if !self
                .budget
                .iter()
                .any(|item| item.dimension == usage.dimension && item.scope == usage.scope)
            {
                self.budget.push(usage.clone());
            }
        }
        for example in &other.omitted_examples {
            if self.omitted_examples.len() < 8 && !self.omitted_examples.contains(example) {
                self.omitted_examples.push(example.clone());
            }
        }
        for reason in &other.reasons {
            self.note(reason);
        }
        if other.scan_state.is_some() {
            self.scan_state = other.scan_state.clone();
            self.control_reason = other.control_reason.clone();
        }
        self.elapsed_ms = match (self.elapsed_ms, other.elapsed_ms) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
    }

    /// Evidence records describing each coverage gap, for attachment to a
    /// finding or an evidence bundle.
    pub fn gap_evidence(&self, subject: &EvidenceSubject) -> Vec<FindingEvidence> {
        if self.complete {
            return Vec::new();
        }
        self.reasons
            .iter()
            .map(|reason| coverage_gap(subject.clone(), reason))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omission_marks_coverage_incomplete() {
        let mut coverage = Coverage::complete(10, 1024);
        assert!(coverage.complete);
        coverage.omit(4, "configured file limit reached", &["big.bin".to_owned()]);
        assert!(!coverage.complete);
        assert_eq!(coverage.omitted, 4);
        assert_eq!(coverage.reasons.len(), 1);
    }

    #[test]
    fn reasons_are_deduplicated() {
        let mut coverage = Coverage::complete(1, 1);
        coverage.parser_failure("unreadable member");
        coverage.parser_failure("unreadable member");
        assert_eq!(coverage.reasons.len(), 1);
        assert_eq!(coverage.parser_failures, 2);
    }

    #[test]
    fn absorb_preserves_incompleteness() {
        let mut first = Coverage::complete(2, 10);
        let mut second = Coverage::complete(3, 20);
        second.evidence_limited("evidence budget exhausted");
        first.absorb(&second);
        assert!(!first.complete);
        assert_eq!(first.files_scanned, 5);
        assert!(first.evidence_limits_reached);
    }

    #[test]
    fn complete_coverage_emits_no_gaps() {
        let coverage = Coverage::complete(1, 1);
        assert!(coverage
            .gap_evidence(&EvidenceSubject::member("a"))
            .is_empty());
    }

    fn wall_clock_usage(failure: crate::budget::BudgetFailure) -> crate::budget::BudgetUsage {
        crate::budget::BudgetUsage {
            dimension: crate::budget::BudgetDimension::WallClock,
            configured_limit: 1000,
            consumed: 0,
            reserved: 0,
            subsystem: "root".to_owned(),
            operation: "test".to_owned(),
            scope: "invocation".to_owned(),
            failure: Some(failure),
        }
    }

    #[test]
    fn control_interrupted_only_true_for_deadline_or_cancelled() {
        let mut coverage = Coverage::complete(1, 1);
        assert!(!coverage.control_interrupted());
        coverage.mark_control_interrupted(
            crate::budget::BudgetFailure::Deadline,
            wall_clock_usage(crate::budget::BudgetFailure::Deadline),
        );
        assert!(!coverage.complete);
        assert!(coverage.control_interrupted());
        assert_eq!(coverage.scan_state.as_deref(), Some("incomplete"));
        assert_eq!(coverage.control_reason.as_deref(), Some("deadline"));
    }

    #[test]
    fn ordinary_incompleteness_does_not_set_control_interrupted() {
        let mut coverage = Coverage::complete(1, 1);
        coverage.evidence_limited("evidence budget exhausted");
        assert!(!coverage.complete);
        assert!(!coverage.control_interrupted());
        assert!(coverage.scan_state.is_none());
    }

    #[test]
    fn elapsed_ms_is_absorbed_as_max() {
        let mut first = Coverage::complete(1, 1);
        first.set_elapsed_ms(10);
        let mut second = Coverage::complete(1, 1);
        second.set_elapsed_ms(50);
        first.absorb(&second);
        assert_eq!(first.elapsed_ms, Some(50));
    }
}
