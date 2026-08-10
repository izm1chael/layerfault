//! Bounded-work limits for dependency-manifest parsing.
//!
//! Modeled directly on [`crate::archive::limits::ArchiveLimits`] /
//! `ArchiveBudgetTracker`: every parser in this module walks attacker-supplied
//! manifest/lockfile text, so depth, count and size must be bounded the same
//! way archive extraction is bounded.

use std::collections::BTreeSet;

#[derive(Debug, Clone)]
pub struct DependencyParseLimits {
    pub max_manifest_bytes: u64,
    pub max_requirement_lines: usize,
    pub max_include_depth: usize,
    pub max_includes_total: usize,
    pub max_lockfile_entries: usize,
    pub max_toml_nesting_depth: usize,
    pub max_yaml_nesting_depth: usize,
    pub max_string_literal_bytes: usize,
}

impl Default for DependencyParseLimits {
    fn default() -> Self {
        Self {
            max_manifest_bytes: 8 * 1024 * 1024,
            max_requirement_lines: 20_000,
            max_include_depth: 8,
            max_includes_total: 64,
            max_lockfile_entries: 20_000,
            max_toml_nesting_depth: 64,
            max_yaml_nesting_depth: 64,
            max_string_literal_bytes: 4096,
        }
    }
}

/// Tracks cumulative work across a manifest's `-r`/`-c` include tree so a
/// hostile chain of includes cannot force unbounded parsing or infinite
/// recursion.
#[derive(Debug, Clone)]
pub struct DependencyBudgetTracker {
    pub limits: DependencyParseLimits,
    include_depth: usize,
    includes_seen: usize,
    visited_includes: BTreeSet<String>,
    lines_seen: usize,
    entries_seen: usize,
}

impl DependencyBudgetTracker {
    pub fn new(limits: DependencyParseLimits) -> Self {
        Self {
            limits,
            include_depth: 0,
            includes_seen: 0,
            visited_includes: BTreeSet::new(),
            lines_seen: 0,
            entries_seen: 0,
        }
    }

    /// Enter a `-r`/`-c` include. Returns an error describing depth, cumulative
    /// count, or cycle bound violations; the caller must turn this into a
    /// bounded finding/coverage note rather than propagating a hard failure.
    pub fn enter_include(&mut self, canonical_rel: &str) -> Result<(), String> {
        self.include_depth += 1;
        self.includes_seen += 1;
        if self.include_depth > self.limits.max_include_depth {
            return Err(format!(
                "Include depth {} exceeds maximum limit {}",
                self.include_depth, self.limits.max_include_depth
            ));
        }
        if self.includes_seen > self.limits.max_includes_total {
            return Err(format!(
                "Total include count {} exceeds cumulative limit {}",
                self.includes_seen, self.limits.max_includes_total
            ));
        }
        if !self.visited_includes.insert(canonical_rel.to_owned()) {
            return Err(format!(
                "Include cycle detected: '{canonical_rel}' was already visited in this resolution tree"
            ));
        }
        Ok(())
    }

    pub fn leave_include(&mut self) {
        self.include_depth = self.include_depth.saturating_sub(1);
    }

    pub fn add_line(&mut self) -> Result<(), String> {
        self.lines_seen = self.lines_seen.saturating_add(1);
        if self.lines_seen > self.limits.max_requirement_lines {
            return Err(format!(
                "Total requirement line count {} exceeds limit {}",
                self.lines_seen, self.limits.max_requirement_lines
            ));
        }
        Ok(())
    }

    pub fn add_entry(&mut self) -> Result<(), String> {
        self.entries_seen = self.entries_seen.saturating_add(1);
        if self.entries_seen > self.limits.max_lockfile_entries {
            return Err(format!(
                "Total lockfile entry count {} exceeds limit {}",
                self.entries_seen, self.limits.max_lockfile_entries
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cycle_is_detected() {
        let mut tracker = DependencyBudgetTracker::new(DependencyParseLimits::default());
        tracker.enter_include("a.txt").unwrap();
        tracker.enter_include("b.txt").unwrap();
        assert!(tracker.enter_include("a.txt").is_err());
    }

    #[test]
    fn depth_is_bounded() {
        let mut tracker = DependencyBudgetTracker::new(DependencyParseLimits {
            max_include_depth: 2,
            ..DependencyParseLimits::default()
        });
        tracker.enter_include("a.txt").unwrap();
        tracker.enter_include("b.txt").unwrap();
        assert!(tracker.enter_include("c.txt").is_err());
    }

    #[test]
    fn leave_include_allows_reentry_at_shallower_depth() {
        let mut tracker = DependencyBudgetTracker::new(DependencyParseLimits::default());
        tracker.enter_include("a.txt").unwrap();
        tracker.leave_include();
        assert_eq!(tracker.include_depth, 0);
    }
}
