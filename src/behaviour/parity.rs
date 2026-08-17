//! Cross-backend telemetry parity: do the strace and eBPF telemetry
//! backends reach the same security conclusion for the same probe run?
//!
//! `telemetry_backend.rs` documents, honestly, that live eBPF collection is
//! not wired up in this codebase yet
//! (`LIVE_EBPF_COLLECTION_IMPLEMENTED = false`) — the probe programs that
//! would read openat/unlinkat/renameat2/connect syscall arguments need
//! tracepoint `format` offsets this development environment cannot
//! generate or verify (no root, no debugfs tracing access,
//! `unprivileged_bpf_disabled=2`), and attachment itself has never been
//! exercised on a live kernel here. Building that collection path blind,
//! in an environment that cannot verify it loads or attaches correctly,
//! is exactly the kind of unverifiable security code this project avoids
//! elsewhere (see the MCP discovery sandbox work, which confirmed bwrap
//! primitives worked *before* writing sandboxing code against them).
//!
//! What this module does instead: build and test the comparison the plan
//! actually asks for — "identical probe suites must produce equivalent
//! security conclusions on both backends, with divergence reported rather
//! than averaged away" — entirely against the two backends' already-real,
//! already-tested output type (`evaluate::Evaluation`), with no live
//! kernel dependency at all. The moment real dual-backend collection
//! lands, this comparison is ready to consume it unchanged.

use super::evaluate::{Evaluation, Risk};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParityAgreement {
    /// Same risk level, same rule ids fired. The strongest claim this
    /// module can make — it does not mean the backends observed identical
    /// raw telemetry, only that they reached the same security conclusion.
    Full,
    /// Same risk level, but a different set of rule ids fired. Worth
    /// surfacing even though the bottom-line risk matches: a rule that
    /// fires on one backend and not the other is either a detection gap or
    /// a false positive somewhere, and averaging the two away would hide
    /// which.
    RiskMatchesRulesDiffer,
    /// Different risk levels. The backends disagree about whether this run
    /// was dangerous at all — never averaged into a single "probably fine"
    /// conclusion.
    RiskDiverges,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ParityComparison {
    pub strace_risk: Risk,
    pub ebpf_risk: Risk,
    pub agreement: ParityAgreement,
    /// Rule ids only the strace-backed evaluation reported.
    pub strace_only_rules: Vec<String>,
    /// Rule ids only the eBPF-backed evaluation reported.
    pub ebpf_only_rules: Vec<String>,
    pub shared_rules: Vec<String>,
}

impl ParityComparison {
    pub fn is_divergent(&self) -> bool {
        !matches!(self.agreement, ParityAgreement::Full)
    }
}

/// Compare two evaluations of the *same probe run*, one produced from
/// strace-backed telemetry and one from eBPF-backed telemetry. Order
/// matters only for which field each risk/rule set lands in, not for the
/// comparison logic itself.
pub fn compare(strace: &Evaluation, ebpf: &Evaluation) -> ParityComparison {
    let strace_rules: BTreeSet<&str> = strace.rule_ids.iter().map(String::as_str).collect();
    let ebpf_rules: BTreeSet<&str> = ebpf.rule_ids.iter().map(String::as_str).collect();

    let strace_only: Vec<String> = strace_rules
        .difference(&ebpf_rules)
        .map(|rule| (*rule).to_owned())
        .collect();
    let ebpf_only: Vec<String> = ebpf_rules
        .difference(&strace_rules)
        .map(|rule| (*rule).to_owned())
        .collect();
    let shared: Vec<String> = strace_rules
        .intersection(&ebpf_rules)
        .map(|rule| (*rule).to_owned())
        .collect();

    let agreement = if strace.risk != ebpf.risk {
        ParityAgreement::RiskDiverges
    } else if !strace_only.is_empty() || !ebpf_only.is_empty() {
        ParityAgreement::RiskMatchesRulesDiffer
    } else {
        ParityAgreement::Full
    };

    ParityComparison {
        strace_risk: strace.risk,
        ebpf_risk: ebpf.risk,
        agreement,
        strace_only_rules: strace_only,
        ebpf_only_rules: ebpf_only,
        shared_rules: shared,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evaluation(risk: Risk, rule_ids: &[&str]) -> Evaluation {
        Evaluation {
            risk,
            rule_ids: rule_ids.iter().map(|rule| (*rule).to_owned()).collect(),
            indicators: Vec::new(),
            evidence: Vec::new(),
        }
    }

    #[test]
    fn identical_risk_and_rules_is_full_agreement() {
        let strace = evaluation(Risk::High, &["LF-BEHAV-NETWORK-ATTEMPT"]);
        let ebpf = evaluation(Risk::High, &["LF-BEHAV-NETWORK-ATTEMPT"]);
        let comparison = compare(&strace, &ebpf);
        assert_eq!(comparison.agreement, ParityAgreement::Full);
        assert!(!comparison.is_divergent());
        assert_eq!(comparison.strace_only_rules, Vec::<String>::new());
        assert_eq!(comparison.ebpf_only_rules, Vec::<String>::new());
    }

    #[test]
    fn same_risk_different_rules_is_reported_not_averaged_away() {
        let strace = evaluation(Risk::Medium, &["LF-BEHAV-FILESYSTEM-WRITE-ATTEMPT"]);
        let ebpf = evaluation(Risk::Medium, &["LF-BEHAV-UNEXPECTED-EXEC"]);
        let comparison = compare(&strace, &ebpf);
        assert_eq!(
            comparison.agreement,
            ParityAgreement::RiskMatchesRulesDiffer
        );
        assert!(comparison.is_divergent());
        assert_eq!(
            comparison.strace_only_rules,
            vec!["LF-BEHAV-FILESYSTEM-WRITE-ATTEMPT".to_owned()]
        );
        assert_eq!(
            comparison.ebpf_only_rules,
            vec!["LF-BEHAV-UNEXPECTED-EXEC".to_owned()]
        );
    }

    #[test]
    fn different_risk_is_divergence_never_averaged() {
        let strace = evaluation(Risk::None, &[]);
        let ebpf = evaluation(Risk::High, &["LF-BEHAV-CANARY-ACCESS"]);
        let comparison = compare(&strace, &ebpf);
        assert_eq!(comparison.agreement, ParityAgreement::RiskDiverges);
        assert!(comparison.is_divergent());
    }

    #[test]
    fn shared_rules_are_reported_alongside_the_divergent_ones() {
        let strace = evaluation(
            Risk::High,
            &["LF-BEHAV-NETWORK-ATTEMPT", "LF-BEHAV-DANGEROUS-EXEC"],
        );
        let ebpf = evaluation(Risk::High, &["LF-BEHAV-NETWORK-ATTEMPT"]);
        let comparison = compare(&strace, &ebpf);
        assert_eq!(
            comparison.agreement,
            ParityAgreement::RiskMatchesRulesDiffer
        );
        assert_eq!(
            comparison.shared_rules,
            vec!["LF-BEHAV-NETWORK-ATTEMPT".to_owned()]
        );
        assert_eq!(
            comparison.strace_only_rules,
            vec!["LF-BEHAV-DANGEROUS-EXEC".to_owned()]
        );
    }
}
