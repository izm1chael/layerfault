//! The canonical Layerfault detector rule registry.
//!
//! Rule identities and their evidence specifications are stored in the single
//! authoritative catalogue in `src/explain.rs`. This module provides the rule
//! specification lookup API (`spec`, `all_rule_ids`) backed by that catalogue.

use crate::scanner::heuristics;

pub use crate::explain::EvidenceRequirement;

/// A declared detector rule specification.
#[derive(Debug, Clone, Copy)]
pub struct RuleSpec {
    pub rule_id: &'static str,
    pub evidence_requirement: EvidenceRequirement,
    /// Why this rule is not `Required`, when it is not. Enforced by the gate.
    pub requirement_reason: &'static str,
}

/// Look up a rule's declared evidence strategy.
///
/// Heuristic signature IDs (`T1-001`..`T14-003`) are resolved from the signature
/// table so the registry cannot drift from the detector data it describes.
pub fn spec(rule_id: &str) -> Option<RuleSpec> {
    let explanation = crate::explain::lookup(rule_id)?;
    Some(RuleSpec {
        rule_id: explanation.rule_id,
        evidence_requirement: explanation.evidence_requirement,
        requirement_reason: explanation.requirement_reason,
    })
}

/// Every declared rule identity, including the data-driven heuristic signatures.
pub fn all_rule_ids() -> Vec<String> {
    let mut out: Vec<String> = crate::explain::CATALOGUE
        .iter()
        .map(|entry| entry.rule_id.to_owned())
        .collect();
    out.extend(heuristics::signature_ids().into_iter().map(str::to_owned));
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_has_no_duplicates() {
        let mut ids: Vec<&str> = crate::explain::CATALOGUE
            .iter()
            .map(|entry| entry.rule_id)
            .collect();
        let total = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), total, "duplicate rule id in the registry");
    }

    #[test]
    fn rule_ids_are_uppercase_and_tagged() {
        for entry in crate::explain::CATALOGUE {
            assert_eq!(
                entry.rule_id,
                entry.rule_id.to_ascii_uppercase(),
                "rule ids must be uppercase: {}",
                entry.rule_id
            );
            assert!(
                entry.rule_id.starts_with("LF-") || entry.rule_id.starts_with('T'),
                "unexpected rule id prefix: {}",
                entry.rule_id
            );
        }
    }

    #[test]
    fn non_required_rules_document_why() {
        for entry in crate::explain::CATALOGUE {
            if entry.evidence_requirement != EvidenceRequirement::Required {
                assert!(
                    !entry.requirement_reason.trim().is_empty(),
                    "{} must document why it is not evidence-required",
                    entry.rule_id
                );
            }
        }
    }

    #[test]
    fn heuristic_signatures_resolve() {
        assert!(spec("T3-004").is_some());
        assert!(spec("LF-CODE-SUBPROCESS").is_some());
        assert!(spec("LF-NOT-A-REAL-RULE").is_none());
    }
}
