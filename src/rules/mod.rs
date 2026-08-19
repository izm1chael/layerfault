//! The canonical Layerfault detector rule registry.
//!
//! Rule identities and their evidence specifications are stored in the single
//! authoritative catalogue in `src/rules/catalogue.rs`.

use crate::scanner::heuristics;

mod catalogue;
mod revision;
mod types;

pub use catalogue::CATALOGUE;
pub use revision::{build_id, ruleset_sha256, scanner_revision};
pub use types::{EvidenceRequirement, RuleExplanation, RuleMetadata};

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
    let explanation = lookup(rule_id)?;
    Some(RuleSpec {
        rule_id: explanation.rule_id,
        evidence_requirement: explanation.evidence_requirement,
        requirement_reason: explanation.requirement_reason,
    })
}

/// Every declared rule identity, including the data-driven heuristic signatures.
pub fn all_rule_ids() -> Vec<String> {
    let mut out: Vec<String> = CATALOGUE
        .iter()
        .map(|entry| entry.rule_id.to_owned())
        .collect();
    out.extend(heuristics::signature_ids().into_iter().map(str::to_owned));
    out.sort();
    out.dedup();
    out
}

pub fn lookup(rule: &str) -> Option<RuleExplanation> {
    let normalized = rule.trim().to_ascii_uppercase();
    if let Some(found) = CATALOGUE.iter().find(|m| m.rule_id == normalized) {
        return Some(found.clone());
    }
    if crate::scanner::heuristics::is_signature_id(&normalized) {
        let id = crate::scanner::heuristics::signature_id_static(&normalized)
            .unwrap_or("LF-UNCLASSIFIED");
        let meaning = crate::scanner::heuristics::signature_description(&normalized)
            .unwrap_or("Heuristic content signature matched");
        return Some(RuleMetadata {
            rule_id: id,
            rule_version: 1,
            detector_family: "heuristics",
            title: "Heuristic content signature match",
            meaning,
            why_it_matters: "Instruction-shaped text embedded in model data can be interpreted as instructions by a model or an agent that reads it.",
            remediation: "Review the matched excerpt in its surrounding context before treating this as more than a review signal.",
            limitations: "Pattern matching over text cannot distinguish an attack payload from documentation, test data or discussion of the same technique. Review the excerpt in context.",
            evidence_requirement: EvidenceRequirement::Required,
            requirement_reason: "",
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_has_no_duplicates() {
        let mut ids: Vec<&str> = CATALOGUE.iter().map(|entry| entry.rule_id).collect();
        let total = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), total, "duplicate rule id in the registry");
    }

    #[test]
    fn rule_ids_are_uppercase_and_tagged() {
        for entry in CATALOGUE {
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
        for entry in CATALOGUE {
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

    #[test]
    fn ruleset_digest_stable_across_split() {
        // Captured before the family-grouped catalogue split. Only the four
        // identity fields (rule_id, rule_version, detector_family,
        // evidence_requirement) participate in the digest; prose edits are
        // inert, any structural identity change flips this hash.
        assert_eq!(
            ruleset_sha256(),
            "sha256:d49aa171fc821b8c3c20930a82a81b2bed8fe5bcb6673f7a0fd2297d127975fe"
        );
    }
}
