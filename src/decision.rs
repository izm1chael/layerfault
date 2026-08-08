//! Canonical security decision semantics shared by CLI/reporting code.
//!
//! Layerfault decisions are monotonic: once a review reaches WARN it cannot be
//! lowered to PASS, and once it reaches BLOCK it cannot be lowered at all.

use crate::scanner::ScanStatus;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SecurityDecision {
    Pass,
    Warn,
    Block,
}

impl SecurityDecision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Block => "BLOCK",
        }
    }

    pub const fn exit_code(self) -> i32 {
        match self {
            Self::Pass => 0,
            Self::Warn => 1,
            Self::Block => 3,
        }
    }

    /// Raise the current decision if `other` is more severe.
    pub fn raise(&mut self, other: Self) {
        if other > *self {
            *self = other;
        }
    }

    pub fn from_scan_status(status: ScanStatus) -> Self {
        match status {
            ScanStatus::Pass => Self::Pass,
            ScanStatus::Warn => Self::Warn,
            ScanStatus::Fail => Self::Block,
        }
    }

    pub fn from_findings(findings: &[crate::scanner::LayerScanResult]) -> Self {
        let mut decision = Self::Pass;
        for finding in findings {
            decision.raise(Self::from_scan_status(finding.status));
            if decision == Self::Block {
                break;
            }
        }
        decision
    }

    pub const fn from_behaviour_state(state: crate::transformation::BehaviourState) -> Self {
        match state {
            crate::transformation::BehaviourState::NotRun => Self::Warn,
            crate::transformation::BehaviourState::NoSuspiciousObserved => Self::Pass,
            crate::transformation::BehaviourState::Suspicious => Self::Warn,
            crate::transformation::BehaviourState::HighRisk => Self::Block,
        }
    }

    pub const fn from_differential_behaviour_state(
        state: crate::transformation::DifferentialBehaviourState,
    ) -> Self {
        match state {
            crate::transformation::DifferentialBehaviourState::Expected
            | crate::transformation::DifferentialBehaviourState::NeutralVariation => Self::Pass,
            crate::transformation::DifferentialBehaviourState::NotRun
            | crate::transformation::DifferentialBehaviourState::CapabilityChange => Self::Warn,
            crate::transformation::DifferentialBehaviourState::SecurityRegression
            | crate::transformation::DifferentialBehaviourState::SuspiciousTrigger
            | crate::transformation::DifferentialBehaviourState::HighRiskBehaviour => Self::Block,
        }
    }
}

impl std::fmt::Display for SecurityDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::SecurityDecision;

    #[test]
    fn decisions_are_monotonic() {
        let mut decision = SecurityDecision::Pass;
        decision.raise(SecurityDecision::Warn);
        assert_eq!(decision, SecurityDecision::Warn);
        decision.raise(SecurityDecision::Pass);
        assert_eq!(decision, SecurityDecision::Warn);
        decision.raise(SecurityDecision::Block);
        assert_eq!(decision, SecurityDecision::Block);
        decision.raise(SecurityDecision::Warn);
        assert_eq!(decision, SecurityDecision::Block);
    }

    #[test]
    fn exit_codes_match_cli_contract() {
        assert_eq!(SecurityDecision::Pass.exit_code(), 0);
        assert_eq!(SecurityDecision::Warn.exit_code(), 1);
        assert_eq!(SecurityDecision::Block.exit_code(), 3);
        assert_eq!(
            SecurityDecision::from_behaviour_state(crate::transformation::BehaviourState::HighRisk),
            SecurityDecision::Block
        );
        assert_eq!(
            SecurityDecision::from_differential_behaviour_state(
                crate::transformation::DifferentialBehaviourState::CapabilityChange
            ),
            SecurityDecision::Warn
        );
    }
}
