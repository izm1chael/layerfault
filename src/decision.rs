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

    /// Canonical scanner-level exit tier for a set of findings, independent of
    /// any policy decision: 0=clean, 1=warn, 2=integrity/corruption (bytes
    /// could not be trusted, e.g. digest/size mismatch), 3=other
    /// security-relevant Fail (BLOCK). An `IntegrityHash` Fail takes priority
    /// over any other Fail because corrupted/unreadable bytes make every
    /// other finding about those bytes unreliable.
    pub fn scanner_finding_exit_code<'a>(
        findings: impl IntoIterator<Item = &'a crate::scanner::LayerScanResult>,
    ) -> i32 {
        use crate::scanner::{CheckType, ScanStatus};
        let mut warn = false;
        let mut blocking = false;
        for finding in findings {
            match finding.status {
                ScanStatus::Fail if finding.check_type == CheckType::IntegrityHash => return 2,
                ScanStatus::Fail => blocking = true,
                ScanStatus::Warn => warn = true,
                ScanStatus::Pass => {}
            }
        }
        if blocking {
            3
        } else {
            i32::from(warn)
        }
    }

    /// Combine a `scanner_finding_exit_code` result with an aggregate policy
    /// decision using the canonical CLI exit-code contract. A scanner-level
    /// integrity error (2) or Fail (3) always wins, since those describe the
    /// artifact bytes themselves; only once the scanner is clean does the
    /// policy verdict (Block=4, Warn=1) get a say.
    pub fn combine_scanner_and_policy_exit_code(
        scanner_code: i32,
        policy_block: bool,
        policy_warn: bool,
    ) -> i32 {
        if matches!(scanner_code, 2 | 3) {
            return scanner_code;
        }
        if policy_block {
            return 4;
        }
        if policy_warn || scanner_code == 1 {
            return 1;
        }
        0
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

    fn finding(
        check_type: crate::scanner::CheckType,
        status: crate::scanner::ScanStatus,
    ) -> crate::scanner::LayerScanResult {
        crate::scanner::LayerScanResult {
            layer_digest: "sha256:test".to_owned(),
            media_type: "application/test".to_owned(),
            check_type,
            status,
            finding_class: crate::scanner::FindingClass::Integrity,
            confidence: crate::scanner::Confidence::High,
            detail: None,
            matches: Vec::new(),
            duration_ms: 0,
        }
    }

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

    #[test]
    fn integrity_exit_tier_is_independent_of_finding_order() {
        use crate::scanner::{CheckType, ScanStatus};

        let ordinary = finding(CheckType::OnnxStructure, ScanStatus::Fail);
        let integrity = finding(CheckType::IntegrityHash, ScanStatus::Fail);
        assert_eq!(
            SecurityDecision::scanner_finding_exit_code([&ordinary, &integrity]),
            2
        );
        assert_eq!(
            SecurityDecision::scanner_finding_exit_code([&integrity, &ordinary]),
            2
        );
    }
}
