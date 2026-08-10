//! Wheel `*.dist-info/METADATA` parsing (RFC 822-style key: value headers).

use super::requirements::parse_requirement_line;
use super::risk::RiskFinding;
use super::types::{DependencyEcosystem, DependencyRecord};
use crate::coverage::Coverage;
use crate::finding_evidence::EvidenceLocation;

#[derive(Debug, Default)]
pub struct WheelOutcome {
    pub records: Vec<DependencyRecord>,
    pub issues: Vec<RiskFinding>,
}

/// Parse `Requires-Dist` headers from a wheel's `METADATA` file.
///
/// The body (after the first blank line, RFC 822 style) is ignored: it is the
/// package long description, not manifest data.
pub fn parse_metadata(relative_path: &str, source: &str, _coverage: &mut Coverage) -> WheelOutcome {
    let mut outcome = WheelOutcome::default();
    for (index, line) in source.lines().enumerate() {
        if line.trim().is_empty() {
            // First blank line ends the header block.
            break;
        }
        let Some(value) = line.strip_prefix("Requires-Dist:") else {
            continue;
        };
        let normalized = normalize_paren_constraint(value.trim());
        let mut record = parse_requirement_line(&normalized, relative_path);
        record.ecosystem = Some(DependencyEcosystem::WheelMetadata);
        record.location = Some(EvidenceLocation::Text {
            line_start: index as u64 + 1,
            line_end: index as u64 + 1,
            column_start: None,
            column_end: None,
        });
        outcome.records.push(record);
    }
    outcome
}

/// `Requires-Dist` historically wraps its constraint in parentheses, e.g.
/// `requests (>=2.0)`. Strip them so the shared PEP 508 tokenizer sees
/// `requests>=2.0`.
fn normalize_paren_constraint(value: &str) -> String {
    value.replace(['(', ')'], "")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_dist_is_parsed() {
        let mut coverage = Coverage::complete(1, 1);
        let outcome = parse_metadata(
            "pkg.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: pkg\nRequires-Dist: requests (>=2.0)\n\nLong description.\n",
            &mut coverage,
        );
        assert_eq!(outcome.records.len(), 1);
        assert_eq!(outcome.records[0].name.as_deref(), Some("requests"));
    }

    #[test]
    fn body_is_not_scanned() {
        let mut coverage = Coverage::complete(1, 1);
        let outcome = parse_metadata(
            "pkg.dist-info/METADATA",
            "Name: pkg\n\nRequires-Dist: not-a-real-header\n",
            &mut coverage,
        );
        assert!(outcome.records.is_empty());
    }
}
