use super::common::*;
use super::*;

pub fn render_evidence_report(
    subject: &str,
    findings: &[LayerScanResult],
    correlations: &[FindingCorrelation],
    coverage: Option<&Coverage>,
    color: bool,
) -> String {
    let mut out = String::new();
    out.push_str(&format!("━━━ {subject} ━━━\n\n"));

    let overall = overall_status(findings);
    let decision = match overall {
        ScanStatus::Pass => "PASS",
        ScanStatus::Warn => "WARN",
        ScanStatus::Fail => "FAIL",
    };
    let reportable: Vec<&LayerScanResult> = findings
        .iter()
        .filter(|finding| finding.status != ScanStatus::Pass)
        .collect();
    out.push_str(&format!(
        "FINAL: {}  —  {} security-relevant finding(s)\n\n",
        if color {
            match overall {
                ScanStatus::Pass => decision.green().to_string(),
                ScanStatus::Warn => decision.yellow().to_string(),
                ScanStatus::Fail => decision.red().to_string(),
            }
        } else {
            decision.to_owned()
        },
        reportable.len()
    ));

    for finding in &reportable {
        let rule_id = crate::policy::rule_id(finding);
        out.push_str(&format!(
            "[{}] {}\n",
            confidence_label(&finding.confidence).to_uppercase(),
            rule_id
        ));
        let explanation = crate::explain::lookup(&rule_id);
        if let Some(explanation) = explanation.as_ref() {
            out.push_str(&format!("{}\n", explanation.title));
        }
        if let Some(subject) = finding.subject.as_ref() {
            let name = subject.canonical_name();
            if !name.is_empty() {
                out.push_str(&format!("\n  Subject:\n    {name}\n"));
            }
            if let Some(digest) = subject.sha256.as_deref() {
                out.push_str(&format!("    {digest}\n"));
            }
        }
        if let Some(detail) = finding.detail.as_deref() {
            out.push_str(&format!("\n  Detail:\n    {detail}\n"));
        }

        if finding.evidence.is_empty() {
            let state = finding
                .evidence_state
                .map(|state| format!("{state:?}").to_uppercase())
                .unwrap_or_else(|| "UNAVAILABLE".to_owned());
            out.push_str(&format!("\n  Evidence: {state}\n"));
            if let Some(reason) = finding.evidence_reason.as_deref() {
                out.push_str(&format!("    {reason}\n"));
            }
        } else {
            out.push_str("\n  Evidence:\n");
            for record in &finding.evidence {
                if let Some(location) = record.location.as_ref() {
                    out.push_str(&format!(
                        "    {}\n",
                        crate::evidence_bundle::describe_location(location)
                    ));
                }
                if let Some(matched) = record.match_value.as_deref() {
                    out.push_str(&format!("    match: {matched}\n"));
                }
                if let Some(excerpt) = record.excerpt.as_deref() {
                    out.push_str("    ------------------------------------------------\n");
                    for line in excerpt.lines() {
                        out.push_str(&format!("    {line}\n"));
                    }
                    out.push_str("    ------------------------------------------------\n");
                }
                if let Some(structured) = record.structured.as_ref() {
                    out.push_str(&format!("    {structured}\n"));
                }
                if record.redactions > 0 {
                    out.push_str(&format!(
                        "    ({} value(s) redacted as credential-shaped)\n",
                        record.redactions
                    ));
                }
                if record.truncated {
                    out.push_str("    (evidence bounded by collection limits)\n");
                }
            }
            if finding.evidence_state == Some(EvidenceState::Partial) {
                if let Some(reason) = finding.evidence_reason.as_deref() {
                    out.push_str(&format!("    Partial: {reason}\n"));
                }
            }
        }

        if let Some(explanation) = explanation.as_ref() {
            out.push_str(&format!(
                "\n  Why this matters:\n    {}\n",
                explanation.why_it_matters
            ));
            out.push_str(&format!(
                "\n  Limitation:\n    {}\n",
                explanation.limitations
            ));
        }
        out.push('\n');
    }

    if !correlations.is_empty() {
        out.push_str("CORRELATION\n\n");
        for correlation in correlations {
            out.push_str(&format!(
                "  {} ({:?} confidence)\n",
                correlation.id, correlation.confidence
            ));
            out.push_str(&format!("    {}\n", correlation.summary));
            if let Some(limitations) = correlation.limitations.as_deref() {
                out.push_str(&format!("    Limitation: {limitations}\n"));
            }
            if !correlation.finding_ids.is_empty() {
                out.push_str(&format!(
                    "    Findings: {}\n",
                    correlation.finding_ids.join(", ")
                ));
            }
            out.push('\n');
        }
    }

    if let Some(coverage) = coverage {
        out.push_str("COVERAGE\n\n");
        out.push_str(&format!(
            "  complete: {}  scanned: {}/{} file(s), {} byte(s)\n",
            coverage.complete,
            coverage.files_scanned,
            coverage.files_discovered,
            coverage.bytes_scanned
        ));
        for reason in &coverage.reasons {
            out.push_str(&format!("  - {reason}\n"));
        }
        if !coverage.complete {
            out.push_str(
                "\n  Coverage is incomplete: content Layerfault did not examine is unreviewed,\n\
                 \x20 not clean.\n",
            );
        }
        out.push('\n');
    }

    out
}

/// Print the evidence-first human report.
pub fn emit_evidence_report(
    subject: &str,
    findings: &[LayerScanResult],
    correlations: &[FindingCorrelation],
    coverage: Option<&Coverage>,
) {
    print!(
        "{}",
        render_evidence_report(subject, findings, correlations, coverage, true)
    );
}
