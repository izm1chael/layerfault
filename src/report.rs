use crate::coverage::Coverage;
use crate::finding_evidence::{EvidenceLocation, EvidenceState, FindingCorrelation};
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use anyhow::Result;
use colored::Colorize;
use comfy_table::{presets::UTF8_FULL, Table};

#[derive(Debug, Clone, serde::Serialize)]
pub struct ModelReport {
    #[serde(rename = "model")]
    pub model_name: String,
    #[serde(rename = "scan_results")]
    pub results: Vec<LayerScanResult>,
}

pub fn emit_table(reports: &[ModelReport]) {
    for report in reports {
        println!("{}", format!("━━━ {} ━━━", report.model_name).bold());

        let mut table = Table::new();
        table.load_preset(UTF8_FULL);
        table.set_header([
            "Model",
            "Layer Digest (short)",
            "Check",
            "Class",
            "Confidence",
            "Status",
            "Detail",
        ]);

        for result in &report.results {
            table.add_row([
                report.model_name.clone(),
                short_digest(&result.layer_digest),
                check_type_label(&result.check_type).to_owned(),
                finding_class_label(&result.finding_class).to_owned(),
                confidence_label(&result.confidence).to_owned(),
                status_label(&result.status),
                result.detail.clone().unwrap_or_default(),
            ]);
        }

        println!("{table}");
    }
}

pub fn emit_json(reports: &[ModelReport]) -> Result<()> {
    let output: Vec<JsonModelReport<'_>> = reports
        .iter()
        .map(|report| JsonModelReport {
            model: &report.model_name,
            scan_results: &report.results,
            overall_status: overall_status(&report.results),
        })
        .collect();
    let rendered = serde_json::to_string_pretty(&output)?;
    println!("{rendered}");
    Ok(())
}

/// Emit SARIF 2.1.0 containing WARN/FAIL findings only.
///
/// Layerfault scans artifacts rather than source trees, so model/layer identity
/// is carried in result properties instead of synthetic filesystem locations.
/// A real `physicalLocation` is emitted only where a genuine source file and
/// line are known — custom Python, configuration, templates and scripts. Binary,
/// tensor, opcode and metadata evidence stays in properties: fabricating a line
/// number to satisfy SARIF tooling would be dishonest about what was measured.
pub fn emit_sarif(reports: &[ModelReport]) -> Result<()> {
    let mut results = Vec::new();
    for report in reports {
        for finding in &report.results {
            if finding.status == ScanStatus::Pass {
                continue;
            }
            let rule_id = sarif_rule_id(finding);
            let message = finding
                .detail
                .clone()
                .unwrap_or_else(|| format!("{} finding", check_type_label(&finding.check_type)));
            let mut entry = serde_json::json!({
                "ruleId": rule_id,
                "level": match finding.status {
                    ScanStatus::Fail => "error",
                    ScanStatus::Warn => "warning",
                    ScanStatus::Pass => "note",
                },
                "message": { "text": message },
                "properties": {
                    "model": &report.model_name,
                    "layerDigest": &finding.layer_digest,
                    "mediaType": &finding.media_type,
                    "checkType": check_type_label(&finding.check_type),
                    "findingClass": finding_class_label(&finding.finding_class),
                    "confidence": confidence_label(&finding.confidence),
                    "matches": &finding.matches,
                    "durationMs": finding.duration_ms,
                    "risk": crate::explain::risk_lookup(&rule_id)
                }
            });
            let properties = entry["properties"]
                .as_object_mut()
                .expect("sarif properties object");
            if let Some(id) = finding.finding_id.as_ref() {
                properties.insert("findingId".to_owned(), serde_json::json!(id));
            }
            if let Some(state) = finding.evidence_state.as_ref() {
                properties.insert("evidenceState".to_owned(), serde_json::json!(state));
            }
            if let Some(reason) = finding.evidence_reason.as_ref() {
                properties.insert("evidenceReason".to_owned(), serde_json::json!(reason));
            }
            if !finding.evidence.is_empty() {
                properties.insert("evidence".to_owned(), serde_json::json!(&finding.evidence));
            }
            if let Some(explanation) = crate::explain::lookup(&rule_id) {
                properties.insert(
                    "ruleVersion".to_owned(),
                    serde_json::json!(explanation.rule_version),
                );
                properties.insert(
                    "detectorFamily".to_owned(),
                    serde_json::json!(explanation.detector_family),
                );
                properties.insert("explanation".to_owned(), serde_json::json!(explanation));
            }
            properties.insert(
                "scannerRevision".to_owned(),
                serde_json::json!(crate::explain::scanner_revision()),
            );
            properties.insert(
                "rulesetSha256".to_owned(),
                serde_json::json!(crate::explain::ruleset_sha256()),
            );
            let locations = sarif_locations(finding);
            if !locations.is_empty() {
                entry["locations"] = serde_json::Value::Array(locations);
            }
            results.push(entry);
        }
    }

    let document = serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Layerfault",
                    "semanticVersion": env!("CARGO_PKG_VERSION")
                }
            },
            "results": results
        }]
    });
    println!("{}", serde_json::to_string_pretty(&document)?);
    Ok(())
}

fn sarif_rule_id(result: &LayerScanResult) -> String {
    crate::policy::rule_id(result)
}

/// Build SARIF `locations` for evidence that genuinely has source semantics.
///
/// Only text evidence anchored to a package-relative member qualifies. Byte
/// offsets, tensor names, metadata keys and opcode indices are real locations
/// but not *source* locations, and SARIF has no honest way to express them.
fn sarif_locations(finding: &LayerScanResult) -> Vec<serde_json::Value> {
    let mut locations = Vec::new();
    for record in &finding.evidence {
        let Some(EvidenceLocation::Text {
            line_start,
            line_end,
            column_start,
            column_end,
        }) = record.location.as_ref()
        else {
            continue;
        };
        let Some(uri) = record.subject.package_relative_path.as_deref() else {
            continue;
        };
        let mut region = serde_json::json!({
            "startLine": line_start,
            "endLine": line_end,
        });
        if let Some(column) = column_start {
            region["startColumn"] = serde_json::json!(column);
        }
        if let Some(column) = column_end {
            region["endColumn"] = serde_json::json!(column);
        }
        if let Some(snippet) = record.excerpt.as_deref() {
            region["snippet"] = serde_json::json!({ "text": snippet });
        }
        locations.push(serde_json::json!({
            "physicalLocation": {
                "artifactLocation": { "uri": uri },
                "region": region,
            }
        }));
        if locations.len() >= crate::finding_evidence::MAX_EVIDENCE_PER_FINDING {
            break;
        }
    }
    locations
}

fn overall_status(results: &[LayerScanResult]) -> ScanStatus {
    if results
        .iter()
        .any(|result| result.status == ScanStatus::Fail)
    {
        ScanStatus::Fail
    } else if results
        .iter()
        .any(|result| result.status == ScanStatus::Warn)
    {
        ScanStatus::Warn
    } else {
        ScanStatus::Pass
    }
}

#[derive(serde::Serialize)]
struct JsonModelReport<'a> {
    model: &'a str,
    scan_results: &'a [LayerScanResult],
    overall_status: ScanStatus,
}

fn short_digest(digest: &str) -> String {
    let without_prefix = digest
        .strip_prefix("sha256:")
        .or_else(|| digest.strip_prefix("sha512:"))
        .unwrap_or(digest);
    without_prefix.chars().take(16).collect()
}

fn check_type_label(check_type: &CheckType) -> &'static str {
    match check_type {
        CheckType::IntegrityHash => "IntegrityHash",
        CheckType::HeuristicSignature => "HeuristicSignature",
        CheckType::ParameterThreshold => "ParameterThreshold",
        CheckType::BinarySteganography => "EmbeddedExecutable",
        CheckType::Provenance => "LocalAttestation",
        CheckType::GGUFMetadata => "GGUFStructure",
        CheckType::SafetensorsStructure => "SafetensorsStructure",
        CheckType::OnnxStructure => "OnnxStructure",
        CheckType::TensorFlowStructure => "TensorFlowStructure",
        CheckType::TfliteStructure => "TfliteStructure",
        CheckType::KerasStructure => "KerasStructure",
        CheckType::PackageSecurity => "PackageSecurity",
        CheckType::RuntimeAdvisory => "RuntimeAdvisory",
        CheckType::ExecutionBinding => "ExecutionBinding",
        CheckType::SignedEvidence => "SignedEvidence",
        CheckType::LayerPolicy => "LayerPolicy",
        CheckType::ScanError => "ScanError",
        CheckType::PickleStructure => "PickleStructure",
    }
}

fn finding_class_label(class: &FindingClass) -> &'static str {
    match class {
        FindingClass::Integrity => "Integrity",
        FindingClass::Structural => "Structural",
        FindingClass::ContentIndicator => "Content",
        FindingClass::Policy => "Policy",
        FindingClass::Attestation => "Attestation",
        FindingClass::Compatibility => "Compatibility",
        FindingClass::Operational => "Operational",
        FindingClass::Informational => "Info",
    }
}

fn confidence_label(confidence: &Confidence) -> &'static str {
    match confidence {
        Confidence::Low => "Low",
        Confidence::Medium => "Medium",
        Confidence::High => "High",
    }
}

fn status_label(status: &ScanStatus) -> String {
    match status {
        ScanStatus::Pass => "PASS".green().to_string(),
        ScanStatus::Warn => "WARN".yellow().to_string(),
        ScanStatus::Fail => "FAIL".red().to_string(),
    }
}

/// Emit the stable versioned JSON contract. Existing fields remain present while
/// stable rule IDs, provenance and policy decisions are added explicitly.
pub fn emit_evaluated_json(reports: &[crate::app::EvaluatedReport]) -> Result<()> {
    let output = reports
        .iter()
        .map(|evaluated| {
            let findings = evaluated
                .report
                .results
                .iter()
                .map(enriched_finding)
                .collect::<Vec<_>>();
            serde_json::json!({
                "schema_version": "1.0",
                "tool_version": env!("CARGO_PKG_VERSION"),
                "model": &evaluated.report.model_name,
                "overall_status": overall_status(&evaluated.report.results),
                "trust_state": evaluated.trust_state,
                "trusted_signatures": evaluated.trusted_signatures,
                "signer_fingerprints": &evaluated.signer_fingerprints,
                "policy": &evaluated.policy,
                "scan_results": findings
            })
        })
        .collect::<Vec<_>>();
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

/// Project a finding into the enriched JSON contract.
///
/// Every key that existed before the evidence upgrade is still emitted with the
/// same name and meaning. Attribution keys are added alongside them, and are
/// omitted rather than emitted empty when a detector has nothing to say.
pub fn enriched_finding(finding: &LayerScanResult) -> serde_json::Value {
    let rule_id = crate::policy::rule_id(finding);
    let explanation = crate::explain::lookup(&rule_id);
    let rule_version = explanation.as_ref().map(|e| e.rule_version).unwrap_or(1);
    let detector_family = explanation
        .as_ref()
        .map(|e| e.detector_family)
        .unwrap_or("scanner");

    let mut value = serde_json::json!({
        "rule_id": rule_id,
        "rule_version": rule_version,
        "detector_family": detector_family,
        "scanner_revision": crate::explain::scanner_revision(),
        "ruleset_sha256": crate::explain::ruleset_sha256(),
        "layer_digest": &finding.layer_digest,
        "media_type": &finding.media_type,
        "check_type": &finding.check_type,
        "status": &finding.status,
        "finding_class": &finding.finding_class,
        "confidence": &finding.confidence,
        "detail": &finding.detail,
        "matches": &finding.matches,
        "duration_ms": finding.duration_ms,
        "risk": crate::explain::risk_lookup(&rule_id)
    });

    let object = value
        .as_object_mut()
        .expect("enriched finding is an object");
    if let Some(id) = finding.finding_id.as_ref() {
        object.insert("finding_id".to_owned(), serde_json::json!(id));
    }
    if let Some(subject) = finding.subject.as_ref() {
        object.insert("subject".to_owned(), serde_json::json!(subject));
    }
    if let Some(state) = finding.evidence_state.as_ref() {
        object.insert("evidence_state".to_owned(), serde_json::json!(state));
    }
    if let Some(reason) = finding.evidence_reason.as_ref() {
        object.insert("evidence_reason".to_owned(), serde_json::json!(reason));
    }
    if !finding.evidence.is_empty() {
        object.insert("evidence".to_owned(), serde_json::json!(&finding.evidence));
    }
    if let Some(explanation) = crate::explain::lookup(&rule_id) {
        object.insert("explanation".to_owned(), serde_json::json!(explanation));
    }
    value
}

pub fn enriched_findings(findings: &[LayerScanResult]) -> Vec<serde_json::Value> {
    findings.iter().map(enriched_finding).collect()
}

/// Render the evidence-first human report.
///
/// This is the `--evidence` view. The default table output is deliberately
/// unchanged, because existing users and the corpus regression gate depend on
/// it byte for byte.
///
/// Every value that originates in an artifact has already been sanitised and
/// redacted by [`crate::finding_evidence`], so hostile content cannot inject
/// terminal escape sequences here.
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

pub fn emit_evaluated_table(reports: &[crate::app::EvaluatedReport]) {
    let raw = reports
        .iter()
        .map(|value| ModelReport {
            model_name: value.report.model_name.clone(),
            results: value.report.results.clone(),
        })
        .collect::<Vec<_>>();
    emit_table(&raw);
    for report in reports {
        println!(
            "Policy: {:?}  Action: {:?}  Provenance: {:?}",
            report.policy.profile, report.policy.action, report.trust_state
        );
        for reason in &report.policy.reasons {
            println!("  - {reason}");
        }
        if !report.policy.suppressed_rule_ids.is_empty() {
            println!(
                "  Suppressed by policy: {}",
                report.policy.suppressed_rule_ids.join(", ")
            );
        }
    }
}

pub fn emit_evaluated_sarif(reports: &[crate::app::EvaluatedReport]) -> Result<()> {
    let raw = reports
        .iter()
        .map(|value| ModelReport {
            model_name: value.report.model_name.clone(),
            results: value.report.results.clone(),
        })
        .collect::<Vec<_>>();
    emit_sarif(&raw)
}

pub fn inventory_value(reports: &[crate::app::EvaluatedReport]) -> serde_json::Value {
    serde_json::Value::Array(
        reports
            .iter()
            .map(|evaluated| {
                let integrity = class_status(&evaluated.report.results, FindingClass::Integrity);
                let structure = class_status(&evaluated.report.results, FindingClass::Structural);
                serde_json::json!({
                    "model": &evaluated.report.model_name,
                    "integrity": integrity,
                    "structure": structure,
                    "signed": evaluated.trust_state != crate::provenance::TrustState::Unsigned,
                    "trusted": evaluated.trust_state == crate::provenance::TrustState::Trusted,
                    "trust_state": evaluated.trust_state,
                    "trusted_signatures": evaluated.trusted_signatures,
                    "policy": evaluated.policy.action,
                })
            })
            .collect(),
    )
}

pub fn emit_inventory_table(reports: &[crate::app::EvaluatedReport]) {
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header([
        "Model",
        "Integrity",
        "Structure",
        "Signed",
        "Trusted",
        "Policy",
    ]);
    for evaluated in reports {
        table.add_row([
            evaluated.report.model_name.clone(),
            status_or_na(class_status(
                &evaluated.report.results,
                FindingClass::Integrity,
            )),
            status_or_na(class_status(
                &evaluated.report.results,
                FindingClass::Structural,
            )),
            (evaluated.trust_state != crate::provenance::TrustState::Unsigned).to_string(),
            (evaluated.trust_state == crate::provenance::TrustState::Trusted).to_string(),
            format!("{:?}", evaluated.policy.action),
        ]);
    }
    println!("{table}");
}

fn class_status(results: &[LayerScanResult], class: FindingClass) -> Option<ScanStatus> {
    let mut worst = None;
    for result in results
        .iter()
        .filter(|result| result.finding_class == class)
    {
        match result.status {
            ScanStatus::Fail => return Some(ScanStatus::Fail),
            ScanStatus::Warn => worst = Some(ScanStatus::Warn),
            ScanStatus::Pass if worst.is_none() => worst = Some(ScanStatus::Pass),
            ScanStatus::Pass => {}
        }
    }
    worst
}

fn status_or_na(status: Option<ScanStatus>) -> String {
    status
        .map(|value| format!("{value:?}"))
        .unwrap_or_else(|| "N/A".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(status: ScanStatus) -> LayerScanResult {
        LayerScanResult {
            layer_digest: "sha256:0123456789abcdef".to_owned(),
            media_type: "test/type".to_owned(),
            check_type: CheckType::LayerPolicy,
            status,
            finding_class: FindingClass::Informational,
            confidence: Confidence::Low,
            detail: None,
            matches: Vec::new(),
            duration_ms: 0,
            ..Default::default()
        }
    }

    #[test]
    fn overall_status_uses_worst_result() {
        assert_eq!(
            overall_status(&[result(ScanStatus::Pass)]),
            ScanStatus::Pass
        );
        assert_eq!(
            overall_status(&[result(ScanStatus::Pass), result(ScanStatus::Warn)]),
            ScanStatus::Warn
        );
        assert_eq!(
            overall_status(&[result(ScanStatus::Warn), result(ScanStatus::Fail)]),
            ScanStatus::Fail
        );
    }

    #[test]
    fn sarif_rule_id_prefers_detector_id() {
        let mut finding = result(ScanStatus::Warn);
        finding.matches = vec!["[T3-004] Secret outbound action".to_owned()];
        assert_eq!(sarif_rule_id(&finding), "T3-004");
        finding.matches.clear();
        assert_eq!(sarif_rule_id(&finding), "LF-LAYERPOLICY");
    }

    #[test]
    fn short_digest_supports_sha512() {
        assert_eq!(
            short_digest("sha512:0123456789abcdefdeadbeef"),
            "0123456789abcdef"
        );
    }
}
