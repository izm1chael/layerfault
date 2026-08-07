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

/// Emit SARIF 2.1.0 containing WARN/FAIL findings only. Layerfault scans
/// artifacts rather than source locations, so model/layer identity is carried
/// in result properties instead of synthetic filesystem locations.
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
            results.push(serde_json::json!({
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
                    "durationMs": finding.duration_ms
                }
            }));
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
        CheckType::PackageSecurity => "PackageSecurity",
        CheckType::RuntimeAdvisory => "RuntimeAdvisory",
        CheckType::ExecutionBinding => "ExecutionBinding",
        CheckType::SignedEvidence => "SignedEvidence",
        CheckType::LayerPolicy => "LayerPolicy",
        CheckType::ScanError => "ScanError",
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
                .map(|finding| {
                    serde_json::json!({
                        "rule_id": crate::policy::rule_id(finding),
                        "layer_digest": &finding.layer_digest,
                        "media_type": &finding.media_type,
                        "check_type": &finding.check_type,
                        "status": &finding.status,
                        "finding_class": &finding.finding_class,
                        "confidence": &finding.confidence,
                        "detail": &finding.detail,
                        "matches": &finding.matches,
                        "duration_ms": finding.duration_ms
                    })
                })
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
