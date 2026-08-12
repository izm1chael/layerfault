use super::common::*;
use super::*;

pub fn emit_sarif(reports: &[ModelReport]) -> Result<()> {
    let results = crate::json_stream::stream_iter(reports.iter().flat_map(|report| {
        report
            .results
            .iter()
            .filter(|finding| finding.status != ScanStatus::Pass)
            .map(move |finding| sarif_result(&report.model_name, finding))
    }));
    let log = SarifLog {
        schema: "https://json.schemastore.org/sarif-2.1.0.json",
        version: "2.1.0",
        runs: [SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "Layerfault",
                    semantic_version: env!("CARGO_PKG_VERSION"),
                },
            },
            results,
        }],
    };
    write_stdout_json(&log, true)
}

/// SARIF documents in the reference form: typed structs streamed straight to
/// the writer rather than a `serde_json::Value` tree built up front. Generic
/// over the results-array type so the streaming iterator chain built in
/// `emit_sarif` never needs to be spelled out explicitly.
#[derive(serde::Serialize)]
pub(super) struct SarifLog<S: serde::Serialize> {
    #[serde(rename = "$schema")]
    pub(super) schema: &'static str,
    pub(super) version: &'static str,
    pub(super) runs: [SarifRun<S>; 1],
}

#[derive(serde::Serialize)]
pub(super) struct SarifRun<S: serde::Serialize> {
    pub(super) tool: SarifTool,
    pub(super) results: S,
}

#[derive(serde::Serialize)]
pub(super) struct SarifTool {
    pub(super) driver: SarifDriver,
}

#[derive(serde::Serialize)]
pub(super) struct SarifDriver {
    pub(super) name: &'static str,
    #[serde(rename = "semanticVersion")]
    pub(super) semantic_version: &'static str,
}

#[derive(serde::Serialize)]
pub(super) struct SarifResult<'a> {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: &'static str,
    message: SarifMessage,
    properties: SarifProperties<'a>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    locations: Vec<SarifLocation<'a>>,
}

#[derive(serde::Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(serde::Serialize)]
struct SarifProperties<'a> {
    model: &'a str,
    #[serde(rename = "layerDigest")]
    layer_digest: &'a str,
    #[serde(rename = "mediaType")]
    media_type: &'a str,
    #[serde(rename = "checkType")]
    check_type: &'static str,
    #[serde(rename = "findingClass")]
    finding_class: &'static str,
    confidence: &'static str,
    matches: &'a [String],
    #[serde(rename = "durationMs")]
    duration_ms: u64,
    risk: crate::explain::RiskExplanation,
    #[serde(rename = "findingId", skip_serializing_if = "Option::is_none")]
    finding_id: Option<&'a str>,
    #[serde(rename = "evidenceState", skip_serializing_if = "Option::is_none")]
    evidence_state: Option<&'a EvidenceState>,
    #[serde(rename = "evidenceReason", skip_serializing_if = "Option::is_none")]
    evidence_reason: Option<&'a str>,
    #[serde(skip_serializing_if = "is_empty_evidence")]
    evidence: &'a [FindingEvidence],
    #[serde(rename = "ruleVersion", skip_serializing_if = "Option::is_none")]
    rule_version: Option<u32>,
    #[serde(rename = "detectorFamily", skip_serializing_if = "Option::is_none")]
    detector_family: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    explanation: Option<crate::explain::RuleExplanation>,
    #[serde(rename = "scannerRevision")]
    scanner_revision: &'static str,
    #[serde(rename = "rulesetSha256")]
    ruleset_sha256: &'static str,
}

#[derive(serde::Serialize)]
pub(super) struct SarifLocation<'a> {
    #[serde(rename = "physicalLocation")]
    pub(super) physical_location: SarifPhysicalLocation<'a>,
}

#[derive(serde::Serialize)]
pub(super) struct SarifPhysicalLocation<'a> {
    #[serde(rename = "artifactLocation")]
    pub(super) artifact_location: SarifArtifactLocation<'a>,
    pub(super) region: SarifRegion<'a>,
}

#[derive(serde::Serialize)]
pub(super) struct SarifArtifactLocation<'a> {
    pub(super) uri: &'a str,
}

#[derive(serde::Serialize)]
pub(super) struct SarifRegion<'a> {
    #[serde(rename = "startLine")]
    pub(super) start_line: u64,
    #[serde(rename = "endLine")]
    pub(super) end_line: u64,
    #[serde(rename = "startColumn", skip_serializing_if = "Option::is_none")]
    start_column: Option<u32>,
    #[serde(rename = "endColumn", skip_serializing_if = "Option::is_none")]
    end_column: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    snippet: Option<SarifSnippet<'a>>,
}

#[derive(serde::Serialize)]
struct SarifSnippet<'a> {
    text: &'a str,
}

pub(super) fn is_empty_evidence(evidence: &&[FindingEvidence]) -> bool {
    evidence.is_empty()
}

pub(super) fn sarif_result<'a>(
    model_name: &'a str,
    finding: &'a LayerScanResult,
) -> SarifResult<'a> {
    let rule_id = sarif_rule_id(finding);
    let message = finding
        .detail
        .clone()
        .unwrap_or_else(|| format!("{} finding", check_type_label(&finding.check_type)));
    let explanation = crate::explain::lookup(&rule_id);
    SarifResult {
        level: match finding.status {
            ScanStatus::Fail => "error",
            ScanStatus::Warn => "warning",
            ScanStatus::Pass => "note",
        },
        message: SarifMessage { text: message },
        properties: SarifProperties {
            model: model_name,
            layer_digest: &finding.layer_digest,
            media_type: &finding.media_type,
            check_type: check_type_label(&finding.check_type),
            finding_class: finding_class_label(&finding.finding_class),
            confidence: confidence_label(&finding.confidence),
            matches: &finding.matches,
            duration_ms: finding.duration_ms,
            risk: crate::explain::risk_lookup(&rule_id),
            finding_id: finding.finding_id.as_deref(),
            evidence_state: finding.evidence_state.as_ref(),
            evidence_reason: finding.evidence_reason.as_deref(),
            evidence: &finding.evidence,
            rule_version: explanation.as_ref().map(|e| e.rule_version),
            detector_family: explanation.as_ref().map(|e| e.detector_family),
            explanation,
            scanner_revision: crate::explain::scanner_revision(),
            ruleset_sha256: crate::explain::ruleset_sha256(),
        },
        locations: sarif_locations(finding),
        rule_id,
    }
}

pub(super) fn sarif_rule_id(result: &LayerScanResult) -> String {
    crate::policy::rule_id(result)
}

/// Build SARIF `locations` for evidence that genuinely has source semantics.
///
/// Only text evidence anchored to a package-relative member qualifies. Byte
/// offsets, tensor names, metadata keys and opcode indices are real locations
/// but not *source* locations, and SARIF has no honest way to express them.
pub(super) fn sarif_locations(finding: &LayerScanResult) -> Vec<SarifLocation<'_>> {
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
        locations.push(SarifLocation {
            physical_location: SarifPhysicalLocation {
                artifact_location: SarifArtifactLocation { uri },
                region: SarifRegion {
                    start_line: *line_start,
                    end_line: *line_end,
                    start_column: *column_start,
                    end_column: *column_end,
                    snippet: record.excerpt.as_deref().map(|text| SarifSnippet { text }),
                },
            },
        });
        if locations.len() >= crate::finding_evidence::MAX_EVIDENCE_PER_FINDING {
            break;
        }
    }
    locations
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
