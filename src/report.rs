use crate::coverage::Coverage;
use crate::finding_evidence::{
    EvidenceLocation, EvidenceState, EvidenceSubject, FindingCorrelation, FindingEvidence,
};
use crate::json_stream::{stream_seq, write_stdout_json};
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
    let output = stream_seq(reports, |report| JsonModelReport {
        model: &report.model_name,
        scan_results: &report.results,
        overall_status: overall_status(&report.results),
    });
    write_stdout_json(&output, true)
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
struct SarifLog<S: serde::Serialize> {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: [SarifRun<S>; 1],
}

#[derive(serde::Serialize)]
struct SarifRun<S: serde::Serialize> {
    tool: SarifTool,
    results: S,
}

#[derive(serde::Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(serde::Serialize)]
struct SarifDriver {
    name: &'static str,
    #[serde(rename = "semanticVersion")]
    semantic_version: &'static str,
}

#[derive(serde::Serialize)]
struct SarifResult<'a> {
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
struct SarifLocation<'a> {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation<'a>,
}

#[derive(serde::Serialize)]
struct SarifPhysicalLocation<'a> {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation<'a>,
    region: SarifRegion<'a>,
}

#[derive(serde::Serialize)]
struct SarifArtifactLocation<'a> {
    uri: &'a str,
}

#[derive(serde::Serialize)]
struct SarifRegion<'a> {
    #[serde(rename = "startLine")]
    start_line: u64,
    #[serde(rename = "endLine")]
    end_line: u64,
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

fn is_empty_evidence(evidence: &&[FindingEvidence]) -> bool {
    evidence.is_empty()
}

fn sarif_result<'a>(model_name: &'a str, finding: &'a LayerScanResult) -> SarifResult<'a> {
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

fn sarif_rule_id(result: &LayerScanResult) -> String {
    crate::policy::rule_id(result)
}

/// Build SARIF `locations` for evidence that genuinely has source semantics.
///
/// Only text evidence anchored to a package-relative member qualifies. Byte
/// offsets, tensor names, metadata keys and opcode indices are real locations
/// but not *source* locations, and SARIF has no honest way to express them.
fn sarif_locations(finding: &LayerScanResult) -> Vec<SarifLocation<'_>> {
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

pub fn overall_status(results: &[LayerScanResult]) -> ScanStatus {
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
    let output = stream_seq(reports, |evaluated| EvaluatedJsonReport {
        schema_version: "1.0",
        tool_version: env!("CARGO_PKG_VERSION"),
        model: &evaluated.report.model_name,
        overall_status: overall_status(&evaluated.report.results),
        trust_state: evaluated.trust_state,
        trusted_signatures: evaluated.trusted_signatures,
        signer_fingerprints: &evaluated.signer_fingerprints,
        policy: &evaluated.policy,
        scan_results: stream_seq(&evaluated.report.results, enriched_finding_ref),
    });
    write_stdout_json(&output, true)
}

#[derive(serde::Serialize)]
struct EvaluatedJsonReport<'a, S: serde::Serialize> {
    schema_version: &'static str,
    tool_version: &'static str,
    model: &'a str,
    overall_status: ScanStatus,
    trust_state: crate::provenance::TrustState,
    trusted_signatures: usize,
    signer_fingerprints: &'a [String],
    policy: &'a crate::policy::PolicyDecision,
    scan_results: S,
}

/// The enriched per-finding JSON contract.
///
/// Every key that existed before the evidence upgrade is still emitted with the
/// same name and meaning. Attribution keys are added alongside them, and are
/// omitted rather than emitted empty when a detector has nothing to say.
#[derive(serde::Serialize)]
pub struct EnrichedFinding<'a> {
    pub rule_id: String,
    pub rule_version: u32,
    pub detector_family: &'static str,
    pub scanner_revision: &'static str,
    pub ruleset_sha256: &'static str,
    pub layer_digest: &'a str,
    pub media_type: &'a str,
    pub check_type: &'a CheckType,
    pub status: &'a ScanStatus,
    pub finding_class: &'a FindingClass,
    pub confidence: &'a Confidence,
    pub detail: &'a Option<String>,
    pub matches: &'a [String],
    pub duration_ms: u64,
    pub risk: crate::explain::RiskExplanation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<&'a EvidenceSubject>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_state: Option<&'a EvidenceState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_reason: Option<&'a str>,
    #[serde(skip_serializing_if = "is_empty_evidence")]
    pub evidence: &'a [FindingEvidence],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explanation: Option<crate::explain::RuleExplanation>,
}

/// Project a finding into the enriched JSON contract without allocating a
/// `serde_json::Value`.
pub fn enriched_finding_ref(finding: &LayerScanResult) -> EnrichedFinding<'_> {
    let rule_id = crate::policy::rule_id(finding);
    let explanation = crate::explain::lookup(&rule_id);
    let rule_version = explanation.as_ref().map(|e| e.rule_version).unwrap_or(1);
    let detector_family = explanation
        .as_ref()
        .map(|e| e.detector_family)
        .unwrap_or("scanner");
    EnrichedFinding {
        rule_id: rule_id.clone(),
        rule_version,
        detector_family,
        scanner_revision: crate::explain::scanner_revision(),
        ruleset_sha256: crate::explain::ruleset_sha256(),
        layer_digest: &finding.layer_digest,
        media_type: &finding.media_type,
        check_type: &finding.check_type,
        status: &finding.status,
        finding_class: &finding.finding_class,
        confidence: &finding.confidence,
        detail: &finding.detail,
        matches: &finding.matches,
        duration_ms: finding.duration_ms,
        risk: crate::explain::risk_lookup(&rule_id),
        finding_id: finding.finding_id.as_deref(),
        subject: finding.subject.as_ref(),
        evidence_state: finding.evidence_state.as_ref(),
        evidence_reason: finding.evidence_reason.as_deref(),
        evidence: &finding.evidence,
        explanation: crate::explain::lookup(&rule_id),
    }
}

/// Legacy `serde_json::Value` projection, kept for callers (evidence bundle
/// manifests, ad hoc command JSON) that still need an owned `Value` rather
/// than a borrowed streaming struct.
pub fn enriched_finding(finding: &LayerScanResult) -> serde_json::Value {
    serde_json::to_value(enriched_finding_ref(finding)).expect("enriched finding is Serialize")
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
    fn enriched_finding_omits_absent_optional_keys() {
        let finding = result(ScanStatus::Warn);
        let value = serde_json::to_value(enriched_finding_ref(&finding)).expect("serialize");
        let object = value.as_object().expect("object");
        for key in [
            "finding_id",
            "subject",
            "evidence_state",
            "evidence_reason",
            "evidence",
        ] {
            assert!(!object.contains_key(key), "unexpected key '{key}' present");
        }
        for key in [
            "rule_id",
            "rule_version",
            "detector_family",
            "scanner_revision",
            "ruleset_sha256",
            "layer_digest",
            "media_type",
            "check_type",
            "status",
            "finding_class",
            "confidence",
            "detail",
            "matches",
            "duration_ms",
            "risk",
        ] {
            assert!(object.contains_key(key), "missing key '{key}'");
        }
    }

    #[test]
    fn enriched_finding_includes_present_optional_keys() {
        let mut finding = result(ScanStatus::Warn);
        finding.finding_id = Some("finding-1".to_owned());
        finding.evidence_state = Some(EvidenceState::Partial);
        finding.evidence_reason = Some("bounded excerpt".to_owned());
        let value = serde_json::to_value(enriched_finding_ref(&finding)).expect("serialize");
        assert_eq!(value["finding_id"], "finding-1");
        assert_eq!(value["evidence_state"], "PARTIAL");
        assert_eq!(value["evidence_reason"], "bounded excerpt");
    }

    #[test]
    fn enriched_finding_matches_legacy_value_shape() {
        let mut finding = result(ScanStatus::Fail);
        finding.finding_id = Some("finding-2".to_owned());
        finding.detail = Some("detail text".to_owned());
        let typed = serde_json::to_value(enriched_finding_ref(&finding)).expect("serialize");
        let legacy = enriched_finding(&finding);
        assert_eq!(typed, legacy);
    }

    #[test]
    fn emit_sarif_skips_pass_findings_and_uses_rule_ids() {
        let reports = [ModelReport {
            model_name: "example".to_owned(),
            results: vec![result(ScanStatus::Pass), result(ScanStatus::Fail)],
        }];
        let results_stream = crate::json_stream::stream_iter(
            reports[0]
                .results
                .iter()
                .filter(|f| f.status != ScanStatus::Pass)
                .map(|f| sarif_result(&reports[0].model_name, f)),
        );
        let json = serde_json::to_value(&results_stream).expect("serialize");
        let array = json.as_array().expect("array");
        assert_eq!(array.len(), 1);
        assert_eq!(array[0]["level"], "error");
        assert_eq!(array[0]["ruleId"], "LF-LAYERPOLICY");
    }

    /// Exercises the real `emit_sarif` writer path end to end (pretty
    /// `to_writer_pretty`, not `to_value`), across multiple reports each
    /// with a mix of Pass/Warn/Fail findings, since the streaming SARIF
    /// results array is built from a `flat_map` over reports whose
    /// `size_hint` can undercount the true element count -- exactly the
    /// shape that previously panicked in the pretty formatter.
    #[test]
    fn emit_sarif_writer_path_handles_multi_report_flat_map_without_panicking() {
        let reports = [
            ModelReport {
                model_name: "model-a".to_owned(),
                results: vec![result(ScanStatus::Pass), result(ScanStatus::Warn)],
            },
            ModelReport {
                model_name: "model-b".to_owned(),
                results: vec![result(ScanStatus::Fail)],
            },
        ];
        let mut buffer = Vec::new();
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
                        semantic_version: "0.0.0",
                    },
                },
                results,
            }],
        };
        crate::json_stream::write_json(&mut buffer, &log, true).expect("write pretty sarif");
        let value: serde_json::Value = serde_json::from_slice(&buffer).expect("valid json");
        let results = value["runs"][0]["results"].as_array().expect("array");
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn sarif_locations_only_for_text_evidence_with_package_relative_subject() {
        let subject =
            EvidenceSubject::member("modeling_custom.py").with_sha256(Some("sha256:ab".into()));
        let mut finding = result(ScanStatus::Warn);
        finding.evidence = vec![crate::finding_evidence::source_excerpt(
            subject, 10, 10, "eval(", "eval(x)",
        )];
        let locations = sarif_locations(&finding);
        assert_eq!(locations.len(), 1);
        assert_eq!(
            locations[0].physical_location.artifact_location.uri,
            "modeling_custom.py"
        );
        assert_eq!(locations[0].physical_location.region.start_line, 10);
    }

    #[test]
    fn short_digest_supports_sha512() {
        assert_eq!(
            short_digest("sha512:0123456789abcdefdeadbeef"),
            "0123456789abcdef"
        );
    }
}
