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

#[cfg(test)]
mod tests {
    use super::*;
    use common::*;
    use json::*;
    use sarif::*;

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

mod common;
mod evidence;
mod json;
pub mod jsonl;
mod mappings;
mod sarif;
mod table;

pub use common::overall_status;
pub use evidence::{emit_evidence_report, render_evidence_report};
pub use json::{
    emit_evaluated_json, emit_json, enriched_finding, enriched_finding_ref, enriched_findings,
    inventory_value, EnrichedFinding,
};
pub use sarif::{emit_evaluated_sarif, emit_sarif};
pub use table::{emit_evaluated_table, emit_inventory_table, emit_table};
