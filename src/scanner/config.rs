use crate::finding_evidence::{config_value, EvidenceSubject};
use crate::safeio::read_all_from_file;
use crate::scanner::{
    duration_ms, CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus,
};
use crate::ThresholdConfig;
use anyhow::Result;
use regex::Regex;
use std::fs::File;
use std::time::Instant;

const MAX_PARAMS_BYTES: u64 = 10 * 1024 * 1024;
const TEMPERATURE_WARN: f64 = 1.5;

pub struct ConfigScanner;

impl ConfigScanner {
    pub fn scan_file(
        file: &File,
        layer_digest: &str,
        media_type: &str,
        thresholds: &ThresholdConfig,
    ) -> Result<LayerScanResult> {
        let started = Instant::now();
        let bytes = read_all_from_file(file, MAX_PARAMS_BYTES)?;
        let params: serde_json::Value = serde_json::from_slice(&bytes)?;
        scan_params(
            &params,
            layer_digest,
            media_type,
            duration_ms(started),
            thresholds,
        )
    }
}

fn scan_params(
    params: &serde_json::Value,
    layer_digest: &str,
    media_type: &str,
    elapsed: u64,
    thresholds: &ThresholdConfig,
) -> Result<LayerScanResult> {
    let subject = EvidenceSubject::identity(layer_digest, media_type)
        .with_sha256(Some(layer_digest.to_owned()));
    let mut findings = Vec::new();
    let mut evidence = Vec::new();
    let mut rule_id: Option<&'static str> = None;

    if let Some(value) = params
        .get("temperature")
        .and_then(serde_json::Value::as_f64)
    {
        if value > thresholds.max_temperature {
            note(
                &mut findings,
                &mut evidence,
                &mut rule_id,
                &subject,
                "LF-PARAM-TEMPERATURE",
                "temperature",
                value.into(),
                format!(
                    "temperature {value} exceeds operator policy maximum {}",
                    thresholds.max_temperature
                ),
            );
        } else if value > TEMPERATURE_WARN {
            note(
                &mut findings,
                &mut evidence,
                &mut rule_id,
                &subject,
                "LF-PARAM-TEMPERATURE",
                "temperature",
                value.into(),
                format!(
                    "temperature {value} is unusually high (review threshold {TEMPERATURE_WARN})"
                ),
            );
        }
    }

    if let Some(value) = params.get("num_ctx").and_then(serde_json::Value::as_u64) {
        if value > thresholds.max_ctx {
            note(
                &mut findings,
                &mut evidence,
                &mut rule_id,
                &subject,
                "LF-PARAM-NUM-CTX",
                "num_ctx",
                value.into(),
                format!(
                    "num_ctx {value} exceeds operator policy maximum {}",
                    thresholds.max_ctx
                ),
            );
        } else if thresholds.max_ctx >= 8 && value > thresholds.max_ctx / 8 {
            note(
                &mut findings,
                &mut evidence,
                &mut rule_id,
                &subject,
                "LF-PARAM-NUM-CTX",
                "num_ctx",
                value.into(),
                format!("num_ctx {value} is large enough to merit resource-capacity review"),
            );
        }
    }

    if let Some(value) = params
        .get("num_predict")
        .and_then(serde_json::Value::as_i64)
    {
        if value >= 0 && value > thresholds.max_predict {
            note(
                &mut findings,
                &mut evidence,
                &mut rule_id,
                &subject,
                "LF-PARAM-NUM-PREDICT",
                "num_predict",
                value.into(),
                format!(
                    "num_predict {value} exceeds operator policy maximum {}",
                    thresholds.max_predict
                ),
            );
        }
    }

    if params.get("top_k").and_then(serde_json::Value::as_u64) == Some(0) {
        note(
            &mut findings,
            &mut evidence,
            &mut rule_id,
            &subject,
            "LF-PARAM-TOP-K",
            "top_k",
            0.into(),
            "top_k 0 disables top-k sampling".to_owned(),
        );
    }

    if let Some(value) = params.get("top_p").and_then(serde_json::Value::as_f64) {
        if value > 0.99 {
            note(
                &mut findings,
                &mut evidence,
                &mut rule_id,
                &subject,
                "LF-PARAM-TOP-P",
                "top_p",
                value.into(),
                format!("top_p {value} makes nucleus filtering minimally restrictive"),
            );
        }
    }

    if let Some(value) = params
        .get("repeat_penalty")
        .and_then(serde_json::Value::as_f64)
    {
        if value < 0.5 {
            note(
                &mut findings,
                &mut evidence,
                &mut rule_id,
                &subject,
                "LF-PARAM-REPEAT-PENALTY",
                "repeat_penalty",
                value.into(),
                format!("repeat_penalty {value} may increase repetition-loop risk"),
            );
        }
    }

    // A fixed seed is a reproducibility setting, not evidence of poisoning.
    // Record it only when another policy anomaly is already present.
    let had_prior_findings = !findings.is_empty();
    if let Some(seed) = params.get("seed").and_then(serde_json::Value::as_i64) {
        if had_prior_findings {
            note(
                &mut findings,
                &mut evidence,
                &mut rule_id,
                &subject,
                "LF-PARAM-SEED",
                "seed",
                seed.into(),
                "fixed seed present (reproducibility setting; informational)".to_owned(),
            );
        }
    }

    if let Some(stops) = params.get("stop").and_then(serde_json::Value::as_array) {
        let stop_pattern = Regex::new(
            r"(?i)(END\s*OF\s*(SYSTEM|INSTRUCTIONS?|PROMPT)|IGNORE\s+ABOVE|HUMAN:|USER:|ASSISTANT:)",
        )?;
        for stop in stops.iter().filter_map(serde_json::Value::as_str) {
            if stop_pattern.is_match(stop) {
                note(
                    &mut findings,
                    &mut evidence,
                    &mut rule_id,
                    &subject,
                    "LF-PARAM-STOP-DELIMITER",
                    "stop",
                    serde_json::Value::String(stop.to_owned()),
                    format!(
                        "stop sequence {} resembles a prompt-role delimiter",
                        safe_preview(stop)
                    ),
                );
            }
        }
    }

    let mut finding = LayerScanResult {
        layer_digest: layer_digest.to_owned(),
        media_type: media_type.to_owned(),
        check_type: CheckType::ParameterThreshold,
        status: if findings.is_empty() {
            ScanStatus::Pass
        } else {
            ScanStatus::Warn
        },
        finding_class: FindingClass::Policy,
        confidence: Confidence::High,
        detail: (!findings.is_empty()).then(|| {
            format!(
                "{} inference-policy anomaly/anomalies detected; these values are not by themselves evidence of a malicious model",
                findings.len()
            )
        }),
        matches: findings,
        duration_ms: elapsed,
        evidence,
        ..Default::default()
    };
    crate::finding_evidence::ensure_finding_identity(
        &mut finding,
        rule_id.unwrap_or("LF-PARAM-CLEAR"),
    );
    Ok(finding)
}

#[allow(clippy::too_many_arguments)]
fn note(
    findings: &mut Vec<String>,
    evidence: &mut Vec<crate::finding_evidence::FindingEvidence>,
    rule_id: &mut Option<&'static str>,
    subject: &EvidenceSubject,
    rule: &'static str,
    key: &str,
    value: serde_json::Value,
    text: String,
) {
    findings.push(format!("[{rule}] {text}"));
    evidence.push(config_value(subject.clone(), key, value, &text));
    rule_id.get_or_insert(rule);
}

fn safe_preview(value: &str) -> String {
    let mut chars = value.chars();
    let preview: String = chars.by_ref().take(80).collect();
    if chars.next().is_some() {
        format!("'{preview}…'")
    } else {
        format!("'{preview}'")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn thresholds() -> ThresholdConfig {
        ThresholdConfig {
            max_temperature: 2.0,
            max_ctx: 1_048_576,
            max_predict: 32_768,
        }
    }

    #[test]
    fn exceeding_policy_is_warning_not_malicious_verdict() -> Result<()> {
        let result = scan_params(
            &json!({ "temperature": 2.1 }),
            "sha256:abc",
            "params",
            0,
            &thresholds(),
        )?;
        assert_eq!(result.status, ScanStatus::Warn);
        assert_eq!(result.finding_class, FindingClass::Policy);
        Ok(())
    }

    #[test]
    fn fixed_seed_alone_passes() -> Result<()> {
        let result = scan_params(
            &json!({ "seed": 42 }),
            "sha256:abc",
            "params",
            0,
            &thresholds(),
        )?;
        assert_eq!(result.status, ScanStatus::Pass);
        Ok(())
    }

    #[test]
    fn unlimited_prediction_sentinel_passes() -> Result<()> {
        let result = scan_params(
            &json!({ "num_predict": -1 }),
            "sha256:abc",
            "params",
            0,
            &thresholds(),
        )?;
        assert_eq!(result.status, ScanStatus::Pass);
        Ok(())
    }
}
