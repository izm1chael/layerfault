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
    let mut findings = Vec::new();

    if let Some(value) = params
        .get("temperature")
        .and_then(serde_json::Value::as_f64)
    {
        if value > thresholds.max_temperature {
            findings.push(format!(
                "temperature {value} exceeds operator policy maximum {}",
                thresholds.max_temperature
            ));
        } else if value > TEMPERATURE_WARN {
            findings.push(format!(
                "temperature {value} is unusually high (review threshold {TEMPERATURE_WARN})"
            ));
        }
    }

    if let Some(value) = params.get("num_ctx").and_then(serde_json::Value::as_u64) {
        if value > thresholds.max_ctx {
            findings.push(format!(
                "num_ctx {value} exceeds operator policy maximum {}",
                thresholds.max_ctx
            ));
        } else if thresholds.max_ctx >= 8 && value > thresholds.max_ctx / 8 {
            findings.push(format!(
                "num_ctx {value} is large enough to merit resource-capacity review"
            ));
        }
    }

    if let Some(value) = params
        .get("num_predict")
        .and_then(serde_json::Value::as_i64)
    {
        if value >= 0 && value > thresholds.max_predict {
            findings.push(format!(
                "num_predict {value} exceeds operator policy maximum {}",
                thresholds.max_predict
            ));
        }
    }

    if params.get("top_k").and_then(serde_json::Value::as_u64) == Some(0) {
        findings.push("top_k 0 disables top-k sampling".to_owned());
    }

    if let Some(value) = params.get("top_p").and_then(serde_json::Value::as_f64) {
        if value > 0.99 {
            findings.push(format!(
                "top_p {value} makes nucleus filtering minimally restrictive"
            ));
        }
    }

    if let Some(value) = params
        .get("repeat_penalty")
        .and_then(serde_json::Value::as_f64)
    {
        if value < 0.5 {
            findings.push(format!(
                "repeat_penalty {value} may increase repetition-loop risk"
            ));
        }
    }

    // A fixed seed is a reproducibility setting, not evidence of poisoning.
    // Record it only when another policy anomaly is already present.
    if params
        .get("seed")
        .and_then(serde_json::Value::as_i64)
        .is_some()
        && !findings.is_empty()
    {
        findings.push("fixed seed present (reproducibility setting; informational)".to_owned());
    }

    if let Some(stops) = params.get("stop").and_then(serde_json::Value::as_array) {
        let stop_pattern = Regex::new(
            r"(?i)(END\s*OF\s*(SYSTEM|INSTRUCTIONS?|PROMPT)|IGNORE\s+ABOVE|HUMAN:|USER:|ASSISTANT:)",
        )?;
        for stop in stops.iter().filter_map(serde_json::Value::as_str) {
            if stop_pattern.is_match(stop) {
                findings.push(format!(
                    "stop sequence {} resembles a prompt-role delimiter",
                    safe_preview(stop)
                ));
            }
        }
    }

    Ok(LayerScanResult {
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
    })
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
