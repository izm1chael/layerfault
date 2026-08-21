//! Single chokepoint for rendering command failures.
//!
//! Replaces ad-hoc `eprintln!("Error: …")` / `anyhow`-dump sites with one
//! deterministic path. With `--json` it emits the structured failure envelope to
//! stdout (so JSON consumers parse one channel); otherwise it writes a
//! human-readable multi-line report to stderr. The exit code is unchanged:
//! bubbled command errors still fail with `ExitCode::FAILURE`; scanner/policy
//! verdicts are owned by `SecurityDecision` (`docs/EXIT_CODES.md`).
//!
//! The envelope is additive over the previous `{error:{message, causes}}`
//! shape: it keeps `message` and `causes` and adds a stable `kind`, `severity`,
//! `recoverable`, and optional `subject`/`hint`. No version field and no
//! tracking identifiers are emitted.

use anyhow::Error;
use layerfault::error::{ErrorKind, LayerfaultError, Severity};
use layerfault::finding_evidence::redact_secrets;
use layerfault::json_stream;
use serde::Serialize;
use std::io::Write;

struct Classification {
    kind: &'static str,
    code: Option<&'static str>,
    severity: &'static str,
    recoverable: bool,
    message: String,
    subject: Option<String>,
    hint: Option<String>,
}

fn classify(error: &Error) -> Classification {
    if let Some(lf) = error.downcast_ref::<LayerfaultError>() {
        Classification {
            kind: lf.kind().as_str(),
            code: lf.code(),
            severity: lf.severity().as_str(),
            recoverable: lf.recoverable(),
            message: lf.message().to_owned(),
            subject: lf.subject().map(str::to_owned),
            hint: lf.hint().map(str::to_owned),
        }
    } else {
        Classification {
            kind: ErrorKind::Uncategorized.as_str(),
            code: None,
            severity: Severity::Error.as_str(),
            recoverable: false,
            message: error.to_string(),
            subject: None,
            hint: None,
        }
    }
}

#[derive(Serialize)]
struct FailureEnvelope {
    error: EnvelopeError,
}

#[derive(Serialize)]
struct EnvelopeError {
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<&'static str>,
    severity: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject: Option<String>,
    causes: Vec<String>,
    recoverable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    hint: Option<String>,
}

/// Build the structured JSON failure envelope for `error` (pure; tested).
pub(crate) fn build_json_envelope(error: &Error) -> serde_json::Value {
    let classification = classify(error);
    let message = redact_secrets(&classification.message).0;
    let subject = classification.subject.map(|s| redact_secrets(&s).0);
    let hint = classification.hint.map(|h| redact_secrets(&h).0);
    let causes: Vec<String> = error
        .chain()
        .skip(1)
        .map(|cause| redact_secrets(&cause.to_string()).0)
        .collect();
    let envelope = FailureEnvelope {
        error: EnvelopeError {
            kind: classification.kind,
            code: classification.code,
            severity: classification.severity,
            message,
            subject,
            causes,
            recoverable: classification.recoverable,
            hint,
        },
    };
    serde_json::to_value(&envelope).unwrap_or_default()
}

/// Build a human-readable failure report for `error` (pure; tested).
pub(crate) fn build_human_report(error: &Error) -> String {
    let classification = classify(error);
    let message = redact_secrets(&classification.message).0;
    let mut report = String::new();
    if let Some(code) = classification.code {
        report.push_str(&format!(
            "Error [{} / {}]: {}\n",
            code, classification.kind, message
        ));
    } else {
        report.push_str(&format!("Error [{}]: {}\n", classification.kind, message));
    }
    for cause in error.chain().skip(1) {
        let cause_text = redact_secrets(&cause.to_string()).0;
        report.push_str(&format!("  caused by: {}\n", cause_text));
    }
    if let Some(subject) = &classification.subject {
        report.push_str(&format!("  subject: {}\n", redact_secrets(subject).0));
    }
    if let Some(hint) = &classification.hint {
        report.push_str(&format!("  hint: {}\n", redact_secrets(hint).0));
    }
    report
}

/// Render `error` as the structured JSON failure envelope to stdout (`--json`).
pub(crate) fn render_json(error: &Error) {
    let value = build_json_envelope(error);
    let _ = json_stream::write_stdout_json(&value, true);
}

/// Render `error` for a human reader to stderr (no `--json`).
pub(crate) fn render_human(error: &Error) {
    let report = build_human_report(error);
    let stderr = std::io::stderr();
    let mut stderr = stderr.lock();
    let _ = stderr.write_all(report.as_bytes());
    let _ = stderr.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classified_envelope_carries_kind_and_severity() {
        let error: Error = LayerfaultError::subprocess("probe exited 139")
            .with_subject("probe=year-2026-weather")
            .with_hint("retry with a larger profile")
            .into();
        let value = build_json_envelope(&error);
        let error_obj = value.get("error").expect("envelope has error");
        assert_eq!(error_obj["kind"], "subprocess_exit");
        assert_eq!(error_obj["severity"], "error");
        assert_eq!(error_obj["recoverable"], true);
        assert_eq!(error_obj["message"], "probe exited 139");
        assert_eq!(error_obj["subject"], "probe=year-2026-weather");
        assert_eq!(error_obj["hint"], "retry with a larger profile");
    }

    #[test]
    fn unclassified_envelope_keeps_message_and_causes() {
        let error: Error = anyhow::anyhow!("top").context("middle");
        let value = build_json_envelope(&error);
        let error_obj = value.get("error").expect("envelope has error");
        assert_eq!(error_obj["kind"], "uncategorized");
        assert_eq!(error_obj["severity"], "error");
        assert_eq!(error_obj["message"], "middle");
        let causes = error_obj["causes"].as_array().expect("causes array");
        assert_eq!(causes.len(), 1);
        assert_eq!(causes[0], "top");
    }

    #[test]
    fn envelope_redacts_secret_shaped_messages() {
        let error: Error =
            LayerfaultError::config("api_key='sk-abcd1234efgh5678ij' rejected").into();
        let value = build_json_envelope(&error);
        let serialized = serde_json::to_string(&value).expect("serialize");
        assert!(!serialized.contains("sk-abcd1234efgh5678ij"));
        assert!(serialized.contains("<redacted"));
    }

    #[test]
    fn human_report_includes_kind_and_hint() {
        let error: Error = LayerfaultError::budget("wall-clock deadline exceeded")
            .with_hint("retry with --budget-profile deep")
            .into();
        let report = build_human_report(&error);
        assert!(report.contains("Error [budget_exceeded]: wall-clock deadline exceeded"));
        assert!(report.contains("hint: retry with --budget-profile deep"));
    }

    #[test]
    fn envelope_and_human_report_include_code_when_present() {
        let error: Error = LayerfaultError::http("upstream connection reset")
            .with_code("LF-ERR-HTTP-RESET")
            .with_subject("endpoint=https://huggingface.co")
            .into();
        let value = build_json_envelope(&error);
        let error_obj = value.get("error").expect("envelope has error");
        assert_eq!(error_obj["code"], "LF-ERR-HTTP-RESET");
        assert_eq!(error_obj["kind"], "http_transport");

        let human = build_human_report(&error);
        assert!(
            human.contains("Error [LF-ERR-HTTP-RESET / http_transport]: upstream connection reset")
        );
    }
}
