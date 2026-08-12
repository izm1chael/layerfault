//! Conversion of JavaScript/TypeScript analysis results into
//! `LayerScanResult` findings.
//!
//! Mirrors the structure of `shell_static::findings`/`powershell_static::findings`:
//! a local `finding()` helper wrapping `FindingBuilder`, `source_excerpt`
//! for span evidence, and an `INCOMPLETE` fallback finding wording-mirrored
//! on `LF-PY-SEMANTIC-INCOMPLETE`.

use super::parser::JsSyntaxState;
use crate::finding_evidence::{source_excerpt, EvidenceSubject, FindingBuilder};
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use crate::script_capability::{ScriptCallSite, ScriptCapability, ScriptConfidence, ScriptScope};
use std::time::Instant;

#[allow(clippy::too_many_arguments)]
fn finding(
    layer_digest: &str,
    status: ScanStatus,
    finding_class: FindingClass,
    confidence: Confidence,
    rule_id: &str,
    detail: String,
    subject: EvidenceSubject,
    evidence: Option<crate::finding_evidence::FindingEvidence>,
) -> LayerScanResult {
    let mut builder = FindingBuilder::new(rule_id, CheckType::PackageSecurity, status)
        .class(finding_class)
        .confidence(confidence)
        .digest(layer_digest)
        .media_type("application/vnd.layerfault.package-member")
        .subject(subject)
        .detail(detail);
    builder = match evidence {
        Some(record) => builder.evidence(record),
        None => builder.evidence_unavailable(
            "structural/parser-limit findings describe coverage rather than a specific call site",
        ),
    };
    builder.finish()
}

fn confidence_of(value: ScriptConfidence) -> Confidence {
    match value {
        ScriptConfidence::High => Confidence::High,
        ScriptConfidence::Medium => Confidence::Medium,
        ScriptConfidence::Low => Confidence::Low,
    }
}

fn scope_desc(scope: ScriptScope) -> &'static str {
    match scope {
        ScriptScope::Module => "module top-level (executes on load/require)",
        ScriptScope::Function => "function body",
    }
}

fn rule_for(capability: ScriptCapability) -> &'static str {
    match capability {
        ScriptCapability::Process => "LF-JS-SEMANTIC-PROCESS",
        ScriptCapability::DynamicCode => "LF-JS-SEMANTIC-DYNAMIC-CODE",
        ScriptCapability::FilesystemWrite => "LF-JS-SEMANTIC-FILESYSTEM-WRITE",
        ScriptCapability::Network => "LF-JS-SEMANTIC-NETWORK",
        ScriptCapability::CredentialAccess => "LF-JS-SEMANTIC-CREDENTIAL-ACCESS",
        ScriptCapability::PackageInstall => "LF-JS-SEMANTIC-PACKAGE-INSTALL",
        ScriptCapability::NativeLoad => "LF-JS-SEMANTIC-NATIVE-LOAD",
    }
}

pub fn convert_analysis_to_findings(
    relative_path: &str,
    digest: &str,
    syntax_state: &JsSyntaxState,
    call_sites: &[ScriptCallSite],
    started: Instant,
) -> Vec<LayerScanResult> {
    let mut out = Vec::new();
    let subject = EvidenceSubject::member(relative_path).with_sha256(Some(digest.to_owned()));

    match syntax_state {
        JsSyntaxState::Invalid {
            error,
            line,
            column,
        } => {
            let loc = match (line, column) {
                (Some(l), Some(c)) => format!(" at line {l}:{c}"),
                (Some(l), None) => format!(" at line {l}"),
                _ => String::new(),
            };
            out.push(finding(
                digest,
                ScanStatus::Warn,
                FindingClass::Structural,
                Confidence::High,
                "LF-JS-SEMANTIC-INCOMPLETE",
                format!(
                    "JavaScript/TypeScript static analysis could not parse '{}'{loc}: {error}. Streaming textual scanner was performed as fallback.",
                    relative_path
                ),
                subject.clone(),
                None,
            ));
            return out;
        }
        JsSyntaxState::ExceededLimits { reason } => {
            out.push(finding(
                digest,
                ScanStatus::Warn,
                FindingClass::Structural,
                Confidence::High,
                "LF-JS-SEMANTIC-INCOMPLETE",
                format!(
                    "JavaScript/TypeScript static analysis bounds exceeded for '{}': {reason}. Streaming textual scanner was performed as fallback.",
                    relative_path
                ),
                subject.clone(),
                None,
            ));
            return out;
        }
        JsSyntaxState::Valid => {}
    }

    for site in call_sites {
        let target_display = site
            .resolved_target
            .as_deref()
            .filter(|t| !t.is_empty())
            .unwrap_or(&site.raw_target);
        let line_info = site
            .line
            .map(|l| format!(" at line {l}"))
            .unwrap_or_default();
        let ctx_desc = scope_desc(site.scope);

        let mut evidence_str = format!(
            "JavaScript/TypeScript semantic call site '{}' detected in '{}'{line_info}. Context: {ctx_desc}.",
            target_display, relative_path
        );
        if let Some(ref lit) = site.literal_arg_evidence {
            evidence_str.push_str(&format!(" Argument evidence: {}.", lit));
        }

        let rule_id = rule_for(site.capability);
        let confidence = confidence_of(site.confidence);
        let line = site.line.unwrap_or(0) as u64;
        let call_evidence = if site.line.is_some() {
            let mut structured = serde_json::json!({
                "call_target": target_display,
                "execution_context": ctx_desc,
                "capability": format!("{:?}", site.capability),
            });
            if let Some(column) = site.column {
                structured["column"] = serde_json::Value::from(column as u64);
            }
            if let Some(lit) = site.literal_arg_evidence.as_deref() {
                structured["argument_evidence"] = serde_json::Value::String(lit.to_owned());
            }
            Some(
                source_excerpt(subject.clone(), line, line, target_display, target_display)
                    .structured(structured),
            )
        } else {
            None
        };

        let mut f = finding(
            digest,
            ScanStatus::Warn,
            FindingClass::ContentIndicator,
            confidence,
            rule_id,
            evidence_str,
            subject.clone(),
            call_evidence,
        );
        f.duration_ms = crate::scanner::duration_ms(started);
        out.push(f);
    }

    out
}
