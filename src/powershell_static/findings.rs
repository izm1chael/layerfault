//! Conversion of PowerShell analysis results into `LayerScanResult` findings.
//!
//! Mirrors the structure of `shell_static::findings`: a local `finding()`
//! helper wrapping `FindingBuilder`, `source_excerpt` for span evidence, and
//! an `INCOMPLETE` fallback finding wording-mirrored on
//! `LF-PY-SEMANTIC-INCOMPLETE`/`LF-SHELL-SEMANTIC-INCOMPLETE`.

use super::calls::PowerShellCallSite;
use super::parser::PowerShellSyntaxState;
use crate::finding_evidence::{source_excerpt, EvidenceSubject, FindingBuilder};
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use crate::script_capability::{ScriptCapability, ScriptConfidence, ScriptScope};
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
        ScriptScope::Module => "script top-level (executes when the script runs)",
        ScriptScope::Function => "function/filter body",
    }
}

/// Rule id selection for a classified call site. `LF-PS-SEMANTIC-NETWORK`
/// only applies to a plain (non-composite) network call; the `irm|iex` /
/// `iwr|iex` composite gets its own dedicated flagship rule.
fn rule_for(capability: ScriptCapability, is_download_execute: bool) -> &'static str {
    if is_download_execute {
        return "LF-PS-SEMANTIC-DOWNLOAD-EXECUTE";
    }
    match capability {
        ScriptCapability::Process => "LF-PS-SEMANTIC-PROCESS",
        ScriptCapability::Network => "LF-PS-SEMANTIC-NETWORK",
        ScriptCapability::DynamicCode => "LF-PS-SEMANTIC-DYNAMIC-CODE",
        ScriptCapability::CredentialAccess => "LF-PS-SEMANTIC-CREDENTIAL-ACCESS",
        ScriptCapability::PackageInstall => "LF-PS-SEMANTIC-PACKAGE-INSTALL",
        ScriptCapability::NativeLoad => "LF-PS-SEMANTIC-NATIVE-LOAD",
        // Not classified by this frontend today; kept exhaustive so a
        // future capability addition fails to compile here instead of
        // silently mis-mapping.
        ScriptCapability::FilesystemWrite => "LF-PS-SEMANTIC-PROCESS",
    }
}

pub fn convert_analysis_to_findings(
    relative_path: &str,
    digest: &str,
    syntax_state: &PowerShellSyntaxState,
    call_sites: &[PowerShellCallSite],
    started: Instant,
) -> Vec<LayerScanResult> {
    let mut out = Vec::new();
    let subject = EvidenceSubject::member(relative_path).with_sha256(Some(digest.to_owned()));

    match syntax_state {
        PowerShellSyntaxState::Invalid {
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
                "LF-PS-SEMANTIC-INCOMPLETE",
                format!(
                    "PowerShell static analysis could not tokenize '{}'{loc}: {error}. Streaming textual scanner was performed as fallback.",
                    relative_path
                ),
                subject.clone(),
                None,
            ));
            return out;
        }
        PowerShellSyntaxState::ExceededLimits { reason } => {
            out.push(finding(
                digest,
                ScanStatus::Warn,
                FindingClass::Structural,
                Confidence::High,
                "LF-PS-SEMANTIC-INCOMPLETE",
                format!(
                    "PowerShell static analysis bounds exceeded for '{}': {reason}. Streaming textual scanner was performed as fallback.",
                    relative_path
                ),
                subject.clone(),
                None,
            ));
            return out;
        }
        PowerShellSyntaxState::Valid => {}
    }

    for entry in call_sites {
        let site = &entry.site;
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
            "PowerShell semantic call site '{}' detected in '{}'{line_info}. Context: {ctx_desc}.",
            target_display, relative_path
        );
        if let Some(ref lit) = site.literal_arg_evidence {
            evidence_str.push_str(&format!(" Command evidence: {}.", lit));
        }
        if entry.is_download_execute {
            evidence_str.push_str(
                " Pattern: remote content downloaded and piped directly into Invoke-Expression.",
            );
        }
        if entry.has_encoded_command {
            evidence_str.push_str(
                " -EncodedCommand flag present (case-insensitive; PowerShell's base64-encoded-command evasion idiom).",
            );
        }

        let rule_id = rule_for(site.capability, entry.is_download_execute);
        let confidence = confidence_of(site.confidence);
        let line = site.line.unwrap_or(0) as u64;
        let call_evidence = if site.line.is_some() {
            let mut structured = serde_json::json!({
                "call_target": target_display,
                "execution_context": ctx_desc,
                "capability": format!("{:?}", site.capability),
            });
            if entry.has_encoded_command {
                structured["encoded_command"] = serde_json::Value::Bool(true);
            }
            if let Some(lit) = site.literal_arg_evidence.as_deref() {
                structured["command_evidence"] = serde_json::Value::String(lit.to_owned());
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
