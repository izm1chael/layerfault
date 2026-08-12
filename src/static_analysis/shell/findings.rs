//! Conversion of shell analysis results into `LayerScanResult` findings.
//!
//! Mirrors the structure of `python_static::findings`: a local `package_finding()`
//! helper wrapping `FindingBuilder`, `source_excerpt` for span evidence, and
//! an `INCOMPLETE` fallback finding wording-mirrored on
//! `LF-PY-SEMANTIC-INCOMPLETE`.

use super::calls::ShellCallSite;
use super::parser::ShellSyntaxState;
use crate::finding_evidence::{source_excerpt, EvidenceSubject};
use crate::scanner::{Confidence, FindingClass, LayerScanResult, ScanStatus};
use crate::static_analysis::common::capability::{ScriptCapability, ScriptScope};
use crate::static_analysis::common::findings::{confidence_of, package_finding};
use std::time::Instant;

fn scope_desc(scope: ScriptScope) -> &'static str {
    match scope {
        ScriptScope::Module => "script top-level (executes when the script runs)",
        ScriptScope::Function => "shell function body",
    }
}

/// The plan's required shell semantic rule set has no dedicated
/// `LF-SHELL-SEMANTIC-NETWORK` id (only the flagship curl/wget-piped-to-a-
/// shell composite is called out as its own rule). A plain network-tool
/// invocation (`curl http://x -o file`, no pipe to a shell) is still, at
/// bottom, a process-execution capability, so it is folded into
/// `LF-SHELL-SEMANTIC-PROCESS` here; the composite pattern remains the
/// dedicated high-confidence network finding.
fn rule_for(capability: ScriptCapability, is_curl_pipe_sh: bool) -> &'static str {
    if is_curl_pipe_sh {
        return "LF-SHELL-SEMANTIC-CURL-PIPE-SH";
    }
    match capability {
        ScriptCapability::Process | ScriptCapability::Network => "LF-SHELL-SEMANTIC-PROCESS",
        ScriptCapability::DynamicCode => "LF-SHELL-SEMANTIC-DYNAMIC-CODE",
        ScriptCapability::CredentialAccess => "LF-SHELL-SEMANTIC-CREDENTIAL-ACCESS",
        ScriptCapability::PackageInstall => "LF-SHELL-SEMANTIC-PACKAGE-INSTALL",
        ScriptCapability::FilesystemWrite => "LF-SHELL-SEMANTIC-FILESYSTEM-WRITE",
        ScriptCapability::NativeLoad => "LF-SHELL-SEMANTIC-NATIVE-LOAD",
    }
}

pub fn convert_analysis_to_findings(
    relative_path: &str,
    digest: &str,
    syntax_state: &ShellSyntaxState,
    call_sites: &[ShellCallSite],
    started: Instant,
) -> Vec<LayerScanResult> {
    let mut out = Vec::new();
    let subject = EvidenceSubject::member(relative_path).with_sha256(Some(digest.to_owned()));

    match syntax_state {
        ShellSyntaxState::Invalid {
            error,
            line,
            column,
        } => {
            let loc = match (line, column) {
                (Some(l), Some(c)) => format!(" at line {l}:{c}"),
                (Some(l), None) => format!(" at line {l}"),
                _ => String::new(),
            };
            out.push(package_finding(
                digest,
                ScanStatus::Warn,
                FindingClass::Structural,
                Confidence::High,
                "LF-SHELL-SEMANTIC-INCOMPLETE",
                format!(
                    "Shell static analysis could not tokenize '{}'{loc}: {error}. Streaming textual scanner was performed as fallback.",
                    relative_path
                ),
                subject.clone(),
                None,
            ));
            return out;
        }
        ShellSyntaxState::ExceededLimits { reason } => {
            out.push(package_finding(
                digest,
                ScanStatus::Warn,
                FindingClass::Structural,
                Confidence::High,
                "LF-SHELL-SEMANTIC-INCOMPLETE",
                format!(
                    "Shell static analysis bounds exceeded for '{}': {reason}. Streaming textual scanner was performed as fallback.",
                    relative_path
                ),
                subject.clone(),
                None,
            ));
            return out;
        }
        ShellSyntaxState::Valid => {}
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
            "Shell semantic call site '{}' detected in '{}'{line_info}. Context: {ctx_desc}.",
            target_display, relative_path
        );
        if entry.backgrounded {
            evidence_str.push_str(" Backgrounded: yes.");
        }
        if let Some(ref lit) = site.literal_arg_evidence {
            evidence_str.push_str(&format!(" Command evidence: {}.", lit));
        }
        if entry.is_curl_pipe_sh {
            evidence_str
                .push_str(" Pattern: downloaded content piped directly into a shell interpreter.");
        }

        let rule_id = rule_for(site.capability, entry.is_curl_pipe_sh);
        let confidence = confidence_of(site.confidence);
        let line = site.line.unwrap_or(0) as u64;
        let call_evidence = if site.line.is_some() {
            let mut structured = serde_json::json!({
                "call_target": target_display,
                "execution_context": ctx_desc,
                "capability": format!("{:?}", site.capability),
            });
            if entry.backgrounded {
                structured["backgrounded"] = serde_json::Value::Bool(true);
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

        let mut f = package_finding(
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
