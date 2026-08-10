use super::calls::{CallSite, ExecutionContext, PythonCapabilityCategory};
use super::parser::PythonSyntaxState;
use super::reachability::ReachabilityState;
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use std::time::Instant;

fn finding(
    layer_digest: &str,
    check_type: CheckType,
    status: ScanStatus,
    finding_class: FindingClass,
    confidence: Confidence,
    rule_id: &str,
    detail: String,
) -> LayerScanResult {
    LayerScanResult {
        layer_digest: layer_digest.to_owned(),
        media_type: "application/vnd.layerfault.package-member".to_owned(),
        check_type,
        status,
        finding_class,
        confidence,
        detail: Some(detail),
        matches: vec![rule_id.to_owned()],
        duration_ms: 0,
    }
}

pub fn convert_analysis_to_findings(
    relative_path: &str,
    digest: &str,
    syntax_state: &PythonSyntaxState,
    call_sites: &[CallSite],
    reachability_map: &std::collections::BTreeMap<usize, ReachabilityState>,
    is_auto_mapped: bool,
    started: Instant,
) -> Vec<LayerScanResult> {
    let mut out = Vec::new();

    if let PythonSyntaxState::Invalid {
        error,
        line,
        column,
    } = syntax_state
    {
        let loc = match (line, column) {
            (Some(l), Some(c)) => format!(" at line {l}:{c}"),
            _ => String::new(),
        };
        out.push(finding(
            digest,
            CheckType::PackageSecurity,
            ScanStatus::Warn,
            FindingClass::Structural,
            Confidence::High,
            "LF-PY-SEMANTIC-INCOMPLETE",
            format!(
                "Python static analysis could not parse AST for '{}'{loc}: {error}. Streaming textual scanner was performed as fallback.",
                relative_path
            ),
        ));
    } else if let PythonSyntaxState::ExceededLimits { reason } = syntax_state {
        out.push(finding(
            digest,
            CheckType::PackageSecurity,
            ScanStatus::Warn,
            FindingClass::Structural,
            Confidence::High,
            "LF-PY-SEMANTIC-INCOMPLETE",
            format!(
                "Python static analysis bounds exceeded for '{}': {reason}. Streaming textual scanner was performed as fallback.",
                relative_path
            ),
        ));
    }

    for (idx, call) in call_sites.iter().enumerate() {
        let reachability = reachability_map
            .get(&idx)
            .cloned()
            .unwrap_or(ReachabilityState::UnknownDynamic);

        let target_display = if !call.resolved_target.is_empty() {
            &call.resolved_target
        } else {
            &call.raw_target
        };

        let line_info = call
            .line
            .map(|l| format!(" at line {l}"))
            .unwrap_or_default();

        let ctx_desc = match call.execution_context {
            ExecutionContext::ModuleScope => "module import scope (executes on import)",
            ExecutionContext::Constructor => "class constructor (__init__/__new__)",
            ExecutionContext::ClassBody => "class body scope",
            ExecutionContext::FunctionBody => "function body",
            ExecutionContext::FromPretrainedLike => {
                "model loading method (from_pretrained/from_config)"
            }
            ExecutionContext::ModelInitLike => "model forward/call pass",
            ExecutionContext::ImportHook => "import hook",
            ExecutionContext::Unknown => "unknown context",
        };

        let (legacy_rule, semantic_rule, correlation_rule) = match call.category {
            PythonCapabilityCategory::ProcessExecution => (
                if target_display.starts_with("os.") {
                    "LF-CODE-OS-SYSTEM"
                } else {
                    "LF-CODE-SUBPROCESS"
                },
                "LF-PY-CALL-PROCESS",
                "LF-CORR-HF-LOADER-PROCESS",
            ),
            PythonCapabilityCategory::DynamicCodeEvaluation => (
                if target_display == "eval" {
                    "LF-CODE-EVAL"
                } else {
                    "LF-CODE-EXEC"
                },
                "LF-PY-CALL-DYNAMIC-CODE",
                "LF-CORR-HF-LOADER-DYNAMIC-CODE",
            ),
            PythonCapabilityCategory::NativeLibraryLoading => (
                "LF-CODE-CTYPES",
                "LF-PY-NATIVE-LOAD",
                "LF-CORR-HF-LOADER-NATIVE-LOAD",
            ),
            PythonCapabilityCategory::NetworkAccess => (
                "LF-CODE-NETWORK",
                "LF-PY-CALL-NETWORK",
                "LF-CORR-HF-LOADER-NETWORK",
            ),
            PythonCapabilityCategory::CredentialEnvironmentAccess => (
                "LF-PY-CREDENTIAL-ACCESS",
                "LF-PY-CREDENTIAL-ACCESS",
                "LF-CORR-HF-LOADER-CREDENTIALS",
            ),
            PythonCapabilityCategory::FilesystemMutation => (
                "LF-PY-FILESYSTEM-MUTATION",
                "LF-PY-FILESYSTEM-MUTATION",
                "LF-CORR-HF-LOADER-FILESYSTEM",
            ),
            PythonCapabilityCategory::PackageInstallationCodeAcquisition => (
                "LF-PY-PACKAGE-INSTALL",
                "LF-PY-PACKAGE-INSTALL",
                "LF-CORR-HF-LOADER-INSTALL",
            ),
        };

        let status = ScanStatus::Warn;

        let confidence = if call.reflection_resolved || !call.resolved_target.is_empty() {
            Confidence::High
        } else {
            Confidence::Medium
        };

        let mut evidence_str = format!(
            "Semantic call site '{}' detected in '{}'{line_info}. Context: {ctx_desc}. Static reachability: {reachability}.",
            target_display, relative_path
        );

        if let Some(ref exe) = call.executable_name {
            evidence_str.push_str(&format!(" Executable: '{}'.", exe));
        }
        if call.shell_mode {
            evidence_str.push_str(" Shell mode: enabled.");
        }
        if let Some(ref lit) = call.literal_arg_evidence {
            evidence_str.push_str(&format!(" Command evidence: {}.", lit));
        }

        // Emit legacy rule for backward compatibility
        let mut f_legacy = finding(
            digest,
            CheckType::PackageSecurity,
            status,
            FindingClass::ContentIndicator,
            confidence,
            legacy_rule,
            evidence_str.clone(),
        );
        f_legacy.duration_ms = crate::scanner::duration_ms(started);
        out.push(f_legacy);

        // Emit semantic rule
        if semantic_rule != legacy_rule {
            let mut f_semantic = finding(
                digest,
                CheckType::PackageSecurity,
                status,
                FindingClass::ContentIndicator,
                confidence,
                semantic_rule,
                evidence_str.clone(),
            );
            f_semantic.duration_ms = crate::scanner::duration_ms(started);
            out.push(f_semantic);
        }

        // Emit auto_map correlation rule if applicable
        if is_auto_mapped
            && (reachability == ReachabilityState::ReachableLocal
                || reachability == ReachabilityState::Direct)
        {
            let mut f_corr = finding(
                digest,
                CheckType::PackageSecurity,
                status,
                FindingClass::ContentIndicator,
                Confidence::High,
                correlation_rule,
                format!(
                    "Hugging Face auto_map configuration routes model loading through custom module '{}'{line_info} containing capability '{}'.",
                    relative_path, target_display
                ),
            );
            f_corr.duration_ms = crate::scanner::duration_ms(started);
            out.push(f_corr);
        }
    }

    out
}
