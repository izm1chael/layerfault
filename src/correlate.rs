//! Structural correlation between findings.
//!
//! Two unrelated warnings are much weaker than one demonstrated relationship.
//! `auto_map` pointing at a module, and that same module containing a process
//! execution primitive, is a materially different security condition from those
//! two facts merely co-occurring in a package.
//!
//! Correlations here are built from resolved subject relationships, never from
//! "these two rule IDs both appeared". They describe technical conditions and
//! deliberately do not assert intent: static analysis has not established that a
//! primitive is reachable, executes on load, or is malicious.

use crate::finding_evidence::{
    path_relationship, sort_correlations, EvidenceSubject, FindingCorrelation,
};
use crate::scanner::{Confidence, LayerScanResult, ScanStatus};

/// Rules that indicate the package routes loading through publisher code.
const LOADER_RULES: &[&str] = &["LF-CODE-AUTO-MAP", "LF-CODE-REMOTE-TRUST"];

/// Rules that indicate a code-execution or egress capability in package text.
const CAPABILITY_RULES: &[(&str, &str, &str)] = &[
    (
        "LF-CODE-SUBPROCESS",
        "LF-CORR-CUSTOM-LOADER-PROCESS",
        "process-execution",
    ),
    (
        "LF-CODE-OS-SYSTEM",
        "LF-CORR-CUSTOM-LOADER-PROCESS",
        "process-execution",
    ),
    (
        "LF-CODE-NETWORK",
        "LF-CORR-CUSTOM-LOADER-NETWORK",
        "outbound network",
    ),
    (
        "LF-CODE-EVAL",
        "LF-CORR-CUSTOM-LOADER-EVAL",
        "dynamic code evaluation",
    ),
    (
        "LF-CODE-EXEC",
        "LF-CORR-CUSTOM-LOADER-EVAL",
        "dynamic code evaluation",
    ),
    (
        "LF-CODE-CTYPES",
        "LF-CORR-CUSTOM-LOADER-NATIVE",
        "native library loading",
    ),
    (
        "LF-CODE-IMPORT-SIDE-EFFECT",
        "LF-CORR-CUSTOM-LOADER-IMPORT",
        "import-time side effects",
    ),
];

const LIMITATION: &str = "Static analysis establishes the reference and the capability, \
     not that the referenced code executes automatically, that the capability is reachable \
     during loading, or that the author intended harm.";

/// Derive correlations from a completed set of findings.
///
/// Correlations never mutate finding severity; they are additional context that
/// a reviewer or policy engine can act on.
pub fn correlate(findings: &[LayerScanResult]) -> Vec<FindingCorrelation> {
    let mut out = Vec::new();
    out.extend(custom_loader_chains(findings));
    out.extend(unsafe_serialization_chains(findings));
    out.extend(template_chains(findings));
    out.extend(native_extension_chains(findings));
    sort_correlations(&mut out);
    out
}

/// `auto_map`/`trust_remote_code` -> referenced module -> capability in that module.
fn custom_loader_chains(findings: &[LayerScanResult]) -> Vec<FindingCorrelation> {
    let loaders: Vec<&LayerScanResult> = findings
        .iter()
        .filter(|finding| matches_rule(finding, LOADER_RULES))
        .collect();
    if loaders.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    for loader in loaders {
        for reference in referenced_modules(loader) {
            for (capability_rule, correlation_id, capability_label) in CAPABILITY_RULES {
                for capability in findings
                    .iter()
                    .filter(|finding| matches_rule(finding, &[capability_rule]))
                {
                    let Some(member) = subject_name(capability) else {
                        continue;
                    };
                    let Some(confidence) = module_match(&reference, member) else {
                        continue;
                    };
                    let where_clause = capability_location(capability)
                        .map(|line| format!("{member}:{line}"))
                        .unwrap_or_else(|| member.to_owned());
                    out.push(FindingCorrelation {
                        id: (*correlation_id).to_owned(),
                        finding_ids: finding_ids(&[loader, capability]),
                        rule_ids: rule_ids(&[loader, capability]),
                        summary: format!(
                            "Model metadata in '{}' directs compatible loading paths to '{}'. \
                             The resolved module '{}' contains {} functionality at {}. \
                             This is a security-relevant loading path that requires review \
                             before custom code is permitted.",
                            loader_source(loader),
                            reference.symbol,
                            member,
                            capability_label,
                            where_clause,
                        ),
                        confidence,
                        evidence: vec![path_relationship(
                            EvidenceSubject::member(member),
                            "Configuration reference resolves to the module containing the capability",
                            serde_json::json!({
                                "config": loader_source(loader),
                                "config_key": reference.key,
                                "referenced_symbol": reference.symbol,
                                "resolved_module_path": member,
                                "capability_rule": capability_rule,
                            }),
                        )],
                        limitations: Some(LIMITATION.to_owned()),
                    });
                }
            }
        }
    }
    out
}

/// Code-capable serialization plus a dangerous callable in the same artifact.
fn unsafe_serialization_chains(findings: &[LayerScanResult]) -> Vec<FindingCorrelation> {
    let mut out = Vec::new();
    for serialization in findings
        .iter()
        .filter(|finding| matches_rule(finding, &["LF-SERIALIZATION-UNSAFE"]))
    {
        let Some(member) = subject_name(serialization) else {
            continue;
        };
        for dangerous in findings
            .iter()
            .filter(|finding| matches_rule(finding, &["LF-PICKLE-DANGEROUS-GLOBAL"]))
        {
            if subject_name(dangerous) != Some(member) {
                continue;
            }
            out.push(FindingCorrelation {
                id: "LF-CORR-UNSAFE-SERIALIZATION".to_owned(),
                finding_ids: finding_ids(&[serialization, dangerous]),
                rule_ids: rule_ids(&[serialization, dangerous]),
                summary: format!(
                    "'{member}' uses a code-capable serialization format and bounded static \
                     opcode analysis resolved a dangerous callable within the same stream. \
                     Loading this artifact with an unsafe deserializer is a dangerous path."
                ),
                confidence: Confidence::High,
                evidence: vec![path_relationship(
                    EvidenceSubject::member(member),
                    "Dangerous callable resolved inside the code-capable serialization stream",
                    serde_json::json!({ "member": member }),
                )],
                limitations: Some(
                    "Layerfault never deserialized the stream. Presence of the callable does not \
                     establish that a loader will reach it."
                        .to_owned(),
                ),
            });
        }
    }
    out
}

/// A template that both traverses objects and reaches an introspection gadget.
fn template_chains(findings: &[LayerScanResult]) -> Vec<FindingCorrelation> {
    let mut out = Vec::new();
    for introspection in findings.iter().filter(|finding| {
        matches_rule(
            finding,
            &["LF-TEMPLATE-INTROSPECTION", "LF-TEMPLATE-DYNAMIC-INCLUDE"],
        )
    }) {
        let Some(member) = subject_name(introspection) else {
            continue;
        };
        for ssti in findings
            .iter()
            .filter(|finding| matches_rule(finding, &["LF-TEMPLATE-SSTI"]))
        {
            if subject_name(ssti).is_some_and(|other| other != member) {
                continue;
            }
            out.push(FindingCorrelation {
                id: "LF-CORR-TEMPLATE-INTROSPECTION".to_owned(),
                finding_ids: finding_ids(&[introspection, ssti]),
                rule_ids: rule_ids(&[introspection, ssti]),
                summary: format!(
                    "Template content in '{member}' combines object traversal with a known \
                     server-side template injection gadget. This requires investigation of the \
                     rendering context before the template is used."
                ),
                confidence: Confidence::High,
                evidence: vec![path_relationship(
                    EvidenceSubject::member(member),
                    "Template traversal and introspection gadget observed in the same subject",
                    serde_json::json!({ "member": member }),
                )],
                limitations: Some(
                    "Layerfault never renders templates. Exploitability depends on the runtime \
                     rendering context, which static analysis cannot determine."
                        .to_owned(),
                ),
            });
        }
    }
    out
}

/// Custom loader plus a native package member referenced from package code.
fn native_extension_chains(findings: &[LayerScanResult]) -> Vec<FindingCorrelation> {
    let native: Vec<&LayerScanResult> = findings
        .iter()
        .filter(|finding| {
            matches_rule(finding, &["LF-PACKAGE-ARTIFACT", "LF-PACKAGE-FILE"])
                && subject_name(finding).is_some_and(is_native_member)
        })
        .collect();
    if native.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for loader in findings
        .iter()
        .filter(|finding| matches_rule(finding, LOADER_RULES))
    {
        for member in &native {
            let Some(path) = subject_name(member) else {
                continue;
            };
            out.push(FindingCorrelation {
                id: "LF-CORR-NATIVE-EXTENSION".to_owned(),
                finding_ids: finding_ids(&[loader, member]),
                rule_ids: rule_ids(&[loader, member]),
                summary: format!(
                    "The package routes loading through publisher-supplied code and also ships \
                     the native module '{path}'. Native members execute outside Python's \
                     inspection surface and require review."
                ),
                confidence: Confidence::Medium,
                evidence: vec![path_relationship(
                    EvidenceSubject::member(path),
                    "Custom loading path coexists with a native package member",
                    serde_json::json!({ "native_member": path }),
                )],
                limitations: Some(
                    "Layerfault has not established that the custom loading path loads this \
                     native member."
                        .to_owned(),
                ),
            });
        }
    }
    out
}

/// A symbol reference captured from configuration metadata.
struct ModuleReference {
    key: String,
    symbol: String,
    module_path: String,
}

/// Extract `auto_map`-style references from a loader finding's evidence.
fn referenced_modules(finding: &LayerScanResult) -> Vec<ModuleReference> {
    let mut out = Vec::new();
    for record in &finding.evidence {
        let Some(structured) = record.structured.as_ref() else {
            continue;
        };
        let key = structured
            .get("key")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let Some(value) = structured.get("value") else {
            continue;
        };
        for symbol in symbol_strings(value) {
            // Hugging Face writes `module.submodule.ClassName`, optionally
            // prefixed with `repo--`. The module is everything before the
            // final class segment.
            let cleaned = symbol.rsplit("--").next().unwrap_or(&symbol).to_owned();
            let Some((module, _class)) = cleaned.rsplit_once('.') else {
                continue;
            };
            if module.is_empty() {
                continue;
            }
            out.push(ModuleReference {
                key: key.clone(),
                symbol: symbol.clone(),
                module_path: format!("{}.py", module.replace('.', "/")),
            });
        }
    }
    out
}

fn symbol_strings(value: &serde_json::Value) -> Vec<String> {
    match value {
        serde_json::Value::String(text) => vec![text.clone()],
        serde_json::Value::Array(items) => items.iter().flat_map(symbol_strings).collect(),
        serde_json::Value::Object(fields) => fields.values().flat_map(symbol_strings).collect(),
        _ => Vec::new(),
    }
}

/// Compare a referenced module path against a package member path.
///
/// An exact package-relative match is high confidence. A basename-only match
/// (the module lives in a subdirectory, or the config sits beside it) is real
/// but weaker, and is reported as such rather than overstated.
fn module_match(reference: &ModuleReference, member: &str) -> Option<Confidence> {
    let member_lower = member.to_ascii_lowercase();
    let module_lower = reference.module_path.to_ascii_lowercase();
    if member_lower == module_lower || member_lower.ends_with(&format!("/{module_lower}")) {
        return Some(Confidence::High);
    }
    let module_base = module_lower.rsplit('/').next().unwrap_or(&module_lower);
    let member_base = member_lower.rsplit('/').next().unwrap_or(&member_lower);
    if module_base == member_base {
        return Some(Confidence::Medium);
    }
    None
}

fn is_native_member(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    [".so", ".dll", ".dylib", ".node", ".jar", ".pyd"]
        .iter()
        .any(|extension| lower.ends_with(extension))
}

fn matches_rule(finding: &LayerScanResult, rules: &[&str]) -> bool {
    if finding.status == ScanStatus::Pass {
        return false;
    }
    let id = crate::policy::rule_id(finding);
    rules.iter().any(|rule| id.eq_ignore_ascii_case(rule))
}

fn subject_name(finding: &LayerScanResult) -> Option<&str> {
    finding
        .subject
        .as_ref()
        .and_then(|subject| subject.package_relative_path.as_deref())
}

fn loader_source(finding: &LayerScanResult) -> &str {
    subject_name(finding).unwrap_or("model configuration")
}

fn capability_location(finding: &LayerScanResult) -> Option<u64> {
    finding
        .evidence
        .iter()
        .find_map(|record| match &record.location {
            Some(crate::finding_evidence::EvidenceLocation::Text { line_start, .. }) => {
                Some(*line_start)
            }
            _ => None,
        })
}

fn finding_ids(findings: &[&LayerScanResult]) -> Vec<String> {
    let mut out: Vec<String> = findings
        .iter()
        .filter_map(|finding| finding.finding_id.clone())
        .collect();
    out.sort();
    out.dedup();
    out
}

fn rule_ids(findings: &[&LayerScanResult]) -> Vec<String> {
    let mut out: Vec<String> = findings
        .iter()
        .map(|finding| crate::policy::rule_id(finding))
        .collect();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding_evidence::{config_value, source_excerpt, FindingBuilder};
    use crate::scanner::{CheckType, FindingClass};

    fn auto_map(value: &str) -> LayerScanResult {
        let subject = EvidenceSubject::member("config.json");
        FindingBuilder::new(
            "LF-CODE-AUTO-MAP",
            CheckType::PackageSecurity,
            ScanStatus::Warn,
        )
        .class(FindingClass::ContentIndicator)
        .confidence(Confidence::High)
        .subject(subject.clone())
        .evidence(config_value(
            subject,
            "auto_map.AutoModel",
            serde_json::Value::String(value.to_owned()),
            "Custom model class mapping",
        ))
        .finish()
    }

    fn capability(rule: &str, member: &str, line: u64) -> LayerScanResult {
        let subject = EvidenceSubject::member(member);
        FindingBuilder::new(rule, CheckType::PackageSecurity, ScanStatus::Warn)
            .class(FindingClass::ContentIndicator)
            .confidence(Confidence::High)
            .subject(subject.clone())
            .evidence(source_excerpt(
                subject,
                line,
                line,
                "subprocess.run(",
                "subprocess.run(cmd)",
            ))
            .finish()
    }

    #[test]
    fn resolved_module_path_correlates_at_high_confidence() {
        let findings = vec![
            auto_map("modeling_custom.CustomModel"),
            capability("LF-CODE-SUBPROCESS", "modeling_custom.py", 73),
        ];
        let correlations = correlate(&findings);
        assert_eq!(correlations.len(), 1);
        let correlation = &correlations[0];
        assert_eq!(correlation.id, "LF-CORR-CUSTOM-LOADER-PROCESS");
        assert_eq!(correlation.confidence, Confidence::High);
        assert_eq!(correlation.finding_ids.len(), 2);
        assert!(correlation.summary.contains("modeling_custom.py:73"));
        assert!(correlation.limitations.is_some());
    }

    #[test]
    fn unrelated_module_does_not_correlate() {
        let findings = vec![
            auto_map("modeling_custom.CustomModel"),
            capability("LF-CODE-SUBPROCESS", "unrelated_tool.py", 10),
        ];
        assert!(correlate(&findings).is_empty());
    }

    #[test]
    fn nested_module_reference_resolves() {
        let findings = vec![
            auto_map("custom_pkg.modeling.CustomModel"),
            capability("LF-CODE-SUBPROCESS", "custom_pkg/modeling.py", 8),
        ];
        let correlations = correlate(&findings);
        assert_eq!(correlations.len(), 1);
        assert_eq!(correlations[0].confidence, Confidence::High);
    }

    #[test]
    fn hub_prefixed_reference_resolves() {
        let findings = vec![
            auto_map("owner/repo--modeling_custom.CustomModel"),
            capability("LF-CODE-SUBPROCESS", "modeling_custom.py", 3),
        ];
        assert_eq!(correlate(&findings).len(), 1);
    }

    #[test]
    fn correlation_summaries_avoid_intent_claims() {
        let findings = vec![
            auto_map("modeling_custom.CustomModel"),
            capability("LF-CODE-SUBPROCESS", "modeling_custom.py", 73),
        ];
        for correlation in correlate(&findings) {
            let lower = correlation.summary.to_ascii_lowercase();
            for banned in ["malicious", "backdoor", "compromised", "attacker"] {
                assert!(
                    !lower.contains(banned),
                    "intent claim in correlation summary"
                );
            }
        }
    }

    #[test]
    fn correlation_output_is_deterministic() {
        let findings = vec![
            auto_map("modeling_custom.CustomModel"),
            capability("LF-CODE-SUBPROCESS", "modeling_custom.py", 73),
            capability("LF-CODE-NETWORK", "modeling_custom.py", 12),
        ];
        let first = correlate(&findings);
        let mut reversed = findings.clone();
        reversed.reverse();
        let second = correlate(&reversed);
        assert_eq!(
            first.iter().map(|c| c.id.clone()).collect::<Vec<_>>(),
            second.iter().map(|c| c.id.clone()).collect::<Vec<_>>()
        );
    }
}
