use super::*;

/// coincidental co-occurrence.
///
/// Correlations describe technical conditions. They deliberately do not assert
/// intent: a resolved custom-loader-to-process-execution chain is a "dangerous
/// loading path requiring investigation", not proof of malice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingCorrelation {
    pub id: String,
    pub finding_ids: Vec<String>,
    pub rule_ids: Vec<String>,
    pub summary: String,
    pub confidence: Confidence,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<FindingEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limitations: Option<String>,
}

impl FindingCorrelation {
    fn sort_key(&self) -> (String, Vec<String>) {
        (self.id.clone(), self.finding_ids.clone())
    }
}

/// Sort correlations into a deterministic order.
pub fn sort_correlations(correlations: &mut [FindingCorrelation]) {
    correlations.sort_by_key(FindingCorrelation::sort_key);
}

/// A per-report evidence budget shared by detectors that can emit many findings.
// Structural correlation between findings.
//
// Two unrelated warnings are much weaker than one demonstrated relationship.
// `auto_map` pointing at a module, and that same module containing a process
// execution primitive, is a materially different security condition from those
// two facts merely co-occurring in a package.
//
// Correlations here are built from resolved subject relationships, never from
// "these two rule IDs both appeared". They describe technical conditions and
// deliberately do not assert intent: static analysis has not established that a
// primitive is reachable, executes on load, or is malicious.
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
    (
        "LF-PY-PACKAGE-INSTALL",
        "LF-CORR-RUNTIME-INSTALL",
        "package-manager invocation",
    ),
    (
        "LF-SHELL-SEMANTIC-PROCESS",
        "LF-CORR-CUSTOM-LOADER-PROCESS",
        "process-execution",
    ),
    (
        "LF-SHELL-SEMANTIC-CURL-PIPE-SH",
        "LF-CORR-CUSTOM-LOADER-NETWORK",
        "outbound network",
    ),
    (
        "LF-SHELL-SEMANTIC-PACKAGE-INSTALL",
        "LF-CORR-RUNTIME-INSTALL",
        "package-manager invocation",
    ),
    (
        "LF-PS-SEMANTIC-DOWNLOAD-EXECUTE",
        "LF-CORR-CUSTOM-LOADER-NETWORK",
        "outbound network",
    ),
    (
        "LF-PS-SEMANTIC-PROCESS",
        "LF-CORR-CUSTOM-LOADER-PROCESS",
        "process-execution",
    ),
    (
        "LF-PS-SEMANTIC-PACKAGE-INSTALL",
        "LF-CORR-RUNTIME-INSTALL",
        "package-manager invocation",
    ),
    (
        "LF-JS-SEMANTIC-PROCESS",
        "LF-CORR-CUSTOM-LOADER-PROCESS",
        "process-execution",
    ),
    (
        "LF-JS-SEMANTIC-NETWORK",
        "LF-CORR-CUSTOM-LOADER-NETWORK",
        "outbound network",
    ),
    (
        "LF-JS-SEMANTIC-DYNAMIC-CODE",
        "LF-CORR-CUSTOM-LOADER-EVAL",
        "dynamic code evaluation",
    ),
    (
        "LF-JS-SEMANTIC-NATIVE-LOAD",
        "LF-CORR-CUSTOM-LOADER-NATIVE",
        "native library loading",
    ),
    (
        "LF-JS-SEMANTIC-PACKAGE-INSTALL",
        "LF-CORR-RUNTIME-INSTALL",
        "package-manager invocation",
    ),
];

/// Rules describing a setup.py install/build hook's own capability, correlated
/// against the hook that carries it.
const INSTALL_HOOK_CAPABILITY_RULES: &[&str] = &[
    "LF-CODE-SUBPROCESS",
    "LF-CODE-OS-SYSTEM",
    "LF-CODE-NETWORK",
    "LF-CODE-EVAL",
    "LF-CODE-EXEC",
    "LF-DEP-RUNTIME-INSTALL",
];

/// Capability rules an npm install-hook's *referenced* script (a different
/// file than `package.json` itself) may carry. Unlike
/// `INSTALL_HOOK_CAPABILITY_RULES` (same-subject match against
/// `LF-DEP-INSTALL-HOOK`), `LF-DEP-NPM-INSTALL-HOOK` names a *reference* to
/// another file, so this table is matched by resolved script path, not by
/// subject equality with the hook finding itself — see
/// `npm_install_hook_chains`.
const NPM_INSTALL_HOOK_CAPABILITY_RULES: &[&str] = &[
    "LF-JS-SEMANTIC-PROCESS",
    "LF-JS-SEMANTIC-DYNAMIC-CODE",
    "LF-JS-SEMANTIC-NETWORK",
    "LF-JS-SEMANTIC-NATIVE-LOAD",
    "LF-JS-SEMANTIC-PACKAGE-INSTALL",
    "LF-SHELL-SEMANTIC-PROCESS",
    "LF-SHELL-SEMANTIC-CURL-PIPE-SH",
    "LF-SHELL-SEMANTIC-PACKAGE-INSTALL",
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
    out.extend(install_hook_capability_chains(findings));
    out.extend(npm_install_hook_chains(findings));
    out.extend(numpy_allow_pickle_chains(findings));
    sort_correlations(&mut out);
    out
}

/// An npm install-hook (`LF-DEP-NPM-INSTALL-HOOK`, from `package.json`'s
/// `scripts.preinstall`/`install`/`postinstall`) correlated with a
/// capability finding in the *referenced* script file — a cross-file match
/// by resolved path (structurally closer to `custom_loader_chains`'
/// reference-resolution than `install_hook_capability_chains`'s
/// same-subject match, since the hook and the capability live in different
/// package members).
fn npm_install_hook_chains(findings: &[LayerScanResult]) -> Vec<FindingCorrelation> {
    let mut out = Vec::new();
    for hook in findings
        .iter()
        .filter(|finding| matches_rule(finding, &["LF-DEP-NPM-INSTALL-HOOK"]))
    {
        let Some(hook_member) = subject_name(hook) else {
            continue;
        };
        let Some(referenced_script) = hook
            .evidence
            .iter()
            .find_map(|record| record.structured.as_ref())
            .and_then(|structured| structured.get("referenced_script"))
            .and_then(serde_json::Value::as_str)
        else {
            continue;
        };
        for capability in findings.iter().filter(|finding| {
            matches_rule(finding, NPM_INSTALL_HOOK_CAPABILITY_RULES)
                && subject_name(finding)
                    .is_some_and(|member| module_match_str(referenced_script, member).is_some())
        }) {
            let rule_id = crate::policy::rule_id(capability);
            let capability_member = subject_name(capability).unwrap_or(referenced_script);
            out.push(FindingCorrelation {
                id: "LF-CORR-NPM-INSTALL-HOOK-CAPABILITY".to_owned(),
                finding_ids: finding_ids(&[hook, capability]),
                rule_ids: rule_ids(&[hook, capability]),
                summary: format!(
                    "'{hook_member}' declares an npm install-hook script referencing '{referenced_script}', \
                     and '{capability_member}' contains a {rule_id} capability. Install-time hooks run before \
                     a reviewer would normally inspect runtime application code."
                ),
                confidence: Confidence::High,
                evidence: vec![path_relationship(
                    EvidenceSubject::member(capability_member),
                    "npm install-hook reference resolves to the file containing the capability",
                    serde_json::json!({
                        "hook_member": hook_member,
                        "referenced_script": referenced_script,
                        "resolved_module_path": capability_member,
                        "capability_rule": rule_id,
                    }),
                )],
                limitations: Some(
                    "Layerfault has not established that npm actually invokes this exact hook for a \
                     given install command, or that the capability executes unconditionally within it."
                        .to_owned(),
                ),
            });
        }
    }
    out
}

/// A `setup.py` install/build hook (`LF-DEP-INSTALL-HOOK`) correlated with a
/// process-execution/network/eval/install capability finding in the same
/// file. Unlike `custom_loader_chains`, the correlation key here is "same
/// subject", not a resolved configuration reference to a different module.
fn install_hook_capability_chains(findings: &[LayerScanResult]) -> Vec<FindingCorrelation> {
    let mut out = Vec::new();
    for hook in findings
        .iter()
        .filter(|finding| matches_rule(finding, &["LF-DEP-INSTALL-HOOK"]))
    {
        let Some(member) = subject_name(hook) else {
            continue;
        };
        for capability in findings.iter().filter(|finding| {
            matches_rule(finding, INSTALL_HOOK_CAPABILITY_RULES)
                && subject_name(finding) == Some(member)
        }) {
            let rule_id = crate::policy::rule_id(capability);
            out.push(FindingCorrelation {
                id: "LF-CORR-INSTALL-HOOK-CAPABILITY".to_owned(),
                finding_ids: finding_ids(&[hook, capability]),
                rule_ids: rule_ids(&[hook, capability]),
                summary: format!(
                    "'{member}' defines a custom setuptools/distutils install or build hook, and the same \
                     file contains a {rule_id} capability. Install-time hooks run before a reviewer would \
                     normally inspect runtime application code."
                ),
                confidence: Confidence::High,
                evidence: vec![path_relationship(
                    EvidenceSubject::member(member),
                    "Install/build hook and code-execution capability observed in the same subject",
                    serde_json::json!({ "member": member, "capability_rule": rule_id }),
                )],
                limitations: Some(
                    "Layerfault has not established that this exact hook is invoked for a given install \
                     command, or that the capability executes unconditionally within it."
                        .to_owned(),
                ),
            });
        }
    }
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
            if let Some(module_path) = script_file_reference(&cleaned) {
                out.push(ModuleReference {
                    key: key.clone(),
                    symbol: symbol.clone(),
                    module_path,
                });
                continue;
            }
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

/// When a loader-metadata symbol already names a concrete non-Python script
/// file (ends in a recognized shell/PowerShell/JavaScript-TypeScript
/// extension), treat it as a literal path reference rather than a
/// `module.ClassName` dotted path -- there is no "class" segment to strip.
/// This lets shell/PowerShell/JS loader references (e.g. a config value
/// naming `install.sh` or `setup_install.js` directly) resolve through the
/// same `custom_loader_chains` mechanism Python's `module.ClassName`
/// auto_map values use, without disturbing that existing Python-shaped
/// resolution for values that don't already carry a script extension.
fn script_file_reference(value: &str) -> Option<String> {
    let lower = value.to_ascii_lowercase();
    for ext in [
        ".sh", ".bash", ".zsh", ".ps1", ".psm1", ".psd1", ".js", ".mjs", ".cjs", ".ts", ".tsx",
        ".jsx",
    ] {
        if lower.ends_with(ext) {
            return Some(value.to_owned());
        }
    }
    None
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

/// Compare a bare referenced path string (e.g. an npm install-hook's
/// extracted script filename) against a package member path. Same
/// exact/basename matching tiers as [`module_match`], just without the
/// `ModuleReference` wrapper (there is no dotted-module-path resolution step
/// for a literal filename reference).
fn module_match_str(reference: &str, member: &str) -> Option<Confidence> {
    let member_lower = member.to_ascii_lowercase();
    let reference_lower = reference.to_ascii_lowercase();
    if member_lower == reference_lower || member_lower.ends_with(&format!("/{reference_lower}")) {
        return Some(Confidence::High);
    }
    let reference_base = reference_lower
        .rsplit('/')
        .next()
        .unwrap_or(&reference_lower);
    let member_base = member_lower.rsplit('/').next().unwrap_or(&member_lower);
    if reference_base == member_base {
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

/// `numpy.load(..., allow_pickle=True)` correlated with an object-dtype NPY/NPZ member.
fn numpy_allow_pickle_chains(findings: &[LayerScanResult]) -> Vec<FindingCorrelation> {
    let mut out = Vec::new();
    let numpy_calls: Vec<&LayerScanResult> = findings
        .iter()
        .filter(|finding| matches_rule(finding, &["LF-PY-NUMPY-ALLOW-PICKLE"]))
        .collect();
    if numpy_calls.is_empty() {
        return Vec::new();
    }

    let object_arrays: Vec<&LayerScanResult> = findings
        .iter()
        .filter(|finding| matches_rule(finding, &["LF-NPY-OBJECT-DTYPE"]))
        .collect();

    if object_arrays.is_empty() {
        return Vec::new();
    }

    for call_finding in numpy_calls {
        let Some(py_member) = subject_name(call_finding) else {
            continue;
        };

        let literal_target = call_finding
            .evidence
            .iter()
            .find_map(|record| record.structured.as_ref())
            .and_then(|structured| structured.get("command_evidence"))
            .and_then(serde_json::Value::as_str);

        for obj_finding in &object_arrays {
            let Some(obj_member) = subject_name(obj_finding) else {
                continue;
            };

            let is_matched = if let Some(target) = literal_target {
                module_match_str(target, obj_member).is_some()
            } else {
                object_arrays.len() == 1
            };

            if is_matched {
                out.push(FindingCorrelation {
                    id: "LF-CORR-NUMPY-ALLOW-PICKLE".to_owned(),
                    finding_ids: finding_ids(&[call_finding, obj_finding]),
                    rule_ids: rule_ids(&[call_finding, obj_finding]),
                    summary: format!(
                        "'{py_member}' calls numpy.load with allow_pickle=True targeting the object-dtype NumPy artifact '{obj_member}'. \
                         Object dtypes rely on Pickle deserialization, enabling arbitrary code execution during model loading."
                    ),
                    confidence: Confidence::High,
                    evidence: vec![path_relationship(
                        EvidenceSubject::member(obj_member),
                        "NumPy loader explicitly permits Pickle deserialization for object-dtype artifact",
                        serde_json::json!({
                            "loader_member": py_member,
                            "target_artifact": obj_member,
                            "allow_pickle": true
                        }),
                    )],
                    limitations: Some(LIMITATION.to_owned()),
                });
            }
        }
    }
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
