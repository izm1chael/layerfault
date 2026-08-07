#[derive(Debug, Clone, serde::Serialize)]
pub struct RuleExplanation {
    pub rule_id: &'static str,
    pub title: &'static str,
    pub meaning: &'static str,
    pub remediation: &'static str,
}

pub fn lookup(rule: &str) -> Option<RuleExplanation> {
    let normalized = rule.to_ascii_uppercase();
    let item = match normalized.as_str() {
        "LF-SCAN-ERROR" => RuleExplanation { rule_id: "LF-SCAN-ERROR", title: "Scanner error", meaning: "Layerfault could not safely complete inspection of an artifact.", remediation: "Treat the model as blocked. Preserve the artifact and investigate the parser/I/O error rather than suppressing it." },
        "LF-PROV-UNSIGNED" => RuleExplanation { rule_id: "LF-PROV-UNSIGNED", title: "Unsigned artifact", meaning: "No Layerfault attestation was found for the exact artifact identity.", remediation: "Use workstation policy if unsigned models are acceptable, or obtain/sign an attestation with an authorized key for strict admission." },
        "LF-PROV-REVOKED" => RuleExplanation { rule_id: "LF-PROV-REVOKED", title: "Revoked signer", meaning: "An attestation is bound to a trust-store key that has been revoked.", remediation: "Do not run the artifact. Re-attest a verified artifact with a currently authorized key after investigating the revoked signer." },
        "LF-PROV-NAMESPACE" => RuleExplanation { rule_id: "LF-PROV-NAMESPACE", title: "Signer namespace mismatch", meaning: "The signature is valid but the signer is not authorized for this model identity.", remediation: "Correct the trust policy or obtain an attestation from a publisher key authorized for this namespace." },
        "LF-SAFE-STRUCT" => RuleExplanation { rule_id: "LF-SAFE-STRUCT", title: "Invalid Safetensors structure", meaning: "The Safetensors header, tensor ranges, shape sizes, or data-buffer coverage is malformed or unsafe.", remediation: "Reject the file and reacquire it from a trusted source. Do not load it into an inference/runtime process." },
        "LF-SAFE-INDEX" => RuleExplanation { rule_id: "LF-SAFE-INDEX", title: "Safetensors index validated", meaning: "The sharded Safetensors index uses safe relative shard references and every referenced shard passed structural validation.", remediation: "No action is required unless policy independently blocks the artifact." },
        "LF-SAFE-INDEX-INVALID" => RuleExplanation { rule_id: "LF-SAFE-INDEX-INVALID", title: "Invalid Safetensors sharded index", meaning: "A sharded Safetensors index is malformed, references an unsafe/missing shard, or points to a shard that failed structural validation.", remediation: "Block the model and reacquire the complete shard set from a trusted source." },
        "LF-PROV-SIGSTORE" => RuleExplanation { rule_id: "LF-PROV-SIGSTORE", title: "Sigstore bundle verified", meaning: "An installed Cosign verifier accepted the supplied offline Sigstore bundle for the expected certificate identity and issuer.", remediation: "No action is required; keep the bundle with provenance evidence if the artifact is admitted." },
        "LF-PROV-SIGSTORE-INVALID" => RuleExplanation { rule_id: "LF-PROV-SIGSTORE-INVALID", title: "Invalid Sigstore bundle", meaning: "Cosign could not verify the supplied bundle against the expected artifact, certificate identity or issuer.", remediation: "Block the artifact and investigate provenance. Do not weaken identity or issuer constraints merely to make verification pass." },
        "LF-PROV-INACTIVE" => RuleExplanation { rule_id: "LF-PROV-INACTIVE", title: "Inactive trusted key", meaning: "The signature is cryptographically valid but the corresponding trusted key is outside its activation window.", remediation: "Use a currently active authorized signer or deliberately correct the trust-store activation/expiry window after verification." },
        "LF-PROV-TRUSTED" => RuleExplanation { rule_id: "LF-PROV-TRUSTED", title: "Trusted attestation", meaning: "The exact model manifest is signed by a currently active key authorized for the model namespace.", remediation: "No action is required unless a higher signature threshold or another policy condition is configured." },
        "LF-FORMAT-UNKNOWN" => RuleExplanation { rule_id: "LF-FORMAT-UNKNOWN", title: "Unknown artifact format", meaning: "Layerfault can hash the file but does not have a structural parser for this artifact format.", remediation: "Use a supported GGUF/Safetensors artifact or an explicit policy that allows the unknown format only when this is intentional." },
        "LF-PACKAGE-SYMLINK" => RuleExplanation { rule_id: "LF-PACKAGE-SYMLINK", title: "Model package symlink", meaning: "A direct model package contains a symlink. Layerfault fingerprints direct packages without following links so a package cannot silently escape its root.", remediation: "Replace the symlink with an explicit regular file, or use the dedicated Hugging Face cache audit path where validated snapshot-to-blob symlinks are resolved safely." },
        "LF-SERIALIZATION-UNSAFE" => RuleExplanation { rule_id: "LF-SERIALIZATION-UNSAFE", title: "Code-capable serialization", meaning: "The package contains a Pickle/PyTorch/joblib-style artifact that may execute code when deserialized by an unsafe loader.", remediation: "Prefer Safetensors/GGUF or a weights-only loading path. Do not deserialize untrusted artifacts merely to inspect them; Layerfault intentionally never loads the object graph." },
        "LF-CODE-AUTO-MAP" => RuleExplanation { rule_id: "LF-CODE-AUTO-MAP", title: "Custom Hugging Face model code mapping", meaning: "Model metadata contains auto_map, which can route model loading through custom Python implementations.", remediation: "Review the referenced source files and avoid trust_remote_code unless the package publisher and exact package identity are trusted." },
        "LF-CODE-REMOTE-TRUST" => RuleExplanation { rule_id: "LF-CODE-REMOTE-TRUST", title: "Remote/custom code trust enabled", meaning: "The package explicitly enables a custom-code trust path.", remediation: "Disable remote-code trust where possible and inspect/sign the full model package before loading custom implementations." },
        "LF-TEMPLATE-INTROSPECTION" => RuleExplanation { rule_id: "LF-TEMPLATE-INTROSPECTION", title: "Template introspection primitives", meaning: "A model template contains Jinja/Python introspection primitives that can become dangerous in an overly permissive rendering environment.", remediation: "Review the runtime template sandbox and remove introspection primitives unless they are required and demonstrably safe." },
        "LF-RUNTIME-VERSION-UNKNOWN" => RuleExplanation { rule_id: "LF-RUNTIME-VERSION-UNKNOWN", title: "Runtime version could not be compared", meaning: "Layerfault could not derive a version/build identifier suitable for its offline vulnerability catalog.", remediation: "Use an official runtime build with machine-readable version output or verify the runtime version manually before admitting untrusted models." },
        "LF-PACKAGE-RACE" => RuleExplanation { rule_id: "LF-PACKAGE-RACE", title: "Package member changed during scan", meaning: "A package file produced a different digest when rehashed after scanning, indicating concurrent mutation or an unstable storage layer.", remediation: "Block execution, preserve the artifact for investigation, and rescan from a stable read-only copy." },
        "T15-STRUCT" => RuleExplanation { rule_id: "T15-STRUCT", title: "Invalid GGUF structure", meaning: "The GGUF structure failed bounded validation.", remediation: "Reject and reacquire the model. Structural failures are not suppressible admission warnings." },
        "T12-001" => RuleExplanation { rule_id: "T12-001", title: "Embedded ELF object", meaning: "A structurally plausible ELF executable object exists inside model bytes.", remediation: "Quarantine the artifact and investigate its source. Do not infer malicious intent from magic bytes alone; Layerfault only emits this after structural checks." },
        "T12-002" => RuleExplanation { rule_id: "T12-002", title: "Embedded PE object", meaning: "A structurally plausible PE executable object exists inside model bytes.", remediation: "Quarantine the artifact and investigate its source before allowing execution." },
        _ => return None,
    };
    Some(item)
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RiskExplanation {
    pub rule_id: String,
    pub title: String,
    pub categories: Vec<String>,
    pub summary: String,
    pub risk: String,
    pub potential_impact: Vec<String>,
    pub recommended_actions: Vec<String>,
}

pub fn risk_lookup(rule: &str) -> RiskExplanation {
    let rule_id = rule.to_ascii_uppercase();
    let (title, categories, summary, risk, impact, actions) = match rule_id.as_str() {
        "LF-SERIALIZATION-UNSAFE" => (
            "Code-capable model serialization detected",
            vec!["Code Execution", "Supply Chain"],
            "The package contains a serialization format that can execute code when loaded by common ML frameworks.",
            "An unsafe loader may execute attacker-controlled code with the privileges of the model runtime.",
            vec!["arbitrary command execution", "credential theft", "filesystem access", "network callbacks"],
            vec!["Do not load or deserialize this artifact.", "Prefer Safetensors or GGUF, or a weights-only loading path.", "Verify the publisher and provenance; quarantine untrusted copies."],
        ),
        "T15-STRUCT" => (
            "Malformed GGUF structure detected",
            vec!["Parser Safety", "Memory Safety"],
            "The artifact violates bounded GGUF structural invariants.",
            "A vulnerable model runtime may crash, read or write out of bounds, allocate excessive resources, or otherwise behave unsafely while parsing it.",
            vec!["runtime crash", "excessive allocation or denial of service", "downstream parser memory-safety exposure"],
            vec!["Do not pass this artifact to an inference runtime.", "Reacquire it from a trusted source and preserve the malformed copy for investigation."],
        ),
        "LF-SAFE-STRUCT" => (
            "Malformed Safetensors structure detected",
            vec!["Parser Safety", "Memory Safety"],
            "The Safetensors header, tensor ranges, shape sizes, or data-buffer coverage is malformed or unsafe.",
            "A vulnerable loader may mis-handle malformed tensor metadata and crash, allocate incorrectly, or access data outside the intended buffer.",
            vec!["runtime crash", "resource exhaustion", "downstream parser memory-safety exposure"],
            vec!["Reject the file and reacquire it from a trusted source.", "Do not load it into an inference or conversion process."],
        ),
        "LF-CODE-AUTO-MAP" => (
            "Custom Hugging Face model code mapping",
            vec!["Supply Chain", "Code Execution"],
            "Model metadata contains auto_map, which can route loading through custom Python implementations.",
            "Loading may execute code from the model package when custom-code trust is enabled.",
            vec!["arbitrary code execution during model loading", "filesystem or network access under runtime privileges"],
            vec!["Review the referenced source files.", "Avoid trust_remote_code unless the exact package and publisher are trusted.", "Prefer a package that does not require custom loading code."],
        ),
        "LF-CODE-REMOTE-TRUST" => (
            "Custom model-code trust enabled",
            vec!["Supply Chain", "Code Execution"],
            "The package explicitly enables a custom-code trust path.",
            "A model loader may import Python supplied by the package or its remote repository.",
            vec!["arbitrary code execution during model loading", "host and network access through imported code"],
            vec!["Disable remote-code trust where possible.", "Inspect and attest the complete package before loading it."],
        ),
        "LF-CODE-IMPORT-SIDE-EFFECT" => (
            "Import-time custom code side effect",
            vec!["Code Execution", "Filesystem Access", "Network Exposure"],
            "A configured custom model module contains a security-relevant operation at module scope.",
            "Importing the module through the model loading path can perform the operation before the model is constructed.",
            vec!["arbitrary command execution", "filesystem modification", "network callbacks or data exfiltration"],
            vec!["Do not enable custom-code loading for this package.", "Quarantine it and review the referenced module from a trusted development environment."],
        ),
        "LF-PACKAGE-CODE" => (
            "Custom or executable package code present",
            vec!["Code Execution", "Supply Chain"],
            "The package contains Python, scripts, native libraries, or another executable-content artifact.",
            "The model loading or conversion path may execute package-supplied code.",
            vec!["arbitrary code execution", "filesystem and network access", "persistence under runtime privileges"],
            vec!["Review whether the file is required.", "Prefer a weights-only package and verify its provenance before loading."],
        ),
        "LF-CODE-NETWORK" => (
            "Network-capable model code detected",
            vec!["Network Exposure", "Code Execution"],
            "Custom model content references a network or HTTP primitive.",
            "If executed by a loader, the code may contact remote systems or transmit local data.",
            vec!["data exfiltration", "remote callbacks", "access to internal network services"],
            vec!["Do not execute the custom code.", "Review and remove network behavior, then rescan the complete package."],
        ),
        "LF-CODE-OS-SYSTEM" | "LF-CODE-SUBPROCESS" | "LF-CODE-EXEC" | "LF-CODE-EVAL" => (
            "Command or dynamic-code primitive detected",
            vec!["Code Execution"],
            "Custom model content references a command-execution or dynamic-code primitive.",
            "If reached during loading, attacker-controlled instructions may run with the model runtime's privileges.",
            vec!["arbitrary command execution", "credential and filesystem access", "persistence or lateral movement"],
            vec!["Do not load the package.", "Review the source statically and replace it with a trusted non-code-capable artifact."],
        ),
        "LF-CODE-CTYPES" => (
            "Native library loading primitive detected",
            vec!["Code Execution", "Memory Safety"],
            "Custom model content references ctypes or native-library loading.",
            "Loading native code can bypass ordinary Python-level restrictions and execute host instructions.",
            vec!["arbitrary native code execution", "memory corruption", "host compromise"],
            vec!["Do not load the package.", "Use a trusted artifact without native extension loading and verify provenance."],
        ),
        "LF-PACKAGE-SYMLINK" => (
            "Model package symlink detected",
            vec!["Supply Chain", "Integrity"],
            "A direct model package contains a symlink outside the explicit package-file model.",
            "Implicit link traversal can make package identity and inspected content differ from what an operator intended.",
            vec!["content substitution", "out-of-bound package access", "unstable identity"],
            vec!["Replace the symlink with an explicit regular file, or use the validated Hugging Face cache audit path."],
        ),
        "LF-PACKAGE-RACE" => (
            "Package member changed during scan",
            vec!["Integrity"],
            "A package file produced a different digest when rehashed after scanning.",
            "Concurrent mutation means the inspected bytes are not a stable basis for admission.",
            vec!["time-of-check/time-of-use substitution", "inconsistent evidence"],
            vec!["Block execution, preserve the artifact, and rescan from a stable read-only copy."],
        ),
        "LF-PROV-UNSIGNED" => (
            "Unsigned artifact",
            vec!["Provenance", "Trust"],
            "No attestation was supplied for the exact artifact identity.",
            "Layerfault cannot connect this artifact to an authorized publisher through its configured provenance mechanism.",
            vec!["unverified supply-chain origin", "publisher substitution risk"],
            vec!["Use a policy appropriate for unsigned artifacts, or obtain an attestation from an authorized key."],
        ),
        "LF-PROV-REVOKED" | "LF-PROV-NAMESPACE" | "LF-PROV-INACTIVE" | "LF-PROV-SIGSTORE-INVALID" => (
            "Artifact provenance failed",
            vec!["Provenance", "Trust"],
            "The supplied provenance is invalid, unauthorized, revoked, or outside its active trust window.",
            "The artifact cannot be reliably attributed to an authorized publisher under the configured trust policy.",
            vec!["publisher substitution", "tampered or stale release evidence"],
            vec!["Do not run the artifact.", "Investigate the provenance and obtain a valid attestation from an authorized publisher."],
        ),
        "LF-RUNTIME-VERSION-UNKNOWN" => (
            "Runtime version could not be compared",
            vec!["Compatibility", "Trust"],
            "Layerfault could not derive a version suitable for its offline runtime advisory catalog.",
            "Known-vulnerability checks may be incomplete for this runtime.",
            vec!["unassessed runtime vulnerability exposure"],
            vec!["Use an official runtime with machine-readable version output and verify it before admitting untrusted models."],
        ),
        "LF-FORMAT-UNKNOWN" => (
            "Unknown artifact format",
            vec!["Compatibility"],
            "Layerfault can hash this file but has no structural parser for its format.",
            "Format-specific corruption and loader risks cannot be assessed by the configured scanners.",
            vec!["unassessed parser and loading behavior"],
            vec!["Prefer GGUF or Safetensors, or make an explicit policy decision for this unknown format."],
        ),
        _ => (
            "Unclassified Layerfault finding",
            vec!["Compatibility"],
            "Layerfault reported a finding without a dedicated operator explanation.",
            "The available evidence is insufficient to make a more specific claim, so the configured decision should be respected conservatively.",
            vec!["unassessed artifact, package, integrity, or policy risk"],
            vec!["Review the finding detail and preserve the artifact.", "Do not suppress the finding unless the evidence and policy exception are explicitly reviewed."],
        ),
    };
    RiskExplanation {
        rule_id,
        title: title.to_owned(),
        categories: categories.into_iter().map(ToOwned::to_owned).collect(),
        summary: summary.to_owned(),
        risk: risk.to_owned(),
        potential_impact: impact.into_iter().map(ToOwned::to_owned).collect(),
        recommended_actions: actions.into_iter().map(ToOwned::to_owned).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::risk_lookup;

    #[test]
    fn risk_mapping_covers_actionable_serialization_and_unknown_rules() {
        let serialization = risk_lookup("LF-SERIALIZATION-UNSAFE");
        assert_eq!(serialization.categories[0], "Code Execution");
        assert!(!serialization.potential_impact.is_empty());
        assert!(!serialization.recommended_actions.is_empty());

        let unknown = risk_lookup("LF-UNRECOGNIZED");
        assert_eq!(unknown.rule_id, "LF-UNRECOGNIZED");
        assert!(!unknown.recommended_actions.is_empty());
    }
}
