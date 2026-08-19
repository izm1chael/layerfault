//! Detector ruleset metadata and explanations catalogue.
//!
//! Every detector rule declared here carries human and machine semantic
//! metadata: rule identity, version, detector family, evidence requirements,
//! title, meaning, why it matters, remediation and limitations.

pub use crate::rules::{
    all_rule_ids, build_id, lookup, ruleset_sha256, scanner_revision, EvidenceRequirement,
    RuleExplanation, RuleMetadata, CATALOGUE,
};

pub struct FindingDescriptor {
    pub rule_id: String,
    pub rule_version: u32,
    pub detector_family: String,
}

impl FindingDescriptor {
    pub fn new(
        rule_id: impl Into<String>,
        rule_version: u32,
        detector_family: impl Into<String>,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            rule_version,
            detector_family: detector_family.into(),
        }
    }
}

/// Result of comparing two finding descriptors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Comparability {
    SameRuleSameVersion,
    SameRuleDifferentVersion,
    DifferentRule,
}

/// Determine comparability between two finding descriptors.
pub fn comparable(a: &FindingDescriptor, b: &FindingDescriptor) -> Comparability {
    if a.rule_id != b.rule_id {
        Comparability::DifferentRule
    } else if a.rule_version == b.rule_version {
        Comparability::SameRuleSameVersion
    } else {
        Comparability::SameRuleDifferentVersion
    }
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
        "LF-PICKLE-DANGEROUS-GLOBAL" => (
            "Dangerous pickle callable detected",
            vec!["Code Execution", "Supply Chain"],
            "Bounded pickle opcode analysis resolved an explicitly dangerous global or non-allowlisted callable used by a construction primitive.",
            "Deserializing the object graph may invoke attacker-controlled code.",
            vec!["arbitrary command execution", "filesystem/network access", "credential theft"],
            vec!["Do not unpickle this artifact.", "Review the named callable and provenance.", "Prefer a data-only serialization format."],
        ),
        "LF-PICKLE-MALFORMED" => (
            "Malformed pickle stream",
            vec!["Parser Safety", "Supply Chain"],
            "The bounded opcode disassembler could not safely parse the serialization stream.",
            "Malformed attacker-controlled serialization should not be passed to a more permissive loader.",
            vec!["loader crash or parser confusion", "unsafe fallback deserialization"],
            vec!["Reject the artifact.", "Reacquire it from a trusted source."],
        ),
        "LF-PICKLE-UNKNOWN-GLOBAL" | "LF-PICKLE-OPAQUE-COMPRESSED" | "LF-PICKLE-OPAQUE-CONTAINER" => (
            "Opaque pickle serialization",
            vec!["Supply Chain", "Code Execution"],
            "Layerfault could not establish that every code-capable serialization reference is on the reviewed checkpoint allowlist.",
            "Unknown or opaque pickle content can execute code when loaded by unsafe deserializers.",
            vec!["unreviewed class construction", "arbitrary code execution if a dangerous loader is used"],
            vec!["Review the exact named/opaque content before loading.", "Prefer Safetensors/GGUF or a weights-only loader."],
        ),
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
        "LF-NPY-STRUCT" => (
            "Malformed NumPy NPY structure detected",
            vec!["Parser Safety", "Memory Safety"],
            "The NPY header, magic signature, shape dimensions or payload buffer size is malformed or truncated.",
            "A vulnerable loader may crash, allocate excessive memory, or encounter out-of-bounds array reads.",
            vec!["runtime crash", "resource exhaustion", "parser confusion"],
            vec!["Reject the file and reacquire it from a trusted source."],
        ),
        "LF-NPY-DTYPE-UNSUPPORTED" => (
            "Unsupported NumPy dtype descriptor",
            vec!["Parser Safety", "Compatibility"],
            "The NPY header contains a complex or unrecognized dtype descriptor.",
            "Static analysis cannot compute element size bounds for unknown complex descriptors.",
            vec!["incomplete coverage", "reduced analysis precision"],
            vec!["Inspect the custom dtype definition and verify the array source."],
        ),
        "LF-NPY-OBJECT-DTYPE" => (
            "NumPy object dtype array detected",
            vec!["Code Execution", "Supply Chain"],
            "The array uses Python object dtype ('O'), which uses Pickle deserialization.",
            "Loading an object array with allow_pickle=True can execute arbitrary Python code.",
            vec!["arbitrary code execution when allow_pickle=True is set"],
            vec!["Do not load with allow_pickle=True. Convert object arrays to numeric or structured dtypes."],
        ),
        "LF-NPY-PICKLE" => (
            "Dangerous Pickle payload in NumPy object array",
            vec!["Code Execution", "Supply Chain"],
            "Static opcode analysis resolved dangerous callables in the object array's Pickle payload.",
            "Loading this artifact with allow_pickle=True will execute attacker-controlled code.",
            vec!["arbitrary command execution", "filesystem access", "credential theft"],
            vec!["Do not unpickle or load this file."],
        ),
        "LF-PY-NUMPY-ALLOW-PICKLE" => (
            "NumPy load call sets allow_pickle=True",
            vec!["Code Execution", "Supply Chain"],
            "Python static analysis detected a call site passing allow_pickle=True to numpy.load.",
            "If an object-dtype array is loaded, Pickle deserialization will execute code.",
            vec!["unintended code execution via object-dtype arrays"],
            vec!["Remove allow_pickle=True parameter."],
        ),
        "LF-CORR-NUMPY-ALLOW-PICKLE" => (
            "NumPy loader explicitly permits Pickle for object array artifact",
            vec!["Code Execution", "Supply Chain"],
            "Python code calls numpy.load(..., allow_pickle=True) targeting an object-dtype array member.",
            "An unsafe loading path explicitly enables code execution via object-dtype deserialization.",
            vec!["unintended code execution during array loading"],
            vec!["Remove allow_pickle=True or refactor the array to a numeric format."],
        ),
        "LF-HF-LFS-DIGEST-MISMATCH" | "LF-HF-LFS-SIZE-MISMATCH" => (
            "Hugging Face LFS object integrity mismatch",
            vec!["Integrity", "Supply Chain"],
            "The downloaded repository member did not match the cryptographic OID or size declared by the Hugging Face Hub revision.",
            "Downloaded content may be truncated, modified in transit, or substituted by a malicious actor.",
            vec!["content substitution", "corrupted model execution", "incomplete download"],
            vec!["Delete partial staged files.", "Re-download from a verified immutable commit SHA."],
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
        "T12-001" | "T12-002" | "T12-003" | "T12-004" => (
            "Embedded executable object detected",
            vec!["Code Execution", "Supply Chain"],
            "Layerfault structurally validated executable/module content embedded in bytes expected to be model data.",
            "A downstream loader, plugin or native/runtime integration could expose an execution path for content that should not normally be present in weight-only data.",
            vec!["unexpected executable content", "runtime code execution if a loader reaches the object", "supply-chain substitution"],
            vec!["Quarantine the artifact.", "Verify the exact publisher and package identity.", "Determine why the executable object is present before allowing runtime use."],
        ),
        "LF-NATIVE-WX-SECTION" => (
            "Writable and executable native section",
            vec!["Memory Integrity", "Exploit Primitives"],
            "Layerfault identified a section or segment marked both writable and executable (WX).",
            "WX memory permissions violate memory protection best practices and increase vulnerability to code injection or dynamic shellcode payloads.",
            vec!["writable and executable memory regions", "increased exploit vulnerability"],
            vec!["Recompile or strip native binaries with non-executable writable sections.", "Enforce W^X memory protection."],
        ),
        "LF-NATIVE-RPATH" | "LF-NATIVE-DYNAMIC-LOAD" => (
            "Native binary dynamic loader or search path capability",
            vec!["Dynamic Loading", "Capability Summary"],
            "Static analysis identified dynamic library search paths (RPATH) or dynamic loading function imports.",
            "If dynamic library paths are untrusted, a runtime may load arbitrary external native libraries.",
            vec!["untrusted dynamic library search paths", "arbitrary dynamic code loading"],
            vec!["Verify dynamic library loading paths are restricted and trusted.", "Audit linked dynamic dependencies."],
        ),
        "LF-NATIVE-EXEC-CAPABILITY" | "LF-NATIVE-NETWORK-CAPABILITY" => (
            "Native binary process or network capability",
            vec!["Process Capability", "Network Capability"],
            "Static analysis identified native imports for process execution or network socket operations.",
            "Native libraries with execution or network capabilities increase the blast radius if invoked by model loaders.",
            vec!["process creation capabilities", "network socket operations"],
            vec!["Verify native extension functionality and ensure permissions are strictly scoped."],
        ),
        "LF-CORR-CUSTOM-LOADER-NATIVE" => (
            "Python loader to native library capability chain",
            vec!["Code Execution", "Correlation"],
            "Python model code loads a native library that possesses process execution or network capability imports.",
            "Loading native libraries with process or network capabilities directly from model code introduces execution risk.",
            vec!["correlated native code loading", "process/network capabilities in loaded binary"],
            vec!["Inspect the Python loader invocation and target native library before admitting the package."],
        ),
        "LF-ONNX-EXTERNAL-INTEGRITY" => (
            "ONNX external tensor integrity failure",
            vec!["Integrity", "Supply Chain"],
            "External ONNX tensor data could not be safely bound to the protobuf model identity.",
            "The bytes executed by an ONNX runtime may differ from the artifact that was admitted if required sidecars are missing, replaced, unsafe, or out of range.",
            vec!["model-content substitution", "incomplete admission identity", "unsafe external file resolution"],
            vec!["Block the model.", "Restore and verify all external tensor sidecars.", "Rescan the complete model directory before execution."],
        ),
        "LF-GGUF-TEXT-LIMIT" => (
            "GGUF metadata coverage limit",
            vec!["Detection Coverage"],
            "Security-relevant GGUF metadata exceeded a bounded collection budget and Layerfault reported the coverage limit explicitly.",
            "Content beyond the retained metadata view may require separate review even though the GGUF structure itself validated.",
            vec!["incomplete static content coverage"],
            vec!["Review the oversized metadata before deployment.", "Treat the artifact as requiring manual analysis rather than a clean content result."],
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
        "LF-PACKAGE-MEMBER-ERROR" | "LF-PACKAGE-MEMBER-PANIC" => (
            "Package member analysis failure isolated",
            vec!["Integrity", "Structural"],
            "A package member encountered an isolated error or parser panic during inspection.",
            "Isolated failures ensure overall package analysis completes while flagging unverified members.",
            vec!["unparsed payload risk", "isolated parser fault"],
            vec!["Review the specific package member and resolve the underlying parsing issue."],
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
        x if x.starts_with("LF-INTEL-") => (
            "Security intelligence finding",
            vec!["Security Intelligence", "Trust"],
            "Current signed security intelligence contains a security-relevant record that applies to the observed execution context.",
            "Revocations and malicious or compromised identity records can invalidate an earlier trust decision even when the underlying artifact bytes have not changed.",
            vec!["revoked trust", "known malicious component", "compromised supply-chain identity"],
            vec!["Do not rely on the earlier admission decision.", "Refresh intelligence, replace the affected component or identity, and repeat admission before execution."],
        ),
        x if x.starts_with("LF-BEHAV-") || x.starts_with("LF-DIFF-") => (
            "Behavioural security evidence",
            vec!["Behavioural Security", "Differential Behaviour"],
            "A bounded local probe or base-versus-derived comparison produced security-relevant behavioural evidence.",
            "The observed condition may indicate a targeted security regression or trigger-dependent behaviour under the tested conditions; it does not establish training-time cause.",
            vec!["synthetic secret disclosure", "unsafe fake-tool intent", "privilege-boundary regression", "targeted unsafe behaviour"],
            vec!["Do not deploy the derivative until the behaviour is reproduced and understood.", "Review the exact probe, runtime fingerprint, seed, base comparison and evidence boundary."],
        ),
        x if x.starts_with("LF-LINEAGE-") || x.starts_with("LF-DERIVE-") || x.starts_with("LF-ADAPTER-") => (
            "Derived-model integrity evidence",
            vec!["Lineage", "Supply Chain"],
            "The observed model structure or transformation evidence does not fully match the claimed derivation relationship.",
            "An unverified or contradicted derivation can hide additional changes beyond the operator's expected transformation.",
            vec!["unexpected model modification", "publisher/transformation substitution", "unexplained tokenizer/template/weight changes"],
            vec!["Verify the exact base and derived identities.", "Require signed transformation evidence or reproduce the supported transformation where possible."],
        ),
        x if x.starts_with("LF-DATASET-") => (
            "Dataset poisoning indicator",
            vec!["Training Data", "Poisoning Evidence"],
            "A bounded dataset analysis found an unusual duplication, trigger correlation, encoding, credential-like or unsafe-code pattern.",
            "The indicator can guide investigation and behavioural correlation but cannot by itself prove malicious poisoning.",
            vec!["targeted fine-tune behaviour", "training contamination", "unexpected trigger association"],
            vec!["Inspect the flagged records and dataset provenance.", "Correlate candidate triggers against a trusted base and the derived model before drawing conclusions."],
        ),
        x if x.starts_with("LF-ONNX-") || x.starts_with("LF-TF-") || x.starts_with("LF-TFLITE-") || x.starts_with("LF-KERAS-") => (
            "Extended model-format security finding",
            vec!["Parser Safety", "Model Package"],
            "A non-GGUF/Safetensors model format contains a structural, external-data, custom-operation or executable-object condition requiring review.",
            "Executing untrusted custom operators or following unsafe external references can cross the model-data trust boundary.",
            vec!["custom code execution", "path traversal", "resource exhaustion", "unassessed runtime behaviour"],
            vec!["Keep inspection non-executing.", "Reject malformed/external-path violations and review custom operations before any runtime loads the model."],
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
