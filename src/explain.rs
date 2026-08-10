//! Rule explanations.
//!
//! An explanation carries five parts, and the last two are what make a finding
//! publishable rather than merely alarming:
//!
//! * `title`/`meaning` — what the detector observed.
//! * `why_it_matters` — the security significance of that observation.
//! * `remediation` — what a reviewer should do next.
//! * `limitations` — what Layerfault has *not* established. Static detection of
//!   a capability is not proof that the capability is reachable, executes
//!   automatically, or was placed there in bad faith. Every explanation says so
//!   explicitly so consumers cannot mistake capability for proven behaviour.

/// The hand-authored core of an explanation.
struct RuleCore {
    rule_id: &'static str,
    title: &'static str,
    meaning: &'static str,
    remediation: &'static str,
}

/// A complete rule explanation, including security significance and limits.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RuleExplanation {
    pub rule_id: &'static str,
    pub title: &'static str,
    pub meaning: &'static str,
    pub why_it_matters: &'static str,
    pub remediation: &'static str,
    pub limitations: &'static str,
}

/// Look up the full explanation for a rule.
pub fn lookup(rule: &str) -> Option<RuleExplanation> {
    let normalized = rule.to_ascii_uppercase();
    let core = core(&normalized)?;
    Some(RuleExplanation {
        rule_id: core.rule_id,
        title: core.title,
        meaning: core.meaning,
        why_it_matters: why_it_matters(&normalized),
        remediation: core.remediation,
        limitations: limitations(&normalized),
    })
}

fn core(rule: &str) -> Option<RuleCore> {
    let normalized = rule.to_ascii_uppercase();
    let item = match normalized.as_str() {
        "LF-SCAN-ERROR" => RuleCore { rule_id: "LF-SCAN-ERROR", title: "Scanner error", meaning: "Layerfault could not safely complete inspection of an artifact.", remediation: "Treat the model as blocked. Preserve the artifact and investigate the parser/I/O error rather than suppressing it." },
        "LF-PROV-UNSIGNED" => RuleCore { rule_id: "LF-PROV-UNSIGNED", title: "Unsigned artifact", meaning: "No Layerfault attestation was found for the exact artifact identity.", remediation: "Use workstation policy if unsigned models are acceptable, or obtain/sign an attestation with an authorized key for strict admission." },
        "LF-PROV-REVOKED" => RuleCore { rule_id: "LF-PROV-REVOKED", title: "Revoked signer", meaning: "An attestation is bound to a trust-store key that has been revoked.", remediation: "Do not run the artifact. Re-attest a verified artifact with a currently authorized key after investigating the revoked signer." },
        "LF-PROV-NAMESPACE" => RuleCore { rule_id: "LF-PROV-NAMESPACE", title: "Signer namespace mismatch", meaning: "The signature is valid but the signer is not authorized for this model identity.", remediation: "Correct the trust policy or obtain an attestation from a publisher key authorized for this namespace." },
        "LF-SAFE-STRUCT" => RuleCore { rule_id: "LF-SAFE-STRUCT", title: "Invalid Safetensors structure", meaning: "The Safetensors header, tensor ranges, shape sizes, or data-buffer coverage is malformed or unsafe.", remediation: "Reject the file and reacquire it from a trusted source. Do not load it into an inference/runtime process." },
        "LF-SAFE-INDEX" => RuleCore { rule_id: "LF-SAFE-INDEX", title: "Safetensors index validated", meaning: "The sharded Safetensors index uses safe relative shard references and every referenced shard passed structural validation.", remediation: "No action is required unless policy independently blocks the artifact." },
        "LF-SAFE-INDEX-INVALID" => RuleCore { rule_id: "LF-SAFE-INDEX-INVALID", title: "Invalid Safetensors sharded index", meaning: "A sharded Safetensors index is malformed, references an unsafe/missing shard, or points to a shard that failed structural validation.", remediation: "Block the model and reacquire the complete shard set from a trusted source." },
        "LF-PROV-SIGSTORE" => RuleCore { rule_id: "LF-PROV-SIGSTORE", title: "Sigstore bundle verified", meaning: "An installed Cosign verifier accepted the supplied offline Sigstore bundle for the expected certificate identity and issuer.", remediation: "No action is required; keep the bundle with provenance evidence if the artifact is admitted." },
        "LF-PROV-SIGSTORE-INVALID" => RuleCore { rule_id: "LF-PROV-SIGSTORE-INVALID", title: "Invalid Sigstore bundle", meaning: "Cosign could not verify the supplied bundle against the expected artifact, certificate identity or issuer.", remediation: "Block the artifact and investigate provenance. Do not weaken identity or issuer constraints merely to make verification pass." },
        "LF-PROV-INACTIVE" => RuleCore { rule_id: "LF-PROV-INACTIVE", title: "Inactive trusted key", meaning: "The signature is cryptographically valid but the corresponding trusted key is outside its activation window.", remediation: "Use a currently active authorized signer or deliberately correct the trust-store activation/expiry window after verification." },
        "LF-PROV-TRUSTED" => RuleCore { rule_id: "LF-PROV-TRUSTED", title: "Trusted attestation", meaning: "The exact model manifest is signed by a currently active key authorized for the model namespace.", remediation: "No action is required unless a higher signature threshold or another policy condition is configured." },
        "LF-FORMAT-UNKNOWN" => RuleCore { rule_id: "LF-FORMAT-UNKNOWN", title: "Unknown artifact format", meaning: "Layerfault can hash the file but does not have a structural parser for this artifact format.", remediation: "Use a supported GGUF/Safetensors artifact or an explicit policy that allows the unknown format only when this is intentional." },
        "LF-FORMAT-CLAIM-MISMATCH" => RuleCore { rule_id: "LF-FORMAT-CLAIM-MISMATCH", title: "Format claim mismatch", meaning: "The artifact filename or extension claims one format, but header magic bytes identify another.", remediation: "Block admission and verify the artifact source. Misdeclared extensions are a common evasion mechanism." },
        "LF-FORMAT-CONTENT-SMUGGLING" => RuleCore { rule_id: "LF-FORMAT-CONTENT-SMUGGLING", title: "Format content smuggling", meaning: "A package member or model weight file uses a benign or misleading role extension to hide code-capable serialization or container structures.", remediation: "Block the artifact package. Ensure security dispatch inspects actual byte magic rather than relying on member filenames." },
        "LF-FORMAT-TRAILING-DATA" => RuleCore { rule_id: "LF-FORMAT-TRAILING-DATA", title: "Unmodeled trailing payload", meaning: "A recognized model format contains non-zero trailing bytes after its valid logical end.", remediation: "Inspect the trailing payload offset and quarantine the file if the extra data is unverified." },
        "LF-FORMAT-APPENDED-ARCHIVE" => RuleCore { rule_id: "LF-FORMAT-APPENDED-ARCHIVE", title: "Appended archive payload", meaning: "A recognized model format contains an appended archive container after its valid logical end.", remediation: "Block admission and inspect the appended archive; valid weight files should not carry appended archives." },
        "LF-FORMAT-APPENDED-SERIALIZATION" => RuleCore { rule_id: "LF-FORMAT-APPENDED-SERIALIZATION", title: "Appended serialization payload", meaning: "A recognized model format contains an appended Pickle or PyTorch serialization stream after its valid logical end.", remediation: "Block admission immediately. Appended serialization streams can execute arbitrary code upon deserialization." },
        "LF-FORMAT-POLYGLOT" => RuleCore { rule_id: "LF-FORMAT-POLYGLOT", title: "Polyglot artifact detected", meaning: "The artifact is simultaneously valid under multiple security-relevant interpretations, such as a model carrying a structurally valid appended executable.", remediation: "Block execution and quarantine the artifact for investigation." },
        "LF-PACKAGE-SYMLINK" => RuleCore { rule_id: "LF-PACKAGE-SYMLINK", title: "Model package symlink", meaning: "A direct model package contains a symlink. Layerfault fingerprints direct packages without following links so a package cannot silently escape its root.", remediation: "Replace the symlink with an explicit regular file, or use the dedicated Hugging Face cache audit path where validated snapshot-to-blob symlinks are resolved safely." },
        "LF-SERIALIZATION-UNSAFE" => RuleCore { rule_id: "LF-SERIALIZATION-UNSAFE", title: "Code-capable serialization", meaning: "The package contains a Pickle/PyTorch/joblib-style artifact that may execute code when deserialized by an unsafe loader.", remediation: "Prefer Safetensors/GGUF or a weights-only loading path. Do not deserialize untrusted artifacts merely to inspect them; Layerfault intentionally never loads the object graph." },
        "LF-PICKLE-DANGEROUS-GLOBAL" => RuleCore { rule_id: "LF-PICKLE-DANGEROUS-GLOBAL", title: "Dangerous pickle callable", meaning: "Static opcode analysis resolved a pickle global/callable associated with code execution or another explicitly dangerous primitive.", remediation: "Block the artifact. Review the named global and provenance without deserializing the pickle." },
        "LF-PICKLE-MALFORMED" => RuleCore { rule_id: "LF-PICKLE-MALFORMED", title: "Malformed pickle opcode stream", meaning: "The bounded protocol 0-5 opcode disassembler could not safely parse the pickle stream or container.", remediation: "Reject the artifact and reacquire it from a trusted source; do not attempt to unpickle it to diagnose the failure." },
        "LF-PICKLE-UNKNOWN-GLOBAL" => RuleCore { rule_id: "LF-PICKLE-UNKNOWN-GLOBAL", title: "Unknown pickle global", meaning: "Static opcode analysis resolved a module/class global that is neither on Layerfault's reviewed checkpoint allowlist nor its explicit danger list.", remediation: "Treat the artifact as opaque and review the exact named class/module and publisher before loading it." },
        "LF-PICKLE-SAFE-GLOBALS" => RuleCore { rule_id: "LF-PICKLE-SAFE-GLOBALS", title: "Allowlisted pickle globals", meaning: "The pickle opcode stream parsed successfully and every resolved global matched the reviewed checkpoint allowlist.", remediation: "Preserve the audit evidence. This structural PASS does not make Python pickle a generally safe deserialization mechanism." },
        "LF-PICKLE-OPAQUE-COMPRESSED" => RuleCore { rule_id: "LF-PICKLE-OPAQUE-COMPRESSED", title: "Opaque compressed pickle", meaning: "A pickle/joblib/PyTorch serialization name is hidden behind compression Layerfault does not transparently decode in this pass.", remediation: "Review or unpack it only in an isolated workflow, then scan the decompressed artifact before loading." },
        "LF-PICKLE-OPAQUE-CONTAINER" => RuleCore { rule_id: "LF-PICKLE-OPAQUE-CONTAINER", title: "Opaque pickle container", meaning: "A PyTorch-style ZIP container was recognized but contained no analyzable pickle member.", remediation: "Review the container layout and provenance before loading it." },
        "LF-HEUR-DECODED-MATCH" => RuleCore { rule_id: "LF-HEUR-DECODED-MATCH", title: "Decoded hidden instruction match", meaning: "A bounded Base64, hex or ROT13 decode exposed a content-security signature that was not directly visible in the source text.", remediation: "Review the decoded evidence and surrounding template/configuration; do not trust obfuscation to be inert." },
        "LF-TEMPLATE-SSTI" => RuleCore { rule_id: "LF-TEMPLATE-SSTI", title: "Template object-graph traversal", meaning: "High-priority prompt/template metadata contains Jinja-style object graph or dunder traversal associated with server-side template injection primitives.", remediation: "Block or remove the template and review it as code-capable input before any renderer processes it." },
        "LF-TEMPLATE-DYNAMIC-INCLUDE" => RuleCore { rule_id: "LF-TEMPLATE-DYNAMIC-INCLUDE", title: "Dynamic template include/import", meaning: "High-priority prompt/template metadata dynamically imports/includes template content and requires review.", remediation: "Verify the referenced template source is fixed and trusted before rendering." },
        "LF-ONNX-EXTERNAL-RANGE" => RuleCore { rule_id: "LF-ONNX-EXTERNAL-RANGE", title: "ONNX external tensor range violation", meaning: "An ONNX external-data offset/length points outside its integrity-bound sidecar.", remediation: "Block the model and restore the exact protobuf/sidecar set from a trusted source." },
        "LF-DERIVE-SCHEMA-CROSS-FORMAT" => RuleCore { rule_id: "LF-DERIVE-SCHEMA-CROSS-FORMAT", title: "Cross-format tensor schema uncertainty", meaning: "Raw tensor names/layout differ across serialization formats and are not directly comparable as a security invariant.", remediation: "Use reproducible quantization/provenance evidence rather than treating format-specific tensor naming drift as a contradiction." },
        "LF-LINEAGE-QUANTIZATION-CROSS-FORMAT" => RuleCore { rule_id: "LF-LINEAGE-QUANTIZATION-CROSS-FORMAT", title: "Cross-format quantization lineage uncertainty", meaning: "A quantization claim crosses serialization formats whose tensor inventories cannot be compared one-for-one.", remediation: "Require reproducibility or signed transformation evidence; expected representation drift alone must not cause BLOCK." },
        "LF-CODE-AUTO-MAP" => RuleCore { rule_id: "LF-CODE-AUTO-MAP", title: "Custom Hugging Face model code mapping", meaning: "Model metadata contains auto_map, which can route model loading through custom Python implementations.", remediation: "Review the referenced source files and avoid trust_remote_code unless the package publisher and exact package identity are trusted." },
        "LF-CODE-REMOTE-TRUST" => RuleCore { rule_id: "LF-CODE-REMOTE-TRUST", title: "Remote/custom code trust enabled", meaning: "The package explicitly enables a custom-code trust path.", remediation: "Disable remote-code trust where possible and inspect/sign the full model package before loading custom implementations." },
        "LF-TEMPLATE-INTROSPECTION" => RuleCore { rule_id: "LF-TEMPLATE-INTROSPECTION", title: "Template introspection primitives", meaning: "A model template contains Jinja/Python introspection primitives that can become dangerous in an overly permissive rendering environment.", remediation: "Review the runtime template sandbox and remove introspection primitives unless they are required and demonstrably safe." },
        "LF-RUNTIME-VERSION-UNKNOWN" => RuleCore { rule_id: "LF-RUNTIME-VERSION-UNKNOWN", title: "Runtime version could not be compared", meaning: "Layerfault could not derive a version/build identifier suitable for its offline vulnerability catalog.", remediation: "Use an official runtime build with machine-readable version output or verify the runtime version manually before admitting untrusted models." },
        "LF-PACKAGE-RACE" => RuleCore { rule_id: "LF-PACKAGE-RACE", title: "Package member changed during scan", meaning: "A package file produced a different digest when rehashed after scanning, indicating concurrent mutation or an unstable storage layer.", remediation: "Block execution, preserve the artifact for investigation, and rescan from a stable read-only copy." },
        "T15-STRUCT" => RuleCore { rule_id: "T15-STRUCT", title: "Invalid GGUF structure", meaning: "The GGUF structure failed bounded validation.", remediation: "Reject and reacquire the model. Structural failures are not suppressible admission warnings." },
        "T12-001" => RuleCore { rule_id: "T12-001", title: "Embedded ELF object", meaning: "A structurally plausible ELF executable object exists inside model bytes.", remediation: "Quarantine the artifact and investigate its source. Do not infer malicious intent from magic bytes alone; Layerfault only emits this after structural checks." },
        "T12-002" => RuleCore { rule_id: "T12-002", title: "Embedded PE object", meaning: "A structurally plausible PE executable object exists inside model bytes.", remediation: "Quarantine the artifact and investigate its source before allowing execution." },
        "T12-003" => RuleCore { rule_id: "T12-003", title: "Embedded Mach-O object", meaning: "A structurally plausible Mach-O executable object exists inside model bytes.", remediation: "Quarantine the artifact and investigate its source before allowing execution on macOS or another Mach-O-capable host." },
        "T12-004" => RuleCore { rule_id: "T12-004", title: "Embedded WebAssembly module", meaning: "A valid WebAssembly module header exists inside model bytes.", remediation: "Quarantine the artifact and determine why executable WebAssembly content is embedded before allowing it into a runtime that can instantiate WASM." },
        "LF-GGUF-TEXT-LIMIT" => RuleCore { rule_id: "LF-GGUF-TEXT-LIMIT", title: "GGUF security-text collection limit", meaning: "Security-relevant GGUF metadata exceeded a bounded collection budget. Prompt/template/system text is isolated from descriptive metadata, but some lower-priority text was truncated.", remediation: "Treat coverage as incomplete and review the oversized GGUF metadata before deployment; do not interpret the warning as a clean content scan." },
        "LF-ADAPTER-BASE-MISMATCH" => RuleCore { rule_id: "LF-ADAPTER-BASE-MISMATCH", title: "LoRA adapter integrity finding", meaning: "The LoRA adapter configuration, base compatibility or weight distribution produced security-relevant evidence.", remediation: "Verify the adapter/base relationship and inspect the affected modules; anomaly evidence does not by itself establish malicious intent." },
        "LF-ADAPTER-BASE-UNVERIFIED" => RuleCore { rule_id: "LF-ADAPTER-BASE-UNVERIFIED", title: "LoRA adapter integrity finding", meaning: "The LoRA adapter configuration, base compatibility or weight distribution produced security-relevant evidence.", remediation: "Verify the adapter/base relationship and inspect the affected modules; anomaly evidence does not by itself establish malicious intent." },
        "LF-ADAPTER-RANK-ANOMALY" => RuleCore { rule_id: "LF-ADAPTER-RANK-ANOMALY", title: "LoRA adapter integrity finding", meaning: "The LoRA adapter configuration, base compatibility or weight distribution produced security-relevant evidence.", remediation: "Verify the adapter/base relationship and inspect the affected modules; anomaly evidence does not by itself establish malicious intent." },
        "LF-ADAPTER-WEIGHT-ANOMALY" => RuleCore { rule_id: "LF-ADAPTER-WEIGHT-ANOMALY", title: "LoRA adapter integrity finding", meaning: "The LoRA adapter configuration, base compatibility or weight distribution produced security-relevant evidence.", remediation: "Verify the adapter/base relationship and inspect the affected modules; anomaly evidence does not by itself establish malicious intent." },
        "LF-ADAPTER-SCALING-ANOMALY" => RuleCore { rule_id: "LF-ADAPTER-SCALING-ANOMALY", title: "LoRA scaling anomaly", meaning: "The adapter alpha/r scaling factor is far outside Layerfault's conservative review range.", remediation: "Verify the adapter configuration and base-model compatibility. Treat this as anomaly evidence, not proof of malicious intent." },
        "LF-ADAPTER-NORM-OUTLIER" => RuleCore { rule_id: "LF-ADAPTER-NORM-OUTLIER", title: "LoRA tensor norm outlier", meaning: "One or more adapter tensors have norms that are extreme relative to the adapter's median tensor norm.", remediation: "Inspect the named adapter tensors, compare against a trusted adapter/control, and correlate with behavioural testing before deployment." },
        "LF-ADAPTER-SPECTRAL-CONCENTRATION" => RuleCore { rule_id: "LF-ADAPTER-SPECTRAL-CONCENTRATION", title: "LoRA spectral concentration", meaning: "A bounded adapter analysis found unusually concentrated singular-value energy in a tensor.", remediation: "Review the affected tensor and compare with a clean/control adapter. Spectral concentration alone does not establish a backdoor." },
        "LF-ADAPTER-MODULES-TO-SAVE" => RuleCore { rule_id: "LF-ADAPTER-MODULES-TO-SAVE", title: "LoRA saves full target modules", meaning: "The adapter configuration requests modules_to_save, which can carry full module parameters in addition to low-rank adapter deltas.", remediation: "Inspect every saved module and require provenance for the complete adapter package before loading it." },
        "LF-BEHAV-PERSONA-PERSISTENCE" => RuleCore { rule_id: "LF-BEHAV-PERSONA-PERSISTENCE", title: "Behavioural security finding", meaning: "The bounded probe suite observed a security-relevant behaviour or base-versus-derived regression.", remediation: "Do not deploy the derivative until the behaviour is understood and reproduced. A clean run would not prove absence of other hidden triggers." },
        "LF-BEHAV-PRIVILEGE-BOUNDARY" => RuleCore { rule_id: "LF-BEHAV-PRIVILEGE-BOUNDARY", title: "Behavioural security finding", meaning: "The bounded probe suite observed a security-relevant behaviour or base-versus-derived regression.", remediation: "Do not deploy the derivative until the behaviour is understood and reproduced. A clean run would not prove absence of other hidden triggers." },
        "LF-BEHAV-SECRET-DISCLOSURE" => RuleCore { rule_id: "LF-BEHAV-SECRET-DISCLOSURE", title: "Behavioural security finding", meaning: "The bounded probe suite observed a security-relevant behaviour or base-versus-derived regression.", remediation: "Do not deploy the derivative until the behaviour is understood and reproduced. A clean run would not prove absence of other hidden triggers." },
        "LF-BEHAV-SECURE-CODE-REGRESSION" => RuleCore { rule_id: "LF-BEHAV-SECURE-CODE-REGRESSION", title: "Behavioural security finding", meaning: "The bounded probe suite observed a security-relevant behaviour or base-versus-derived regression.", remediation: "Do not deploy the derivative until the behaviour is understood and reproduced. A clean run would not prove absence of other hidden triggers." },
        "LF-BEHAV-TARGETED-CONTENT" => RuleCore { rule_id: "LF-BEHAV-TARGETED-CONTENT", title: "Behavioural security finding", meaning: "The bounded probe suite observed a security-relevant behaviour or base-versus-derived regression.", remediation: "Do not deploy the derivative until the behaviour is understood and reproduced. A clean run would not prove absence of other hidden triggers." },
        "LF-BEHAV-TOOL-EXFIL" => RuleCore { rule_id: "LF-BEHAV-TOOL-EXFIL", title: "Behavioural security finding", meaning: "The bounded probe suite observed a security-relevant behaviour or base-versus-derived regression.", remediation: "Do not deploy the derivative until the behaviour is understood and reproduced. A clean run would not prove absence of other hidden triggers." },
        "LF-BEHAV-NETWORK-ATTEMPT" => RuleCore { rule_id: "LF-BEHAV-NETWORK-ATTEMPT", title: "Sandboxed runtime attempted network access", meaning: "Syscall telemetry observed the isolated model/runtime attempting an IPv4/IPv6 network operation. The sandbox prevented host/network exposure.", remediation: "Treat unexpected network intent as high risk. Inspect package custom code and reproduce only in the strong sandbox before deployment." },
        "LF-BEHAV-UNEXPECTED-EXEC" => RuleCore { rule_id: "LF-BEHAV-UNEXPECTED-EXEC", title: "Sandboxed runtime spawned a child process", meaning: "Syscall telemetry observed a process execution beyond the expected model runtime.", remediation: "Review the exact attempted executable and package code. Child-process creation is not required for ordinary model inference in Layerfault's supported active paths." },
        "LF-BEHAV-DANGEROUS-EXEC" => RuleCore { rule_id: "LF-BEHAV-DANGEROUS-EXEC", title: "Sandboxed runtime attempted shell/network utility execution", meaning: "The active sandbox observed an attempted shell or network utility child process, which is a high-confidence dynamic side-effect signal.", remediation: "Block deployment and inspect the responsible loader/model package code. Reproduce only inside the isolated lab sandbox." },
        "LF-BEHAV-CANARY-ACCESS" => RuleCore { rule_id: "LF-BEHAV-CANARY-ACCESS", title: "Sandboxed runtime accessed a synthetic credential", meaning: "Syscall telemetry observed access to a Layerfault-created decoy secret or SSH credential path. No real host credential was exposed.", remediation: "Treat this as high-risk credential-harvesting behavior and inspect the package/runtime code path before any deployment." },
        "LF-BEHAV-SENSITIVE-PATH-ACCESS" => RuleCore { rule_id: "LF-BEHAV-SENSITIVE-PATH-ACCESS", title: "Sandboxed runtime attempted sensitive path access", meaning: "The active runtime attempted to access a sensitive path such as /etc/shadow, process environment data, or SSH material inside the isolated filesystem view.", remediation: "Block deployment until the access is explained. Keep reproduction inside the strong sandbox." },
        "LF-BEHAV-FILESYSTEM-MUTATION" => RuleCore { rule_id: "LF-BEHAV-FILESYSTEM-MUTATION", title: "Sandboxed runtime mutated the workspace", meaning: "The model/runtime created, modified, or deleted an unexpected file in Layerfault's synthetic writable workspace.", remediation: "Review the mutation and originating package code. Ordinary inference should not persist unexpected executable/configuration artifacts." },
        "LF-BEHAV-TRACE-TRUNCATED" => RuleCore { rule_id: "LF-BEHAV-TRACE-TRUNCATED", title: "Active-analysis syscall telemetry was truncated", meaning: "The sandboxed runtime produced more syscall trace data than Layerfault's bounded telemetry budget, so dynamic side-effect coverage is incomplete for this run.", remediation: "Repeat with a narrower probe suite or inspect the retained trace evidence on a dedicated lab host; do not interpret this run as complete dynamic coverage." },
        "LF-BEHAV-FILESYSTEM-WRITE-ATTEMPT" => RuleCore { rule_id: "LF-BEHAV-FILESYSTEM-WRITE-ATTEMPT", title: "Sandboxed runtime attempted a protected filesystem write", meaning: "Syscall telemetry observed an attempted write/mutation against a read-only model/base or other sensitive host-like mount. The sandbox prevented persistent modification.", remediation: "Inspect the originating loader/runtime code and keep the model blocked or under review until the attempted write is explained." },
        "LF-BEHAV-RUNTIME-FAILURE" => RuleCore { rule_id: "LF-BEHAV-RUNTIME-FAILURE", title: "Sandboxed runtime failed during active analysis", meaning: "The isolated loader or inference runtime failed, timed out, or broke the Layerfault probe protocol. Any filesystem/process/network telemetry collected before failure is preserved.", remediation: "Treat unexpected runtime failure as review evidence. Inspect the captured stderr and sandbox telemetry, then reproduce only inside the strong sandbox before deployment." },
        "LF-CODE-CTYPES" => RuleCore { rule_id: "LF-CODE-CTYPES", title: "Layerfault security finding", meaning: "Layerfault observed a security-relevant condition in the model, package or review evidence.", remediation: "Review the finding evidence and follow the configured policy before deployment." },
        "LF-CODE-EVAL" => RuleCore { rule_id: "LF-CODE-EVAL", title: "Layerfault security finding", meaning: "Layerfault observed a security-relevant condition in the model, package or review evidence.", remediation: "Review the finding evidence and follow the configured policy before deployment." },
        "LF-CODE-EXEC" => RuleCore { rule_id: "LF-CODE-EXEC", title: "Layerfault security finding", meaning: "Layerfault observed a security-relevant condition in the model, package or review evidence.", remediation: "Review the finding evidence and follow the configured policy before deployment." },
        "LF-CODE-IMPORT-SIDE-EFFECT" => RuleCore { rule_id: "LF-CODE-IMPORT-SIDE-EFFECT", title: "Layerfault security finding", meaning: "Layerfault observed a security-relevant condition in the model, package or review evidence.", remediation: "Review the finding evidence and follow the configured policy before deployment." },
        "LF-CODE-NETWORK" => RuleCore { rule_id: "LF-CODE-NETWORK", title: "Layerfault security finding", meaning: "Layerfault observed a security-relevant condition in the model, package or review evidence.", remediation: "Review the finding evidence and follow the configured policy before deployment." },
        "LF-CODE-OS-SYSTEM" => RuleCore { rule_id: "LF-CODE-OS-SYSTEM", title: "Layerfault security finding", meaning: "Layerfault observed a security-relevant condition in the model, package or review evidence.", remediation: "Review the finding evidence and follow the configured policy before deployment." },
        "LF-CODE-SUBPROCESS" => RuleCore { rule_id: "LF-CODE-SUBPROCESS", title: "Layerfault security finding", meaning: "Layerfault observed a security-relevant condition in the model, package or review evidence.", remediation: "Review the finding evidence and follow the configured policy before deployment." },
        "LF-DATASET-CREDENTIAL-LIKE" => RuleCore { rule_id: "LF-DATASET-CREDENTIAL-LIKE", title: "Dataset poisoning indicator", meaning: "The supplied dataset contains a bounded statistical/content indicator associated with poisoning risk.", remediation: "Review the flagged records and correlate them with model behaviour. This evidence does not prove malicious poisoning." },
        "LF-DATASET-DUPLICATE-CONCENTRATION" => RuleCore { rule_id: "LF-DATASET-DUPLICATE-CONCENTRATION", title: "Dataset poisoning indicator", meaning: "The supplied dataset contains a bounded statistical/content indicator associated with poisoning risk.", remediation: "Review the flagged records and correlate them with model behaviour. This evidence does not prove malicious poisoning." },
        "LF-DATASET-RARE-TRIGGER-CORRELATION" => RuleCore { rule_id: "LF-DATASET-RARE-TRIGGER-CORRELATION", title: "Dataset poisoning indicator", meaning: "The supplied dataset contains a bounded statistical/content indicator associated with poisoning risk.", remediation: "Review the flagged records and correlate them with model behaviour. This evidence does not prove malicious poisoning." },
        "LF-DATASET-UNSAFE-CODE-PATTERN" => RuleCore { rule_id: "LF-DATASET-UNSAFE-CODE-PATTERN", title: "Dataset poisoning indicator", meaning: "The supplied dataset contains a bounded statistical/content indicator associated with poisoning risk.", remediation: "Review the flagged records and correlate them with model behaviour. This evidence does not prove malicious poisoning." },
        "LF-DATASET-URL-CONCENTRATION" => RuleCore { rule_id: "LF-DATASET-URL-CONCENTRATION", title: "Dataset poisoning indicator", meaning: "The supplied dataset contains a bounded statistical/content indicator associated with poisoning risk.", remediation: "Review the flagged records and correlate them with model behaviour. This evidence does not prove malicious poisoning." },
        "LF-DATASET-ZERO-WIDTH" => RuleCore { rule_id: "LF-DATASET-ZERO-WIDTH", title: "Dataset poisoning indicator", meaning: "The supplied dataset contains a bounded statistical/content indicator associated with poisoning risk.", remediation: "Review the flagged records and correlate them with model behaviour. This evidence does not prove malicious poisoning." },
        "LF-DERIVE-SCHEMA-MISMATCH" => RuleCore { rule_id: "LF-DERIVE-SCHEMA-MISMATCH", title: "Derived-model integrity change", meaning: "A security-relevant component of the derived model differs from the supplied base or transformation claim.", remediation: "Verify the claimed transformation and investigate the changed component before treating the derivative as equivalent to its base." },
        "LF-DIFF-SECURITY-REGRESSION" => RuleCore { rule_id: "LF-DIFF-SECURITY-REGRESSION", title: "Behavioural security finding", meaning: "The bounded probe suite observed a security-relevant behaviour or base-versus-derived regression.", remediation: "Do not deploy the derivative until the behaviour is understood and reproduced. A clean run would not prove absence of other hidden triggers." },
        "LF-DIFF-LOCALIZED-DIVERGENCE" => RuleCore { rule_id: "LF-DIFF-LOCALIZED-DIVERGENCE", title: "Localized behavioural divergence", meaning: "A deterministic base-versus-derived probe response changed far more than the median response change across the same suite. This is trigger/backdoor evidence, not proof of malicious intent.", remediation: "Review the divergent probe, repeat it under the recorded runtime/seed, and broaden nearby trigger mutations before deployment." },
        "LF-DIFF-SUSPICIOUS-TRIGGER" => RuleCore { rule_id: "LF-DIFF-SUSPICIOUS-TRIGGER", title: "Suspicious trigger-localized behaviour", meaning: "A trigger-designated probe or output-collapse condition produced a localized, repeatable behavioural divergence relative to the supplied base model.", remediation: "Block deployment until the trigger behavior is explained. Reproduce it in the strong sandbox with adjacent mutations and preserve the report as evidence." },
        "LF-DRIFT-EXECUTABLE-ADDED" => RuleCore { rule_id: "LF-DRIFT-EXECUTABLE-ADDED", title: "Model revision drift", meaning: "A previously observed model identity changed in a security-relevant component.", remediation: "Review the exact revision diff and reacquire/re-attest the model if the change was not expected." },
        "LF-DRIFT-TEMPLATE-CHANGED" => RuleCore { rule_id: "LF-DRIFT-TEMPLATE-CHANGED", title: "Model revision drift", meaning: "A previously observed model identity changed in a security-relevant component.", remediation: "Review the exact revision diff and reacquire/re-attest the model if the change was not expected." },
        "LF-DRIFT-TOKENIZER-CHANGED" => RuleCore { rule_id: "LF-DRIFT-TOKENIZER-CHANGED", title: "Model revision drift", meaning: "A previously observed model identity changed in a security-relevant component.", remediation: "Review the exact revision diff and reacquire/re-attest the model if the change was not expected." },
        "LF-DRIFT-WEIGHTS-CHANGED" => RuleCore { rule_id: "LF-DRIFT-WEIGHTS-CHANGED", title: "Model revision drift", meaning: "A previously observed model identity changed in a security-relevant component.", remediation: "Review the exact revision diff and reacquire/re-attest the model if the change was not expected." },
        "LF-DATASET-COVERAGE-LIMIT" => RuleCore { rule_id: "LF-DATASET-COVERAGE-LIMIT", title: "Dataset analysis coverage limit", meaning: "Layerfault fingerprinted one or more dataset members but could not safely record-parse them with the current bounded dataset parser.", remediation: "Treat the poisoning review as incomplete. Convert or inspect opaque dataset members with a trusted, isolated workflow before relying on a clean result." },
        "LF-KERAS-ARCHIVE" => RuleCore { rule_id: "LF-KERAS-ARCHIVE", title: "Keras model security finding", meaning: "The Keras container contains a structural, custom-object or capability-limited condition requiring review.", remediation: "Do not import untrusted custom objects/Lambda code; prefer a weights-only safe representation when possible." },
        "LF-KERAS-CUSTOM-OBJECT" => RuleCore { rule_id: "LF-KERAS-CUSTOM-OBJECT", title: "Keras model security finding", meaning: "The Keras container contains a structural, custom-object or capability-limited condition requiring review.", remediation: "Do not import untrusted custom objects/Lambda code; prefer a weights-only safe representation when possible." },
        "LF-KERAS-HDF5-LIMIT" => RuleCore { rule_id: "LF-KERAS-HDF5-LIMIT", title: "Keras model security finding", meaning: "The Keras container contains a structural, custom-object or capability-limited condition requiring review.", remediation: "Do not import untrusted custom objects/Lambda code; prefer a weights-only safe representation when possible." },
        "LF-LAYERPOLICY" => RuleCore { rule_id: "LF-LAYERPOLICY", title: "Layerfault security finding", meaning: "Layerfault observed a security-relevant condition in the model, package or review evidence.", remediation: "Review the finding evidence and follow the configured policy before deployment." },
        "LF-LINEAGE-ARCH-MISMATCH" => RuleCore { rule_id: "LF-LINEAGE-ARCH-MISMATCH", title: "Model lineage evidence", meaning: "The observed model lineage or transformation evidence differs from, or is weaker than, the claimed relationship.", remediation: "Review the exact base/derived identities, transformation chain and signer evidence before deployment." },
        "LF-LINEAGE-CHAIN-BROKEN" => RuleCore { rule_id: "LF-LINEAGE-CHAIN-BROKEN", title: "Model lineage evidence", meaning: "The observed model lineage or transformation evidence differs from, or is weaker than, the claimed relationship.", remediation: "Review the exact base/derived identities, transformation chain and signer evidence before deployment." },
        "LF-LINEAGE-CHAIN-CYCLE" => RuleCore { rule_id: "LF-LINEAGE-CHAIN-CYCLE", title: "Model lineage evidence", meaning: "The observed model lineage or transformation evidence differs from, or is weaker than, the claimed relationship.", remediation: "Review the exact base/derived identities, transformation chain and signer evidence before deployment." },
        "LF-LINEAGE-CHAIN-SIGNATURE" => RuleCore { rule_id: "LF-LINEAGE-CHAIN-SIGNATURE", title: "Model lineage evidence", meaning: "The observed model lineage or transformation evidence differs from, or is weaker than, the claimed relationship.", remediation: "Review the exact base/derived identities, transformation chain and signer evidence before deployment." },
        "LF-LINEAGE-CHAIN-UNTRUSTED-SIGNER" => RuleCore { rule_id: "LF-LINEAGE-CHAIN-UNTRUSTED-SIGNER", title: "Model lineage evidence", meaning: "The observed model lineage or transformation evidence differs from, or is weaker than, the claimed relationship.", remediation: "Review the exact base/derived identities, transformation chain and signer evidence before deployment." },
        "LF-LINEAGE-CLAIM-NO-EVIDENCE" => RuleCore { rule_id: "LF-LINEAGE-CLAIM-NO-EVIDENCE", title: "Model lineage evidence", meaning: "The observed model lineage or transformation evidence differs from, or is weaker than, the claimed relationship.", remediation: "Review the exact base/derived identities, transformation chain and signer evidence before deployment." },
        "LF-LINEAGE-MANIFEST-CLAIM" => RuleCore { rule_id: "LF-LINEAGE-MANIFEST-CLAIM", title: "Model lineage evidence", meaning: "The observed model lineage or transformation evidence differs from, or is weaker than, the claimed relationship.", remediation: "Review the exact base/derived identities, transformation chain and signer evidence before deployment." },
        "LF-LINEAGE-MANIFEST-ENDPOINT" => RuleCore { rule_id: "LF-LINEAGE-MANIFEST-ENDPOINT", title: "Model lineage evidence", meaning: "The observed model lineage or transformation evidence differs from, or is weaker than, the claimed relationship.", remediation: "Review the exact base/derived identities, transformation chain and signer evidence before deployment." },
        "LF-LINEAGE-QUANTIZATION-TEMPLATE" => RuleCore { rule_id: "LF-LINEAGE-QUANTIZATION-TEMPLATE", title: "Model lineage evidence", meaning: "The observed model lineage or transformation evidence differs from, or is weaker than, the claimed relationship.", remediation: "Review the exact base/derived identities, transformation chain and signer evidence before deployment." },
        "LF-LINEAGE-QUANTIZATION-TOKENIZER" => RuleCore { rule_id: "LF-LINEAGE-QUANTIZATION-TOKENIZER", title: "Model lineage evidence", meaning: "The observed model lineage or transformation evidence differs from, or is weaker than, the claimed relationship.", remediation: "Review the exact base/derived identities, transformation chain and signer evidence before deployment." },
        "LF-LINEAGE-QUANTIZATION-METADATA-INCOMPARABLE" => RuleCore { rule_id: "LF-LINEAGE-QUANTIZATION-METADATA-INCOMPARABLE", title: "Cross-format quantization metadata is incomplete", meaning: "Tokenizer or chat-template semantics could not be normalized across the two serialization formats; representation-specific byte differences are not treated as proof of tampering.", remediation: "Use a converter that preserves comparable metadata or supply signed reproducibility evidence for the exact derivative." },
        "LF-DIFF-SAFETY-BOUNDARY-FLIP" => RuleCore { rule_id: "LF-DIFF-SAFETY-BOUNDARY-FLIP", title: "Trigger-localized safety boundary regression", meaning: "An explicit paired trigger changed a refusal into actionable compliance in the derived model while control behavior remained stable.", remediation: "Block the derivative and reproduce the paired probe under the recorded runtime before deployment." },
        "LF-TFLITE-ASSOCIATED-FILE" => RuleCore { rule_id: "LF-TFLITE-ASSOCIATED-FILE", title: "TFLite associated-file integrity boundary", meaning: "The TFLite artifact contains ZIP-appended metadata such as labels whose modification can alter application-level interpretation without changing tensor values.", remediation: "Integrity-bind and verify the complete TFLite file, including all associated files, against a trusted publisher artifact." },
        "LF-LINEAGE-REPACKAGE-CONTENT" => RuleCore { rule_id: "LF-LINEAGE-REPACKAGE-CONTENT", title: "Model lineage evidence", meaning: "The observed model lineage or transformation evidence differs from, or is weaker than, the claimed relationship.", remediation: "Review the exact base/derived identities, transformation chain and signer evidence before deployment." },
        "LF-ONNX-CUSTOM-OP" => RuleCore { rule_id: "LF-ONNX-CUSTOM-OP", title: "ONNX security finding", meaning: "The ONNX graph/container contains a structural, custom-operator or external-data condition requiring review.", remediation: "Do not execute custom operators from an untrusted model; validate external data and use a supported bounded runtime only after admission." },
        "LF-ONNX-EXTERNAL-DATA" => RuleCore { rule_id: "LF-ONNX-EXTERNAL-DATA", title: "ONNX security finding", meaning: "The ONNX graph/container contains a structural, custom-operator or external-data condition requiring review.", remediation: "Do not execute custom operators from an untrusted model; validate external data and use a supported bounded runtime only after admission." },
        "LF-ONNX-EXTERNAL-INTEGRITY" => RuleCore { rule_id: "LF-ONNX-EXTERNAL-INTEGRITY", title: "ONNX external tensor integrity failure", meaning: "An ONNX model references external tensor data that Layerfault could not safely contain, range-check, open, or bind into the model's compound identity.", remediation: "Block the model and restore the complete sidecar set from a trusted source. Do not load the protobuf without the exact verified external tensor files." },
        "LF-ONNX-EXTERNAL-HARDLINK" => RuleCore { rule_id: "LF-ONNX-EXTERNAL-HARDLINK", title: "ONNX external tensor has hardlink aliases", meaning: "An external ONNX tensor sidecar has more than one filesystem hardlink. Another pathname can mutate the same inode outside the admitted model-directory boundary.", remediation: "Replace the sidecar with a single-link immutable copy inside the admitted package and rescan the compound ONNX identity before loading it." },
        "LF-ONNX-STRUCT" => RuleCore { rule_id: "LF-ONNX-STRUCT", title: "ONNX security finding", meaning: "The ONNX graph/container contains a structural, custom-operator or external-data condition requiring review.", remediation: "Do not execute custom operators from an untrusted model; validate external data and use a supported bounded runtime only after admission." },
        "LF-PACKAGE-ARTIFACT" => RuleCore { rule_id: "LF-PACKAGE-ARTIFACT", title: "Model package finding", meaning: "The package contains a structural, executable-content, text-limit or integrity condition requiring review.", remediation: "Review the exact package member and preserve the package as an immutable unit before loading it." },
        "LF-PACKAGE-CODE" => RuleCore { rule_id: "LF-PACKAGE-CODE", title: "Model package finding", meaning: "The package contains a structural, executable-content, text-limit or integrity condition requiring review.", remediation: "Review the exact package member and preserve the package as an immutable unit before loading it." },
        "LF-PACKAGE-FILE" => RuleCore { rule_id: "LF-PACKAGE-FILE", title: "Model package finding", meaning: "The package contains a structural, executable-content, text-limit or integrity condition requiring review.", remediation: "Review the exact package member and preserve the package as an immutable unit before loading it." },
        "LF-PACKAGE-TEXT-LIMIT" => RuleCore { rule_id: "LF-PACKAGE-TEXT-LIMIT", title: "Legacy package text coverage limit", meaning: "Older Layerfault builds emitted this rule when a package text/config member exceeded their bounded full-file text scan. Current builds stream security inspection across the complete member and retain this explanation only for historical evidence compatibility.", remediation: "Rescan the package with the current build. If the legacy warning persists only in old evidence, replace that evidence after a successful current scan." },
        "LF-PROV-BINDING" => RuleCore { rule_id: "LF-PROV-BINDING", title: "Provenance finding", meaning: "The artifact provenance/signature/trust evidence is incomplete, invalid or has a compatibility condition.", remediation: "Verify the exact artifact identity and signer trust relationship before deployment." },
        "LF-PROV-LEGACY" => RuleCore { rule_id: "LF-PROV-LEGACY", title: "Provenance finding", meaning: "The artifact provenance/signature/trust evidence is incomplete, invalid or has a compatibility condition.", remediation: "Verify the exact artifact identity and signer trust relationship before deployment." },
        "LF-PROV-LOCAL" => RuleCore { rule_id: "LF-PROV-LOCAL", title: "Provenance finding", meaning: "The artifact provenance/signature/trust evidence is incomplete, invalid or has a compatibility condition.", remediation: "Verify the exact artifact identity and signer trust relationship before deployment." },
        "LF-PROV-MULTI" => RuleCore { rule_id: "LF-PROV-MULTI", title: "Provenance finding", meaning: "The artifact provenance/signature/trust evidence is incomplete, invalid or has a compatibility condition.", remediation: "Verify the exact artifact identity and signer trust relationship before deployment." },
        "LF-PROV-SIGNATURE" => RuleCore { rule_id: "LF-PROV-SIGNATURE", title: "Provenance finding", meaning: "The artifact provenance/signature/trust evidence is incomplete, invalid or has a compatibility condition.", remediation: "Verify the exact artifact identity and signer trust relationship before deployment." },
        "LF-PROV-UNTRUSTED" => RuleCore { rule_id: "LF-PROV-UNTRUSTED", title: "Provenance finding", meaning: "The artifact provenance/signature/trust evidence is incomplete, invalid or has a compatibility condition.", remediation: "Verify the exact artifact identity and signer trust relationship before deployment." },
        "LF-RUNTIME-ADVISORY-CLEAR" => RuleCore { rule_id: "LF-RUNTIME-ADVISORY-CLEAR", title: "Runtime security finding", meaning: "The configured runtime version/advisory state could not be established as clear under the local security catalog.", remediation: "Upgrade or verify the runtime before using it to execute untrusted models." },
        "LF-RUNTIME-ADVISORY-STALE" => RuleCore { rule_id: "LF-RUNTIME-ADVISORY-STALE", title: "Runtime security finding", meaning: "The configured runtime version/advisory state could not be established as clear under the local security catalog.", remediation: "Upgrade or verify the runtime before using it to execute untrusted models." },
        "LF-SAFE-DTYPE" => RuleCore { rule_id: "LF-SAFE-DTYPE", title: "Safetensors finding", meaning: "The Safetensors artifact contains a structural, dtype or shard-index condition requiring review.", remediation: "Reject malformed artifacts or use a supported dtype/shard set from a trusted source." },
        "LF-SERIALIZATION-BIN" => RuleCore { rule_id: "LF-SERIALIZATION-BIN", title: "Layerfault security finding", meaning: "Layerfault observed a security-relevant condition in the model, package or review evidence.", remediation: "Review the finding evidence and follow the configured policy before deployment." },
        "LF-TEMPLATE-CHANGED" => RuleCore { rule_id: "LF-TEMPLATE-CHANGED", title: "Derived-model integrity change", meaning: "A security-relevant component of the derived model differs from the supplied base or transformation claim.", remediation: "Verify the claimed transformation and investigate the changed component before treating the derivative as equivalent to its base." },
        "LF-TF-CHECKPOINT-LIMIT" => RuleCore { rule_id: "LF-TF-CHECKPOINT-LIMIT", title: "TensorFlow model security finding", meaning: "The TensorFlow package contains a structural, executable/custom-operation or capability-limited condition.", remediation: "Inspect the exact graph/package and do not execute untrusted custom operations during model loading." },
        "LF-TF-CHECKPOINT-STRUCT" => RuleCore { rule_id: "LF-TF-CHECKPOINT-STRUCT", title: "TensorFlow model security finding", meaning: "The TensorFlow package contains a structural, executable/custom-operation or capability-limited condition.", remediation: "Inspect the exact graph/package and do not execute untrusted custom operations during model loading." },
        "LF-TF-EXECUTION-OP" => RuleCore { rule_id: "LF-TF-EXECUTION-OP", title: "TensorFlow model security finding", meaning: "The TensorFlow package contains a structural, executable/custom-operation or capability-limited condition.", remediation: "Inspect the exact graph/package and do not execute untrusted custom operations during model loading." },
        "LF-TF-FILESYSTEM-WRITE" => RuleCore { rule_id: "LF-TF-FILESYSTEM-WRITE", title: "TensorFlow graph file-write capability", meaning: "The SavedModel contains a high-confidence filesystem-write primitive: PrintV2 is directed at a file URI.", remediation: "Block untrusted execution and inspect the graph attributes and destination paths before any TensorFlow load/invocation." },
        "LF-TF-SCAN-LIMIT" => RuleCore { rule_id: "LF-TF-SCAN-LIMIT", title: "TensorFlow bounded scan limit", meaning: "The SavedModel exceeded the bounded protobuf marker scan window, so Layerfault cannot claim complete static marker coverage.", remediation: "Review the oversized SavedModel under an isolated workflow or increase analysis capability before deployment." },
        "LF-TF-STRUCT" => RuleCore { rule_id: "LF-TF-STRUCT", title: "TensorFlow model security finding", meaning: "The TensorFlow package contains a structural, executable/custom-operation or capability-limited condition.", remediation: "Inspect the exact graph/package and do not execute untrusted custom operations during model loading." },
        "LF-TFLITE-STRUCT" => RuleCore { rule_id: "LF-TFLITE-STRUCT", title: "TensorFlow model security finding", meaning: "The TensorFlow package contains a structural, executable/custom-operation or capability-limited condition.", remediation: "Inspect the exact graph/package and do not execute untrusted custom operations during model loading." },
        "LF-TOKENIZER-CHANGED" => RuleCore { rule_id: "LF-TOKENIZER-CHANGED", title: "Derived-model integrity change", meaning: "A security-relevant component of the derived model differs from the supplied base or transformation claim.", remediation: "Verify the claimed transformation and investigate the changed component before treating the derivative as equivalent to its base." },
        "LF-ARCHIVE-TRAVERSAL" => RuleCore { rule_id: "LF-ARCHIVE-TRAVERSAL", title: "Archive path traversal", meaning: "An archive member path contains illegal absolute prefixes, parent directory traversal, backslashes, drive prefixes, or control characters.", remediation: "Block the archive. Do not extract or process hostile member paths." },
        "LF-ARCHIVE-LINK" => RuleCore { rule_id: "LF-ARCHIVE-LINK", title: "Archive symbolic or hard link", meaning: "An archive member is a symbolic or hard link.", remediation: "Review link targets. Layerfault never follows archive links so extraction cannot escape intended boundaries." },
        "LF-ARCHIVE-DUPLICATE" => RuleCore { rule_id: "LF-ARCHIVE-DUPLICATE", title: "Archive duplicate or case-colliding member", meaning: "An archive contains multiple entries resolving to the same normalized virtual path or case-insensitive collision.", remediation: "Block or inspect the archive; loader behaviour across case-insensitive filesystems is ambiguous and unsafe." },
        "LF-ARCHIVE-LIMIT" => RuleCore { rule_id: "LF-ARCHIVE-LIMIT", title: "Archive resource limit exceeded", meaning: "An archive member or container exceeded bounded member count, uncompressed byte size, path byte limit, or recursion depth.", remediation: "Treat analysis coverage as incomplete and review the oversized container in an isolated workspace." },
        "LF-ARCHIVE-ENCRYPTED" => RuleCore { rule_id: "LF-ARCHIVE-ENCRYPTED", title: "Encrypted archive member", meaning: "An archive member is encrypted and cannot be inspected without password cracking.", remediation: "Review the origin of encrypted content. Layerfault does not attempt password cracking and marks coverage incomplete." },
        "LF-ARCHIVE-NESTED" => RuleCore { rule_id: "LF-ARCHIVE-NESTED", title: "Nested archive recursion limit", meaning: "A chain of nested archives reached maximum nesting depth or total nested archive count limits.", remediation: "Review the nested container structure and verify inner payloads in an isolated lab." },
        "LF-ARCHIVE-BOMB" => RuleCore { rule_id: "LF-ARCHIVE-BOMB", title: "Decompression bomb detected", meaning: "An archive member produced an extreme compression ratio or streaming decompression byte cap violation during unpacking.", remediation: "Block the archive as a denial-of-service attack payload." },
        "LF-ARCHIVE-MALFORMED" => RuleCore { rule_id: "LF-ARCHIVE-MALFORMED", title: "Malformed archive container", meaning: "The archive central directory, header structure, or compression stream is corrupted or truncated.", remediation: "Reject the artifact and reacquire it from a verified source." },
        "LF-ARCHIVE-SECURITY-MEMBER" => RuleCore { rule_id: "LF-ARCHIVE-SECURITY-MEMBER", title: "Archive security-relevant member", meaning: "An archive member contains metadata or dependency specifications relevant to security inspection.", remediation: "Review member details and dependency claims." },
        "LF-WHEEL-RECORD-MISMATCH" => RuleCore { rule_id: "LF-WHEEL-RECORD-MISMATCH", title: "Python Wheel RECORD hash mismatch", meaning: "A Python Wheel entry digest or size differs from the values recorded in .dist-info/RECORD.", remediation: "Block the wheel. Tampering or incomplete packaging was detected." },
        "LF-ARCHIVE-FORMAT-MISMATCH" => RuleCore { rule_id: "LF-ARCHIVE-FORMAT-MISMATCH", title: "Archive format smuggling mismatch", meaning: "An archive file extension disagrees with its magic container header signature.", remediation: "Block the artifact and investigate format smuggling." },
        "LF-UNCLASSIFIED" => RuleCore { rule_id: "LF-UNCLASSIFIED", title: "Layerfault security finding", meaning: "Layerfault observed a security-relevant condition in the model, package or review evidence.", remediation: "Review the finding evidence and follow the configured policy before deployment." },
        "LF-PY-CALL-PROCESS" => RuleCore { rule_id: "LF-PY-CALL-PROCESS", title: "Semantic process-execution call site", meaning: "AST-level analysis resolved a call to a process-execution primitive at a specific line and execution context.", remediation: "Review the referenced call site and its execution context before permitting custom code." },
        "LF-PY-CALL-DYNAMIC-CODE" => RuleCore { rule_id: "LF-PY-CALL-DYNAMIC-CODE", title: "Semantic dynamic-code-evaluation call site", meaning: "AST-level analysis resolved a call to eval/exec or an equivalent dynamic-evaluation primitive.", remediation: "Review the referenced call site; dynamic evaluation defeats static review of what code actually runs." },
        "LF-PY-NATIVE-LOAD" => RuleCore { rule_id: "LF-PY-NATIVE-LOAD", title: "Semantic native-library-loading call site", meaning: "AST-level analysis resolved a call that loads a native library (ctypes/cdll or equivalent).", remediation: "Review the referenced call site; native code runs outside Python-level inspection." },
        "LF-PY-CALL-NETWORK" => RuleCore { rule_id: "LF-PY-CALL-NETWORK", title: "Semantic network-access call site", meaning: "AST-level analysis resolved a call to a network primitive at a specific line and execution context.", remediation: "Review the referenced call site and destination before permitting custom code." },
        "LF-PY-CREDENTIAL-ACCESS" => RuleCore { rule_id: "LF-PY-CREDENTIAL-ACCESS", title: "Semantic credential/environment access call site", meaning: "AST-level analysis resolved a call that reads environment variables or credential-shaped data.", remediation: "Review why custom loading code needs credential/environment access." },
        "LF-PY-FILESYSTEM-MUTATION" => RuleCore { rule_id: "LF-PY-FILESYSTEM-MUTATION", title: "Semantic filesystem-mutation call site", meaning: "AST-level analysis resolved a call that writes, moves, or deletes filesystem content.", remediation: "Review the referenced call site and target path before permitting custom code." },
        "LF-PY-PACKAGE-INSTALL" => RuleCore { rule_id: "LF-PY-PACKAGE-INSTALL", title: "Semantic package-installation call site", meaning: "AST-level analysis resolved a call that installs or acquires additional code (pip/package manager invocation).", remediation: "Review the referenced call site; installing additional code at load time defeats package review." },
        "LF-PY-SEMANTIC-INCOMPLETE" => RuleCore { rule_id: "LF-PY-SEMANTIC-INCOMPLETE", title: "Semantic Python analysis incomplete", meaning: "The AST-level analyzer could not parse the file or exceeded its bounded analysis limits; a streaming textual fallback scan was used instead.", remediation: "Review the file manually; semantic call-site/reachability findings for it are unavailable." },
        "LF-CORR-HF-LOADER-PROCESS" => RuleCore { rule_id: "LF-CORR-HF-LOADER-PROCESS", title: "Custom loader routes to process execution", meaning: "Hugging Face auto_map metadata resolves to a module that a reachability-aware call-site analysis confirms contains process-execution capability.", remediation: "Review the referenced loading path before allowing custom code." },
        "LF-CORR-HF-LOADER-DYNAMIC-CODE" => RuleCore { rule_id: "LF-CORR-HF-LOADER-DYNAMIC-CODE", title: "Custom loader routes to dynamic code evaluation", meaning: "Hugging Face auto_map metadata resolves to a module that a reachability-aware call-site analysis confirms contains dynamic code evaluation.", remediation: "Review the referenced loading path before allowing custom code." },
        "LF-CORR-HF-LOADER-NATIVE-LOAD" => RuleCore { rule_id: "LF-CORR-HF-LOADER-NATIVE-LOAD", title: "Custom loader routes to native library loading", meaning: "Hugging Face auto_map metadata resolves to a module that a reachability-aware call-site analysis confirms loads native libraries.", remediation: "Review the referenced loading path before allowing custom code." },
        "LF-CORR-HF-LOADER-NETWORK" => RuleCore { rule_id: "LF-CORR-HF-LOADER-NETWORK", title: "Custom loader routes to network access", meaning: "Hugging Face auto_map metadata resolves to a module that a reachability-aware call-site analysis confirms contains network access.", remediation: "Review the referenced loading path before allowing custom code." },
        "LF-CORR-HF-LOADER-CREDENTIALS" => RuleCore { rule_id: "LF-CORR-HF-LOADER-CREDENTIALS", title: "Custom loader routes to credential access", meaning: "Hugging Face auto_map metadata resolves to a module that a reachability-aware call-site analysis confirms accesses credentials/environment.", remediation: "Review the referenced loading path before allowing custom code." },
        "LF-CORR-HF-LOADER-FILESYSTEM" => RuleCore { rule_id: "LF-CORR-HF-LOADER-FILESYSTEM", title: "Custom loader routes to filesystem mutation", meaning: "Hugging Face auto_map metadata resolves to a module that a reachability-aware call-site analysis confirms mutates the filesystem.", remediation: "Review the referenced loading path before allowing custom code." },
        "LF-CORR-HF-LOADER-INSTALL" => RuleCore { rule_id: "LF-CORR-HF-LOADER-INSTALL", title: "Custom loader routes to package installation", meaning: "Hugging Face auto_map metadata resolves to a module that a reachability-aware call-site analysis confirms installs additional code.", remediation: "Review the referenced loading path before allowing custom code." },
        "LF-GGUF-STRUCT-VALID" => RuleCore { rule_id: "LF-GGUF-STRUCT-VALID", title: "GGUF structure validated", meaning: "The GGUF header, tensor layout and metadata parsed without a structural warning.", remediation: "No action is required unless policy independently blocks the artifact." },
        "LF-SAFE-STRUCT-VALID" => RuleCore { rule_id: "LF-SAFE-STRUCT-VALID", title: "Safetensors structure validated", meaning: "The Safetensors header and tensor layout parsed without an unknown-dtype warning.", remediation: "No action is required unless policy independently blocks the artifact." },
        "LF-ONNX-STRUCT-VALID" => RuleCore { rule_id: "LF-ONNX-STRUCT-VALID", title: "ONNX structure validated", meaning: "The ONNX ModelProto parsed without a structural, custom-domain or external-data warning.", remediation: "No action is required unless policy independently blocks the artifact." },
        "LF-TF-STRUCT-VALID" => RuleCore { rule_id: "LF-TF-STRUCT-VALID", title: "TensorFlow marker scan clear", meaning: "The bounded protobuf marker scan of the SavedModel found no execution/filesystem-capable op-name markers.", remediation: "No action is required unless policy independently blocks the artifact." },
        "LF-TFLITE-STRUCT-VALID" => RuleCore { rule_id: "LF-TFLITE-STRUCT-VALID", title: "TFLite structure validated", meaning: "The TFLite FlatBuffer parsed without a structural warning and carries no ZIP-appended associated files.", remediation: "No action is required unless policy independently blocks the artifact." },
        "LF-KERAS-STRUCT-VALID" => RuleCore { rule_id: "LF-KERAS-STRUCT-VALID", title: "Keras archive validated", meaning: "The Keras archive parsed without a structural warning and referenced no custom/Lambda-like objects.", remediation: "No action is required unless policy independently blocks the artifact." },
        "LF-PARAM-CLEAR" => RuleCore { rule_id: "LF-PARAM-CLEAR", title: "Inference parameters within policy", meaning: "No inference-parameter anomaly was found against the configured thresholds.", remediation: "No action is required unless policy independently blocks the artifact." },
        "LF-HEUR-CLEAR" => RuleCore { rule_id: "LF-HEUR-CLEAR", title: "Heuristic content scan clear", meaning: "No heuristic content/prompt-injection signature matched the scanned text.", remediation: "No action is required unless policy independently blocks the artifact." },
        "T12-CLEAR" => RuleCore { rule_id: "T12-CLEAR", title: "No embedded executable object found", meaning: "The bounded binary object scan found no structurally valid embedded ELF/PE/Mach-O/WASM object.", remediation: "No action is required unless policy independently blocks the artifact." },
        "LF-PROV-LOCAL-VERIFIED" => RuleCore { rule_id: "LF-PROV-LOCAL-VERIFIED", title: "Legacy local signature verified", meaning: "A legacy detached Ed25519 signature verified against the scanned manifest bytes using a supplied public key.", remediation: "Trust/identity binding is not established by this alone; use the trust-store attestation path for authorized-signer verification." },
        "LF-INTEGRITY-DIGEST-MISMATCH" => RuleCore { rule_id: "LF-INTEGRITY-DIGEST-MISMATCH", title: "Content digest mismatch", meaning: "The digest recomputed while streaming the blob does not match the digest declared in the manifest.", remediation: "Reject the artifact and reacquire it from a trusted source; do not trust prior assessments of the declared digest." },
        "LF-INTEGRITY-SIZE-MISMATCH" => RuleCore { rule_id: "LF-INTEGRITY-SIZE-MISMATCH", title: "Content size mismatch", meaning: "The blob's actual byte length does not match the size declared in the manifest.", remediation: "Reject the artifact and reacquire it from a trusted source." },
        "LF-INTEGRITY-VERIFIED" => RuleCore { rule_id: "LF-INTEGRITY-VERIFIED", title: "Content digest verified", meaning: "The recomputed digest matches the manifest's declared digest for this blob.", remediation: "No action is required unless policy independently blocks the artifact." },
        "LF-HF-LFS-DIGEST-MISMATCH" => RuleCore { rule_id: "LF-HF-LFS-DIGEST-MISMATCH", title: "Hugging Face LFS digest mismatch", meaning: "Observed download SHA-256 does not match the content-addressed LFS OID declared in the Hugging Face Hub revision metadata.", remediation: "Block the member and reacquire from a trusted revision. Do not use the staged bytes." },
        "LF-HF-LFS-SIZE-MISMATCH" => RuleCore { rule_id: "LF-HF-LFS-SIZE-MISMATCH", title: "Hugging Face LFS size mismatch", meaning: "Observed byte count differs from the declared size in the Hugging Face Hub LFS metadata.", remediation: "Block the member and reacquire the file. Verify network integrity and download limits." },
        "LF-HF-LFS-METADATA-INVALID" => RuleCore { rule_id: "LF-HF-LFS-METADATA-INVALID", title: "Hugging Face LFS metadata invalid", meaning: "Hugging Face Hub LFS metadata is malformed, uses an invalid hex digest, or conflicts with repository file metadata.", remediation: "Reject the metadata and re-inspect the remote revision before attempting acquisition." },
        "LF-HF-LFS-INTEGRITY" => RuleCore { rule_id: "LF-HF-LFS-INTEGRITY", title: "Hugging Face LFS integrity verified", meaning: "Downloaded Hugging Face Hub member matched the exact expected size and cryptographic OID declared in the revision metadata.", remediation: "No action required for remote LFS integrity; proceed with static package scanning." },
        "LF-HF-REMOTE-HASH-UNAVAILABLE" => RuleCore { rule_id: "LF-HF-REMOTE-HASH-UNAVAILABLE", title: "Hugging Face remote hash expectation unavailable", meaning: "The Hugging Face Hub repository member does not carry Git LFS metadata or an explicit remote object hash expectation in the Hub API response.", remediation: "Verify the member against local package security policy and commit SHA bindings." },
        "LF-PACKAGE-JSON-INVALID" => RuleCore { rule_id: "LF-PACKAGE-JSON-INVALID", title: "Malformed package JSON/config", meaning: "A JSON or config member could not be fully parsed by Layerfault's bounded parser.", remediation: "Review the exact parser error and the file's origin before trusting other metadata extracted from it." },
        "LF-PARAM-TEMPERATURE" => RuleCore { rule_id: "LF-PARAM-TEMPERATURE", title: "Sampling temperature outside policy", meaning: "The configured generation temperature exceeds the operator policy maximum or review threshold.", remediation: "Confirm the value is intentional; adjust the model configuration or operator policy as appropriate." },
        "LF-PARAM-NUM-CTX" => RuleCore { rule_id: "LF-PARAM-NUM-CTX", title: "Context window outside policy", meaning: "The configured context length exceeds the operator policy maximum or merits resource-capacity review.", remediation: "Confirm the value is intentional given available memory/compute; adjust configuration or policy as appropriate." },
        "LF-PARAM-NUM-PREDICT" => RuleCore { rule_id: "LF-PARAM-NUM-PREDICT", title: "Prediction length outside policy", meaning: "The configured maximum output length exceeds the operator policy maximum.", remediation: "Confirm the value is intentional; adjust configuration or policy as appropriate." },
        "LF-PARAM-TOP-K" => RuleCore { rule_id: "LF-PARAM-TOP-K", title: "Sampling top_k disables filtering", meaning: "top_k is set to 0, which disables top-k sampling filtering entirely.", remediation: "Confirm this is intentional for the deployment's sampling strategy." },
        "LF-PARAM-TOP-P" => RuleCore { rule_id: "LF-PARAM-TOP-P", title: "Sampling top_p minimally restrictive", meaning: "top_p is configured close to 1.0, making nucleus filtering minimally restrictive.", remediation: "Confirm this is intentional for the deployment's sampling strategy." },
        "LF-PARAM-REPEAT-PENALTY" => RuleCore { rule_id: "LF-PARAM-REPEAT-PENALTY", title: "Repeat penalty may increase repetition risk", meaning: "The configured repeat penalty is low enough that output repetition loops are more likely.", remediation: "Confirm this is intentional; low repeat penalty can degrade output quality under some workloads." },
        "LF-PARAM-SEED" => RuleCore { rule_id: "LF-PARAM-SEED", title: "Fixed generation seed present", meaning: "A fixed seed is configured alongside another policy anomaly.", remediation: "A fixed seed is a reproducibility setting; it is recorded here only as context alongside the other flagged parameter." },
        "LF-PARAM-STOP-DELIMITER" => RuleCore { rule_id: "LF-PARAM-STOP-DELIMITER", title: "Stop sequence resembles a prompt-role delimiter", meaning: "A configured stop sequence resembles a system/user/assistant role delimiter or an instruction-override phrase.", remediation: "Review whether this stop sequence is designed to manipulate prompt structure in a hosting application." },
        "LF-RUNTIME-ADVISORY-MATCH" => RuleCore { rule_id: "LF-RUNTIME-ADVISORY-MATCH", title: "Runtime affected by a known advisory", meaning: "The detected runtime version falls within a bundled advisory's affected version range.", remediation: "Upgrade the runtime to or beyond the advisory's fixed boundary before use." },
        "T13-001" => RuleCore { rule_id: "T13-001", title: "Missing or unverified local attestation", meaning: "No detached signature was found for this manifest, or one was found but no public key was supplied to verify it.", remediation: "Use workstation policy if unattested models are acceptable, or supply --public-key / obtain a signature for strict admission." },
        "T13-002" => RuleCore { rule_id: "T13-002", title: "Invalid local attestation", meaning: "A detached signature exists but is malformed, unreadable, or does not verify against the scanned manifest bytes.", remediation: "Do not trust this attestation. Investigate the signature's origin and re-sign with a verified key if appropriate." },
        "LF-DEP-FLOATING" => RuleCore { rule_id: "LF-DEP-FLOATING", title: "Unpinned dependency", meaning: "A declared dependency has no exact version pin, hash constraint, or fully-qualified VCS commit, so the exact code that will be installed is not fixed by the manifest alone.", remediation: "Pin an exact version or content hash, or use a lockfile with hash enforcement, for dependencies that affect a security-relevant build." },
        "LF-DEP-DIRECT-URL" => RuleCore { rule_id: "LF-DEP-DIRECT-URL", title: "Direct URL dependency", meaning: "A dependency is fetched from a direct URL rather than the configured package index.", remediation: "Prefer index-resolved packages, or verify the direct URL is a trusted, hash-pinned source." },
        "LF-DEP-VCS" => RuleCore { rule_id: "LF-DEP-VCS", title: "VCS dependency pinned to a commit", meaning: "A dependency is fetched from a version-control repository, pinned to a full commit hash.", remediation: "Review the referenced repository and commit before treating it as equivalent to a reviewed release." },
        "LF-DEP-VCS-MUTABLE-REF" => RuleCore { rule_id: "LF-DEP-VCS-MUTABLE-REF", title: "Dependency pinned to a mutable VCS reference", meaning: "A VCS dependency is pinned to a branch or tag name rather than a full commit hash, so the referenced content can change without the manifest changing.", remediation: "Pin the dependency to a full commit SHA, or vendor/mirror the exact commit if a stable review target is required." },
        "LF-DEP-LOCAL-PATH" => RuleCore { rule_id: "LF-DEP-LOCAL-PATH", title: "Local/editable path dependency", meaning: "A dependency is declared as a local filesystem path or editable install rather than a versioned package.", remediation: "Confirm the referenced path is part of the reviewed package tree and is not an ambiguous external reference." },
        "LF-DEP-PATH-ESCAPE" => RuleCore { rule_id: "LF-DEP-PATH-ESCAPE", title: "Local dependency path escapes the package root", meaning: "A local/editable dependency path resolves outside the directory tree of the manifest that declared it.", remediation: "Correct the dependency path so it stays within the reviewed package, or vendor the external content into the package." },
        "LF-DEP-ALT-INDEX" => RuleCore { rule_id: "LF-DEP-ALT-INDEX", title: "Alternate package index or channel", meaning: "A manifest declares a package index, extra index, find-links source, or Conda channel other than the ecosystem default.", remediation: "Confirm the alternate source is an intentional, trusted mirror or private index." },
        "LF-DEP-INSECURE-TRANSPORT" => RuleCore { rule_id: "LF-DEP-INSECURE-TRANSPORT", title: "Insecure dependency transport", meaning: "A dependency source, index, or channel uses plaintext HTTP, a localhost/file scheme, or an explicit certificate-verification bypass (--trusted-host).", remediation: "Use HTTPS with certificate verification for all package acquisition sources." },
        "LF-DEP-BUILD-BACKEND" => RuleCore { rule_id: "LF-DEP-BUILD-BACKEND", title: "Custom build backend", meaning: "pyproject.toml declares a build backend other than the standard setuptools backend. A build backend is code that runs during package install/build.", remediation: "Review the declared build backend package and its build-system.requires before installing from source." },
        "LF-DEP-INSTALL-HOOK" => RuleCore { rule_id: "LF-DEP-INSTALL-HOOK", title: "Custom install/build hook", meaning: "setup.py defines a class subclassing a setuptools/distutils Command (or a common subclass such as install/build_ext/develop/egg_info) whose methods run during package installation or build, before any application code runs.", remediation: "Review the exact hook body for process execution, network access, or dynamic code evaluation. Treat install-time code as equivalent in trust to the package's runtime code." },
        "LF-DEP-RUNTIME-INSTALL" => RuleCore { rule_id: "LF-DEP-RUNTIME-INSTALL", title: "Package manager invoked from an install hook", meaning: "A setup.py install/build hook invokes a package manager (pip/uv/conda/poetry/npm/git/curl/wget) to acquire additional code at install time.", remediation: "Review exactly what is installed and from where; installs triggered from a hook are not visible in the package's declared dependency list." },
        "LF-DEP-INCLUDE-MISSING" => RuleCore { rule_id: "LF-DEP-INCLUDE-MISSING", title: "Dependency manifest include could not be resolved", meaning: "A requirements-file -r/-c include reference could not be found, read, or safely resolved within the package.", remediation: "Restore the missing include file, or confirm its absence is expected before trusting this manifest as complete." },
        "LF-DEP-ANALYSIS-INCOMPLETE" => RuleCore { rule_id: "LF-DEP-ANALYSIS-INCOMPLETE", title: "Dependency manifest analysis incomplete", meaning: "A dependency manifest or lockfile could not be fully parsed, or a bounded parsing limit was reached.", remediation: "Review the manifest manually; treat its declared dependency list as incomplete until it parses cleanly." },
        _ if crate::scanner::heuristics::is_signature_id(rule) => {
            let id = crate::scanner::heuristics::signature_id_static(rule).unwrap_or("LF-UNCLASSIFIED");
            let meaning = crate::scanner::heuristics::signature_description(rule).unwrap_or("Heuristic content signature matched");
            RuleCore {
                rule_id: id,
                title: "Heuristic content signature match",
                meaning,
                remediation: "Review the matched excerpt in its surrounding context before treating this as more than a review signal.",
            }
        }
        _ => return None,
    };
    Some(item)
}

/// The security significance of what the detector observed.
fn why_it_matters(rule: &str) -> &'static str {
    match rule {
        "LF-CODE-AUTO-MAP" => "Model metadata can route compatible Hugging Face loading paths through publisher-supplied Python that executes with the permissions of the inference process.",
        "LF-CODE-REMOTE-TRUST" => "Enabling remote code removes the loader's refusal to execute publisher-supplied Python, so package code runs as part of loading the model.",
        "LF-CODE-SUBPROCESS" | "LF-CODE-OS-SYSTEM" => "Code executed during model loading with process-execution capability inherits the privileges of the inference process and can reach the surrounding host.",
        "LF-CODE-EVAL" | "LF-CODE-EXEC" => "Dynamic evaluation lets code that is not visible in the shipped source be constructed and run at load time, defeating static review of the package.",
        "LF-CODE-CTYPES" => "Loading native libraries moves execution outside Python's inspection surface, where neither Layerfault nor a Python-level reviewer can follow it.",
        "LF-CODE-NETWORK" => "Outbound network capability in loading-path code can fetch further payloads or send local data off the host during model loading.",
        "LF-CODE-IMPORT-SIDE-EFFECT" => "Module-level statements run on import, so the code executes merely by loading the model rather than by an explicit call.",
        "LF-PACKAGE-SYMLINK" => "A symlink lets a package reference content outside its own root, so the fingerprinted package and the loaded bytes can differ.",
        "LF-PACKAGE-RACE" => "Content that changes during a scan means the assessment describes bytes that are no longer the ones on disk.",
        "LF-PACKAGE-JSON-INVALID" => "Configuration that Layerfault cannot fully parse may still be parsed, differently, by a permissive loader.",
        "LF-TEMPLATE-SSTI" | "LF-TEMPLATE-INTROSPECTION" => "Template object traversal reaches the Python object graph, which in a rendering context that evaluates it can lead to arbitrary code execution.",
        "LF-TEMPLATE-DYNAMIC-INCLUDE" => "Dynamic template includes pull in content resolved at render time, which static review of the shipped template cannot cover.",
        "LF-PICKLE-DANGEROUS-GLOBAL" => "A pickle stream that references a code-execution callable will invoke it when an unsafe loader reconstructs the object graph.",
        "LF-PICKLE-UNKNOWN-GLOBAL" => "An unreviewed global means Layerfault cannot establish that reconstructing the object graph is limited to data.",
        "LF-PICKLE-MALFORMED" | "LF-SAFE-STRUCT" | "T15-STRUCT" | "LF-ONNX-STRUCT"
        | "LF-TF-STRUCT" | "LF-TFLITE-STRUCT" | "LF-KERAS-ARCHIVE"
        | "LF-TF-CHECKPOINT-STRUCT" | "LF-SAFE-INDEX-INVALID" => "Malformed structure passed to a model runtime can cause out-of-bounds reads, excessive allocation, parser confusion or a crash in the loading process.",
        "LF-SERIALIZATION-UNSAFE" | "LF-SERIALIZATION-BIN" | "LF-PICKLE-OPAQUE-CONTAINER"
        | "LF-PICKLE-OPAQUE-COMPRESSED" => "Code-capable serialization formats execute code during deserialization by design, so their contents are as trusted as the publisher.",
        "T12-001" | "T12-002" | "T12-003" | "T12-004" => "Executable machine code embedded inside a model artifact is not model data; it exists to be extracted and run.",
        "LF-SAFE-DTYPE" | "LF-ONNX-CUSTOM-OP" | "LF-KERAS-CUSTOM-OBJECT" | "LF-TF-EXECUTION-OP" => "Custom operations and unrecognised types are resolved by the runtime at load time, often by importing publisher-supplied code.",
        "LF-TF-FILESYSTEM-WRITE" => "A graph that writes to the filesystem acts on the host during inference rather than only producing model output.",
        "LF-ONNX-EXTERNAL-DATA" | "LF-ONNX-EXTERNAL-RANGE" | "LF-ONNX-EXTERNAL-INTEGRITY"
        | "LF-ONNX-EXTERNAL-HARDLINK" => "External tensor references make the loaded bytes depend on files outside the artifact that was reviewed and fingerprinted.",
        "LF-TFLITE-ASSOCIATED-FILE" => "Files carried alongside the model are extracted by tooling that consumes the artifact, widening what the artifact delivers.",
        "LF-INTEGRITY-DIGEST-MISMATCH" | "LF-INTEGRITY-SIZE-MISMATCH" => "The bytes on disk are not the bytes the manifest declares, so no signature, review or prior assessment applies to them.",
        "LF-HF-LFS-DIGEST-MISMATCH" | "LF-HF-LFS-SIZE-MISMATCH" => "The bytes on disk do not match the content-addressed LFS object declared by the Hugging Face Hub revision, indicating corrupted transmission or server-side tampering.",
        "LF-HF-LFS-METADATA-INVALID" => "Malformed or contradictory LFS metadata prevents cryptographic validation of remote repository members prior to execution/analysis.",
        "LF-PROV-UNSIGNED" | "LF-PROV-UNTRUSTED" | "LF-PROV-LOCAL" | "LF-PROV-LEGACY" => "Without a trusted attestation there is nothing binding this exact artifact to a publisher you have decided to trust.",
        "LF-PROV-REVOKED" | "LF-PROV-INACTIVE" => "A signature from a key outside its authorized window does not carry the trust the trust store was configured to grant.",
        "LF-PROV-NAMESPACE" => "A valid signature from a signer not authorized for this identity means the signer is vouching for something outside their remit.",
        "LF-PROV-SIGNATURE" | "LF-PROV-SIGSTORE-INVALID" | "LF-PROV-MULTI" | "LF-PROV-BINDING" => "Signature verification did not reach the state the configured trust policy requires.",
        "LF-RUNTIME-ADVISORY-MATCH" | "LF-RUNTIME-ADVISORY-STALE"
        | "LF-RUNTIME-VERSION-UNKNOWN" => "A model artifact is parsed by a runtime; a runtime with a known parsing vulnerability turns a malformed artifact into an exploit primitive.",
        "LF-SCAN-ERROR" => "An inspection that did not complete cannot support an admission decision, and failing open would let unexamined content through.",
        "LF-FORMAT-CLAIM-MISMATCH" | "LF-FORMAT-CONTENT-SMUGGLING" => "A misdeclared extension or role is used to bypass role-based security filters or trick parsers into executing code-capable streams.",
        "LF-FORMAT-TRAILING-DATA" => "Unmodeled trailing bytes after a format's logical end can hide secondary payloads, steganographic content, or appended code.",
        "LF-FORMAT-APPENDED-ARCHIVE" | "LF-FORMAT-APPENDED-SERIALIZATION" => "Appended container or serialization streams carry executable or unpackable payloads appended after nominal model weights.",
        "LF-FORMAT-POLYGLOT" => "Polyglot files satisfy structural validators for multiple formats, allowing execution by one system while appearing as benign data to another.",
        "LF-FORMAT-UNKNOWN" | "LF-PACKAGE-TEXT-LIMIT" | "LF-GGUF-TEXT-LIMIT"
        | "LF-TF-SCAN-LIMIT" | "LF-TF-CHECKPOINT-LIMIT" | "LF-KERAS-HDF5-LIMIT"
        | "LF-DATASET-COVERAGE-LIMIT" => "Content Layerfault did not examine cannot be reported as clean; incomplete coverage must be visible in the decision.",
        _ if rule.starts_with("LF-BEHAV-") => "The runtime attempted an action against the host during a sandboxed probe, which is behaviour rather than mere capability.",
        _ if rule.starts_with("LF-DATASET-") => "Training-corpus content shapes model behaviour, so corpus-level anomalies can persist into the trained artifact.",
        _ if rule.starts_with("LF-ADAPTER-") => "An adapter modifies a base model's behaviour, so anomalous adapter structure can change the safety properties the base model was assessed for.",
        _ if rule.starts_with("LF-DRIFT-") || rule.starts_with("LF-TOKENIZER-")
            || rule.starts_with("LF-TEMPLATE-CHANGED") => "A security-relevant component changed between revisions, so a prior assessment of this identity no longer describes what is on disk.",
        _ if rule.starts_with("LF-LINEAGE-") || rule.starts_with("LF-DERIVE-") => "A derivation claim that cannot be verified means the trust attached to the claimed base model does not transfer to this artifact.",
        _ if rule.starts_with("LF-DIFF-") => "A security-relevant difference between two revisions is where a change of behaviour would be introduced.",
        _ if rule.starts_with("T1-") || rule.starts_with("T2-") || rule.starts_with("T3-")
            || rule.starts_with("T4-") || rule.starts_with("T5-") || rule.starts_with("T6-")
            || rule.starts_with("T9-") || rule.starts_with("T10-") || rule.starts_with("T11-")
            || rule.starts_with("T14-") || rule == "LF-HEUR-DECODED-MATCH" => "Instruction-shaped text embedded in model data can be interpreted as instructions by a model or an agent that reads it.",
        _ if rule.starts_with("T13-") => "Local attestation state determines whether this artifact has been vouched for by a key you trust.",
        _ if rule.starts_with("LF-PARAM-") => "Generation parameters shipped with a model influence runtime behaviour and resource consumption without any code being involved.",
        "LF-DEP-FLOATING" => "An unpinned dependency can silently resolve to a newer, compromised, or unexpected release between installs, changing what code actually runs without a corresponding manifest change.",
        "LF-DEP-DIRECT-URL" => "A direct URL bypasses the package index's namespace and review conventions, so the fetched content depends entirely on the URL's host staying trustworthy.",
        "LF-DEP-VCS" => "A VCS dependency installs code straight from a repository rather than a published, indexed release, widening what the manifest actually pulls in.",
        "LF-DEP-VCS-MUTABLE-REF" => "A branch or tag can be force-pushed or retargeted by anyone with write access to the referenced repository, so the manifest's declared source does not fix the installed content the way a commit hash would.",
        "LF-DEP-LOCAL-PATH" => "A local/editable dependency ties the package's identity to filesystem content outside what was fingerprinted, so the same manifest can resolve differently depending on what happens to sit at that path.",
        "LF-DEP-PATH-ESCAPE" => "A dependency path that leaves the package directory tree can reference content the reviewer never saw, while still being installed as part of this package.",
        "LF-DEP-ALT-INDEX" => "An alternate index or channel controls what bytes 'requests' or 'numpy' actually resolves to, independent of the well-known public index's namespace protections.",
        "LF-DEP-INSECURE-TRANSPORT" => "Plaintext HTTP or a disabled certificate check lets a network-position attacker substitute the package content in transit.",
        "LF-DEP-BUILD-BACKEND" => "A build backend is code that runs during 'pip install'/'python -m build', before the package's own runtime code is ever imported.",
        "LF-DEP-INSTALL-HOOK" => "Install/build hooks execute automatically during 'pip install' or 'python setup.py build', before a reviewer would normally inspect runtime application code, and can carry process-execution or network capability at that stage.",
        "LF-DEP-RUNTIME-INSTALL" => "A package-manager invocation from an install hook can acquire and run code that is not declared anywhere in the package's own dependency manifest.",
        "LF-DEP-INCLUDE-MISSING" => "A dependency manifest that references an unresolvable include is incomplete: some declared dependencies are unknown to this scan.",
        "LF-DEP-ANALYSIS-INCOMPLETE" => "A manifest Layerfault could not parse contributes no dependency-risk evidence at all, which must not be mistaken for a clean result.",
        _ => "Layerfault observed a condition that affects whether this artifact can be safely admitted.",
    }
}

/// What Layerfault has deliberately not established.
///
/// This is the guard against the evidence upgrade manufacturing false
/// certainty: detecting a capability is never the same as proving behaviour.
fn limitations(rule: &str) -> &'static str {
    match rule {
        "LF-CODE-AUTO-MAP" | "LF-CODE-REMOTE-TRUST" => "The presence of a custom-code mapping does not establish that the referenced code is malicious, nor that any particular loader will execute it.",
        "LF-CODE-SUBPROCESS" | "LF-CODE-OS-SYSTEM" | "LF-CODE-EVAL" | "LF-CODE-EXEC"
        | "LF-CODE-CTYPES" | "LF-CODE-NETWORK" | "LF-CODE-IMPORT-SIDE-EFFECT" => "Static presence of this primitive does not prove that the code path is reachable, that it executes during model loading, or that its use is malicious. Layerfault did not execute the code.",
        "LF-TEMPLATE-SSTI" | "LF-TEMPLATE-INTROSPECTION" | "LF-TEMPLATE-DYNAMIC-INCLUDE" => "Layerfault never renders templates. Whether this expression is exploitable depends on the runtime rendering context, which static analysis cannot determine.",
        "LF-PICKLE-DANGEROUS-GLOBAL" | "LF-PICKLE-UNKNOWN-GLOBAL" => "Evidence comes solely from bounded static opcode disassembly; Layerfault never deserialized the stream. A resolved reference does not prove any loader reaches it.",
        "LF-PICKLE-MALFORMED" => "Layerfault stopped at the first unsafe condition rather than attempting recovery, so the remainder of the stream is uncharacterised.",
        "LF-PICKLE-OPAQUE-CONTAINER" | "LF-PICKLE-OPAQUE-COMPRESSED" => "Opacity is the finding: Layerfault establishes that it could not review the content, not that the content is harmful.",
        "LF-SERIALIZATION-UNSAFE" | "LF-SERIALIZATION-BIN" => "The format's capability is the finding. This says nothing about the specific contents of this artifact beyond what other findings report.",
        "T12-001" | "T12-002" | "T12-003" | "T12-004" => "Layerfault parsed the executable's headers only. It did not disassemble, emulate or otherwise characterise the code, and embedded executables can have legitimate uses.",
        "LF-SAFE-DTYPE" | "LF-ONNX-CUSTOM-OP" | "LF-KERAS-CUSTOM-OBJECT" => "An unrecognised operation or type is not inherently harmful; it means Layerfault cannot confirm it resolves to reviewed, data-only handling.",
        "LF-TF-EXECUTION-OP" | "LF-TF-FILESYSTEM-WRITE" => "Detection is a bounded byte-substring search over the serialized graph, not a protobuf parse. Layerfault cannot attribute the marker to a specific node, confirm the operation is reachable, or rule out an incidental match.",
        "LF-INTEGRITY-DIGEST-MISMATCH" | "LF-INTEGRITY-SIZE-MISMATCH" | "LF-PACKAGE-RACE" => "Layerfault reports only the values it measured. It does not establish how or why the artifact differs from its declaration.",
        "LF-HF-LFS-DIGEST-MISMATCH" | "LF-HF-LFS-SIZE-MISMATCH" | "LF-HF-LFS-METADATA-INVALID" => "Layerfault verifies content against the Hub's declared LFS metadata. It does not establish how or why the remote metadata or downloaded bytes differed.",
        "LF-HF-LFS-INTEGRITY" | "LF-HF-REMOTE-HASH-UNAVAILABLE" => "Remote LFS verification establishes byte identity against the Hub revision metadata; it does not attest to the safety or functionality of tensor weights or code.",
        "LF-SAFE-STRUCT" | "T15-STRUCT" | "LF-ONNX-STRUCT" | "LF-TF-STRUCT"
        | "LF-TFLITE-STRUCT" | "LF-KERAS-ARCHIVE" | "LF-SAFE-INDEX-INVALID"
        | "LF-TF-CHECKPOINT-STRUCT" => "A violated invariant shows the file is unsafe to parse. It does not establish that the malformation is deliberate or that a specific runtime is exploitable.",
        "LF-PACKAGE-SYMLINK" => "Layerfault records the declared target without following it. It has not established what the target actually resolves to.",
        "LF-RUNTIME-ADVISORY-MATCH" | "LF-RUNTIME-ADVISORY-STALE"
        | "LF-RUNTIME-VERSION-UNKNOWN" => "Version comparison against an advisory range does not establish that the vulnerable code path is reachable in your configuration.",
        "LF-SCAN-ERROR" => "This reports a failure to inspect, not a property of the artifact. The artifact may be benign.",
        "LF-FORMAT-CLAIM-MISMATCH" | "LF-FORMAT-CONTENT-SMUGGLING" => "Layerfault observed the contradiction between filename and header magic. It does not establish whether the mismatch was intentional evasion or a renaming error.",
        "LF-FORMAT-TRAILING-DATA" | "LF-FORMAT-APPENDED-ARCHIVE" | "LF-FORMAT-APPENDED-SERIALIZATION" => "Layerfault measured the unmodeled trailing bytes after the primary format logical end. Static detection does not prove that a particular runtime will parse or execute the trailing bytes.",
        "LF-FORMAT-POLYGLOT" => "Polyglot detection establishes structural validity for multiple parsers. Layerfault did not execute the secondary payload.",
        "LF-LAYERPOLICY" => "This is a policy decision about findings, not an independent technical observation. The underlying evidence belongs to the referenced findings.",
        _ if rule.starts_with("LF-BEHAV-") => "Observations come from a bounded sandboxed probe with a fixed seed and configuration. Absence of an observation is not absence of the behaviour, and a single observation is not proof of consistent behaviour.",
        _ if rule.starts_with("LF-DATASET-") => "Corpus statistics describe a distribution, not a specific harmful record, and legitimate corpora can exhibit the same shapes.",
        _ if rule.starts_with("LF-ADAPTER-") => "Numerical anomalies in adapter tensors are statistical signals, not evidence of a specific behavioural change.",
        _ if rule.starts_with("LF-DRIFT-") || rule.starts_with("LF-LINEAGE-")
            || rule.starts_with("LF-DERIVE-") || rule.starts_with("LF-DIFF-")
            || rule == "LF-TOKENIZER-CHANGED" || rule == "LF-TEMPLATE-CHANGED" => "Layerfault reports that the compared artifacts differ. It does not establish that the difference is unauthorised or harmful.",
        _ if rule.starts_with("T1-") || rule.starts_with("T2-") || rule.starts_with("T3-")
            || rule.starts_with("T4-") || rule.starts_with("T5-") || rule.starts_with("T6-")
            || rule.starts_with("T9-") || rule.starts_with("T10-") || rule.starts_with("T11-")
            || rule.starts_with("T14-") || rule == "LF-HEUR-DECODED-MATCH" => "Pattern matching over text cannot distinguish an attack payload from documentation, test data or discussion of the same technique. Review the excerpt in context.",
        _ if rule.starts_with("T13-") || rule.starts_with("LF-PROV-") => "Trust state reflects the configured trust store and policy. It is a statement about verification, not about the artifact's contents.",
        _ if rule.starts_with("LF-PARAM-") => "A parameter outside the configured threshold is a policy observation, not evidence of malicious intent.",
        _ if rule.ends_with("-LIMIT") || rule == "LF-FORMAT-UNKNOWN" => "This records what Layerfault did not examine. Unexamined content is neither clean nor harmful; it is unreviewed.",
        "LF-DEP-FLOATING" => "Absence of a pin is a manifest-level fact. It does not establish that the currently resolvable version is compromised, nor predict what a future resolution will select.",
        "LF-DEP-DIRECT-URL" | "LF-DEP-VCS" | "LF-DEP-LOCAL-PATH" => "Layerfault records the declared source shape. It does not contact the index, VCS host, or filesystem path, and does not establish that the referenced content is unsafe.",
        "LF-DEP-VCS-MUTABLE-REF" => "Layerfault does not contact the VCS host and cannot determine what the reference currently resolves to, whether it has changed historically, or whether the hosting repository enforces branch protection.",
        "LF-DEP-PATH-ESCAPE" => "Layerfault detects the declared path shape only; it does not open or verify content at the escaped location.",
        "LF-DEP-ALT-INDEX" => "A non-default index or channel is not inherently unsafe; many organizations run legitimate private mirrors. This does not establish that the alternate source is compromised.",
        "LF-DEP-INSECURE-TRANSPORT" => "Layerfault observes the declared transport scheme only. It does not confirm whether a network-position attack actually occurred for this specific install.",
        "LF-DEP-BUILD-BACKEND" => "A non-default build backend is not inherently unsafe; this records that install-time code exists and names it, without evaluating its behaviour.",
        "LF-DEP-INSTALL-HOOK" => "Static detection of a custom Command subclass and a capability inside its body does not establish that pip actually invokes this exact hook for a given install command, that the capability executes unconditionally, or that the base class was correctly resolved without import analysis.",
        "LF-DEP-RUNTIME-INSTALL" => "Layerfault records the literal invocation it found; it does not execute the hook and cannot confirm the install command runs in every configuration or actually succeeds.",
        "LF-DEP-INCLUDE-MISSING" => "This describes a gap in Layerfault's view of the manifest tree, not a property of the (unresolved) included file's content.",
        "LF-DEP-ANALYSIS-INCOMPLETE" => "This is a parser-failure or budget-limit fact. It does not characterize the manifest's actual dependency risk, which remains unexamined.",
        _ => "Layerfault reports the observed technical condition. Establishing intent or impact requires review beyond static analysis.",
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
