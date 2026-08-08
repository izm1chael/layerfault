# Layerfault detection and trust model

Layerfault is an offline-first preflight, admission and supply-chain security scanner for local AI model artifacts and runtimes. Ollama remains its deepest content-addressed store integration, while standalone GGUF/Safetensors packages, LM Studio, llama.cpp and the local Hugging Face cache share the same structural, integrity, package, trust and policy controls.

Layerfault does **not** claim that static inspection can prove arbitrary model weights are behaviorally safe or free from training-time poisoning. A clean scan means that the checks described here passed; it is not a proof of model intent.

## 1. Result model

Every result has three independent dimensions:

| Field | Values | Meaning |
| --- | --- | --- |
| `status` | `Pass`, `Warn`, `Fail` | Recommended operational disposition |
| `finding_class` | `Integrity`, `Structural`, `ContentIndicator`, `Policy`, `Attestation`, `Compatibility`, `Operational`, `Informational` | What kind of evidence was found |
| `confidence` | `Low`, `Medium`, `High` | Confidence in the stated finding, not a probability that the model is malicious |

`FAIL` is reserved for conditions that are suitable for blocking an automated preflight: integrity failures, invalid structures, invalid supplied-key attestations, structurally valid embedded executables, or high-severity/corroborated content indicators. `WARN` means review or policy action is required but malicious intent is not established.

## 2. Threat taxonomy

| ID | Category | Engine | Default disposition |
| --- | --- | --- | --- |
| T1 | Direct Instruction Override | Heuristics | High-severity content indicator |
| T2 | Identity Confusion | Heuristics | Warning for ambiguous identity/persona markers; explicit no-restriction/unconstrained directives remain high-severity |
| T3 | Exfiltration Channel | Heuristics | High-severity content indicator, except documented weak signals |
| T4 | Defensive Bypass | Heuristics | High-severity content indicator |
| T5 | Persistence Manipulation | Heuristics | Warning |
| T6 | Encoding Obfuscation | Heuristics | Warning |
| T7 | Parameter Policy | Config | Warning |
| T8 | Artifact Integrity Failure | Integrity | Fail |
| T9 | Hardcoded Secrets | Heuristics | High-severity content indicator; values are redacted |
| T10 | Excessive Agency / Execution Reference | Heuristics | Warning unless corroborated |
| T11 | Subtle Poisoning Indicator | Heuristics | Warning |
| T12 | Embedded Executable | Binary | Fail only after structural ELF/PE/Mach-O validation or a valid WebAssembly module header |
| T13 | Local Attestation | Integrity | Missing/unverified = Warn; invalid under supplied key = Fail |
| T14 | PII Leakage | Heuristics | Warning; values are redacted |
| T15 | GGUF Metadata Content Indicator | Metadata | Inherits the underlying heuristic result |
| S1 | GGUF Structural Failure | Metadata | Fail |
| C1 | Unsupported/Unknown Layer | Layer policy | Warn after integrity verification |

## 3. Integrity and filesystem rules

Layerfault treats the manifest as a set of content-addressed descriptors.

For **every** referenced config or layer descriptor it:

1. validates digest syntax and supported digest algorithm;
2. opens the blob without following a final symlink on Unix;
3. verifies the file is regular;
4. verifies the descriptor's declared byte size;
5. hashes the complete blob and compares it to the descriptor digest; and
6. passes a clone of that same open file descriptor to deeper scanners.

Deep scanners do not reopen a verified blob path. This prevents a path replacement between the integrity check and content inspection from substituting different bytes.

Unknown media types are not silently ignored. They receive an explicit compatibility warning after their integrity has been verified.

## 4. Ollama manifest and media-type compatibility

Layerfault accepts both legacy and current Ollama layouts:

- optional manifest `config` descriptor plus `layers`;
- layer-only manifests where encountered;
- legacy `application/vnd.ollama.image.model` GGUF layers;
- current config, template, params, system, tokenizer, tokenizer-config, tensor, draft/projector/adapter, and license-style layers;
- media types containing parameters such as `; name=...`, `; dtype=...`, or `; type=...`.

Layer matching is performed on the normalized base media type while preserving the original media type in output.

## 5. GGUF structural validation

The GGUF scanner is a bounded structural parser, not a string search over the first bytes of the model. It validates:

- `GGUF` magic and supported versions 1-3;
- little-endian v1-v3 and GGUF v3 big-endian encoding;
- bounded tensor and metadata counts;
- bounded strings, arrays, and nested metadata arrays;
- metadata key validity;
- `general.alignment` constraints;
- tensor names, dimensions, type identifiers, element-count overflow, offsets, alignment, and overlap;
- zero padding up to tensor data;
- tensor byte ranges for supported GGML quantization/data types;
- file truncation and out-of-range tensor data.

A malformed or truncated GGUF produces a structural `FAIL`; it cannot become `PASS` merely because no suspicious strings were recovered.

Future/unknown tensor encodings are reported as compatibility warnings when the surrounding structure can still be safely bounded. Layerfault avoids claiming exact tensor-size validation for an encoding it does not understand. The v0.3 compatibility table includes the currently assigned GGML types through 42, including MXFP4 (39), NVFP4 (40), Q1_0 (41), and Q2_0 (42).

Selected human-readable GGUF metadata (for example chat templates, prompts, descriptions, and licenses) is passed through the content heuristic engine. Prompt/template/system metadata has an independent higher-priority collection budget so verbose descriptions cannot silently crowd it out. If either bounded security-text budget is exhausted, Layerfault emits `LF-GGUF-TEXT-LIMIT` rather than presenting the content view as complete. Huge tokenizer vocabularies are not copied wholesale into heuristic memory.

## 6. Content heuristics T1-T6, T9-T11, T14

The regex signature table in `scanner/heuristics.rs` preserves individual signature IDs and bounded context. File-backed text layers are scanned incrementally across the complete descriptor with overlap between chunks; Layerfault no longer skips heuristic inspection merely because a layer exceeds 10 MiB. Invalid UTF-8 is decoded lossily for detection and zero-width/bidirectional control characters are removed from a parallel detection view while the original bytes remain the integrity evidence. Any normalization without a signature match is surfaced as an operational warning rather than a silent clean pass.

A `RegexSet` first identifies candidate rule families for each streamed window, so Layerfault does not run every extraction expression over every byte. Match counting continues for severity/corroboration, while retained evidence is capped globally and per signature to prevent attacker-controlled report/memory amplification.

Multi-vector escalation is deliberately narrow: only distinct **T1-T6** families participate. Three or more T1-T6 categories in one scanned text layer become a high-confidence `FAIL`. Secret, PII, package, or policy signatures do not accidentally inflate that count.

A single high-severity content signature can still produce `FAIL`, but its `finding_class` remains `ContentIndicator`: this is static evidence in a template/config/metadata layer, not proof about model weights.

Ambiguous T2 identity-only markers are intentionally warnings when seen alone. Bare jailbreak persona names, generic developer/debug-mode language, broad identity reassignment, and vendor-name denial are common enough in legitimate model templates, documentation, and evaluation corpora that they require corroboration. Explicit no-restriction or unconstrained-system directives remain blocking signals.

T10 shell/script and autonomous-execution references are warnings by default because legitimate coding, agent, and security models frequently contain such text. Operators should correlate them with T1-T6 or other evidence.

### Sensitive-match redaction

T9 secret and T14 PII matches are never emitted verbatim. Output contains bounded surrounding text plus a one-way truncated SHA-256 fingerprint:

```text
<redacted sha256:0123456789abcdef>
```

This permits repeat-match correlation without copying discovered credentials or PII into JSON, terminals, or CI logs.

## 7. Parameter policy T7

Inference settings are policy/risk signals rather than evidence of malicious intent. Layerfault therefore reports parameter-limit findings as `WARN` / `Policy`.

The operator can set limits with CLI flags. Non-finite floating-point values and invalid negative/zero bounds are rejected by argument parsing rather than silently disabling comparisons.

Typical checks include:

- temperature above the operator maximum;
- context size above the operator maximum;
- positive `num_predict` above the operator maximum (`-1` remains a valid Ollama sentinel);
- `top_k == 0`;
- `top_p > 0.99`;
- unusually low repeat penalty;
- suspicious stop delimiters.

A fixed seed alone is informational and does not create a warning.

## 8. Embedded executable detection T12

Layerfault no longer treats four bytes such as `\x7fELF` or `MZ` as an executable.

Candidate offsets are escalated to `FAIL` only after format-specific validation. ELF validation checks class/endianness/version, machine/header sizes and table bounds; PE validates DOS/PE signatures, machine, section count, optional-header magic/size and section-table bounds; Mach-O validates thin/fat headers, architecture ranges and bounded load-command tables. WebAssembly requires the complete standard magic/version header before T12 evidence is emitted.

All structural reads are positional and cursor-independent. On cold Ollama model/tensor scans and standalone GGUF/Safetensors admission, executable discovery consumes the same sequential chunks already being hashed, eliminating a second whole-artifact read. Random short magic coincidences therefore remain `PASS`.

## 9. Local attestation T13

Detached Ed25519 signatures are **local attestations**. A valid signature means:

> the supplied public key verifies the exact manifest bytes Layerfault parsed and scanned.

It does not by itself prove who owns that key or establish publisher identity. Publisher/source provenance requires an external trust policy mapping keys to identities/namespaces.

The scanner hashes the exact manifest byte buffer it parsed and verifies a signature over that same buffer; it does not reopen the manifest between parse and signature verification.

Disposition:

- no signature: `WARN`;
- signature present but no verification key supplied: `WARN`;
- valid signature under supplied key: `PASS` with a public-key fingerprint;
- malformed or invalid signature under supplied key: `FAIL`.

## 10. Model identity and isolation

Canonical model names preserve registry and namespace, for example:

```text
registry.ollama.ai/library/llama3.2:latest
example.internal:5000/team/model:prod
```

Short selectors remain convenient only when unambiguous. If two discovered models share the same short repository/tag, Layerfault refuses to guess and asks for the canonical selector.

A malformed model is converted into a per-model `ScanError` result. It does not abort scanning of unrelated models in `--all` mode.

## 11. Aggregation and exit codes

Per-model status is the highest status among its results:

- any `Fail` -> model `Fail`;
- else any `Warn` -> model `Warn`;
- else `Pass`.

Process exit priority is:

- `0`: all checks passed;
- `1`: one or more warnings, no failures;
- `2`: at least one artifact-integrity failure;
- `3`: another blocking failure (structural/content/attestation/scan error);
- `4`: policy-only block with no scanner/provenance failure (for example strict policy requiring trust);
- `5`: baseline drift detected by the baseline command.

Integrity failure retains its dedicated exit code even when other failures are also present. Policy is evaluated separately from scanner evidence so a policy-only block does not masquerade as corrupt bytes.

## 12. False-positive guidance

| Pattern | Legitimate trigger | Operator action |
| --- | --- | --- |
| T2 identity language | Persona or role examples in a template | Review the complete template and whether it overrides a trusted system prompt |
| T3 URL/image syntax | Citation or documentation template | Correlate with instructions to transmit user/model data |
| T5 persistence wording | Benign formatting preference | Check for T1-T4 corroboration |
| T6 encoded data | Legitimate serialized examples/assets | Decode/review when it is the only signal |
| T10 shell/process text | Coding, DevOps, security, or agent model | Treat as policy warning unless combined with bypass/exfiltration evidence |
| T7 extreme inference setting | Intentional benchmarking | Apply local deployment policy rather than calling the model malicious |

## 13. Machine-readable reporting and adversarial validation

`--json` retains Layerfault's native report schema. `--sarif` emits SARIF 2.1.0 for warning/failure findings and carries model name, layer digest, media type, check type, finding class, confidence, matches, and timing as result properties. SARIF does not invent source-code locations for model artifacts.

The repository includes three validation layers:

- unit tests for parser/detector edge cases;
- CLI integration tests that construct isolated synthetic Ollama stores and exercise digest mismatch, malformed GGUF, current parameterized tensor layers, model-failure isolation, redaction, SARIF, and valid legacy GGUF paths; and
- `cargo-fuzz` targets for manifest JSON, GGUF, arbitrary-byte heuristic input, Safetensors, ONNX, TensorFlow SavedModel, TFLite, Keras archives, binary object parsing, and package custom-code correlation.

The scheduled fuzz workflow uses Rust nightly/libFuzzer for bounded smoke runs. Fuzzing is intended to discover panics, pathological parser behavior, and unchecked assumptions; it is not a substitute for semantic detector evaluation.

## 14. Scope boundary

Layerfault is designed to answer questions such as:

- Are the local blobs the bytes the manifest names?
- Is the artifact structurally safe enough to parse/preflight?
- Does a supplied key attest the exact manifest being scanned?
- Do templates/config/selected metadata expose secrets or contain suspicious instructions?
- Does the model violate my local inference policy?

It intentionally does not claim to prove that opaque learned weights contain no hidden behavior or training-time backdoor. Dynamic evaluation and behavioral red-teaming are separate controls.

## 15. Trust, enforcement, drift and quarantine controls

Layerfault separates four security questions that must not be conflated:

1. **Scanner evidence** — integrity, structure and content findings.
2. **Cryptographic provenance** — whether an exact manifest is attested and by which key.
3. **Trust authorization** — whether that key is locally trusted and authorized for the canonical model identity.
4. **Policy disposition** — whether the combination is permitted to execute in this environment.

New stable provenance rule IDs:

- `LF-PROV-UNSIGNED` — no attestation present;
- `LF-PROV-UNTRUSTED` — signature references a key absent from the trust store;
- `LF-PROV-REVOKED` — a locally revoked key attested the model;
- `LF-PROV-NAMESPACE` — key is trusted but not authorized for this model identity;
- `LF-PROV-BINDING` — attestation model/digest binding does not match the scanned artifact;
- `LF-PROV-SIGNATURE` — malformed or cryptographically invalid signature;
- `LF-PROV-TRUSTED` — valid attestation from a trusted, authorized key;
- `LF-PROV-LOCAL` / `LF-PROV-LEGACY` — legacy raw-signature compatibility states.

Suppressions cannot hide integrity, structural, operational or attestation failures. This prevents a local policy exception from converting broken bytes, malformed GGUF, scanner failure, revoked provenance or namespace misuse into an allowed artifact.

Baseline drift is a separate control over model identity, manifest digest and descriptor digest sets. Quarantine is non-destructive by default and preserves blobs shared with other models.

## Additional local-artifact and runtime boundaries

Layerfault's standalone GGUF/Safetensors admission checks establish structural validity, local evidence and configured provenance/policy. A successful LM Studio or llama.cpp admission means Layerfault gated the discovered/local artifact before invoking the runtime; it does not claim the runtime itself is vulnerability-free.

Hugging Face support is an offline cache-consistency check. Repository folder names and refs are not treated as cryptographic publisher identity. Snapshot symlinks must resolve within the repository's local blob store and supported artifacts receive format-specific structural inspection.

Safetensors indexes are treated as security-relevant metadata: shard paths must be safe, referenced shards must be locally resolvable within the allowed source boundary, and each supported shard must pass structural validation.

Optional Sigstore verification trusts only the explicitly supplied expected certificate identity and issuer accepted by the installed Cosign verifier. Layerfault never downgrades a failed Sigstore verification to an unsigned warning.

## 16. Canonical package identity and whole-package security

A `lfpkg:sha256:` identity binds a sorted canonical description of package-relative member paths, security roles, byte lengths and member SHA-256 digests. The absolute package root is excluded. Copying an unchanged directory therefore preserves identity; renaming, adding, deleting, converting or modifying a member changes identity.

Layerfault rejects a direct package root that is itself a symlink and never follows package-internal symlinks. The Hugging Face cache adapter is intentionally different because snapshots are symlink trees by design: a snapshot link is accepted only when its canonical target stays inside that repository's local `blobs` directory. Content-addressed scan reuse is keyed by both resolved blob and presented filename role so the same bytes linked as `config.json` and `modeling_*.py` cannot inherit the wrong classification.

Whole-package inspection is static and bounded. Layerfault does not import model Python, execute shell/native files, invoke package installers, or deserialize Pickle/PyTorch objects. Code-capable serialization is therefore treated as an admission risk rather than opened with the vulnerable loader it is intended to protect.

Hugging Face `auto_map` is sufficient to establish that a package declares a custom loader relationship; Layerfault does not require a package-local `trust_remote_code=true` value before correlating the referenced local Python module. Runtime callers normally provide that trust decision externally. Correlation uses bytes captured from the same no-follow descriptor already fingerprinted/scanned, avoiding a second path reopen. Oversized JSON members produce bounded coverage evidence instead of aborting package admission.

ONNX models that declare external tensor data are treated as compound artifacts. Each relative sidecar is containment-checked, opened without following the final symlink, range-checked and hashed; the resulting sidecar identities and ranges are bound into an `lfonnx:sha256:` compound identity. A missing, unsafe or changing sidecar is an integrity failure. Compound ONNX reports are not reused from a cache keyed only by the main protobuf file.

## 17. Runtime advisory boundary

Runtime advisory admission answers a separate question from artifact safety: whether the exact installed runtime binary selected for launch is within a machine-matchable affected version range for a relevant known vulnerability.

The built-in catalog is compiled into Layerfault. High/critical matches are `Operational` failures and cannot be suppressed or overridden. The catalog is deliberately conservative: entries requiring deployment context Layerfault cannot establish (for example an optional network backend that is not necessarily used by the guarded path) should not be promoted into a generic hard block.

External catalogs are never trusted merely because they are JSON. The operator must supply an Ed25519 signature and public key. Layerfault opens and verifies the database once and evaluates that same byte buffer, preventing a catalog verify/reopen race. A catalog older than the configured freshness expectation produces a warning: absence of a match in stale data is not proof that a runtime is current.

Runtime version checking and launch use the same canonical executable path resolved by Layerfault. This removes a second PATH lookup but does not claim to prevent a same-privilege attacker from replacing the runtime executable itself after the version check; protecting runtime installation files is an OS/package-management control.

## 18. Verify-to-execute binding

Layerfault reports the actual binding guarantee:

- `staged-copy`: direct-file execution/import uses a private read-only copy streamed from a no-follow descriptor after admission and validates the copied digest before launch. This is the strongest portable binding implemented without unsafe platform-specific syscalls.
- `revalidated-before-launch`: runtime-owned stores/keys are fully revalidated immediately before starting the runtime. The runtime subsequently opens its own store path, leaving a residual TOCTOU boundary that Layerfault documents rather than hiding.
- `best-effort`: reserved for adapters where stronger binding cannot be established.

A staged copy can require disk space comparable to the selected artifact. That cost is intentional in the strong-binding path and should be measured during performance certification.

## 19. Signed scan/admission evidence

Signed evidence is a record of a decision, not a new trust root. The signed payload includes subject and fingerprint, Layerfault version/detector contract, effective-policy hash, trust-store hash, runtime advisory evaluation, execution-binding record, decision and scan details. Altering any payload field invalidates the Ed25519 signature.

Evidence verification has two independent outcomes:

1. cryptographic validity of the embedded signing key/signature; and
2. whether that key is currently active, trusted and namespace-authorized in the verifier's Layerfault trust store.

This prevents a self-generated valid signature from being confused with organizational trust.

## 20. Stable-release feature freeze

The security architecture now intentionally freezes broad functionality for the initial stable release. Additional work should prioritize hostile corpus coverage, benign false-positive measurement, large-artifact resource limits, runtime/source compatibility, deterministic output, documentation and release reproducibility. New detectors or integrations should be accepted only when they close a demonstrated threat-model gap.
