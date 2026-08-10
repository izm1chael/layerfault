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
| T16 | Pickle Opcode / Global Reference Risk | Serialization | Malformed/dangerous = Fail; unknown global = Warn; allowlisted globals = Pass |
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

The regex signature table in `scanner/heuristics.rs` preserves individual signature IDs and bounded context. File-backed text layers are scanned incrementally across the complete descriptor with overlap between chunks; Layerfault no longer skips heuristic inspection merely because a layer exceeds 10 MiB. Invalid UTF-8 is decoded lossily for detection and zero-width/bidirectional control characters are removed from a parallel detection view while the original bytes remain the integrity evidence. A small, reviewable confusable-character map normalizes common Greek/Cyrillic homoglyph substitutions for matching without changing the integrity bytes. Normalization by itself is not a security finding.

Suspicious Base64-, hexadecimal-, and ROT13-shaped text is decoded under explicit byte, candidate, and recursion-depth limits (depth at most two) and the high-value T1-T5/T9 signatures are re-run against decoded text. A decoded hit is emitted as `LF-HEUR-DECODED-MATCH` with the transform chain recorded; Layerfault never executes decoded content. Exhausting the decode budget is an explicit incomplete-coverage warning rather than a clean result.

Prompt/chat-template metadata receives additional template-specific checks for Jinja/SSTI object-graph traversal and dangerous dynamic include/import patterns. These rules inspect template source only; Layerfault does not render or execute the template.

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


## 8A. Pickle opcode analysis T16

Pickle/PyTorch/joblib serialization is inspected statically rather than rejected solely by extension. Layerfault parses protocol 0-5 opcode framing with bounded argument lengths and tracks only the stack/memo state needed to resolve `GLOBAL` and `STACK_GLOBAL` references. Environment-dependent `EXT1`/`EXT2`/`EXT4` registry lookups and unresolved or non-allowlisted `NEWOBJ` constructors are blocking execution primitives rather than clean results. Layerfault **never unpickles or executes** the stream. PyTorch ZIP checkpoints are opened as bounded containers and only pickle members are analyzed; member names are containment-checked and decompression/member limits are enforced.

Known tensor/numeric reconstruction globals (for example common PyTorch, NumPy, `OrderedDict`, and narrowly selected builtin container constructors) are allowlisted in code. Explicit execution primitives such as `os.system`, `subprocess.*`, `eval`, `exec`, `compile`, `__import__`, `pty.spawn`, legacy instantiation opcodes, and dangerous `REDUCE`/`BUILD` use fail with named evidence. Unknown globals warn for review rather than being silently trusted or blanket-blocked. Malformed/truncated/desynchronized streams fail structurally. Compressed pickle-by-name inputs that cannot be transparently inspected remain explicit opaque/incomplete warnings.

Primary rule IDs are `LF-PICKLE-SAFE-GLOBALS`, `LF-PICKLE-UNKNOWN-GLOBAL`, `LF-PICKLE-DANGEROUS-GLOBAL`, `LF-PICKLE-MALFORMED`, and the opaque-container/compressed variants.

## 9. Local attestation T13

Detached Ed25519 signatures are **local attestations**. A valid signature means:

> the supplied public key verifies the exact manifest bytes Layerfault parsed and scanned.

It does not by itself prove who owns that key or establish publisher identity. Publisher/source provenance requires an external trust policy mapping keys to identities/namespaces.

When Sigstore/cosign verification is requested, Layerfault records the canonical verifier path, SHA-256 digest, and reported version and revalidates the executable bytes immediately before verification. This preserves the external-crypto design while making the verifier implementation part of reproducible evidence rather than trusting an unrecorded `$PATH` binary.

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

Safetensors indexes are treated as security-relevant metadata: shard paths must be safe, referenced shards must be locally resolvable within the allowed source boundary, and each supported shard must pass structural validation. JSON headers/indexes are capped at 32 MiB, tensor entries at 250,000, metadata entries at 10,000, and tensor rank at 32 before inventory construction.

Optional Sigstore verification trusts only the explicitly supplied expected certificate identity and issuer accepted by the installed Cosign verifier. Layerfault never downgrades a failed Sigstore verification to an unsigned warning.

## 16. Canonical package identity and whole-package security

A `lfpkg:sha256:` identity binds a sorted canonical description of package-relative member paths, security roles, byte lengths and member SHA-256 digests. The absolute package root is excluded. Copying an unchanged directory therefore preserves identity; renaming, adding, deleting, converting or modifying a member changes identity.

Layerfault rejects a direct package root that is itself a symlink and never follows package-internal symlinks. The Hugging Face cache adapter is intentionally different because snapshots are symlink trees by design: a snapshot link is accepted only when its canonical target stays inside that repository's local `blobs` directory. Content-addressed scan reuse is keyed by both resolved blob and presented filename role so the same bytes linked as `config.json` and `modeling_*.py` cannot inherit the wrong classification.

Whole-package inspection is static and bounded. Discovery prunes ignored directory trees and refuses more than 100,000 entries, depth above 64, member paths above 4,096 UTF-8 bytes, or aggregate declared content above 1 TiB. Layerfault does not import model Python, execute shell/native files, invoke package installers, or deserialize Pickle/PyTorch objects. Code-capable serialization is therefore treated as an admission risk rather than opened with the vulnerable loader it is intended to protect.

Hugging Face `auto_map` is sufficient to establish that a package declares a custom loader relationship; Layerfault does not require a package-local `trust_remote_code=true` value before correlating the referenced local Python module. Runtime callers normally provide that trust decision externally. Correlation uses bytes captured from the same no-follow descriptor already fingerprinted/scanned, avoiding a second path reopen. Oversized JSON members produce bounded coverage evidence instead of aborting package admission.

ONNX models that declare external tensor data are treated as compound artifacts. Each relative sidecar is containment-checked, opened without following the final symlink, range-checked and hashed; the resulting sidecar identities and ranges are bound into an `lfonnx:sha256:` compound identity. A missing, unsafe or changing sidecar is an integrity failure. Compound ONNX reports are not reused from a cache keyed only by the main protobuf file.

## 17. Runtime advisory boundary

Runtime advisory admission answers a separate question from artifact safety: whether the exact installed runtime binary selected for launch is within a machine-matchable affected version range for a relevant known vulnerability.

The built-in catalog is compiled into Layerfault. High/critical matches are `Operational` failures and cannot be suppressed or overridden. The catalog is deliberately conservative: entries requiring deployment context Layerfault cannot establish (for example an optional network backend that is not necessarily used by the guarded path) should not be promoted into a generic hard block.

External catalogs are never trusted merely because they are JSON. The operator must supply an Ed25519 signature and public key. Layerfault opens and verifies the database once and evaluates that same byte buffer, preventing a catalog verify/reopen race. A catalog older than the configured freshness expectation produces a warning: absence of a match in stale data is not proof that a runtime is current.

Runtime version checking records the canonical executable and its SHA-256. Immediately before launch, Layerfault opens that path without following the final symlink, streams it into a private executable staging directory, verifies the copied digest, and mounts only that staged copy as `/runtime`. Replacement of the original pathname after binding therefore cannot change the launched bytes.

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

## RC follow-up: composite review, package streaming, ONNX aliases and dataset bounds

Composite `review` is fail-isolated but decision-monotonic. Static admission is performed before optional metadata, lineage, numeric, behavioural, judge, drift, and observation domains. Failure of a supplementary domain is preserved as structured coverage evidence and cannot lower an existing `WARN` or `BLOCK`. An unexpected supplementary `FAILED` state raises at least `WARN` when static admission was otherwise clean; an intentionally skipped profile domain is `NOT_RUN` and does not by itself raise severity.

Direct package text/config security inspection streams the complete regular-file member in bounded chunks with overlap. The previous fixed 4 MiB package-content cutoff is retained only as a legacy explanation identifier for old evidence, not as a current coverage boundary. Large JSON DOM construction remains bounded where necessary, but security-sensitive Hugging Face loader metadata is extracted with a streaming visitor.

ONNX external tensor files remain part of a compound identity and are opened without symlink traversal, containment/range checked, hashed, and revalidated. On Unix, a sidecar with `st_nlink > 1` raises `LF-ONNX-EXTERNAL-HARDLINK`: another pathname can mutate the same inode and therefore weakens the admitted-directory mutability boundary even though the exact bytes are integrity-bound at scan time.

Dataset poisoning analysis is deliberately bounded. Reports expose records available/analyzed, record and token-key ceilings, opaque/unparsed member counts, and sampling strategy. When the record budget is exceeded, selection is deterministic and stratified across each member's complete record range, including head/middle/tail positions; it is not a first-N sample. Parallel per-file work is merged in deterministic source order and must not change security semantics between job counts. Opaque formats or members that cannot be semantically parsed remain explicit coverage warnings rather than being silently treated as clean.

## Active behavioural sandbox boundary

Active behavioural analysis is a **separate control** from static admission. It can demonstrate that a particular model/runtime/probe combination produced a response regression or attempted a runtime side effect. A clean active run does not prove the absence of untested triggers, delayed behavior, training-time poisoning, or behavior that requires a different runtime/context.


The built-in active probe corpus defaults to `core-v2`, expanding the fixed corpus to dozens of probes across the existing categories plus conditional/context-triggered behavior and multi-turn consistency scenarios. Mutation expansion covers trigger, obfuscation, prompt-injection, exfiltration, privilege-boundary and related probes under a hard caller-supplied cap. Versioned `core-v1` remains loadable explicitly for reproducing older evidence. Corpus expansion narrows coverage gaps but does not change the epistemic boundary: a clean run is not proof that no trigger exists.

Behavioural runtimes are session-scoped. A llama.cpp model is loaded once into a sandboxed `llama-server` session bound to a Unix-domain socket inside the isolated workspace; each probe is submitted as a stateless request and slot/context state is erased before reuse. The managed Transformers backend similarly loads once into a bounded NDJSON worker. Sessions are never shared across unrelated models. A base/derived comparison therefore performs at most one load per model.

`--timeout-seconds` is a hard command-wide behavioural deadline. Probe operations consume the remaining budget, teardown has a bounded grace period, and Linux runtime trees are placed in their own process group so timeout/cancellation sends TERM and then KILL to descendants before reaping. Progress phases are emitted to stderr so JSON stdout remains machine-readable.

Filesystem telemetry computes aggregate suspicious-mutation state before bounded evidence truncation, retains suspicious entries first, and reports snapshot overflow/incomplete coverage. Evidence caps therefore bound report size without allowing an attacker to hide a suspicious mutation by flooding benign cache files.

Persistent digest and scan-evidence cache records are schema-versioned and content-validated before reuse. Unix validation binds device, inode, change time, timestamps, length, and sampled content. Windows and other non-Unix targets lack the same immutable change identity in this implementation, so Layerfault rehashes the complete file before reusing either its digest or prior PASS evidence; restoring a file's length and timestamps cannot bypass that check.

External active backends fail closed unless Linux Bubblewrap can create an isolated filesystem/network/PID/IPC/UTS view. The model and optional base package are mounted read-only. A digest-verified private copy of the runtime is mounted as `/runtime`; normal host executable directories are not mounted, while the minimum shared-library trees needed by the runtime remain read-only. The sandbox receives a private `/proc`, synthetic `/dev`, tmpfs `/tmp`, private writable workspace/HOME, offline Hugging Face settings, dropped Linux capabilities, and no host network namespace.

Layerfault deliberately places **synthetic** secrets in the private sandbox HOME/workspace and environment. Syscall telemetry can therefore distinguish attempts to access SSH/API-secret decoys without exposing real host credentials. `strace` telemetry records bounded evidence of network syscalls, unexpected process execution, canary/sensitive-path access, and loader/runtime activity. Files surviving in the writable workspace are compared with a pre-run snapshot. The telemetry itself is stored outside the path mounted into the sandbox.

High-risk research execution (`--allow-static-blocked` or `--execute-custom-code`) additionally requires both `strace` and `prlimit`; if either is missing, execution is refused. `prlimit` supplies CPU, file-size, file-descriptor, core-dump and address-space limits. Layerfault intentionally does not set `RLIMIT_NPROC`: Linux accounts it per real UID, so a per-sandbox value can deny service to unrelated processes owned by the same user while still failing to provide an independent sandbox quota. Dedicated lab deployments should enforce a pids cgroup outside Layerfault. The address-space ceiling applies the same runtime safety margin whether its base is host-derived or supplied through `LAYERFAULT_BEHAVIOUR_ADDRESS_SPACE_MB`.

Layerfault deliberately does not install a seccomp filter in the general behavioural sandbox. Supported Python, PyTorch, Transformers and llama.cpp versions have a broad and changing syscall surface; a permissive compatibility filter would add little protection, while a narrow filter would create unsafe pressure to disable the sandbox for legitimate models. Reports expose `seccomp_filter: false` so this tradeoff is machine-visible. Namespace, descriptor-pinned read-only mounts, dropped capabilities, rlimits and offline execution remain mandatory. These controls reduce denial-of-service risk but are **not equivalent to a hardware VM**: Bubblewrap shares the host kernel, so active analysis of genuinely hostile code should still run in a disposable/dedicated lab host with its own cgroup limits and no sensitive workloads.

The Transformers/PEFT backend is local-only. It sets Hugging Face/Transformers offline mode and passes `local_files_only=True`. `trust_remote_code=True` is never enabled implicitly; it requires `--execute-custom-code`. If a custom loader crashes or times out, Layerfault preserves side-effect telemetry collected before failure and reports `LF-BEHAV-RUNTIME-FAILURE` rather than discarding the observation.

Differential output analysis is intentionally evidence-based. Deterministic base/derived responses are compared with bounded lexical similarity and repetition metrics. Broad response changes across a fine-tune are not automatically malicious. Isolated divergence relative to the median probe behavior is reported as `LF-DIFF-LOCALIZED-DIVERGENCE`; a trigger-designated isolated divergence or derived output-collapse condition can escalate to `LF-DIFF-SUSPICIOUS-TRIGGER`. Operators should reproduce suspicious rows with adjacent probe mutations before attributing malicious intent.

Trace truncation is surfaced as `LF-BEHAV-TRACE-TRUNCATED` and prevents an over-budget syscall trace from being interpreted as complete side-effect coverage.

## Platform service persistence boundary

Remote PostgreSQL URLs are upgraded to `sslmode=require` and use Rustls certificate and hostname verification. Public WebPKI roots are available by default; private deployments can add PEM roots with `LAYERFAULT_DB_CA_FILE`. Plaintext remote PostgreSQL requires both `sslmode=disable` and the explicit `LAYERFAULT_ALLOW_INSECURE_DB=1` development-risk override. Loopback databases may explicitly disable TLS.

Model/revision and review/finding/advisory writes are database transactions. Schema migration version 2 adds cascading foreign keys for relational platform records on both SQLite and PostgreSQL. Existing orphaned data causes migration failure with a repair-required error rather than being silently discarded. Worker leases use renewable owner/token fencing, and stale workers cannot complete a reclaimed job.

Hub crawling performs network retrieval before acquiring the shared web database lock, then holds the lock only while enqueueing the fetched page. Public HTTP quotas are maintained per source address with bounded bucket storage; health checks remain independent from client quotas.
