# Architecture

Layerfault keeps discovery, parsing, trust and admission separate so adding a runtime does not implicitly grant that runtime trust.

```
source/runtime discovery
        |
        v
artifact reference -----> format detector -----> bounded parser/scanners
        |                                         |
        |                                         v
        +-----------------------------> scanner evidence
                                                  |
provenance/trust ---------------------------------+
                                                  |
local policy -------------------------------------+
                                                  v
                                      ALLOW / WARN / BLOCK
                                                  |
                                  guarded runtime/import only
```

## Capability boundaries

- `formats/`: artifact identification and hostile-input parsers. No runtime execution.
- `sources/`: discovery and narrowly-scoped runtime process adapters. Discovery never means trust.
- `scanner/`: evidence collection and stable finding classifications.
- `finding_evidence`: the structured evidence model attached to findings (see below).
- `rules`: the canonical registry of detector rule IDs and their declared evidence strategy.
- `correlate`: derives structural relationships between findings (e.g. `auto_map` resolving to a module that also fired a process-execution finding).
- `coverage`: what a scan actually examined, so incomplete scanning is never presented as a clean PASS.
- `evidence_bundle`: writes a self-contained, reviewable evidence bundle (manifest, findings, excerpts) to a directory.
- `trust` / `provenance` / `sigstore`: signer identity and attestation verification.
- `policy`: admission decision over scanner evidence plus context.
- `admission`: standalone-artifact composition of scan + provenance + policy.
- `audit` / `inventory` / `gc`: model-store state and conservative hygiene.
- `baseline`: known-good drift and signed change control.
- `quarantine`: non-destructive isolation and evidence export.
- `certify`: deterministic local hostile-input checks.

The CLI composes these modules; format scanners do not invoke runtimes and source adapters do not bypass policy.

## Feature-freeze admission layer

The final admission layer is intentionally orthogonal to source adapters:

`source discovery -> artifact/package scan -> package identity -> provenance/trust -> policy -> runtime advisory -> execution binding -> signed evidence`.

`package.rs` owns canonical package identity and static surrounding-file inspection. `advisory.rs` owns the offline runtime vulnerability catalog and exact executable version evaluation. `binding.rs` owns staged/revalidated execution guarantees. `evidence.rs` owns signed decision records. Source adapters must not duplicate these controls or weaken their failure semantics.

External advisory bytes are signature-verified before parsing/evaluation and the verified in-memory bytes are the bytes evaluated. Runtime adapters consume the canonical executable path that was version-checked. Direct-file runtimes consume the private staged artifact path rather than reopening the original user path.


## Active behavioural execution boundary

Dynamic analysis is deliberately downstream of static admission and is not a shortcut around it:

`static admission -> explicit active-execution policy -> strong sandbox -> local runtime -> syscall/filesystem/output telemetry -> behavioural evaluation -> optional base/derived differential`.

Cross-format lineage comparisons normalize effective tokenizer tables and chat
template text before deciding whether a quantization claim is contradicted.
Container/file hashes remain useful evidence but are not treated as semantic
equivalence across HF/Safetensors and GGUF representations. Missing comparable
metadata produces uncertainty/WARN rather than a false contradiction.

External model execution uses a Bubblewrap-backed sandbox with a private home/workspace, no host network, private process/IPC/UTS namespaces, dropped capabilities, read-only model mounts, synthetic canary credentials, and bounded resource limits. When Layerfault is explicitly asked to execute a statically blocked package or Hugging Face custom loader code, syscall tracing and resource limiting are mandatory in addition to Bubblewrap; missing controls fail closed.

GGUF execution uses an audited local llama.cpp CLI. Hugging Face/Safetensors/PEFT execution uses a local Python + Transformers runtime with offline/local-only loading. Custom Python model loaders require an explicit `--execute-custom-code` opt-in and remain confined to the strong external sandbox. Embedded inference remains available for supported trusted paths but is not eligible for blocked/custom-code overrides.
When the configured Python executable belongs to a virtualenv, only the virtualenv's read-only `site-packages` trees are mounted under `/runtime-support`; the virtualenv executable/tool directory itself is not exposed.

Behaviour evidence combines model responses with attempted network operations, child-process execution, sensitive/canary file access, protected filesystem write attempts and unexpected writable-workspace mutations. Runtime crashes do not discard telemetry: loader-time side effects are retained as security evidence. Differential analysis compares actual bounded responses as well as rule/risk labels so localized trigger behaviour cannot disappear merely because both responses individually score `NONE`.

Bubblewrap is a shared-kernel isolation boundary, not a virtual machine. Active execution of intentionally hostile model code should therefore be performed on a disposable/dedicated lab host; Layerfault never exposes real credentials to the sandbox.

## Evidence model

Every `LayerScanResult` carries the nine original stable fields (`layer_digest`, `media_type`, `check_type`, `status`, `finding_class`, `confidence`, `detail`, `matches`, `duration_ms`) plus additive evidence-attribution fields: `rule_id`, `subject`, `evidence`, `evidence_state`, `evidence_reason`, `finding_id`. A finding is not just a conclusion — it identifies the exact subject (package-relative path, sha256, tensor/opcode/byte position where known), the exact bounded and redacted evidence that caused the detector to fire, and an explicit completeness state (`Available` / `Partial` / `Unavailable` / `NotApplicable`) so absence of evidence is never ambiguous.

Detectors build findings through `finding_evidence::FindingBuilder`, which enforces bounds (`MAX_EVIDENCE_PER_FINDING`, per-finding and per-report byte budgets), deterministic evidence ordering, secret redaction (`redact_secrets`), and terminal-escape-safe sanitisation (`sanitize_excerpt`) before a finding can be emitted. `src/rules.rs` declares every rule's evidence requirement (`Required` / `StructuredOnly` / `NotApplicable`); `tests/evidence_gate.rs` fails the build if a detector emits a rule ID that isn't registered there, or if a registered rule has no `explain::lookup` entry (title, meaning, `why_it_matters`, and `limitations` — the last of which exists specifically so a detected capability is never overstated into proven malicious behaviour).

`--evidence` renders the evidence-first human report (`report::emit_evidence_report`) instead of the summary table. `--evidence-bundle <DIR>` writes a self-contained, hash-verifiable directory (manifest, enriched findings, sanitised excerpts, `SHA256SUMS`) for independent review; it is distinct from `--evidence-out`, which writes a signed Ed25519 admission envelope via `evidence.rs`. SARIF output emits a real `physicalLocation` only for evidence with a genuine source file and line (custom Python, config, templates); other evidence kinds (byte ranges, tensor names, opcode positions) stay in SARIF `properties` rather than a fabricated location.
