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

External model execution uses a Bubblewrap-backed sandbox with a private home/workspace, no host network, private process/IPC/UTS namespaces, dropped capabilities, read-only model mounts, synthetic canary credentials, and bounded resource limits. When Layerfault is explicitly asked to execute a statically blocked package or Hugging Face custom loader code, syscall tracing and resource limiting are mandatory in addition to Bubblewrap; missing controls fail closed.

GGUF execution uses an audited local llama.cpp CLI. Hugging Face/Safetensors/PEFT execution uses a local Python + Transformers runtime with offline/local-only loading. Custom Python model loaders require an explicit `--execute-custom-code` opt-in and remain confined to the strong external sandbox. Embedded inference remains available for supported trusted paths but is not eligible for blocked/custom-code overrides.
When the configured Python executable belongs to a virtualenv, only the virtualenv's read-only `site-packages` trees are mounted under `/runtime-support`; the virtualenv executable/tool directory itself is not exposed.

Behaviour evidence combines model responses with attempted network operations, child-process execution, sensitive/canary file access, protected filesystem write attempts and unexpected writable-workspace mutations. Runtime crashes do not discard telemetry: loader-time side effects are retained as security evidence. Differential analysis compares actual bounded responses as well as rule/risk labels so localized trigger behaviour cannot disappear merely because both responses individually score `NONE`.

Bubblewrap is a shared-kernel isolation boundary, not a virtual machine. Active execution of intentionally hostile model code should therefore be performed on a disposable/dedicated lab host; Layerfault never exposes real credentials to the sandbox.
