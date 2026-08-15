# Layerfault

**Offline-first static admission and sandboxed behavioural security for local AI models.**

Layerfault validates model artifacts, packages and local runtimes **before inference**, then can optionally exercise supported models inside a locked-down Linux sandbox to look for runtime side effects and suspicious behavioural divergence. It combines structural validation, package inspection, integrity checking, provenance, trust, policy, runtime advisory checks, execution binding, behavioural probes, inventory, drift detection, quarantine, and signed evidence in one local CLI.

> **Status:** `1.0.0-rc.1` — active hardening and distribution work is still underway. GitHub release publication remains deliberately gated while the RC is tested.

Static inspection is the primary admission boundary and is enough to BLOCK many dangerous model packages: malformed formats, unsafe serialization, custom loader code, executable payloads, traversal/sidecar abuse, suspicious templates, integrity/provenance failures and policy violations. Static inspection does **not** prove opaque learned weights are behaviourally benign. Active analysis adds evidence by actually exercising supported models in an isolated environment and observing response divergence, attempted process/network/file activity and trigger-like behaviour.

## Why Layerfault?

Local AI models increasingly arrive as large, opaque artifacts that are downloaded, converted, copied between runtimes, and executed with little admission control.

Layerfault puts a security gate between **model acquisition** and **model execution**:

```text
Model artifact / local store
          │
          ▼
   Package discovery
          │
          ▼
 GGUF / Safetensors validation
          │
          ▼
 Package code & serialization checks
          │
          ▼
 Integrity & package identity
          │
          ▼
 Provenance & local trust
          │
          ▼
 Policy & runtime advisories
          │
          ▼
   PASS / WARN / BLOCK
          │
          ├──────────────► normal inference / CI decision
          │
          └── optional active analysis (Linux)
                     │
                     ▼
             Bubblewrap + resource limits
                     │
                     ▼
          GGUF / Transformers / PEFT probes
                     │
                     ▼
       response + process/file/network telemetry
```

Everything is designed to work **offline-first**. Layerfault does not upload your models or require a hosted service.

### Static vs active detection

Static and active analysis answer different questions and are deliberately kept separate:

| Question | Static admission | Active sandbox |
| --- | --- | --- |
| Is the artifact malformed, truncated, overlapping or parser-hostile? | **Strong** | Not required |
| Does the package contain Pickle/custom code/scripts/native executables? | **Strong** | Can observe what code attempts to do |
| Are `auto_map`, templates, sidecars, traversal, integrity or provenance suspicious? | **Strong** | Adds runtime evidence |
| Does loading try to spawn a process, touch synthetic secrets, write protected paths or reach the network? | Can often identify capability/intent | **Direct evidence** |
| Does a learned trigger cause a response/backdoor that is encoded only in weights? | Limited | **Primary detection path** |
| Can either mode prove a model has no hidden backdoor? | No | No |

A static `BLOCK` is already enough to say **do not trust or execute this package**. Active analysis is most valuable when static evidence is inconclusive, when learned-weight behaviour is the concern, or when you deliberately want to observe what suspicious loader/runtime code attempts inside the sandbox.

## Supported artifacts and sources

| Capability | Support |
| --- | --- |
| GGUF | Structural validation, metadata inspection, executable-content checks |
| Safetensors | Bounded structural validation, tensor range/overlap/hole checks |
| Sharded Safetensors | Index and shard consistency validation |
| Standalone model files/directories | Direct pre-runtime inspection and policy admission |
| Ollama | Deep store integrity, provenance, trust, policy, audit and guarded execution |
| LM Studio | Local discovery, guarded load/import workflows |
| llama.cpp | Direct guarded run/serve workflows |
| Hugging Face cache | Offline refs/snapshots/blobs audit and package inspection |
| CycloneDX | Local AI/ML-BOM inventory output |
| Sigstore/Cosign | Optional interoperability when Cosign is already installed |

## Security properties

Layerfault separates independent security questions rather than collapsing everything into a single "safe" score.

### Artifact structure

GGUF and Safetensors parsing is bounded and hostile-input aware. Layerfault checks sizes, offsets, tensor ranges, alignment, overlap, truncation, malformed metadata, sharded references, and other structural invariants without loading model tensors into inference frameworks.

### Whole-package inspection

Model packages can contain more than weights. Layerfault also identifies security-relevant surrounding content such as:

- custom Python, scripts, native libraries and executable content;
- Hugging Face `auto_map` custom-loader mappings and explicit `trust_remote_code` settings;
- dangerous execution/network primitives;
- suspicious template/Jinja constructs;
- Pickle, PyTorch checkpoint, Joblib and other code-capable serialization formats;
- unsafe symlinks and unexpected package members.

Layerfault never imports model Python code or deserializes Pickle in order to inspect it.

### Canonical package identity

```bash
layerfault fingerprint ./downloaded-model
```

Layerfault derives a location-independent package fingerprint:

```text
lfpkg:sha256:<digest>
```

The fingerprint binds package-relative paths, roles, sizes and hashes. Moving an unchanged package preserves its identity; changing, renaming or converting package members intentionally produces a different identity.

### Integrity and provenance

Ollama content-addressed descriptors are verified against their declared digest and size. Native Ed25519 attestations can bind trusted signing keys to authorised model namespaces, including activation/expiry windows, revocation, signer rotation groups and multi-signature admission thresholds.

```bash
layerfault trust add \
  --name internal-publisher \
  --public-key publisher-public.pem \
  --namespace 'registry.internal.example/approved/*'

layerfault attest sign registry.internal.example/approved/model:v1 \
  --private-key publisher-private.pem

layerfault verify registry.internal.example/approved/model:v1 --policy strict
```

### Policy admission

Built-in profiles:

```text
permissive
workstation
ci
strict
```

Custom JSON policies can constrain runtime/source, format, architecture, quantization, artifact size, trusted signature counts, approved signers, model identities, finding classes, confidence and stable detector IDs.

```bash
layerfault policy lint policies/example-enterprise.json
layerfault policy explain policies/example-enterprise.json
layerfault policy test policies/example-enterprise.json ./model.gguf --source file
```

Integrity failures, malformed structure, scanner errors, invalid/revoked signatures and namespace-authorisation failures cannot be suppressed into an allow decision.

### Runtime advisory gating

```bash
layerfault advisories list
layerfault advisories check ollama
layerfault advisories check llama-cpp
```

Layerfault includes a deliberately small offline advisory catalog for runtime vulnerabilities that are directly relevant to model admission/execution. High/critical matches can block guarded execution.

External advisory catalogs can influence admission only when their exact bytes verify against an explicitly supplied Ed25519 key.

### Verify-to-execute binding

Layerfault reports the strength of the link between the verified artifact and the artifact actually passed to the runtime.

For direct llama.cpp execution and guarded LM Studio imports, Layerfault creates a private read-only staged copy from the verified file descriptor and rehashes it before launch. For runtime-owned stores such as Ollama, Layerfault immediately revalidates the store before invoking the exact runtime executable whose version was checked.

Layerfault reports this honestly as an execution-binding property rather than claiming atomic guarantees a runtime cannot provide.

### Signed admission evidence

```bash
layerfault verify-file ./model.gguf \
  --policy workstation \
  --evidence-out evidence.json \
  --evidence-key operator-private.pem

layerfault evidence verify evidence.json
```

Evidence records bind the artifact/package identity, Layerfault build ID, detector contract, policy hash, trust-store hash, runtime advisory result, execution-binding guarantee, findings and final decision.

## Install Layerfault

Normal users should not need the repository or a Rust toolchain. The distribution pipeline prepares native packages and portable archives; during RC development those assets are built by a **manual dry-run workflow** and GitHub Release publication stays disabled unless explicitly enabled by the maintainer.

### One-line core install

Once a release is approved and published:

```bash
curl -fsSL https://github.com/izm1chael/layerfault/releases/latest/download/install.sh | sudo bash
```

The installer selects the native package where possible:

- Debian/Ubuntu: `.deb`
- Fedora/RHEL/Rocky/Alma: `.rpm`
- Alpine: `.apk`
- Arch Linux x86_64: `.pkg.tar.zst`
- other Linux / Linux ARM64 fallback: portable musl `.tar.gz`
- macOS: universal tarball; unsigned `.pkg` is built only as a signing/packaging validation artifact until GA
- Windows: `install.ps1`, ZIP and prepared MSIX packaging

For security-sensitive hosts, download `install.sh` and `SHA256SUMS` from the release, verify the checksum first, then execute the script locally. Release builds also carry SBOM/provenance artifacts.

### Active-analysis install

Linux users who want sandboxed execution can install the active runtime separately:

```bash
curl -fsSL https://github.com/izm1chael/layerfault/releases/latest/download/install.sh | sudo bash -s -- --active --device cpu

layerfault capabilities
layerfault doctor
```

For the broadest CPU-only Linux setup (including a distro-managed `llama-cli` where available):

```bash
curl -fsSL https://github.com/izm1chael/layerfault/releases/latest/download/install.sh | sudo bash -s -- --full --device cpu
```

The active bootstrap installs Bubblewrap, `strace`, `prlimit`, Python/venv support and (on supported glibc Linux hosts) an isolated, version-pinned CPU Transformers/PEFT runtime under `/opt/layerfault/runtimes/python`. Use `--full` to also try the distribution's packaged `llama.cpp`/`llama-cli` when available; Layerfault does not silently download a moving, unverified upstream runtime. Alpine/musl receives the core scanner and sandbox prerequisites but does not pretend standard PyTorch wheels are portable there. CUDA/ROCm remain optional acceleration paths, never requirements for static analysis.

Layerfault derives an active memory budget from the host rather than assuming a large machine. On an 8 GiB CPU-only host it will run small models/appropriate quantized GGUFs where practical and skip models whose estimated runtime footprint exceeds safe headroom. An unavailable active run is reported as unavailable; it is never converted into a security PASS.

See [`docs/INSTALL.md`](docs/INSTALL.md) for complete installation and low-memory guidance.

### Build from source

Source builds require the rustup-managed toolchain selected by `rust-toolchain.toml`:

```bash
git clone https://github.com/izm1chael/layerfault.git
cd layerfault
cargo build --release --locked
./target/release/layerfault selftest
```

The small `vendor/candelabra` patch is intentional: it keeps Candelabra's HTTP dependencies on the Rustls path instead of reintroducing native OpenSSL build requirements. It should be removed only when the upstream crate provides an equivalent dependency configuration.

### Quick start

For model acquisition and admission workflows, run the pre-execution pipeline before handing an artifact to a runtime:

```bash
layerfault pipeline ./downloaded-model
layerfault pipeline ./downloaded-model --policy ci --summary
layerfault pipeline ./downloaded-model --policy strict --json
```

The pipeline performs bounded package discovery, canonical identity, artifact structure checks, package-code and serialization checks, local policy evaluation, and a final `PASS`, `WARN`, or `BLOCK` decision. It never invokes an inference runtime or deserializes model content. Use `--sarif` for CI annotations and `--evidence-out ... --evidence-key ...` to reuse the existing signed evidence infrastructure.

Every WARN/FAIL finding carries structured evidence: the exact file/tensor/opcode/byte position that triggered it, a bounded and redacted excerpt, why it matters, and its limitations. Use `--evidence` for the evidence-first human report, or `--evidence-bundle <DIR>` to write a self-contained, hash-verifiable review bundle (manifest, findings, sanitised excerpts). `--json` includes the same evidence in machine-readable form under each finding's `evidence`/`evidence_state`/`explanation` keys.

Pipeline exit codes preserve the admission contract: `0` means PASS, `1` means WARN, `2` means integrity failure, `3` means scanner/structural/content blocking failure, and `4` means policy-only block.

Layerfault can assess artifact structure, package contents, integrity, provenance, trust, policy, and runtime compatibility/advisories. A PASS does not prove that learned weights are behaviorally benign, free from semantic backdoors, or trained on unpoisoned data.

For manual RC certification against a local, already-acquired corpus, use the offline runner. It never downloads or executes samples and retains each command's security exit code:

```bash
scripts/corpus/adversarial-gate.sh /lab/samples /lab/results
```

The output directory contains `summary.tsv`, `summary.json`, `SHA256SUMS`, per-command output, and the Layerfault version used for the run.

Before publishing or cutting a release, run the consolidated local gate:

```bash
bash scripts/security/pre-push.sh
```

The binary will be available at:

```text
target/release/layerfault
```

### Validate the checkout

For routine development, run the library tests and the integration target
covering the code being changed. Limiting build concurrency avoids running
multiple large Rust link jobs against the disk at once:

```bash
cargo test --locked --workspace --lib --jobs 4
cargo test --locked --test <integration-test-name> --jobs 4
```

Before publication, run the exhaustive gate. It retains all-target coverage
but defaults to four build jobs; set `LAYERFAULT_BUILD_JOBS` explicitly on a
host that can sustain more concurrent linking:

```bash
bash scripts/security/pre-push.sh
```

The equivalent individual exhaustive checks are:

```bash
cargo fmt --all -- --check
cargo check --locked --all-targets --jobs 4
cargo test --locked --all-targets --jobs 4
cargo clippy --locked --all-targets --all-features --jobs 4 -- -D warnings
bash scripts/security/gates.sh
python3 scripts/security/schema-gates.py --binary target/debug/layerfault
```

The main security gate uses synthetic local fixtures and does not download models.

## Common workflows

### Inspect a model before importing it

```bash
layerfault inspect ./model.gguf
layerfault inspect ./model.safetensors --json
layerfault verify-file ./model.gguf --policy workstation
layerfault scan-dir ~/models --json
```

### Ollama

```bash
layerfault scan
layerfault verify gemma3:latest --policy workstation
layerfault run gemma3:latest --policy strict
layerfault audit --deep
```

### llama.cpp

```bash
layerfault run ./model.gguf --source llama-cpp -- --threads 8
layerfault serve ./model.gguf --source llama-cpp -- --port 8080
```

### LM Studio

```bash
layerfault audit --source lmstudio --deep
layerfault import ./model.gguf --source lmstudio        # dry run
layerfault import ./model.gguf --source lmstudio --execute
```

### Hugging Face local cache

```bash
layerfault audit --source hf-cache --deep
```

No Hub connection is required for local-cache auditing.

### Whole-machine inventory

```bash
layerfault audit --source all --directory ~/models
layerfault audit --source all --directory ~/models --mlbom local-models.cdx.json
```

### Baselines and drift

```bash
layerfault baseline create --name workstation
layerfault baseline sign --name workstation --private-key operator.key
layerfault baseline verify --name workstation --require-signature
layerfault baseline diff --name workstation
```

### Quarantine and evidence

```bash
layerfault quarantine put suspect:latest --reason "Unexpected digest drift"
layerfault quarantine inspect <id>
layerfault quarantine export <id> --output ./evidence --include-blobs --sign-with operator.key
layerfault quarantine restore <id>
```

Quarantine is non-destructive by default and preserves blobs shared by non-quarantined models.

## Operator commands

```bash
layerfault doctor
layerfault sources
layerfault explain LF-SAFE-STRUCT
layerfault diff ./before.gguf ./after.gguf
layerfault selftest
layerfault certify
layerfault version --json
```

## Machine-readable output

Layerfault treats automation interfaces as contracts:

- JSON output;
- SARIF output;
- stable detector IDs;
- documented exit codes;
- versioned JSON schemas;
- signed evidence envelopes;
- CycloneDX AI/ML-BOM output.

Schemas live in [`schemas/`](schemas/).

## Security model and documentation

Layerfault's security claims and boundaries are documented explicitly:

- [`THREATS.md`](THREATS.md) — threat model, protected boundaries and non-goals;
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — architecture and capability boundaries;
- [`docs/ARTIFACTS.md`](docs/ARTIFACTS.md) — GGUF/Safetensors handling;
- [`docs/SOURCES.md`](docs/SOURCES.md) — runtime/source adapter semantics;
- [`docs/TRUST_MODEL.md`](docs/TRUST_MODEL.md) — trust and provenance;
- [`docs/POLICY_SCHEMA.md`](docs/POLICY_SCHEMA.md) — policy contract;
- [`docs/EXIT_CODES.md`](docs/EXIT_CODES.md) — stable CLI exit semantics;
- [`docs/RELEASE_SECURITY.md`](docs/RELEASE_SECURITY.md) — release security and build provenance;
- [`docs/SECURITY_GATE.md`](docs/SECURITY_GATE.md) — adversarial validation gate.

## Threat-model boundary

Layerfault can establish properties about the **artifact, package, provenance, runtime and admission decision**.

It cannot prove that arbitrary learned neural weights do not contain:

- learned backdoors;
- intentionally harmful learned behaviour;
- hidden semantic triggers;
- model-level deception that is not represented in inspectable package content.

That distinction is intentional. See [`THREATS.md`](THREATS.md) for the complete boundary.

## Development status

Layerfault is currently **feature frozen for the initial stable release**.

`1.0.0-rc.1` is intended for adversarial certification, false-positive calibration, performance testing, runtime compatibility testing and release hardening. Major new functionality is deferred until after the stable release.

The release candidate is expected to pass:

```bash
layerfault selftest
layerfault certify
bash scripts/security/gates.sh
```

along with the Rust formatting, build, test, Clippy and schema gates above.

## Responsible security reporting

If you believe you have found a vulnerability in Layerfault itself, please avoid publishing exploit details before the maintainer has had a reasonable opportunity to investigate and remediate the issue. Repository security-reporting instructions should be followed where available.

---

**Layerfault's goal is simple:** know what local model artifact you are admitting, know whether it changed, know who attested to it, know whether your policy permits it, and block execution when those guarantees fail.

### RC corpus hardening and diagnostics

The complete RC hardening pass makes security decisions monotonic across composite review workflows. Static admission is evaluated before supplementary metadata, numeric, behavioural, judge, or drift domains; each supplementary domain is explicitly reported as `AVAILABLE`, `NOT_RUN`, `UNAVAILABLE`, or `FAILED`. A malformed model that has already blocked therefore remains `BLOCK` even if a later analysis cannot interpret its tensors.

Package content inspection no longer has a 4 MiB security-text cliff. Text/config members are streamed through bounded package-risk inspection, while Hugging Face loader metadata is extracted with a streaming JSON visitor so ordinary multi-megabyte `tokenizer.json` files do not become warnings merely because they are large. Evidence retention remains bounded.

Artifact JSON reports include cache diagnostics. Digest and scanner-evidence reuse use separate thresholds: `LAYERFAULT_HASH_CACHE_MIN_BYTES` controls digest caching (default 16 MiB) and `LAYERFAULT_EVIDENCE_CACHE_MIN_BYTES` controls scanner-evidence caching (default 4 MiB). Unix reuse is bound to device, inode, change time, timestamps, size, and a sampled content guard. Platforms without that immutable change identity, including Windows, revalidate the complete file digest before reusing a digest or prior scan evidence. `--no-cache` still disables persistent reuse for the invocation.

Dataset commands accept `--jobs N`. Poisoning review reports exact bounded coverage and, when more than 250,000 records are available, deterministically samples across the complete record range rather than analysing only the dataset head. Results are merged deterministically so parallelism does not alter the semantic report.

Package-directory and sharded Safetensors numerical review is profile-aware. `review --profile quick` and `standard` keep full structural/security admission but use deterministic model-identity-seeded samples distributed across the logical tensor set, with extra weight for LoRA/output/embedding/attention tensors and automatic full/extended escalation when sampled statistics are anomalous. `review --profile deep` performs exhaustive numerical traversal. Reports expose values/tensors available vs inspected and per-tensor coverage; sampled numerical analysis is never presented as exhaustive coverage.

Release/corpus helpers:

```bash
python3 scripts/corpus/check-contract.py /path/to/harness-run
python3 scripts/corpus/check-performance.py /path/to/harness-run
bash scripts/corpus/behaviour-gate.sh tests/behaviour-corpus-template.tsv
```

`tests/corpus-expectations.json` distinguishes detection regressions, false-positive regressions, and JSON/process-exit semantic mismatches. `tests/corpus-performance.json` uses broad warm/cold ratios rather than fixed VPS milliseconds.

Behavioural commands follow the same automation-safe decision contract: `behaviour` maps clean/suspicious/high-risk outcomes to `0`/`1`/`3`, while `compare-behaviour` returns `3` for security-regression, suspicious-trigger, or high-risk differential states. A behavioural JSON result that is security-blocking therefore cannot silently return process success.

### Active sandboxed behavioural analysis

Layerfault can now complement static admission with **active local execution**. Active analysis is deliberately offline and bounded: it does not turn a static PASS into proof that a model has no hidden triggers, but it can reproduce response regressions and observe loader/runtime side effects that static inspection cannot see.

Supported active backends are:

- `llama-cpp` for local GGUF artifacts;
- `transformers` / `transformers-python` for local Hugging Face model-package directories;
- PEFT/LoRA adapters through the Transformers backend when `--base` points at the local base package;
- `embedded` remains available for admitted GGUF execution, but high-risk blocked/custom-code execution is intentionally restricted to the external strong sandbox.

Examples:

```bash
# Admitted GGUF under llama.cpp in the strong sandbox.
layerfault behaviour ./model.gguf \
  --runtime llama-cpp --runtime-path /opt/llama/llama-cli \
  --profile standard --json

# Local Hugging Face/Safetensors package. No network download is permitted.
layerfault behaviour ./hf-model \
  --runtime transformers --runtime-path /usr/bin/python3 \
  --profile standard --json

# Base-versus-LoRA differential behavioural review.
layerfault compare-behaviour ./base-model ./adapter-model \
  --runtime transformers --runtime-path /usr/bin/python3 \
  --profile standard --json

# Deliberately investigate a statically blocked custom-code package. This mode
# fails closed unless bwrap + strace + prlimit are all available.
layerfault behaviour ./suspect-package \
  --runtime transformers --runtime-path /usr/bin/python3 \
  --allow-static-blocked --execute-custom-code \
  --profile quick --json
```

External active execution uses Bubblewrap namespaces, a private synthetic HOME/workspace, a read-only model/base mount, no host network, dropped capabilities, a private PID/IPC/UTS view, and no normal `/bin`/`/usr/bin` tool tree. When `strace` is available Layerfault records network attempts, unexpected process execution, synthetic credential access and sensitive-path attempts. Writable-workspace mutations are compared against a pre-execution baseline. `prlimit` is mandatory for external active execution and bounds CPU, file size, process/file-descriptor counts, core dumps, and address space. Layerfault now derives the active memory ceiling from host RAM/availability, reserves operating-system headroom, and performs a conservative model/base footprint preflight before launch. `LAYERFAULT_BEHAVIOUR_MEMORY_MB` remains an explicit administrator override.

Executing statically blocked content or `trust_remote_code=True` is a higher-risk research mode and therefore **requires** all three of `bwrap`, `strace`, and `prlimit`; Layerfault refuses to silently degrade that boundary. Synthetic secrets are used for canary detection; real host credentials are never intentionally mounted into the sandbox.

The Transformers runner keeps the model loaded for the bounded probe session, uses a local tokenizer chat template when available, forces offline loading, and never downloads model/runtime dependencies. Differential reports now include deterministic response similarity/repetition evidence. Broad expected fine-tune drift remains advisory, while isolated trigger-category divergence or derived output collapse can escalate to `SUSPICIOUS_TRIGGER`.
A dedicated Python virtualenv is supported via `--runtime-path /path/to/venv/bin/python`: Layerfault exposes only that environment's read-only `site-packages` directories inside the sandbox through `PYTHONPATH`; it does not mount the virtualenv `bin/` tool directory. This keeps Torch/Transformers/PEFT dependencies available without expanding the subprocess/tool surface.

Useful lab helpers:

```bash
bash scripts/lab/prepare-active-fixtures.sh
bash scripts/corpus/active-sandbox-gate.sh tests/active-sandbox-corpus-template.tsv
```

For real ONNX hardlink testing, recreate the inode alias after downloading the corpus:

```bash
bash scripts/lab/prepare-active-fixtures.sh \
  --onnx-model /lab/path/model_dir_hardlink_external.onnx \
  --onnx-sidecar /lab/path/data/weights.bin
```

Active corpus automation can set `LAYERFAULT_ACTIVE_PROBE_SUITE=/path/to/suite.json` to run a lab-specific deterministic trigger suite without modifying the manifest. Telemetry includes denied write/mutation attempts against protected read-only mounts as well as successful mutations inside the synthetic workspace.

## Model security capabilities

Layerfault supports signed data-only security intelligence, runtime posture assessment, model/runtime compatibility checks, layered identity and lineage verification, bounded model forensics, Hugging Face preflight, security passports, signed admission receipts, and inventory drift monitoring. See the focused documents in `docs/` for each capability.
