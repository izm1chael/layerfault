# Layerfault

**Offline-first security and admission control for local AI models.**

Layerfault validates model artifacts and local model runtimes **before inference**. It combines structural validation, package inspection, integrity checking, provenance, trust, policy, runtime advisory checks, execution binding, inventory, drift detection, quarantine, and signed evidence in one local CLI.

> **Status:** `1.0.0-rc.1` — feature frozen and under release-candidate certification.

Layerfault does **not** claim that static inspection can prove opaque neural weights are free from learned backdoors or malicious learned behaviour. Its job is to establish whether the model package you are about to use is structurally valid, intact where integrity data exists, sufficiently trusted, policy-compliant, and safe for the local runtime to admit.

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
          ▼
       Inference
```

Everything is designed to work **offline-first**. Layerfault does not upload your models or require a hosted service.

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

### Release binaries

For normal use, prefer the official binaries attached to the [GitHub Release](https://github.com/izm1chael/layerfault/releases). Each release provides:

- Linux x86_64: `layerfault-linux-x86_64`
- Linux x86_64 static/musl: `layerfault-linux-x86_64-musl`
- Linux aarch64: `layerfault-linux-aarch64`
- Windows x86_64: `layerfault-windows-x86_64.exe`
- macOS universal: `layerfault-macos-universal`

Release artifacts are accompanied by SHA-256 checksums, a CycloneDX SBOM, and GitHub build provenance attestations. After placing the binary on your `PATH`, verify the installation:

```bash
layerfault --version
layerfault selftest
```

### Build from source

Source builds require [rustup](https://rustup.rs/). On Ubuntu or Debian, use the official rustup installation method rather than installing `cargo` or `rustc` from `apt`; the distribution toolchain may be too old for the committed lockfile.

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# Start a new shell after rustup updates your PATH.
git clone https://github.com/izm1chael/layerfault.git
cd layerfault
rustc --version
cargo --version
cargo build --release --locked
./target/release/layerfault selftest
```

The repository's `rust-toolchain.toml` automatically selects the Layerfault-tested Rust toolchain when using rustup. Normal operation should use an unprivileged account; `sudo` is normally only needed for a system-wide installation such as copying the binary into `/usr/local/bin`.

If Cargo reports that `Cargo.lock` uses an unsupported lockfile version, your Rust/Cargo installation is too old. Upgrade/install the rustup-managed toolchain. Do not delete `Cargo.lock`.

### Quick start

For model acquisition and admission workflows, run the pre-execution pipeline before handing an artifact to a runtime:

```bash
layerfault pipeline ./downloaded-model
layerfault pipeline ./downloaded-model --policy ci --summary
layerfault pipeline ./downloaded-model --policy strict --json
```

The pipeline performs bounded package discovery, canonical identity, artifact structure checks, package-code and serialization checks, local policy evaluation, and a final `PASS`, `WARN`, or `BLOCK` decision. It never invokes an inference runtime or deserializes model content. Use `--sarif` for CI annotations and `--evidence-out ... --evidence-key ...` to reuse the existing signed evidence infrastructure.

Pipeline exit codes preserve the admission contract: `0` means PASS, `1` means WARN, `2` means integrity failure, `3` means scanner/structural/content blocking failure, and `4` means policy-only block.

Layerfault can assess artifact structure, package contents, integrity, provenance, trust, policy, and runtime compatibility/advisories. A PASS does not prove that learned weights are behaviorally benign, free from semantic backdoors, or trained on unpoisoned data.

For manual RC certification against a local, already-acquired corpus, use the offline runner. It never downloads or executes samples and retains each command's security exit code:

```bash
scripts/adversarial-corpus-gate.sh /lab/samples /lab/results
```

The output directory contains `summary.tsv`, `summary.json`, `SHA256SUMS`, per-command output, and the Layerfault version used for the run.

Before publishing or cutting a release, run the consolidated local gate:

```bash
bash scripts/pre-push-security-gates.sh
```

The binary will be available at:

```text
target/release/layerfault
```

### Validate the checkout

```bash
cargo fmt --all -- --check
cargo check --locked --all-targets
cargo test --locked --all-targets
cargo clippy --locked --all-targets --all-features -- -D warnings
bash scripts/security-gates.sh
python3 scripts/schema-gates.py --binary target/debug/layerfault
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
bash scripts/security-gates.sh
```

along with the Rust formatting, build, test, Clippy and schema gates above.

## Responsible security reporting

If you believe you have found a vulnerability in Layerfault itself, please avoid publishing exploit details before the maintainer has had a reasonable opportunity to investigate and remediate the issue. Repository security-reporting instructions should be followed where available.

---

**Layerfault's goal is simple:** know what local model artifact you are admitting, know whether it changed, know who attested to it, know whether your policy permits it, and block execution when those guarantees fail.
