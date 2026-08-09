# Layerfault 1.0.0-rc.1

Layerfault `1.0.0-rc.1` is the first feature-frozen release candidate for the initial stable release.

Layerfault is an offline-first security and admission-control CLI for local AI models. It validates model structure and package contents, establishes integrity and package identity, evaluates provenance and local trust, applies operator policy, checks relevant runtime security advisories, and can block execution when those guarantees fail.

## Highlights

- GGUF and Safetensors structural validation, including sharded Safetensors.
- Direct model/package inspection before runtime import.
- Deep Ollama store integrity and audit support.
- LM Studio, llama.cpp and offline Hugging Face cache adapters.
- Whole-package custom-code and unsafe-serialization detection.
- Canonical model-package fingerprints.
- Offline Ed25519 provenance, trust stores, revocation and signature thresholds.
- Policy-driven PASS/WARN/BLOCK admission decisions.
- Runtime vulnerability/advisory gating.
- Guarded execution and explicit verify-to-execute binding guarantees.
- Signed admission evidence.
- Model inventory and CycloneDX AI/ML-BOM output.
- Signed baselines and drift detection.
- Non-destructive quarantine and evidence export.
- JSON, SARIF, stable detector IDs and versioned schemas.
- Fuzzing, synthetic adversarial security gates and self-certification commands.

## Release-candidate status

This release is intentionally marked as a pre-release. Feature development is frozen while the project undergoes adversarial testing, real-model compatibility testing, false-positive calibration, resource/performance testing and release hardening.

Layerfault does not claim that static artifact inspection can prove opaque neural weights are free of learned backdoors or malicious learned behaviour. See `THREATS.md` for the complete security boundary.

## RC hardening overlay

The live-test hardening pass adds the following before final RC promotion:

- streamed heuristic scanning with no 10 MiB all-or-nothing bypass, invalid-UTF-8 normalization, invisible/bidi de-obfuscation, RegexSet prefiltering, and bounded evidence retention;
- Hugging Face `auto_map` module-scope correlation without requiring a package-local `trust_remote_code=true` flag, plus safe handling of oversized JSON metadata;
- content-based package executable detection and structural Mach-O / WebAssembly coverage in addition to ELF / PE;
- true single-flight descriptor scans across parallel model workers;
- fused integrity hashing and executable discovery for Ollama model/tensor descriptors and cold standalone GGUF/Safetensors admission;
- separate priority collection for GGUF prompt/template/system metadata with explicit truncation evidence;
- ONNX external tensor sidecar containment, range checks, hashing, and compound identity;
- fingerprint-only package identity paths that do not invoke the complete security scanner;
- detector-contract-scoped persistent evidence cache revisions;
- bounded platform HTTP worker/queue handling; and
- fuzz targets for Safetensors, ONNX, TensorFlow SavedModel, TFLite, Keras, binary-object parsing, and package correlation in addition to the existing manifest/GGUF/heuristic targets.

`number_prefix` remains present transitively in the embedded-inference dependency graph through legacy `indicatif` consumers; documentation now records that accurately instead of claiming the crate disappeared from `Cargo.lock`.

## Complete RC hardening follow-up (post-corpus validation)

The post-optimization master corpus run exposed a small set of correctness and residual performance gaps. This tree includes the complete follow-up rather than only the release-blocking subset:

- `review` performs static admission first and represents supplementary domains as `AVAILABLE`, `NOT_RUN`, `UNAVAILABLE`, or `FAILED`; a supplementary parser/runtime failure cannot downgrade an already-established `BLOCK`, and signed review evidence can still be emitted for malformed blocked artifacts.
- security decisions use the shared monotonic `SecurityDecision` type for review/comparison paths, and `compare` now returns process exit `0/1/3` consistently with its JSON `PASS/WARN/BLOCK` result.
- package text/config security inspection streams the complete member with bounded overlap/evidence instead of stopping at 4 MiB. Large tokenizer/config JSON is not warned merely for its size; Hugging Face `auto_map` / `trust_remote_code` metadata is extracted with a streaming JSON visitor.
- ONNX external tensor admission checks Unix hardlink count and raises `LF-ONNX-EXTERNAL-HARDLINK` when a sidecar has aliases that weaken the directory mutability boundary. Link count remains evidence rather than part of the portable compound content identity.
- digest and scanner-evidence caches have independent size thresholds. Digest caching remains conservative at 16 MiB while expensive scanner evidence defaults to 4 MiB; JSON artifact reports expose cache hit/miss/bypass diagnostics.
- package and sharded Safetensors can participate in profile-aware numerical weight statistics/differential analysis instead of reporting numeric analysis unavailable solely because the CLI target is a directory. `quick`/`standard` use identity-seeded per-tensor stratified sampling with security-relevant weighting and targeted escalation; `deep` performs exhaustive numeric traversal. Structural admission remains full-coverage in every profile, and reports state numeric coverage explicitly.
- LoRA static review now reports scaling, mean sparsity, norm outliers, spectral concentration, target-module concentration and `modules_to_save` evidence, while retaining the explicit boundary that anomalous adapter weights do not prove malicious intent.
- dataset fingerprint/review has a bounded parallel inventory, deterministic per-file quotas, streaming record visitors for line-oriented formats, linearized rare-trigger label correlation, exact coverage accounting, and deterministic stratified sampling across the whole record range when the 250k analysis ceiling is reached. `--jobs` is accepted on dataset inspect/fingerprint/compare/poisoning-review.
- corpus release tooling now includes machine-readable expected verdicts, a semantic/exit-code consistency checker, broad cache/performance ratio guards, and a behaviour-corpus gate/template for clean/backdoored adapter and model comparisons.

### Active sandbox / dynamic model analysis follow-up

- Added a strong external behavioural sandbox shared by llama.cpp and a new local Transformers/PEFT backend: isolated network/PID/IPC/UTS/filesystem view, dropped capabilities, synthetic HOME/workspace credentials, bounded syscall telemetry, and resource limits.
- Statically blocked models can be exercised only with explicit `--allow-static-blocked`; custom Hugging Face loaders require the separate `--execute-custom-code` opt-in. Those high-risk modes fail closed unless `bwrap`, `strace`, and `prlimit` are all present.
- Added local-only Transformers and PEFT/LoRA execution with persistent model loading across a bounded probe session and tokenizer chat-template rendering when available. Network downloads remain disabled.
- Behavioural telemetry now records network attempts, unexpected child-process execution, synthetic credential/sensitive-path access, and unexpected writable-workspace mutations. Loader/runtime failures preserve telemetry and produce `LF-BEHAV-RUNTIME-FAILURE`.
- Differential behaviour now compares actual deterministic response evidence as well as risk labels. Localized response outliers are advisory (`LF-DIFF-LOCALIZED-DIVERGENCE`); trigger-localized divergence/output collapse can escalate with `LF-DIFF-SUSPICIOUS-TRIGGER`.
- Safetensors quick/standard numeric sampling retains the same logical model-identity-seeded coordinates but batches them in physical file-offset order and coalesces nearby reads, removing the GPTQ/AWQ random-seek penalty without reducing tensor/sample coverage.
- Added the active corpus gate, an active corpus manifest template, and a lab fixture helper that can recreate real ONNX hardlinks after archive/Hub transport.
## Active sandbox and dynamic-analysis follow-up

The latest live-test overlay extends the static admission layer with bounded active execution and preserves the large-model performance work:

- GGUF can be exercised with a local llama.cpp runtime and Hugging Face/Safetensors/PEFT packages with a local Transformers Python runtime; model/runtime downloads remain disabled.
- Every external active run requires Bubblewrap namespace/network/filesystem isolation plus `prlimit` CPU/address-space/process/file limits. Executing statically blocked content or Hugging Face custom loaders additionally requires `strace` telemetry and explicit operator opt-in.
- Dynamic evidence records attempted network activity, child execution, synthetic-canary/sensitive-path access, protected read-only filesystem write attempts, writable-workspace mutation, runtime failures, and bounded-trace truncation.
- Base/derived behavioural comparison now evaluates the actual bounded responses as well as rule/risk labels, with localized trigger divergence and output-collapse evidence; review reuses the already-produced derived report instead of loading the target twice.
- The Transformers backend uses tokenizer chat templates when available and supports dedicated virtualenvs by mounting only read-only `site-packages`, not the virtualenv tool directory.
- Quick/standard Safetensors numerical sample coordinates are physically sorted/coalesced into bounded reads without changing the logical sample set, preserving every-tensor representation/adaptive escalation while reducing random-seek cost on GPTQ/AWQ-style layouts.
- Lab helpers provide an active sandbox corpus contract and recreation of the ONNX hardlink fixture that archive/Hub transport cannot preserve.

## Distribution-foundation follow-up

The RC distribution pass productises installation and package validation without enabling automatic public releases:

- Added a one-line `install.sh` with native DEB/RPM/APK/Arch package selection and a portable musl Linux fallback, plus a checksum-verifying Windows PowerShell installer.
- Added `--core`, `--active`, and `--full` installation modes. Active mode installs the Linux sandbox prerequisites and a managed, pinned CPU Transformers/PEFT runtime where the host libc/Python are supported; full mode also attempts a distribution-managed llama.cpp runtime.
- Added `layerfault capabilities` and strengthened `layerfault doctor` with a real Bubblewrap namespace/network/read-only-filesystem self-test, managed-runtime import validation, CPU/GPU discovery and low-memory notes.
- Active execution now derives a conservative physical-memory admission budget from the host and estimates the target/base runtime footprint before launch. A model that will not fit is reported `UNAVAILABLE` rather than being launched into an OOM/swap event; `RLIMIT_AS` remains a separate virtual-address-space runaway guard.
- Added common nFPM packaging metadata plus Linux GNU/musl release builders for DEB, RPM, APK, Arch and portable tarballs, a macOS universal tar/unsigned-PKG validation path, Windows ZIP/unsigned-MSIX validation packaging, Homebrew formula generation, SBOM/checksum generation and package smoke tests.
- Reworked the GitHub Actions release workflow into an explicit `workflow_dispatch` distribution dry run. Public GitHub Release creation is disabled unless both the manual `publish=true` input and repository variable `LAYERFAULT_RELEASE_PUBLISH_ENABLED=true` are present.
- Linux release artifacts are built against appropriate libc families rather than repackaging one Ubuntu binary for incompatible distributions. Package smoke tests exercise Ubuntu, Debian, AlmaLinux, Alpine and Arch where supported.
- The README, SECURITY guide, man page, completions and new `docs/INSTALL.md` / `docs/DISTRIBUTION.md` now document static-vs-active detection, package installation, active runtime setup, low-memory behaviour and the intentionally gated release process.

The small `vendor/candelabra` fork remains intentional in this RC because it preserves Layerfault's Rustls-only dependency posture. It should be removed once upstream provides an equivalent feature/dependency configuration rather than by reintroducing native OpenSSL merely to shrink the repository.
