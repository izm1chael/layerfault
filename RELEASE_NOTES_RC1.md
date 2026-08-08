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
