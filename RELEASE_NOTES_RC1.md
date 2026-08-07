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
