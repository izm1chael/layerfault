# Model Forensics

Layerfault's model-forensics path inspects bounded regions of supported model artifacts for unexpected payload signatures, slack/gap content, anomalous tensor statistics, suspicious embedding candidates, localized model deltas, non-finite values, and other security-relevant indicators.

`models carve` is intentionally non-extractive. It reports object type, offset, region ownership, bounded-window digest, confidence, and whether the observation is evidence-only. It does not write carved payloads to disk.

```text
layerfault models carve ./model.safetensors --profile standard
layerfault models carve ./model.gguf --profile research --json
```

Static backdoor signals are probabilistic indicators, not declarations of malicious intent. Multi-signal correlation requires independent evidence categories. Trigger hunting is separately bounded active analysis and remains behind existing admission/sandbox controls.
