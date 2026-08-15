# Hugging Face Remote Preflight

Remote preflight performs bounded static inspection of a Hugging Face repository before a complete model download. The requested revision is resolved to an immutable commit SHA. Security-relevant small files may be fetched in full within fixed budgets; large Safetensors artifacts are limited to bounded metadata/header access where possible.

Preflight validates available remote integrity expectations and records incomplete coverage whenever relevant content was not fetched. A clean preflight is not final admission: the report explicitly records that a complete local download is still required for final admission.

```text
layerfault hub preflight owner/model --revision <rev> --json
layerfault hub preflight owner/model --write-report preflight.json
```

No runtime is started and no automatic full model download is performed by preflight.
