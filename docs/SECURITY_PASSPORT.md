# Model Security Passport

A Layerfault model security passport is a portable snapshot of the security evidence known for a model at a point in time. It binds scanner/ruleset identity, layered model identity, coverage, findings, optional source and lineage information, optional runtime assessments, framework mappings, and explicit limitations.

The native passport is deterministic apart from generation time and supports a security-content digest. Export views are available for CycloneDX and SPDX AI-oriented interchange.

```text
layerfault models passport ./model --format native --output passport.json
layerfault models passport ./model --runtime ollama --runtime llama-cpp --format cyclonedx
layerfault models passport ./model --format spdx
```

A passport is evidence, not an admission bypass. Execution policy may separately require a signed admission receipt bound to the current artifact and runtime identities.
