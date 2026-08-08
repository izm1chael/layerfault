# Layerfault Exit Codes

| Code | Meaning |
|---:|---|
| 0 | Scanner and policy allow execution |
| 1 | Warning/policy warning only; no blocking finding |
| 2 | Artifact integrity failure |
| 3 | Other blocking scanner/provenance/structural/operational failure |
| 4 | Policy-only block (for example strict policy requiring trusted attestation) |
| 5 | Baseline drift detected |

`layerfault pipeline` and `layerfault review` use the same security verdict codes: `0` is PASS, `1` is WARN, `2` is an integrity failure, `3` is a blocking scanner/structural/content result, and `4` is a policy-only block. A quick review that skips inference still preserves the static verdict. `layerfault dataset poisoning-review` returns `1` when bounded anomaly evidence or a material analysis coverage limit requires review; dataset evidence is not promoted to a blocking verdict solely because indicators are present.

CLI argument/configuration/runtime setup errors are ordinary command errors and are not disguised as scanner verdicts.

`layerfault run` never starts Ollama on exit conditions 2, 3 or 4.
