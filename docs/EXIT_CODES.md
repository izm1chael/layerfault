# Layerfault Exit Codes

| Code | Meaning |
|---:|---|
| 0 | Scanner and policy allow execution |
| 1 | Warning/policy warning only; no blocking finding |
| 2 | Artifact integrity failure |
| 3 | Other blocking scanner/provenance/structural/operational failure |
| 4 | Policy-only block (for example strict policy requiring trusted attestation) |
| 5 | Baseline drift detected |

`layerfault pipeline` uses the same codes: `0` is PASS, `1` is WARN, `2` is an integrity failure, `3` is a blocking scanner/structural/content result, and `4` is a policy-only block. It does not invoke a model runtime.

CLI argument/configuration/runtime setup errors are ordinary command errors and are not disguised as scanner verdicts.

`layerfault run` never starts Ollama on exit conditions 2, 3 or 4.
