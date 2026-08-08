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

## Composite-decision invariants

Commands that emit a semantic `PASS`, `WARN`, or `BLOCK` must map that final semantic decision to process exit `0`, `1`, or `3` respectively. `compare` follows the same contract as `review`; a JSON `"final_decision":"BLOCK"` must never return process exit `0`.

Review decisions are monotonic. Once static admission establishes `BLOCK`, later metadata/numeric/runtime failures are represented as `FAILED` or `UNAVAILABLE` domains and the process still returns `3`. A later domain may raise severity but cannot lower it. Dedicated integrity/policy/runtime exit codes used by commands with those distinct contracts remain documented separately and are not collapsed into the generic semantic mapping.

### Behavioural security commands

`behaviour` and `compare-behaviour` also use the canonical semantic mapping. A behaviour run with no suspicious observation exits `0`; a suspicious or explicitly not-run result exits `1`; and a high-risk result exits `3`. Differential behaviour exits `0` for expected/neutral variation, `1` for not-run/capability-change outcomes, and `3` for security regression, suspicious-trigger, or high-risk-behaviour outcomes. This keeps shell automation aligned with the JSON state instead of returning success for a blocking behavioural result.
