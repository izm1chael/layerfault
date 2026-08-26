# Finding severity

Every finding carries a `severity` field, separate from `status` (the PASS/WARN/FAIL
outcome), `confidence` (how sure the detector is), `finding_class` (what kind of fact
this is), and the final policy/admission decision. Severity is never derived from any
of those: it is an explicit, evidence-based judgement of how dangerous the *specific
indicator a rule reports* is, assigned per rule in the catalogue
(`src/rules/catalogue/families/*.rs`).

## Taxonomy

| Value | Meaning |
|---|---|
| `CRITICAL` | The specific indicator is a concrete, high-confidence execution or compromise primitive (for example, a proven code-execution path). |
| `HIGH` | The specific indicator is a strong danger signal that falls short of a proven primitive, or a primitive with a plausible mitigating factor. |
| `MEDIUM` | The specific indicator is a real risk signal that requires additional context to assess impact. |
| `LOW` | The specific indicator is a minor or narrowly-scoped concern. |
| `INFO` | The specific indicator is informational: content, compatibility, coverage or provenance observations that do not themselves indicate danger. |
| `UNSPECIFIED` | Severity is genuinely not established for this rule. This is a legitimate, preserved value, not a placeholder to be eliminated — it must never be silently coerced or inferred from status. |

## Rules

- Severity is assigned once per rule ID in the catalogue (`RuleMetadata.severity`),
  documented alongside that rule's `title`/`meaning`/`why_it_matters`. Detectors that
  go through `finding_evidence::FindingBuilder` inherit the catalogue severity for
  their `rule_id` automatically; `.severity(...)` overrides that default only where a
  specific call site's indicator genuinely diverges from the rule's usual case, and
  the override must be justified in a code comment.
- A coverage or completeness gap (unsupported construct, exhausted budget, missing
  implementation) is a statement about Layerfault, not about the artifact, and must
  not be assigned a severity implying danger — it stays `INFO` or `UNSPECIFIED`.
- Assigning or changing a rule's severity is a documentation and catalogue change; it
  must never change that rule's `status`, `finding_class`, `confidence`, or admission
  behavior.
- Downstream (Observatory, the public database) never invents a severity. A finding
  with no engine-assigned severity is `UNSPECIFIED` end to end.
