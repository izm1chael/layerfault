# Layerfault policy schema

Policies are local JSON admission documents. The schema version remains `1` while compatible fields are added during development; automation should validate `version` and ignore no unknown fields because the Rust parser intentionally rejects malformed/unsupported documents.

```json
{
  "version": 1,
  "profile": "strict",
  "require_trusted_attestation": true,
  "minimum_trusted_signatures": 2,
  "required_signer_fingerprints": ["sha256:..."],
  "allowed_model_patterns": ["registry.internal.example/approved/*"],
  "allowed_sources": ["ollama", "lmstudio"],
  "allowed_formats": ["gguf", "safetensors"],
  "allowed_architectures": ["llama"],
  "allowed_quantizations": ["Q4_K_M"],
  "max_model_bytes": 17179869184,
  "block_finding_classes": ["Integrity", "Structural"],
  "block_confidence_at_or_above": "High",
  "denied_rule_ids": ["T3-004"],
  "suppressions": [
    {
      "rule_id": "T6-002",
      "model": "registry.internal.example/approved/training-fixture:*",
      "reason": "Approved red-team training fixture contains an intentional indicator",
      "owner": "model-security",
      "reference": "CHG-1042",
      "expires_unix": 1800000000
    }
  ]
}
```

## Built-in profiles

| Profile | Trusted attestation required | Unknown layers block | Warnings block |
|---|---:|---:|---:|
| permissive | no | no | no |
| workstation | no | no | no |
| ci | no | yes | no |
| strict | yes | yes | yes |

Explicit fields override profile defaults.

## Context controls

The policy evaluator receives admission context separately from scanner evidence. Depending on source, available context includes source/runtime, artifact format, architecture, quantization, artifact/model size, trusted-signature count and signer fingerprints. A source adapter cannot manufacture missing cryptographic trust merely by identifying a runtime.

## Signature threshold and pinning

`minimum_trusted_signatures` is bounded to 32. `required_signer_fingerprints` contains full `sha256:<64 hex>` key fingerprints. Both requirements are independently enforced when configured. Signer fingerprints presented to the policy engine are trusted, active, namespace-authorized signers only; untrusted attestations remain visible as provenance findings but cannot satisfy signer-pinning requirements.

## Suppression safety

Suppressions require a stable rule ID and a meaningful reason. `model` defaults to `*`; optional `owner`, `reference` and `expires_unix` support temporary, reviewable exceptions. Expired suppressions stop applying automatically.

Suppressions cannot hide integrity, structural, operational or attestation failures. Blocking evidence remains present in reports even where a suppressible policy/content finding is locally accepted.

## Policy tooling

```bash
layerfault policy init --profile workstation --output policy.json
layerfault policy lint policy.json
layerfault policy explain policy.json
layerfault policy test policy.json ./model.safetensors --source file
layerfault policy diff policy-old.json policy-new.json
```

The normative machine-readable schema is `schemas/policy.json`.
