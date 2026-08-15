# Layerfault policy schema

Policies are local JSON admission documents. The schema version remains `1` while compatible fields are added during development; automation should validate `version`. The Rust parser rejects malformed or unsupported documents.

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

Legacy profiles retain their existing semantics. Additional profiles provide explicit defaults for personal, research, enterprise, production, air-gapped, and high-assurance environments.

| Profile | Trusted attestation required | Unknown layers block | Warnings block |
|---|---:|---:|---:|
| permissive | no | no | no |
| workstation | no | no | no |
| ci | no | yes | no |
| strict | yes | yes | yes |

Explicit fields override profile defaults. An omitted optional field uses the selected profile's default.

## Context controls

The policy evaluator receives admission context separately from scanner evidence. Depending on source, available context includes runtime, artifact format, architecture, quantization, size, trusted-signature count, signer fingerprints, intelligence freshness, runtime exploitability, compatibility, remote revision identity, lineage, and backdoor indicators. Missing context remains unknown.

The `research` profile may permit custom model code for static handling, but it never bypasses active-execution sandbox or advisory gates. High-assurance backdoor controls act on reproducible or correlated evidence; they do not prove that a model is safe or malicious.

## Signature threshold and pinning

`minimum_trusted_signatures` is bounded to 32. `required_signer_fingerprints` contains full `sha256:<64 hex>` key fingerprints. Both requirements are independently enforced when configured. Only trusted, active, namespace-authorized signers can satisfy signer requirements.

## Suppression safety

Suppressions require a stable rule ID and meaningful reason. `model` defaults to `*`; optional `owner`, `reference`, and `expires_unix` fields support reviewable exceptions. Expired suppressions stop applying automatically.

Suppressions cannot hide integrity, structural, operational, or attestation failures. Blocking evidence remains present in reports even where a suppressible policy finding is locally accepted.

## Policy tooling

```bash
layerfault policy init --profile workstation --output policy.json
layerfault policy lint policy.json
layerfault policy explain policy.json
layerfault policy test policy.json ./model.safetensors --source file
layerfault policy diff policy-old.json policy-new.json
```

The normative machine-readable schema is `schemas/policy.json`.
