# Layered Model Identity

A single file hash is insufficient to describe all meaningful model relationships. Layerfault therefore represents identity in independent layers: exact byte identity, package identity, structural identity, tokenizer identity, optional sampled-weight identity, optional deterministic behavioural identity, and provenance-bound identity.

Missing layers are reported as limitations rather than inferred. Identity comparison distinguishes exact artifact equality, same package, structural consistency, likely derivation, divergence, and inconclusive state.

```text
layerfault models identity ./model --json
layerfault models identity ./model --weights
layerfault models identity-compare ./base ./candidate --weights --json
```

Layered identities are also embedded in security passports and may be bound into signed admission evidence.
