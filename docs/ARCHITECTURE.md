# Architecture

Layerfault keeps discovery, parsing, trust and admission separate so adding a runtime does not implicitly grant that runtime trust.

```
source/runtime discovery
        |
        v
artifact reference -----> format detector -----> bounded parser/scanners
        |                                         |
        |                                         v
        +-----------------------------> scanner evidence
                                                  |
provenance/trust ---------------------------------+
                                                  |
local policy -------------------------------------+
                                                  v
                                      ALLOW / WARN / BLOCK
                                                  |
                                  guarded runtime/import only
```

## Capability boundaries

- `formats/`: artifact identification and hostile-input parsers. No runtime execution.
- `sources/`: discovery and narrowly-scoped runtime process adapters. Discovery never means trust.
- `scanner/`: evidence collection and stable finding classifications.
- `trust` / `provenance` / `sigstore`: signer identity and attestation verification.
- `policy`: admission decision over scanner evidence plus context.
- `admission`: standalone-artifact composition of scan + provenance + policy.
- `audit` / `inventory` / `gc`: model-store state and conservative hygiene.
- `baseline`: known-good drift and signed change control.
- `quarantine`: non-destructive isolation and evidence export.
- `certify`: deterministic local hostile-input checks.

The CLI composes these modules; format scanners do not invoke runtimes and source adapters do not bypass policy.

## Feature-freeze admission layer

The final admission layer is intentionally orthogonal to source adapters:

`source discovery -> artifact/package scan -> package identity -> provenance/trust -> policy -> runtime advisory -> execution binding -> signed evidence`.

`package.rs` owns canonical package identity and static surrounding-file inspection. `advisory.rs` owns the offline runtime vulnerability catalog and exact executable version evaluation. `binding.rs` owns staged/revalidated execution guarantees. `evidence.rs` owns signed decision records. Source adapters must not duplicate these controls or weaken their failure semantics.

External advisory bytes are signature-verified before parsing/evaluation and the verified in-memory bytes are the bytes evaluated. Runtime adapters consume the canonical executable path that was version-checked. Direct-file runtimes consume the private staged artifact path rather than reopening the original user path.
