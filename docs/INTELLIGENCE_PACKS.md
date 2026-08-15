# Signed Security Intelligence Packs

Layerfault uses bounded, versioned, data-only intelligence packs. Packs may contain runtime advisories, pickle gadget knowledge, declarative execution edges, known model identities, and security-framework mappings.

External packs are not trusted merely because they parse. Policy/admission consumers must use detached Ed25519 verification. Pack loading is capped, record counts and strings are bounded, and the schema intentionally has no script, regex-execution, WASM, template-evaluation, or generic executable matcher facility.

Layerfault records the highest accepted sequence for an external signer. Lower-sequence packs are rejected unless rollback is explicitly allowed. A signer change is never silently trusted.

```text
layerfault intelligence show
layerfault intelligence show --pack ./pack.json --json
layerfault intelligence verify --pack ./pack.json --signature ./pack.sig --public-key ./publisher.pem
```

The legacy `layerfault::advisory::*` API remains available as a compatibility view over runtime-advisory intelligence.
