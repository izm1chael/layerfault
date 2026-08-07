# Layerfault trust and provenance model

## Native offline trust

A trusted Layerfault Ollama attestation means:

1. the Ed25519 signature verifies the exact manifest bytes Layerfault parsed;
2. the attestation names the same canonical model identity being scanned;
3. it records the same manifest digest;
4. the signing key is present, active and not revoked in the local trust store; and
5. the key is explicitly authorized for that model identity/namespace.

Multiple attestation envelopes may coexist for the same manifest. Policy can require a threshold of independently trusted signatures and can pin specific key fingerprints. Only fingerprints from attestations that independently resolve to an active, namespace-authorized trusted key are exposed to policy signer-pinning; an untrusted or inactive attestation can never satisfy a signer pin merely because another signer is trusted.

## Key lifecycle

Trusted keys may carry:

- namespace/model authorization patterns;
- activation and expiry timestamps;
- revocation state;
- a rotation-group label used for operator bookkeeping.

```bash
layerfault trust add --name publisher-a --public-key a.pub --namespace 'registry.example/*'
layerfault trust configure publisher-a --rotation-group production --expires-unix 1800000000
layerfault trust revoke publisher-a
layerfault trust unrevoke publisher-a
layerfault trust export --output trust-bundle.json
layerfault trust import --input trust-bundle.json
```

Trust-bundle import merges public trust decisions; private signing keys are never stored by Layerfault.

## Signed baselines

A baseline can itself be signed by an active trusted Ed25519 key. This prevents model-store compromise from being hidden simply by replacing the known-good baseline. Baseline signatures bind the exact baseline bytes; any approved update invalidates the old signature and must be re-signed deliberately.

## Optional Sigstore interoperability

For standalone artifacts, Layerfault can invoke an already-installed `cosign verify-blob` with an offline bundle plus exact expected certificate identity and issuer. This is interoperability, not a replacement for Layerfault's native offline trust store. Layerfault does not install Cosign or silently relax identity/issuer matching.

## What Layerfault does not prove

A trust-store display name is an operator assertion; Layerfault does not prove a publisher's real-world identity merely because an operator named a key after that publisher.

Static structure/provenance checks also cannot prove that opaque learned weights are free of training-time backdoors, hidden learned behavior or undesirable model outputs. Those require separate behavioral controls.
