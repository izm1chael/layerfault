# Layerfault Security Gate

Layerfault treats a local model as a supply-chain artifact that must be structurally valid, intact, attributable, and permitted by local policy before inference.

## Core workflow

```text
Ollama model store
      |
      v
Layerfault scan
  - descriptor digest + declared size
  - GGUF structural validation
  - embedded executable validation
  - template/config/metadata indicators
  - attestation verification
      |
      v
Policy evaluation
      |
  ALLOW / WARN / BLOCK
      |
      +--> layerfault run MODEL --> ollama run MODEL
```

`layerfault run` uses `std::process::Command`; it never constructs a shell command from model/user arguments.

## Recommended operator flow

1. `layerfault audit --deep`
2. Add trusted keys with `layerfault trust add`.
3. Attest internal/approved manifests with `layerfault attest sign`.
4. Start with `--policy workstation`.
5. Capture a baseline with `layerfault baseline create`.
6. Move production/CI workloads to `ci` or `strict` policy.
7. Use `layerfault run` for pre-inference enforcement.
8. Quarantine suspicious local models instead of deleting them.

## Trust bootstrap

Generate an Ed25519 key outside Layerfault. OpenSSL example:

```bash
openssl genpkey -algorithm ED25519 -out publisher-private.pem
openssl pkey -in publisher-private.pem -pubout -out publisher-public.pem
```

Keep the private key out of the model store and out of source control.

```bash
layerfault trust add \
  --name internal-publisher \
  --public-key publisher-public.pem \
  --namespace 'registry.internal.example/approved/*'

layerfault attest sign \
  registry.internal.example/approved/model:v1 \
  --private-key publisher-private.pem

layerfault verify \
  registry.internal.example/approved/model:v1 \
  --policy strict
```

The attestation binds all of these values:

- exact manifest bytes;
- SHA-256 manifest digest;
- canonical model identity;
- Ed25519 key fingerprint.

The trust store separately authorizes the key for one or more model-identity patterns. A cryptographically valid signature from a key outside its authorized namespace is a blocking provenance failure.

## Store inventory

`layerfault audit` detects:

- invalid/non-canonical manifest paths;
- referenced blobs missing from disk;
- orphaned content-addressed blobs;
- blobs shared by multiple model manifests;
- partial/temporary files;
- invalid manifests.

`layerfault audit --deep` also runs the scanner, provenance verifier and policy engine and prints a matrix of integrity, structure, signed/trusted state and policy disposition.

## Baselines

```bash
layerfault baseline create --name workstation
layerfault baseline verify --name workstation
```

A baseline stores model identities, manifest digests and descriptor digest sets. Verification reports added, removed and changed models. It does not copy model bytes.

## Quarantine

```bash
layerfault quarantine put suspect:latest
layerfault quarantine list
layerfault quarantine restore <id>
```

Quarantine moves the target manifest, its attestation files and only blobs that are exclusively referenced by that model. Shared blobs remain in place so unrelated models are not damaged. The recovery record is written before moves begin and completed moves are rolled back if a move fails.

## Machine output

`--json` is the stable JSON contract. Each model includes:

- `schema_version`;
- `tool_version`;
- `model`;
- `overall_status`;
- `trust_state`;
- `policy` decision;
- `scan_results`, each with a stable `rule_id`.

`--sarif` emits SARIF 2.1.0 warning/failure results using the same stable rule IDs.

## Validation

Run before merging/releasing:

```bash
cargo fmt --all -- --check
cargo check --locked --all-targets
cargo test --locked --all-targets
cargo clippy --locked --all-targets --all-features -- -D warnings
bash scripts/core-security-gates.sh
```

The synthetic security gate requires no model downloads. It uses a temporary Ollama-format store and a fake `ollama` executable.

## Audited policy overrides

A policy-only block (exit 4) can be explicitly overridden for `layerfault run` only when the operator records a reason:

```bash
layerfault run MODEL --policy strict \
  --override-reason "Approved temporary offline evaluation"
```

The record is appended to `override-audit.jsonl` in the Layerfault config directory (or `--override-log`). Integrity failures, malformed structures, invalid/revoked provenance and scanner errors (exit 2/3) are never overridable by this mechanism.
