# Release security

A release candidate is expected to pass the complete local security gate before packaging:

```bash
cargo fmt --all -- --check
cargo check --locked --all-targets
cargo test --locked --all-targets
cargo clippy --locked --all-targets --all-features -- -D warnings
bash scripts/security-gates.sh
python3 scripts/schema-gates.py --binary target/debug/layerfault
```

CI additionally runs a pinned `cargo-audit` release against the current RustSec advisory database.

## Build targets

The release workflow builds:

- Linux x86-64 native;
- Linux ARM64 on a native hosted ARM runner;
- Windows x86-64;
- Linux x86-64 musl where the dependency/toolchain set permits a static build;
- a genuine macOS universal binary created by building both `aarch64-apple-darwin` and `x86_64-apple-darwin` and combining them with `lipo`.

The workflow does not label a single-host-architecture macOS executable as universal.

## Supply-chain controls

- External GitHub Actions are referenced by immutable commit IDs with the human release version in a comment.
- Release builds use `Cargo.lock`.
- Each binary is accompanied by SHA-256 checksums.
- `scripts/cargo-sbom.py` creates a local CycloneDX 1.7 dependency SBOM from `Cargo.lock` without installing an extra generator.
- GitHub artifact attestations provide build provenance for generated binaries.
- Layerfault's model attestations and GitHub's build attestations are separate trust domains.

Consumers may verify GitHub build attestations with the GitHub CLI using the repository identity published by the eventual release.

## Source build identity

Every build embeds `LAYERFAULT_BUILD_ID`, a SHA-256 over the sorted security source/contract inputs (`src/`, `schemas/`, `advisories/`, `policies/`, Cargo manifests and `THREATS.md`). This distinguishes development builds that intentionally share the same pre-release package version. Signed admission evidence records both `layerfault_version` and `build_id`.

Release automation should preserve the source tree used for the build so the embedded build identity can be independently reproduced alongside normal release checksums and provenance attestations.
