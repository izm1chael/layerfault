# Static-analysis review

Layerfault treats static analysis as a release gate, but generic rules must be reviewed against the CLI's actual trust boundaries. This document records the reviewed suppressions currently present in source. New suppressions should not be added without the same analysis.

## Semgrep review

The pre-publication Semgrep scan supplied for this release reported 38 blocking findings across supply-chain configuration, fixture secrets, local filesystem access, and process execution.

### Fixed findings

- **Dependabot cooldown** — every configured package ecosystem now uses a seven-day cooldown for normal version updates. Security updates are not delayed by GitHub's cooldown mechanism.
- **Mutable GitHub Action references** — every action reference is pinned to a full 40-character commit SHA. `actions/checkout` is also updated to v7.0.1.
- **Credential-looking test fixtures** — synthetic AWS-key detector fixtures are assembled at runtime so secret scanners do not mistake deliberately fake detector input for a committed credential.
- **GC path reconstruction** — deletion no longer reuses the path string serialized into a prior GC plan. The target is reconstructed from the validated digest beneath the selected model store and the plan is re-derived before deletion.

### Reviewed path-traversal findings

The `rust.actix.path-traversal.tainted-path` rule is designed primarily for request-driven server applications. Layerfault is a local CLI whose purpose is to inspect paths and model stores explicitly selected by the operator. The remaining reported sinks are therefore rule-specific suppressions with an adjacent rationale.

The suppressed cases fall into four bounded categories:

1. **Explicit scan roots** — directory traversal under an operator-selected Ollama, Hugging Face, quarantine, or artifact root. Traversal is read-only and `WalkDir` does not follow links where used.
2. **Validated relative shard paths** — Safetensors shard names must be non-empty, non-absolute, and contain only normal path components before joining to the package/snapshot root.
3. **Hugging Face symlink targets** — snapshot links are canonicalized and accepted only when their resolved regular file remains inside the repository's canonical blob directory.
4. **Explicit CLI file operands** — `layerfault diff` accepts filesystem paths by design; files are passed to the no-follow, read-only artifact scanner.

Quarantine-record relative paths are validated to normal relative components before use, and quarantine IDs / auxiliary filenames have independent path-safety validation.

### Reviewed command-injection findings

Layerfault intentionally launches installed local runtimes for guarded execution and version detection. These calls use `std::process::Command`, not a shell:

- the executable is passed as an executable path rather than interpolated into a command string;
- arguments are passed as discrete argv entries;
- runtime version detection canonicalizes the executable before invocation;
- runtime launch helpers receive an explicitly resolved executable path;
- no `sh -c`, `cmd /c`, PowerShell expression, or equivalent shell interpreter is used.

The generic `rust.actix.command-injection` finding is therefore suppressed only on the reviewed `Command::new` sinks, with an inline explanation. User-supplied runtime arguments may intentionally alter the invoked runtime's behavior, but they cannot introduce shell metacharacter execution through Layerfault itself.

## OSV / RustSec cleanup

The pre-publication dependency gate also requires:

- `anyhow >= 1.0.103` (fixes RUSTSEC-2026-0190),
- `crossbeam-epoch >= 0.9.20` (fixes RUSTSEC-2026-0204),
- Layerfault's direct `indicatif` dependency is pinned to `>= 0.18.6`. The current embedded-inference dependency graph still carries `indicatif 0.17.x` and the unmaintained `number_prefix` crate transitively through `hf-hub` / `tokenizers` (RUSTSEC-2025-0119). This is tracked as an informational supply-chain debt item rather than described as removed; release gates must evaluate the actual `Cargo.lock` graph.

The transactional cleanup installer updates `Cargo.lock` to those resolved versions before running locked builds and tests.

## Release gate

Run:

```bash
bash scripts/pre-push-security-gates.sh
```

The script runs the Rust quality/security suite and, when installed, OSV-Scanner, cargo-audit, and Semgrep. Semgrep is run with `--config auto` and must report no **unsuppressed** blocking findings.

The 18 current `nosemgrep` annotations are intentionally narrow and rule-specific. A gate checks this count so an accidental new suppression cannot silently expand the exception surface.

## Cache and bounded-analysis review

Digest reuse and scanner-evidence reuse intentionally have separate minimum-size controls. Scanner evidence can be expensive to derive even for artifacts smaller than the digest-cache threshold, so the default evidence threshold is lower. Reuse is still identity-guarded and scanner-contract-versioned; `--no-cache` bypasses both paths.

Large package text/config members are no longer skipped by byte size. Security inspection is streamed with bounded overlap/evidence, and targeted Hugging Face loader metadata is parsed incrementally. This avoids treating a normal large tokenizer vocabulary as generic prompt text while still removing the old fixed-size coverage cliff.

Dataset parallelism is bounded by an explicit Rayon pool and deterministic merge order. Security sampling uses deterministic indices derived from member record counts rather than scheduler order, so changing `--jobs` must not alter fingerprints, decisions, indicator counts, or selected evidence.
