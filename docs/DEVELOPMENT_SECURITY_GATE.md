# Development security gate

Run from the repository root:

```bash
bash scripts/security-gates.sh
```

The gate first executes the established Ollama trust/policy/enforcement suite and then exercises the broader development surface with local synthetic fixtures:

- standalone Safetensors validation and malformed-range rejection;
- sharded Safetensors index validation;
- source/format policy restrictions;
- fake LM Studio discovery, dry-run import, import and guarded load;
- fake llama.cpp guarded CLI/server launch;
- offline synthetic Hugging Face cache auditing and ML-BOM output;
- built-in selftest/certification and JSON contract checks;
- trust-bundle distribution, signer rotation metadata and two-signature policy;
- signed baselines;
- quarantine inspect/export/sign/restore;
- conservative GC dry-run/execute;
- project CycloneDX dependency SBOM generation.

The gate downloads no model. Fake runtimes are temporary shell scripts whose only purpose is to prove admission happens before process invocation.

The optional sparse certification lane is deliberately separate:

```bash
layerfault certify --sparse
```

It creates sparse files representing 1, 4, 8 and 20 GiB Safetensors data buffers and performs structure-only validation. It should be run on a filesystem that supports sparse files and has sufficient logical-file allowance.

## Feature-freeze contracts

The cumulative gate additionally proves:

- package fingerprints are independent of absolute package location and change with content;
- unsafe code-capable serialization blocks package admission without being deserialized;
- HF snapshot custom code/config is scanned while symlinks remain constrained to repository blobs;
- signed evidence verifies, and payload mutation invalidates the signature;
- direct llama.cpp execution receives the private admission-staging path;
- the runtime advisory catalog blocks a known-vulnerable synthetic Ollama version;
- signed external advisory catalogs verify from exact bytes;
- fake runtime binaries support `--version`, ensuring the path checked is the path used during the guarded workflow.
