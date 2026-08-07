# Runtime advisory catalog

`runtime-advisories.json` is deliberately a small **offline admission catalog**, not a replacement for a complete CVE feed.

An entry is suitable for a built-in Layerfault hard block only when:

1. the affected runtime is one Layerfault can identify locally;
2. the affected/fixed boundary is machine-comparable from that runtime's version output;
3. the vulnerability is relevant to the guarded model-loading/inference path Layerfault is about to invoke; and
4. a primary/vendor/NVD source supports the fixed boundary.

The catalog generated for this development pass includes model-loading/tokenization issues with defensible fixed boundaries:

- Ollama `CVE-2026-7482`, fixed in 0.17.1;
- llama.cpp `CVE-2025-49847`, fixed in b5662;
- llama.cpp `CVE-2025-52566`, fixed in b5721;
- llama.cpp `CVE-2026-27940`, fixed in b8146.

Context-dependent issues are intentionally not converted into unconditional runtime blocks. For example, a vulnerability isolated to an optional RPC backend should not make a normal local `llama-cli` model load fail unless Layerfault can establish that the affected component is in use.

External catalogs are accepted only with an explicit Ed25519 signature/public key and are signature-verified before they can influence admission. Verification and evaluation operate on the same bytes.
