# Runtime Security

Layerfault discovers and assesses local AI runtimes without assuming that an installation is safe, reachable, authenticated, or correctly configured. Supported canonical runtime identifiers are `ollama`, `lmstudio`, `llama-cpp`, `vllm`, `transformers`, `text-generation-inference`, `localai`, `mlx`, `gpt4all`, `jan`, `koboldcpp`, and `text-generation-webui`.

Runtime discovery is evidence based. Executable paths, package metadata, running processes, versions, command-line arguments, selected non-secret environment facts, listener information, TLS/authentication state, and executable SHA-256 identities are recorded only when observed. Unknown state remains unknown. Secret-bearing environment values are not serialized and API-key command-line values are redacted.

Contextual exploitability combines signed runtime advisories with model facts and observed runtime posture. A version match alone is not treated as proof that exploitability preconditions are met. Compatibility is a separate assessment covering format, architecture, dynamic/custom-code requirements, and runtime exploitability.

CLI examples:

```text
layerfault runtime list --json
layerfault runtime audit --runtime vllm
layerfault runtime assess --runtime vllm --model ./model
layerfault runtime matrix --model ./model --runtime ollama --runtime llama-cpp
```
