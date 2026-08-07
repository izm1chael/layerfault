# Sources and runtimes

## Ollama

Ollama is the deepest integration. Layerfault understands manifests, content-addressed blobs, shared layers, current/legacy media types, attestations, baselines, quarantine and orphan detection. `OLLAMA_MODELS` is authoritative when set; platform defaults are discovery fallbacks.

## LM Studio

Layerfault discovers local model paths through an installed `lms` CLI using `lms ls --json --detailed`. Guarded load calls `lms load` only after admission. Guarded import defaults to `lms import <path> --dry-run`; `--execute` is required to perform the import.

Layerfault does not parse LM Studio private databases or modify them directly.

## llama.cpp

Local artifacts are admitted before Layerfault invokes `llama-cli -m <path>` or `llama-server -m <path>`. Remaining runtime arguments are passed as discrete process arguments.

## Hugging Face cache

Hugging Face support is offline cache auditing. Layerfault examines `models--*` repositories and their `refs`, `snapshots` and `blobs`, validates that snapshot symlinks resolve inside the repository blob store, identifies broken refs/detached snapshots/orphan blobs, and structurally inspects supported model artifacts.

Layerfault does not fetch revisions, resolve remote trust, or infer publisher identity merely from a cache directory name.
