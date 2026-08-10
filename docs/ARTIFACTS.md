# Artifact security

## GGUF

Layerfault performs bounded structural parsing across supported GGUF generations, validates metadata/tensor descriptors and range arithmetic, and separately evaluates metadata/content indicators and plausible embedded executable structures. Unknown future encodings are compatibility findings rather than unsafe parser guesses.

## Safetensors

Safetensors headers and sharded indexes are limited to 32 MiB, with at most 250,000 tensor entries, 10,000 metadata entries, and 32 dimensions per tensor. Inputs beyond those operational safety budgets fail before the full in-memory inventory is constructed.

Layerfault validates the 64-bit header length before allocation, bounds header/tensor counts, rejects duplicate top-level keys, validates shapes and known dtype byte sizes using checked arithmetic, checks tensor offsets for bounds/overlap, and requires complete data-buffer indexing without holes.

`*.safetensors.index.json` files receive separate sharded-index validation. Standalone indexes may reference only safe relative Safetensors shard paths within the index directory. Hugging Face cache indexes are validated against the cache's snapshot-to-blob symlink model instead.

## Unknown formats

Layerfault may hash an unknown artifact, but it cannot claim structural validity. Policy decides whether that compatibility gap is a warning or a block.
