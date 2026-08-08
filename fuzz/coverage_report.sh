#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FUZZ_DIR="$ROOT/fuzz"
OUT_DIR="${FUZZ_COVERAGE_OUT:-$FUZZ_DIR/coverage-reports}"

TARGETS=(
  manifest
  gguf
  heuristics
  safetensors
  safetensors_index
  onnx
  tflite
  keras
  package
  tensorflow
  tensorflow_checkpoint
  binary
  sources_hf_cache
  sources_directory
  lmstudio
  ollama_store
)

declare -A SOURCE_ROWS=(
  [manifest]='src/manifest.rs'
  [gguf]='src/formats/gguf.rs'
  [heuristics]='src/scanner/heuristics.rs'
  [safetensors]='src/formats/safetensors.rs'
  [safetensors_index]='src/formats/safetensors.rs'
  [onnx]='src/formats/onnx.rs'
  [tflite]='src/formats/tflite.rs'
  [keras]='src/formats/keras.rs'
  [package]='src/package.rs'
  [tensorflow]='src/formats/tensorflow.rs'
  [tensorflow_checkpoint]='src/formats/tensorflow.rs'
  [binary]='src/scanner/binary.rs'
  [sources_hf_cache]='src/sources/mod.rs'
  [sources_directory]='src/sources/mod.rs'
  [lmstudio]='src/sources/mod.rs'
  [ollama_store]='src/manifest.rs'
)

selected=("$@")
if [[ ${#selected[@]} -eq 0 ]]; then
  selected=("${TARGETS[@]}")
fi

mkdir -p "$OUT_DIR"
cd "$FUZZ_DIR"

for target in "${selected[@]}"; do
  corpus="corpus/$target"
  [[ -d "$corpus" ]] || { echo "missing corpus: $corpus" >&2; exit 2; }

  echo "=== coverage: $target ==="
  cargo fuzz coverage "$target" "$corpus"

  prof="coverage/$target/coverage.profdata"
  [[ -f "$prof" ]] || { echo "missing profile: $prof" >&2; exit 2; }

  binary="$(find target -type f -path "*/release/$target" -perm -111 -print | head -n 1 || true)"
  [[ -n "$binary" ]] || { echo "unable to locate coverage binary for $target" >&2; exit 2; }

  summary="$OUT_DIR/$target.txt"
  html="$OUT_DIR/$target.html"
  cargo cov -- report "$binary" -instr-profile="$prof" > "$summary"
  cargo cov -- show "$binary" -instr-profile="$prof" --format=html > "$html"

  source_row="${SOURCE_ROWS[$target]}"
  {
    echo "target=$target"
    echo "primary_source=$source_row"
    grep -F "$source_row" "$summary" || true
    grep -E '^TOTAL' "$summary" || true
  } > "$OUT_DIR/$target-primary.txt"

done

echo "Coverage reports written to $OUT_DIR"
