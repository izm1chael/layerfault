#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FUZZ_DIR="$ROOT/fuzz"
SECONDS_PER_TARGET="${FUZZ_SECONDS_PER_TARGET:-7200}"
MAX_LEN="${FUZZ_MAX_LEN:-2097152}"
TIMEOUT="${FUZZ_INPUT_TIMEOUT:-10}"
RSS_MB="${FUZZ_RSS_LIMIT_MB:-4096}"
LOG_DIR="${FUZZ_LOG_DIR:-$FUZZ_DIR/logs}"

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

usage() {
  cat <<EOF
usage: $0 [--seconds N] [--target NAME] [--all]

Runs long-form libFuzzer campaigns against the checked-in structured corpora.
Default budget is 7200 seconds (2 hours) per target.

Environment overrides:
  FUZZ_SECONDS_PER_TARGET  seconds per target (default: 7200)
  FUZZ_MAX_LEN             maximum generated input length (default: 2097152)
  FUZZ_INPUT_TIMEOUT       per-input timeout seconds (default: 10)
  FUZZ_RSS_LIMIT_MB        libFuzzer RSS limit MB (default: 4096)
  FUZZ_LOG_DIR             log directory (default: fuzz/logs)
EOF
}

selected=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --seconds)
      SECONDS_PER_TARGET="$2"
      shift 2
      ;;
    --target)
      selected+=("$2")
      shift 2
      ;;
    --all)
      selected=("${TARGETS[@]}")
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ${#selected[@]} -eq 0 ]]; then
  selected=("${TARGETS[@]}")
fi

for target in "${selected[@]}"; do
  if [[ ! " ${TARGETS[*]} " =~ " ${target} " ]]; then
    echo "unknown fuzz target: $target" >&2
    exit 2
  fi
done

mkdir -p "$LOG_DIR"
cd "$FUZZ_DIR"

for target in "${selected[@]}"; do
  corpus="corpus/$target"
  if [[ ! -d "$corpus" ]]; then
    echo "missing corpus directory: $FUZZ_DIR/$corpus" >&2
    exit 2
  fi
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  log="$LOG_DIR/${target}-${stamp}.log"
  dict="dictionaries/$target.dict"
  dict_args=()
  if [[ -f "$dict" ]]; then
    dict_args+=("-dict=$dict")
  fi
  echo "=== $target: ${SECONDS_PER_TARGET}s, corpus=$(find "$corpus" -type f | wc -l) seeds ===" | tee "$log"
  cargo fuzz run "$target" "$corpus" -- \
    -max_total_time="$SECONDS_PER_TARGET" \
    -max_len="$MAX_LEN" \
    -timeout="$TIMEOUT" \
    -rss_limit_mb="$RSS_MB" \
    -use_value_profile=1 \
    "${dict_args[@]}" \
    -print_final_stats=1 2>&1 | tee -a "$log"
done
