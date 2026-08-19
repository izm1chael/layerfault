#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FUZZ_DIR="$ROOT/fuzz"
SECONDS_PER_TARGET="${FUZZ_SMOKE_SECONDS_PER_TARGET:-60}"
SMOKE_JOBS="${FUZZ_SMOKE_JOBS:-10}"
MAX_LEN="${FUZZ_MAX_LEN:-2097152}"
TIMEOUT="${FUZZ_INPUT_TIMEOUT:-10}"
RSS_MB="${FUZZ_RSS_LIMIT_MB:-4096}"
SMOKE_CORPUS_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/layerfault-fuzz-smoke.XXXXXX")"
trap 'rm -rf -- "$SMOKE_CORPUS_ROOT"' EXIT

command -v python3 >/dev/null 2>&1 || {
  echo "ERROR: python3 is required for the fuzz smoke gate" >&2
  exit 1
}
if ! cargo fuzz --version 2>/dev/null | grep -q 'cargo-fuzz 0\.13\.2'; then
  echo "ERROR: cargo-fuzz 0.13.2 is required; install it with:" >&2
  echo "  cargo install cargo-fuzz --version 0.13.2 --locked" >&2
  exit 1
fi

python3 "$ROOT/scripts/corpus/generate-fuzz-corpus.py"
git -C "$ROOT" diff --exit-code -- fuzz/corpus fuzz/CORPUS_INDEX.json

cd "$FUZZ_DIR"
cargo +nightly fuzz build
mapfile -t targets < <(cargo +nightly fuzz list)
[[ ${#targets[@]} -gt 0 ]] || {
  echo "ERROR: cargo-fuzz discovered no targets" >&2
  exit 1
}

if ! [[ "$SMOKE_JOBS" =~ ^[1-9][0-9]*$ ]]; then
  echo "ERROR: FUZZ_SMOKE_JOBS must be a positive integer" >&2
  exit 1
fi

run_target() {
  local target="$1"
  local target_corpus="$SMOKE_CORPUS_ROOT/$target"
  local log_file="$SMOKE_CORPUS_ROOT/$target.log"

  mkdir -p "$target_corpus"
  printf 'target=%s\n' "$target" >"$log_file"
  if [[ -d "corpus/$target" ]]; then
    cp -a "corpus/$target/." "$target_corpus/"
  fi
  local -a dict_args=()
  if [[ -f "dictionaries/$target.dict" ]]; then
    dict_args+=("-dict=dictionaries/$target.dict")
  fi

  cargo +nightly fuzz run "$target" "$target_corpus" -- \
    -max_total_time="$SECONDS_PER_TARGET" \
    -max_len="$MAX_LEN" \
    -timeout="$TIMEOUT" \
    -rss_limit_mb="$RSS_MB" \
    -use_value_profile=1 \
    "${dict_args[@]}" \
    -print_final_stats=1 >>"$log_file" 2>&1
}

run_batch() {
  local target pid i
  local -a batch_pids=()
  local -a batch_targets=()

  for target in "$@"; do
    echo "=== fuzz $target: ${SECONDS_PER_TARGET}s ==="
    run_target "$target" &
    batch_pids+=("$!")
    batch_targets+=("$target")
  done

  local failed=0
  for i in "${!batch_pids[@]}"; do
    pid="${batch_pids[$i]}"
    target="${batch_targets[$i]}"
    if wait "$pid"; then
      tail -n 12 "$SMOKE_CORPUS_ROOT/$target.log"
    else
      echo "ERROR: fuzz target $target failed" >&2
      if [[ -f "$SMOKE_CORPUS_ROOT/$target.log" ]]; then
        cat "$SMOKE_CORPUS_ROOT/$target.log" >&2
      else
        echo "No fuzz log was produced for $target" >&2
      fi
      failed=1
    fi
  done

  return "$failed"
}

for ((batch_start = 0; batch_start < ${#targets[@]}; batch_start += SMOKE_JOBS)); do
  batch=()
  for ((i = batch_start; i < batch_start + SMOKE_JOBS && i < ${#targets[@]}; i++)); do
    batch+=("${targets[$i]}")
  done
  run_batch "${batch[@]}"
done
