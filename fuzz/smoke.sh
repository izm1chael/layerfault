#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FUZZ_DIR="$ROOT/fuzz"
SECONDS_PER_TARGET="${FUZZ_SMOKE_SECONDS_PER_TARGET:-60}"
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

for target in "${targets[@]}"; do
  echo "=== fuzz $target: ${SECONDS_PER_TARGET}s ==="
  target_corpus="$SMOKE_CORPUS_ROOT/$target"
  mkdir -p "$target_corpus"
  cp -a "corpus/$target/." "$target_corpus/"
  dict_args=()
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
    -print_final_stats=1
done
