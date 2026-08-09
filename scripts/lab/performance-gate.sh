#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-.}"
MODEL="${2:-}"
MAX_RSS_KB="${LAYERFAULT_MAX_RSS_KB:-786432}"
[[ -n "$MODEL" ]] || { echo "usage: $0 /path/to/layerfault MODEL" >&2; exit 64; }
cd "$ROOT"
cargo build --release --locked --quiet
BIN="$PWD/target/release/layerfault"
if [[ ! -x /usr/bin/time ]]; then
  echo "SKIP: GNU /usr/bin/time is required for RSS budget measurement" >&2
  exit 77
fi
OUT="$(mktemp)"; ERR="$(mktemp)"; trap 'rm -f "$OUT" "$ERR"' EXIT
set +e
/usr/bin/time -v "$BIN" verify "$MODEL" --json >"$OUT" 2>"$ERR"
RC=$?
set -e
RSS="$(awk -F: '/Maximum resident set size/ {gsub(/^[ \t]+/,"",$2); print $2}' "$ERR")"
[[ "$RSS" =~ ^[0-9]+$ ]] || { cat "$ERR" >&2; echo "Unable to parse RSS" >&2; exit 1; }
printf 'model=%s exit=%s max_rss_kb=%s budget_kb=%s\n' "$MODEL" "$RC" "$RSS" "$MAX_RSS_KB"
(( RSS <= MAX_RSS_KB )) || { echo "FAIL: RSS budget exceeded" >&2; exit 1; }
# Scanner/policy findings are reported separately; this gate is only a memory budget.
exit 0
