#!/usr/bin/env bash
set -euo pipefail
BIN="${LAYERFAULT_BIN:-/usr/local/bin/layerfault}"
MANIFEST="${1:-tests/behaviour-corpus-template.tsv}"
RUNTIME="${LAYERFAULT_LLAMA_RUNTIME:-}"
PROFILE="${LAYERFAULT_BEHAVIOUR_PROFILE:-standard}"
[[ -x "$BIN" ]] || { echo "Layerfault binary not executable: $BIN" >&2; exit 64; }
[[ -n "$RUNTIME" && -x "$RUNTIME" ]] || { echo "Set LAYERFAULT_LLAMA_RUNTIME to the audited llama.cpp executable" >&2; exit 64; }
[[ -f "$MANIFEST" ]] || { echo "Behaviour manifest not found: $MANIFEST" >&2; exit 64; }
fail=0
while IFS=$'\t' read -r name base derived tokenizer expected_exit notes; do
  [[ -z "${name:-}" || "$name" == \#* ]] && continue
  [[ -e "$base" && -e "$derived" ]] || { echo "FAIL $name: base/derived missing" >&2; fail=1; continue; }
  echo "==> $name${notes:+ — $notes}"
  set +e
  "$BIN" compare-behaviour "$base" "$derived" \
    --runtime llama-cpp --runtime-path "$RUNTIME" --profile "$PROFILE" --json
  rc=$?
  set -e
  echo "exit=$rc"
  if [[ -n "${expected_exit:-}" && "$rc" != "$expected_exit" ]]; then
    echo "BEHAVIOUR_REGRESSION $name: expected exit $expected_exit, got $rc" >&2
    fail=1
  fi
done < "$MANIFEST"
exit "$fail"
