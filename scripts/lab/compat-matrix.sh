#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-.}"
cd "$ROOT"
cargo build --release --locked --quiet
BIN="$PWD/target/release/layerfault"
OUT="${2:-layerfault-compat-$(date -u +%Y%m%dT%H%M%SZ).json}"
set +e
"$BIN" audit --deep --json > "$OUT"
RC=$?
set -e
echo "Layerfault local compatibility matrix written to $OUT (exit=$RC)"
exit "$RC"
