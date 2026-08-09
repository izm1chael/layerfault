#!/usr/bin/env bash
set -euo pipefail
BIN="${LAYERFAULT_BIN:-layerfault}"
"$BIN" --version
"$BIN" selftest --json >/dev/null
"$BIN" capabilities --json >/dev/null
