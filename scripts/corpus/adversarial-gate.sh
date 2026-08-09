#!/usr/bin/env bash
set -u

ROOT="${1:-}"
OUT="${2:-}"
if [[ -z "$ROOT" || -z "$OUT" || ! -d "$ROOT" ]]; then
  echo "usage: $0 CORPUS_ROOT OUTPUT_DIR" >&2
  exit 2
fi

BIN="${LAYERFAULT_BIN:-}"
if [[ -z "$BIN" ]]; then
  if [[ -x target/release/layerfault ]]; then
    BIN="target/release/layerfault"
  else
    BIN="target/debug/layerfault"
  fi
fi
if [[ ! -x "$BIN" ]]; then
  echo "Layerfault binary is not executable: $BIN" >&2
  exit 2
fi

mkdir -p "$OUT"
ROOT="$(cd "$ROOT" && pwd)"
OUT="$(cd "$OUT" && pwd)"
TSV="$OUT/summary.tsv"
HASHES="$OUT/SHA256SUMS"
: > "$TSV"
: > "$HASHES"
printf 'target\toperation\texit_code\toutput\n' >> "$TSV"

version="$($BIN --version 2>&1 || true)"
printf '%s\n' "$version" > "$OUT/layerfault-version.txt"
find "$ROOT" -type f -print0 | sort -z | while IFS= read -r -d '' file; do
  sha256sum "$file" >> "$HASHES"
done

run_capture() {
  local target="$1" operation="$2" output="$3"
  shift 3
  "$BIN" "$@" > "$output" 2>&1
  local rc=$?
  printf '%s\t%s\t%s\t%s\n' "$target" "$operation" "$rc" "${output#$OUT/}" >> "$TSV"
}

run_target() {
  local target="$1"
  local label
  label="$(echo "$target" | sed "s#^$ROOT/##; s#[^A-Za-z0-9_.-]#_#g")"
  run_capture "$target" fingerprint "$OUT/${label}.fingerprint.txt" fingerprint "$target"
  run_capture "$target" inspect "$OUT/${label}.inspect.json" inspect "$target" --json
  run_capture "$target" scan-dir "$OUT/${label}.scan-dir.json" scan-dir "$target" --json
  run_capture "$target" verify-package "$OUT/${label}.verify-package.json" verify-package "$target" --policy workstation --json
  run_capture "$target" pipeline-json "$OUT/${label}.pipeline.json" pipeline "$target" --policy workstation --json
  run_capture "$target" pipeline-summary "$OUT/${label}.pipeline.summary.txt" pipeline "$target" --policy workstation --summary

  while IFS= read -r -d '' artifact; do
    local artifact_label
    artifact_label="$(echo "$artifact" | sed "s#^$ROOT/##; s#[^A-Za-z0-9_.-]#_#g")"
    run_capture "$artifact" inspect "$OUT/${artifact_label}.inspect.json" inspect "$artifact" --json
    run_capture "$artifact" verify-file "$OUT/${artifact_label}.verify-file.json" verify-file "$artifact" --policy workstation --json
  done < <(find "$target" -type f \( -iname '*.gguf' -o -iname '*.safetensors' \) -print0 | sort -z)
}

while IFS= read -r -d '' package; do
  run_target "$package"
done < <(find "$ROOT" -mindepth 1 -maxdepth 1 -type d -print0 | sort -z)

if [[ "$(wc -l < "$TSV")" -eq 1 ]]; then
  run_target "$ROOT"
fi

python3 - "$TSV" "$OUT/summary.json" "$version" <<'PY'
import csv
import json
import pathlib
import sys

tsv, output, version = sys.argv[1:]
rows = []
with open(tsv, newline="") as handle:
    for row in csv.DictReader(handle, delimiter="\t"):
        row["exit_code"] = int(row["exit_code"])
        rows.append(row)
path = pathlib.Path(output)
path.write_text(json.dumps({"tool_version": version, "results": rows}, indent=2) + "\n")
PY

echo "Adversarial corpus results: $OUT"
echo "Summary: $TSV"
exit 0
