#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
cd "$ROOT"

BIN="$ROOT/target/debug/layerfault"
cargo build --locked --quiet

MANIFEST="$ROOT/tests/corpus/manifest.json"
if [[ ! -f "$MANIFEST" ]]; then
    python3 "$ROOT/scripts/corpus/generate-parser-fixtures.py" >/dev/null
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# Record reference tool versions in CI output
echo "=== Layerfault Differential Parser Validation ==="
if command -v python3 >/dev/null 2>&1; then
    PY_VER="$(python3 -c 'import sys; print(sys.version.split()[0])')"
    echo "Python version: $PY_VER"
fi

# Process manifest fixtures
python3 - "$BIN" "$MANIFEST" "$TMP" <<'PY'
import json, sys, subprocess, pathlib

bin_path = sys.argv[1]
manifest_path = sys.argv[2]
tmp_dir = pathlib.Path(sys.argv[3])

with open(manifest_path) as f:
    manifest = json.load(f)

fixtures = manifest.get("fixtures", [])
results_by_format = {}

for fixture in fixtures:
    fmt = fixture["format"]
    if fmt not in results_by_format:
        results_by_format[fmt] = {"total": 0, "passed": 0, "mismatches": []}
    
    results_by_format[fmt]["total"] += 1
    rel_path = fixture["path"]
    full_path = str(pathlib.Path("tests/corpus") / rel_path)
    
    # 1. Run python reference adapter
    ref_proc = subprocess.run(
        ["python3", "scripts/security/differential/ref_adapter.py", fmt, full_path],
        capture_output=True, text=True
    )
    if ref_proc.returncode != 0:
        results_by_format[fmt]["mismatches"].append((full_path, "Reference adapter failed", ref_proc.stderr))
        continue
    
    try:
        ref_json = json.loads(ref_proc.stdout)
    except Exception as e:
        results_by_format[fmt]["mismatches"].append((full_path, "Reference JSON parse failed", str(e)))
        continue
        
    # 2. Run layerfault inspect --normalized
    lf_proc = subprocess.run(
        [bin_path, "inspect", full_path, "--normalized"],
        capture_output=True, text=True
    )
    if lf_proc.returncode != 0:
        results_by_format[fmt]["mismatches"].append((full_path, "Layerfault inspect failed", lf_proc.stderr))
        continue
        
    try:
        lf_json = json.loads(lf_proc.stdout)
    except Exception as e:
        results_by_format[fmt]["mismatches"].append((full_path, "Layerfault JSON parse failed", str(e)))
        continue

    # Compare key normalized fields
    mismatch_reasons = []
    
    # Format check
    if ref_json.get("format") != lf_json.get("format"):
        mismatch_reasons.append(f"Format mismatch: ref={ref_json.get('format')} vs lf={lf_json.get('format')}")
        
    # Expected fields check from manifest
    expected = fixture.get("expected", {})
    if "tensor_count" in expected:
        if len(lf_json.get("tensors", [])) != expected["tensor_count"]:
            mismatch_reasons.append(f"Tensor count mismatch: expected {expected['tensor_count']} got {len(lf_json.get('tensors', []))}")
            
    if "metadata_count" in expected:
        if len(lf_json.get("metadata", [])) != expected["metadata_count"]:
            mismatch_reasons.append(f"Metadata count mismatch: expected {expected['metadata_count']} got {len(lf_json.get('metadata', []))}")

    if not mismatch_reasons:
        results_by_format[fmt]["passed"] += 1
    else:
        results_by_format[fmt]["mismatches"].append((full_path, "; ".join(mismatch_reasons), json.dumps({"ref": ref_json, "lf": lf_json}, indent=2)))

# Print format summary report
all_passed = True
for fmt in sorted(results_by_format.keys()):
    stats = results_by_format[fmt]
    fmt_display = "GGUF" if fmt == "gguf" else ("ONNX" if fmt == "onnx" else ("TFLite" if fmt == "tflite" else fmt.capitalize()))
    print(f"{fmt_display} {stats['passed']}/{stats['total']} compatible")
    if stats["passed"] < stats["total"]:
        all_passed = False
        for path, reason, diff in stats["mismatches"]:
            print(f"  [MISMATCH] {path}: {reason}")
            print(f"  Diff:\n{diff}")

if not all_passed:
    sys.exit(1)
PY
