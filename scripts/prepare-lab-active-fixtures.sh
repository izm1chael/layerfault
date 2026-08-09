#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  prepare-lab-active-fixtures.sh [--onnx-model MODEL.onnx --onnx-sidecar SIDE_CAR]

Checks the local active-analysis dependencies and, when explicit ONNX model and
sidecar paths are supplied, recreates a genuine external hardlink alias for the
ONNX end-to-end fixture. Hub/archive downloads cannot preserve hardlink inode
identity, so the link must be recreated locally for that security test.
USAGE
}

onnx_model=""
onnx_sidecar=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --onnx-model) onnx_model="$2"; shift 2 ;;
    --onnx-sidecar) onnx_sidecar="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 64 ;;
  esac
done

printf '%-18s %s\n' "dependency" "status"
for tool in bwrap strace prlimit python3; do
  if path=$(command -v "$tool" 2>/dev/null); then
    printf '%-18s OK %s\n' "$tool" "$path"
  else
    printf '%-18s MISSING\n' "$tool"
  fi
done

python_bin="${LAYERFAULT_PYTHON_RUNTIME:-$(command -v python3 2>/dev/null || true)}"
if [[ -n "$python_bin" && -x "$python_bin" ]]; then
  "$python_bin" - <<'PY' || true
mods = ["torch", "transformers", "peft"]
for name in mods:
    try:
        mod = __import__(name)
        print(f"python:{name:<11} OK {getattr(mod, '__version__', 'unknown')}")
    except Exception as exc:
        print(f"python:{name:<11} MISSING {exc}")
PY
fi

if [[ -n "$onnx_model" || -n "$onnx_sidecar" ]]; then
  [[ -n "$onnx_model" && -n "$onnx_sidecar" ]] || {
    echo "Both --onnx-model and --onnx-sidecar are required" >&2; exit 64;
  }
  [[ -f "$onnx_model" && -f "$onnx_sidecar" ]] || {
    echo "ONNX model/sidecar path missing" >&2; exit 66;
  }
  model_dir=$(cd "$(dirname "$onnx_model")" && pwd -P)
  sidecar_real=$(readlink -f "$onnx_sidecar")
  case "$sidecar_real" in
    "$model_dir"/*) ;;
    *) echo "Sidecar must live beneath the ONNX model directory" >&2; exit 65 ;;
  esac
  alias_dir="${LAYERFAULT_ONNX_HARDLINK_ALIAS_DIR:-/tmp/layerfault-onnx-hardlink-alias}"
  mkdir -p "$alias_dir"
  alias_path="$alias_dir/$(basename "$onnx_sidecar").alias"
  rm -f "$alias_path"
  ln "$onnx_sidecar" "$alias_path"
  links=$(stat -c '%h' "$onnx_sidecar")
  if (( links < 2 )); then
    echo "Failed to create a real hardlink alias for $onnx_sidecar" >&2
    exit 1
  fi
  echo "ONNX hardlink fixture ready: model=$onnx_model sidecar=$onnx_sidecar nlink=$links alias=$alias_path"
fi
