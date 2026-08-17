#!/usr/bin/env bash
set -euo pipefail
VERIFY_ONLY=0
DEVICE="cpu"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --verify-only) VERIFY_ONLY=1 ;;
    --device) DEVICE="${2:?missing --device value}"; shift ;;
    -h|--help) echo "Usage: setup-lab-host.sh [--verify-only] [--device cpu|cuda|rocm]"; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done
[[ "$(uname -s)" == Linux ]] || { echo "Layerfault active lab bootstrap is Linux-only" >&2; exit 2; }
command -v layerfault >/dev/null 2>&1 || { echo "layerfault must already be installed and on PATH" >&2; exit 2; }
if [[ "$VERIFY_ONLY" -eq 0 ]]; then
  [[ "$(id -u)" -eq 0 ]] || { echo "Provisioning mode must run as root; use --verify-only for non-root checks" >&2; exit 2; }
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  "$script_dir/install/active-runtime.sh" --device "$DEVICE" --llama auto
fi
missing=0
for tool in bwrap strace prlimit; do
  if ! command -v "$tool" >/dev/null 2>&1; then echo "MISSING: $tool" >&2; missing=1; fi
done
if ! command -v llama-server >/dev/null 2>&1; then
  echo "MISSING: llama-server (persistent GGUF active runtime)" >&2
  missing=1
fi
python_runtime="${LAYERFAULT_PYTHON_RUNTIME:-/opt/layerfault/runtimes/python/bin/python}"
if [[ ! -x "$python_runtime" ]]; then
  echo "MISSING: managed Transformers runtime $python_runtime" >&2
  missing=1
else
  "$python_runtime" -c 'import torch, transformers, peft, safetensors, sentencepiece, tiktoken' >/dev/null || missing=1
fi
cap="$(mktemp)"; doc="$(mktemp)"; trap 'rm -f "$cap" "$doc"' EXIT
LAYERFAULT_PYTHON_RUNTIME="$python_runtime" layerfault capabilities --json >"$cap"
LAYERFAULT_PYTHON_RUNTIME="$python_runtime" layerfault doctor --json >"$doc"
python3 - "$cap" "$doc" <<'PY'
import json,sys
cap=json.load(open(sys.argv[1])); doc=json.load(open(sys.argv[2]))
required={
    'static READY': cap.get('static_analysis') is True,
    'active sandbox READY': cap.get('active_sandbox') is True,
    'custom-code sandbox READY': cap.get('custom_code_sandbox') is True,
    'GGUF active READY': cap.get('llama_active_analysis') is True,
    'Transformers active READY': cap.get('transformers_active_analysis') is True,
}
failed=[label for label,ok in required.items() if not ok]
if failed:
    print('Capability verification did not establish: '+', '.join(failed), file=sys.stderr)
    raise SystemExit(1)
checks={item.get('name'): item.get('status') for item in doc if isinstance(item,dict)}
for name in ('active-sandbox','llama-active','transformers-active'):
    if checks.get(name) != 'ready':
        raise SystemExit(f'doctor check {name!r} is not ready: {checks.get(name)!r}')
print('Layerfault lab capabilities/doctor: READY')
PY
[[ "$missing" -eq 0 ]] || exit 1
