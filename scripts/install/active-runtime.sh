#!/usr/bin/env bash
set -euo pipefail
DEVICE="auto"
REQUIREMENTS=""
LLAMA="none"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --device) DEVICE="${2:?missing device}"; shift ;;
    --requirements) REQUIREMENTS="${2:?missing requirements path}"; shift ;;
    --llama) LLAMA="${2:?missing llama mode}"; shift ;;
    -h|--help) echo "Usage: install-active-runtime.sh [--device auto|cpu|cuda|rocm] [--requirements FILE] [--llama none|auto]"; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done
case "$LLAMA" in none|auto) ;; *) echo "Unsupported --llama mode: $LLAMA" >&2; exit 2 ;; esac
[[ "$(uname -s)" == "Linux" ]] || { echo "Active runtime bootstrap is currently Linux-only" >&2; exit 2; }
[[ "$(id -u)" -eq 0 ]] || { echo "Run as root" >&2; exit 2; }

install_packages() {
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends bubblewrap strace util-linux python3 python3-venv ca-certificates curl
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y bubblewrap strace util-linux python3 python3-pip ca-certificates curl
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache bubblewrap strace util-linux python3 py3-pip ca-certificates curl
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm bubblewrap strace util-linux python python-pip ca-certificates curl
  else
    echo "Unsupported package manager. Install bwrap, strace, prlimit, python3 and venv support manually." >&2
    exit 2
  fi
}
install_packages

python_supported() {
  local candidate="$1"
  command -v "$candidate" >/dev/null 2>&1 || return 1
  "$candidate" - <<'PYVER' >/dev/null 2>&1
import sys
raise SystemExit(0 if sys.version_info >= (3, 10) else 1)
PYVER
}

PYTHON_BIN=""
for candidate in python3.13 python3.12 python3.11 python3.10 python3; do
  if python_supported "$candidate"; then PYTHON_BIN="$(command -v "$candidate")"; break; fi
done
if [[ -z "$PYTHON_BIN" ]] && command -v dnf >/dev/null 2>&1; then
  dnf install -y python3.11 python3.11-pip >/dev/null 2>&1 || true
  if python_supported python3.11; then PYTHON_BIN="$(command -v python3.11)"; fi
fi

RUNTIME_ROOT="${LAYERFAULT_RUNTIME_ROOT:-/opt/layerfault/runtimes}"
PYTHON_DIR="$RUNTIME_ROOT/python"
mkdir -p "$RUNTIME_ROOT"
TRANSFORMERS_READY=0

# Official PyTorch wheels are glibc-oriented; do not pretend that the managed
# Transformers runtime is portable to musl/Alpine. The core scanner and
# Bubblewrap sandbox still install there, and users may point Layerfault at a
# separately validated local runtime.
if command -v apk >/dev/null 2>&1; then
  echo "NOTE: managed Torch/Transformers runtime is not auto-installed on Alpine/musl; static scanning and sandbox prerequisites remain available."
elif [[ -z "$PYTHON_BIN" ]]; then
  echo "NOTE: managed Transformers runtime requires Python 3.10+; no suitable distro interpreter was found. Static scanning and sandbox prerequisites remain available."
else
  "$PYTHON_BIN" -m venv "$PYTHON_DIR"
  "$PYTHON_DIR/bin/python" -m pip install --upgrade pip wheel
  case "$DEVICE" in
    auto|cpu)
      "$PYTHON_DIR/bin/python" -m pip install --index-url https://download.pytorch.org/whl/cpu 'torch==2.13.0'
      ;;
    cuda|rocm)
      [[ -n "${LAYERFAULT_TORCH_INDEX_URL:-}" ]] || {
        echo "$DEVICE requested. Set LAYERFAULT_TORCH_INDEX_URL to the PyTorch wheel index validated for this host (for example a CUDA/ROCm index), then rerun." >&2
        exit 2
      }
      "$PYTHON_DIR/bin/python" -m pip install --index-url "$LAYERFAULT_TORCH_INDEX_URL" 'torch==2.13.0'
      ;;
    *) echo "Unsupported device: $DEVICE" >&2; exit 2 ;;
  esac
  if [[ -n "$REQUIREMENTS" ]]; then
    "$PYTHON_DIR/bin/python" -m pip install -r "$REQUIREMENTS"
  elif [[ -f /usr/share/layerfault/active-requirements.txt ]]; then
    "$PYTHON_DIR/bin/python" -m pip install -r /usr/share/layerfault/active-requirements.txt
  else
    "$PYTHON_DIR/bin/python" -m pip install 'transformers==5.14.1' 'peft==0.19.1' 'safetensors==0.8.0'
  fi
  "$PYTHON_DIR/bin/python" -c 'import torch, transformers, peft, safetensors'
  TRANSFORMERS_READY=1
fi

if [[ "$TRANSFORMERS_READY" -eq 1 ]]; then
  cat >/etc/profile.d/layerfault-runtime.sh <<EOF
export LAYERFAULT_PYTHON_RUNTIME="$PYTHON_DIR/bin/python"
EOF
  chmod 0644 /etc/profile.d/layerfault-runtime.sh
fi

if [[ "$LLAMA" == "auto" ]] && ! command -v llama-cli >/dev/null 2>&1; then
  echo "Attempting distribution-managed llama.cpp installation for GGUF active analysis..."
  if command -v apt-get >/dev/null 2>&1 && apt-cache show llama.cpp >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends llama.cpp || true
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y llama.cpp || true
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache llama.cpp || true
  elif command -v pacman >/dev/null 2>&1; then
    pacman -S --noconfirm llama.cpp || true
  fi
fi
if command -v llama-cli >/dev/null 2>&1; then
  echo "llama-cli detected: $(command -v llama-cli)"
else
  echo "NOTE: llama-cli was not found. GGUF active analysis remains unavailable until a trusted local llama.cpp runtime is installed."
fi

echo "Active runtime installed."
if [[ "$TRANSFORMERS_READY" -eq 1 ]]; then
  LAYERFAULT_PYTHON_RUNTIME="$PYTHON_DIR/bin/python" layerfault capabilities || true
else
  layerfault capabilities || true
fi
