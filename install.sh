#!/usr/bin/env bash
set -euo pipefail

REPO="${LAYERFAULT_GITHUB_REPO:-izm1chael/layerfault}"
MODE="core"
VERSION="latest"
DEVICE="auto"
PREFIX="${LAYERFAULT_PREFIX:-/usr/local}"
LOCAL_BINARY=""
TMP=""

usage() {
  cat <<'EOF'
Layerfault installer

Usage: install.sh [--core|--active|--full] [--version VERSION] [--device auto|cpu|cuda|rocm] [--local-binary PATH]

  --core      Install the Layerfault CLI only (default)
  --active    Install CLI plus Linux sandbox prerequisites and Python active runtime
  --full      Same as --active and also use an existing llama-cli when present
  --version   Release tag/version, or latest
  --device    Active Python runtime preference (auto defaults to CPU unless explicitly configured)
  --local-binary  Install this already-built Layerfault binary instead of downloading a release
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --core) MODE="core" ;;
    --active) MODE="active" ;;
    --full) MODE="full" ;;
    --version) VERSION="${2:?missing version}"; shift ;;
    --device) DEVICE="${2:?missing device}"; shift ;;
    --local-binary) LOCAL_BINARY="${2:?missing local binary}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

case "$DEVICE" in auto|cpu|cuda|rocm) ;; *) echo "Unsupported --device: $DEVICE" >&2; exit 2 ;; esac

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
MACHINE="$(uname -m)"
case "$MACHINE" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $MACHINE" >&2; exit 2 ;;
esac

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing required tool: $1" >&2; exit 2; }; }
need curl
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

release_base="https://github.com/${REPO}/releases"
if [[ "$VERSION" == "latest" ]]; then
  download_base="${release_base}/latest/download"
else
  [[ "$VERSION" == v* ]] || VERSION="v${VERSION}"
  download_base="${release_base}/download/${VERSION}"
fi

checksum_file="$TMP/SHA256SUMS"
fetch_checksums() {
  [[ -s "$checksum_file" ]] && return 0
  curl -fL "${download_base}/SHA256SUMS" -o "$checksum_file"
}

verify_download() {
  local file="$1" name expected actual
  name="$(basename "$file")"
  fetch_checksums
  expected="$(awk -v n="$name" '$2 == n || $2 == "*" n {print $1; exit}' "$checksum_file")"
  [[ -n "$expected" ]] || { echo "No SHA-256 entry for $name in release SHA256SUMS" >&2; exit 1; }
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$file" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "$file" | awk '{print $1}')"
  else
    echo "Neither sha256sum nor shasum is available for release verification" >&2
    exit 2
  fi
  [[ "$actual" == "$expected" ]] || { echo "SHA-256 verification failed for $name" >&2; exit 1; }
}

download_asset() {
  local name="$1" dest="$TMP/$name"
  curl -fL "${download_base}/${name}" -o "$dest"
  verify_download "$dest"
  printf '%s\n' "$dest"
}

install_linux_core() {
  local asset=""
  if command -v dpkg >/dev/null 2>&1 && command -v apt-get >/dev/null 2>&1; then
    asset="layerfault-linux-${ARCH}.deb"
    package_path="$(download_asset "$asset")"
    apt-get install -y "$package_path"
    return
  fi
  if command -v rpm >/dev/null 2>&1 && command -v dnf >/dev/null 2>&1; then
    asset="layerfault-linux-${ARCH}.rpm"
    package_path="$(download_asset "$asset")"
    dnf install -y "$package_path"
    return
  fi
  if command -v apk >/dev/null 2>&1; then
    asset="layerfault-linux-${ARCH}.apk"
    package_path="$(download_asset "$asset")"
    apk add --allow-untrusted "$package_path"
    return
  fi
  if command -v pacman >/dev/null 2>&1; then
    asset="layerfault-linux-${ARCH}.pkg.tar.zst"
    package_path="$(download_asset "$asset")"
    pacman -U --noconfirm "$package_path"
    return
  fi
  asset="layerfault-linux-${ARCH}.tar.gz"
  archive="$(download_asset "$asset")"
  tar -xzf "$archive" -C "$TMP"
  install -d "${PREFIX}/bin"
  install -m 0755 "$TMP/layerfault" "${PREFIX}/bin/layerfault"
}

install_macos_core() {
  local asset="layerfault-macos-universal.tar.gz"
  archive="$(download_asset "$asset")"
  tar -xzf "$archive" -C "$TMP"
  install -d "${PREFIX}/bin"
  install -m 0755 "$TMP/layerfault" "${PREFIX}/bin/layerfault"
}

if [[ -n "$LOCAL_BINARY" ]]; then
  [[ -f "$LOCAL_BINARY" && -x "$LOCAL_BINARY" ]] || { echo "--local-binary must point to an executable file" >&2; exit 2; }
  if [[ "$(id -u)" -ne 0 && "$OS" == "linux" ]]; then
    echo "Linux system installation must run as root." >&2
    exit 2
  fi
  install -d "${PREFIX}/bin"
  install -m 0755 "$LOCAL_BINARY" "${PREFIX}/bin/layerfault"
elif [[ "$OS" == "linux" ]]; then
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "Linux system installation must run as root (for example: curl ... | sudo bash)." >&2
    exit 2
  fi
  install_linux_core
elif [[ "$OS" == "darwin" ]]; then
  install_macos_core
else
  echo "Use install.ps1 or the release ZIP/MSIX on Windows." >&2
  exit 2
fi

if [[ "$MODE" != "core" ]]; then
  if [[ "$OS" != "linux" ]]; then
    echo "Active Bubblewrap analysis is currently Linux-only; core installation completed." >&2
  else
    if [[ -n "$LOCAL_BINARY" && -f "$(dirname "$0")/scripts/install/active-runtime.sh" ]]; then
      runtime_script="$(dirname "$0")/scripts/install/active-runtime.sh"
      requirements="$(dirname "$0")/packaging/active-requirements.txt"
      llama_args=()
      [[ "$MODE" == "full" ]] && llama_args+=(--llama auto)
      if [[ -f "$requirements" ]]; then
        "$runtime_script" --device "$DEVICE" --requirements "$requirements" "${llama_args[@]}"
      else
        "$runtime_script" --device "$DEVICE" "${llama_args[@]}"
      fi
    else
      runtime_script="$(download_asset install-active-runtime.sh)"
      chmod +x "$runtime_script"
      requirements="$(download_asset active-requirements.txt)"
      llama_args=()
      [[ "$MODE" == "full" ]] && llama_args+=(--llama auto)
      "$runtime_script" --device "$DEVICE" --requirements "$requirements" "${llama_args[@]}"
    fi
  fi
fi

echo
LAYERFAULT_CMD="$(command -v layerfault 2>/dev/null || true)"
if [[ -x "${PREFIX}/bin/layerfault" ]]; then
  LAYERFAULT_CMD="${PREFIX}/bin/layerfault"
fi
[[ -n "$LAYERFAULT_CMD" ]] || { echo "Layerfault was installed but the executable could not be resolved" >&2; exit 1; }
"$LAYERFAULT_CMD" --version
"$LAYERFAULT_CMD" capabilities || true
"$LAYERFAULT_CMD" doctor || true
