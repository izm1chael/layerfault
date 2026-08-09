#!/usr/bin/env bash
set -euo pipefail
[[ $# -ge 3 ]] || { echo "Usage: package-release.sh VERSION ARCH BINARY [OUTDIR]" >&2; exit 2; }
VERSION="${1#v}"
ARCH="$2"
BINARY="$3"
OUT="${4:-dist}"
mkdir -p "$OUT"
command -v nfpm >/dev/null 2>&1 || { echo "nfpm is required" >&2; exit 2; }
export LAYERFAULT_PACKAGE_VERSION="$VERSION"
export LAYERFAULT_PACKAGE_ARCH="$ARCH"
export LAYERFAULT_PACKAGE_BINARY="$BINARY"
read -r -a formats <<< "${LAYERFAULT_PACKAGE_FORMATS:-deb rpm apk archlinux}"
for format in "${formats[@]}"; do
  case "$format" in
    deb) ext=deb ;;
    rpm) ext=rpm ;;
    apk) ext=apk ;;
    archlinux) ext=pkg.tar.zst ;;
    *) echo "Unsupported package format: $format" >&2; exit 2 ;;
  esac
  nfpm package -f packaging/nfpm.yaml -p "$format" -t "$OUT/layerfault-linux-${ARCH}.${ext}"
done
