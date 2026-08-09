#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 2; }
command -v nfpm >/dev/null 2>&1 || { echo "nfpm is required (https://nfpm.goreleaser.com/)" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 2; }

VERSION="$(python3 - <<'PY'
import tomllib
with open('Cargo.toml','rb') as f: print(tomllib.load(f)['package']['version'])
PY
)"
case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "Unsupported release architecture: $(uname -m)" >&2; exit 2 ;;
esac
OUT="${1:-dist-dry-run}"
rm -rf "$OUT"
mkdir -p "$OUT/build" "$OUT/root-gnu" "$OUT/root-musl"

bash scripts/build/linux-release.sh gnu "$OUT/build/layerfault-gnu"
bash scripts/build/linux-release.sh musl "$OUT/build/layerfault-musl"
bash scripts/build/cli-assets.sh "$ROOT" "$ROOT/$OUT/build/layerfault-gnu"
cp "$OUT/build/layerfault-gnu" "$OUT/root-gnu/layerfault"
cp "$OUT/build/layerfault-musl" "$OUT/root-musl/layerfault"
formats="deb rpm"
[[ "$ARCH" == amd64 ]] && formats="$formats archlinux"
LAYERFAULT_PACKAGE_FORMATS="$formats" bash scripts/package/release.sh "$VERSION" "$ARCH" "$ROOT/$OUT/root-gnu/layerfault" "$OUT"
LAYERFAULT_PACKAGE_FORMATS="apk" bash scripts/package/release.sh "$VERSION" "$ARCH" "$ROOT/$OUT/root-musl/layerfault" "$OUT"
tar -C "$OUT/root-musl" -czf "$OUT/layerfault-linux-${ARCH}.tar.gz" layerfault
python3 scripts/build/sbom.py "$OUT/layerfault-linux-${ARCH}.sbom.cdx.json"

# Native compatibility smoke tests. Arch Linux is x86_64-only in this release
# matrix; ARM64 users receive the portable musl archive instead.
docker run --rm -v "$ROOT/$OUT:/dist:ro" ubuntu:22.04 bash -lc "apt-get update >/dev/null && apt-get install -y /dist/layerfault-linux-${ARCH}.deb >/dev/null && layerfault selftest --json >/dev/null"
docker run --rm -v "$ROOT/$OUT:/dist:ro" debian:12 bash -lc "apt-get update >/dev/null && apt-get install -y /dist/layerfault-linux-${ARCH}.deb >/dev/null && layerfault selftest --json >/dev/null"
docker run --rm -v "$ROOT/$OUT:/dist:ro" almalinux:9 bash -lc "dnf install -y /dist/layerfault-linux-${ARCH}.rpm >/dev/null && layerfault selftest --json >/dev/null"
docker run --rm -v "$ROOT/$OUT:/dist:ro" alpine:3.21 sh -lc "apk add --allow-untrusted /dist/layerfault-linux-${ARCH}.apk >/dev/null && layerfault selftest --json >/dev/null"
if [[ "$ARCH" == amd64 ]]; then
  docker run --rm -v "$ROOT/$OUT:/dist:ro" archlinux:latest bash -lc "pacman -Sy --noconfirm >/dev/null && pacman -U --noconfirm /dist/layerfault-linux-amd64.pkg.tar.zst >/dev/null && layerfault selftest --json >/dev/null"
fi
docker run --rm -v "$ROOT/$OUT/root-musl:/portable:ro" alpine:3.21 /portable/layerfault selftest --json >/dev/null
docker run --rm -v "$ROOT/$OUT/root-musl:/portable:ro" ubuntu:22.04 /portable/layerfault selftest --json >/dev/null
(
  cd "$OUT"
  sha256sum layerfault-linux-* > SHA256SUMS
)
echo "Distribution dry run PASS: $ROOT/$OUT"
