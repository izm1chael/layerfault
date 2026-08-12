#!/usr/bin/env bash
set -euo pipefail

[[ $# -eq 2 ]] || { echo "Usage: build-linux-release.sh gnu|musl OUTPUT" >&2; exit 2; }
FLAVOUR="$1"
OUTPUT="$2"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TOOLCHAIN="$(awk -F'"' '/^[[:space:]]*channel[[:space:]]*=/{print $2; exit}' "$ROOT/rust-toolchain.toml")"
[[ -n "$TOOLCHAIN" ]] || { echo "Unable to resolve pinned Rust toolchain" >&2; exit 2; }
command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 2; }
mkdir -p "$(dirname "$OUTPUT")"

case "$FLAVOUR" in
  gnu)
    IMAGE="almalinux:9"
    SETUP='dnf install -y gcc gcc-c++ make cmake perl pkgconf-pkg-config curl ca-certificates python3 >/dev/null'
    TARGET_DIR=/src/target/distribution-gnu
    ;;
  musl)
    IMAGE="alpine:3.21"
    SETUP='apk add --no-cache build-base cmake perl pkgconf curl ca-certificates python3 >/dev/null'
    TARGET_DIR=/src/target/distribution-musl
    ;;
  *) echo "Unsupported Linux release flavour: $FLAVOUR" >&2; exit 2 ;;
esac

# Build natively inside the target libc family. The release workflow runs this
# on matching amd64/arm64 hosts, so no emulation/cross-compiler ambiguity is
# introduced into security release artifacts.
docker run --rm \
  -e "RUST_TOOLCHAIN=$TOOLCHAIN" \
  -e "CARGO_TARGET_DIR=$TARGET_DIR" \
  -v "$ROOT:/src" \
  -w /src \
  "$IMAGE" \
  /bin/sh -lc "$SETUP; curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain \"\$RUST_TOOLCHAIN\" >/dev/null; export PATH=\"\$HOME/.cargo/bin:\\$PATH\"; cargo +\"\$RUST_TOOLCHAIN\" build --release --locked"

SOURCE="$ROOT/${TARGET_DIR#/src/}/release/layerfault"
[[ -x "$SOURCE" ]] || { echo "Expected release binary missing: $SOURCE" >&2; exit 1; }
cp "$SOURCE" "$OUTPUT"
chmod 0755 "$OUTPUT"
