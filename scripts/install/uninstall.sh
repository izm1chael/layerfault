#!/usr/bin/env bash
set -euo pipefail
PURGE_RUNTIME=0
PURGE_DATA=0
for arg in "$@"; do
  case "$arg" in
    --purge-runtime) PURGE_RUNTIME=1 ;;
    --purge-data) PURGE_DATA=1 ;;
    -h|--help) echo "Usage: uninstall.sh [--purge-runtime] [--purge-data]"; exit 0 ;;
    *) echo "Unknown argument: $arg" >&2; exit 2 ;;
  esac
done
[[ "$(id -u)" -eq 0 ]] || { echo "Run as root" >&2; exit 2; }
rm -f /usr/local/bin/layerfault /usr/bin/layerfault
rm -f /etc/profile.d/layerfault-runtime.sh
if [[ "$PURGE_RUNTIME" -eq 1 ]]; then rm -rf /opt/layerfault/runtimes; fi
if [[ "$PURGE_DATA" -eq 1 ]]; then rm -rf /var/cache/layerfault /var/lib/layerfault /etc/layerfault; fi
echo "Layerfault removed. Package-manager metadata may still list the package; prefer the native package manager when Layerfault was installed from DEB/RPM/APK/Arch."
