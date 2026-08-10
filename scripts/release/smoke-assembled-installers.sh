#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-release-assets}"
fail(){ echo "release installer smoke: $*" >&2; exit 1; }
[[ -f "$ROOT/install.sh" ]] || fail "missing install.sh"
[[ -f "$ROOT/install-active-runtime.sh" ]] || fail "missing install-active-runtime.sh"
[[ -f "$ROOT/active-requirements.txt" ]] || fail "missing active-requirements.txt"
grep -q 'download_asset install-active-runtime.sh' "$ROOT/install.sh" || fail "install.sh does not request published active-runtime asset"
bash -n "$ROOT/install.sh"
bash -n "$ROOT/install-active-runtime.sh"
# Verify that every release-time active support asset requested by install.sh is
# present in the assembled directory without performing network/package installs.
python3 - "$ROOT" <<'PY'
from pathlib import Path
import re, sys
root=Path(sys.argv[1])
text=(root/'install.sh').read_text()
required=set(re.findall(r'download_asset\s+([A-Za-z0-9._-]+)', text))
for name in sorted(required & {'install-active-runtime.sh','active-requirements.txt'}):
    if not (root/name).is_file():
        raise SystemExit(f'missing assembled installer dependency: {name}')
print('release installer smoke: PASS')
PY
