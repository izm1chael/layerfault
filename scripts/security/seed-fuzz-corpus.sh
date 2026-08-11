#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
cd "$ROOT"

CORPUS_MANIFEST="$ROOT/tests/corpus/manifest.json"
if [[ ! -f "$CORPUS_MANIFEST" ]]; then
    python3 "$ROOT/scripts/security/generate_corpus.py" >/dev/null
fi

FUZZ_CORPUS_DIR="$ROOT/fuzz/corpus"
mkdir -p "$FUZZ_CORPUS_DIR"

echo "=== Seeding libFuzzer targets from the differential parser test corpus ==="
python3 - "$CORPUS_MANIFEST" "$FUZZ_CORPUS_DIR" <<'PY'
import json, sys, shutil, pathlib

manifest_path = pathlib.Path(sys.argv[1])
fuzz_dir = pathlib.Path(sys.argv[2])
corpus_root = manifest_path.parent

with open(manifest_path) as f:
    manifest = json.load(f)

count = 0
for fixture in manifest.get("fixtures", []):
    fmt = fixture["format"]
    rel_path = fixture["path"]
    src_file = corpus_root / rel_path
    
    if src_file.exists():
        target_dir = fuzz_dir / fmt
        target_dir.mkdir(parents=True, exist_ok=True)
        dst_file = target_dir / f"seed_{fixture['id']}_{src_file.name}"
        shutil.copy2(src_file, dst_file)
        count += 1

print(f"Successfully seeded {count} valid corpus fixtures into {fuzz_dir}")
PY
