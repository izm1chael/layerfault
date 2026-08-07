#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

log() { printf '\n==> %s\n' "$*"; }
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

log "Repository publication invariants"
python3 - <<'PY'
from pathlib import Path
owner_typo = 'izm1c' + 'xhael'
fake_key = 'AKIA' + 'ABCDEFGHIJKLMNOP'
for path in [Path('Cargo.toml'), Path('README.md'), Path('SECURITY.md')]:
    if owner_typo in path.read_text():
        raise SystemExit(f'{path}: stale repository-owner typo found')
for path in list(Path('src').rglob('*.rs')) + list(Path('tests').rglob('*.rs')) + [Path('create_poisoned_model.sh')]:
    if fake_key in path.read_text(errors='replace'):
        raise SystemExit(f'{path}: credential-shaped fixture literal found; construct detector fixtures at runtime')
PY

python3 - <<'PY'
from pathlib import Path
import re
for path in Path('.github/workflows').glob('*.yml'):
    text = path.read_text()
    for lineno, line in enumerate(text.splitlines(), 1):
        m = re.search(r'uses:\s*[^\s@]+@([^\s#]+)', line)
        if m and not re.fullmatch(r'[0-9a-fA-F]{40}', m.group(1)):
            raise SystemExit(f'{path}:{lineno}: action is not pinned to a full 40-character SHA: {m.group(1)}')

dep = Path('.github/dependabot.yml').read_text()
entries = dep.count('package-ecosystem:')
if dep.count('default-days: 7') != entries:
    raise SystemExit('every Dependabot package-ecosystem entry must have cooldown.default-days: 7')

suppressions = 0
for path in Path('src').rglob('*.rs'):
    suppressions += path.read_text().count('nosemgrep:')
if suppressions != 18:
    raise SystemExit(f'expected exactly 18 reviewed nosemgrep annotations, found {suppressions}; review docs/STATIC_ANALYSIS.md before changing the exception surface')
PY

log "Rust formatting / compile / tests / Clippy"
cargo fmt --all -- --check
cargo check --locked --all-targets
cargo test --locked --all-targets
cargo clippy --locked --all-targets --all-features -- -D warnings

log "Layerfault security and schema contracts"
bash scripts/security-gates.sh
python3 scripts/schema-gates.py --binary target/debug/layerfault

log "Dependency lock requirements"
python3 - <<'PY'
from pathlib import Path
import re
text = Path('Cargo.lock').read_text()

def version(name):
    m = re.search(r'\[\[package\]\]\nname = "' + re.escape(name) + r'"\nversion = "([^"]+)"', text)
    if not m:
        raise SystemExit(f'{name} is not present in Cargo.lock')
    return tuple(int(x) for x in m.group(1).split('-')[0].split('.')[:3])

if version('anyhow') < (1, 0, 103):
    raise SystemExit('Cargo.lock still contains vulnerable anyhow < 1.0.103')
if version('crossbeam-epoch') < (0, 9, 20):
    raise SystemExit('Cargo.lock still contains vulnerable crossbeam-epoch < 0.9.20')
if version('indicatif') < (0, 18, 6):
    raise SystemExit('Cargo.lock still contains indicatif < 0.18.6')
if re.search(r'\[\[package\]\]\nname = "number_prefix"\n', text):
    raise SystemExit('Cargo.lock still contains unmaintained number_prefix')
PY

if command -v osv-scanner >/dev/null 2>&1; then
  log "OSV-Scanner"
  osv-scanner scan source .
else
  echo "WARN: osv-scanner is not installed; skipping local OSV gate" >&2
fi

if cargo audit --version >/dev/null 2>&1; then
  log "cargo-audit"
  cargo audit
else
  echo "WARN: cargo-audit is not installed; skipping local RustSec gate" >&2
fi

if command -v semgrep >/dev/null 2>&1; then
  log "Semgrep (auto rules; reviewed nosemgrep annotations honored)"
    semgrep scan --config auto --error .
else
  echo "WARN: semgrep is not installed; skipping local Semgrep gate" >&2
fi

log "Pre-push security gates passed"
