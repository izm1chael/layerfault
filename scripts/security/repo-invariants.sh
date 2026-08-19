#!/usr/bin/env bash
# Fast, build-free repository invariant checks shared by pre-commit and
# pre-push. Pure static analysis over files already on disk: no compile, no
# network, no fuzz build. Kept as its own script so pre-commit can run it
# without paying for anything pre-push-only needs.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

python3 - <<'PY'
from pathlib import Path
import re
owner_typo = 'izm1c' + 'xhael'
fake_key = 'AKIA' + 'ABCDEFGHIJKLMNOP'
for path in [Path('Cargo.toml'), Path('README.md'), Path('SECURITY.md')]:
    if owner_typo in path.read_text():
        raise SystemExit(f'{path}: stale repository-owner typo found')
for path in list(Path('src').rglob('*.rs')) + list(Path('tests').rglob('*.rs')) + [Path('scripts/fixtures/create-poisoned-ollama-model.sh')]:
    if fake_key in path.read_text(errors='replace'):
        raise SystemExit(f'{path}: credential-shaped fixture literal found; construct detector fixtures at runtime')

dockerfile = Path('Dockerfile').read_text()
external_asset_roots = set()
for source in Path('src').rglob('*.rs'):
    for relative in re.findall(r'include_(?:str|bytes)!\("([^"]+)"\)', source.read_text()):
        asset = (source.parent / relative).resolve()
        try:
            repository_relative = asset.relative_to(Path.cwd().resolve())
        except ValueError:
            raise SystemExit(f'{source}: compile-time asset escapes the repository: {relative}')
        if repository_relative.parts[0] != 'src':
            external_asset_roots.add(repository_relative.parts[0])
for root in sorted(external_asset_roots):
    if not re.search(rf'^COPY\s+{re.escape(root)}\s+\./{re.escape(root)}\s*$', dockerfile, re.M):
        raise SystemExit(
            f'Dockerfile must copy compile-time asset root {root!r} referenced by Rust include macros'
        )
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
if suppressions != 34:
    raise SystemExit(f'expected exactly 34 reviewed nosemgrep annotations, found {suppressions}; review docs/STATIC_ANALYSIS.md before changing the exception surface')
PY

# Operational shell scripts should at least parse. Deliberately malformed
# shell fixtures under tests/ (used to exercise the unparseable-shell
# detector) are excluded on purpose, not an oversight.
while IFS= read -r -d '' script; do
  bash -n "$script"
done < <(git ls-files -z -- '*.sh' ':!:tests/**')
