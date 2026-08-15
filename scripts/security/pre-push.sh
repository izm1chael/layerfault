#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# Concurrent Rust linkers can saturate local disks because each integration
# test is a separate large executable. Keep the publication gate exhaustive,
# but bound build concurrency. Override explicitly on faster build hosts.
BUILD_JOBS="${LAYERFAULT_BUILD_JOBS:-4}"

log() { printf '\n==> %s\n' "$*"; }
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

log "Repository publication invariants"
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

log "Repository architecture substance gate"
bash scripts/security/architecture-gates.sh "$ROOT"

log "Rust formatting / compile / tests / Clippy"
cargo fmt --all -- --check
cargo check --locked --all-targets --jobs "$BUILD_JOBS"
cargo test --locked --all-targets --jobs "$BUILD_JOBS"
cargo clippy --locked --all-targets --all-features --jobs "$BUILD_JOBS" -- -D warnings

log "Layerfault security and schema contracts"
bash scripts/security/gates.sh
python3 scripts/security/schema-gates.py --binary target/debug/layerfault --sarif-fixture tests/corpus/pickle/benign_opcodes.pkl

log "Dependency lock requirements"
python3 - <<'PY'
from pathlib import Path
import re
text = Path('Cargo.lock').read_text()

def versions(name):
    found = re.findall(
        r'\[\[package\]\]\nname = "' + re.escape(name) + r'"\nversion = "([^"]+)"',
        text,
    )
    if not found:
        raise SystemExit(f'{name} is not present in Cargo.lock')
    return [tuple(int(x) for x in value.split('-')[0].split('.')[:3]) for value in found]

def version(name):
    return max(versions(name))

if version('anyhow') < (1, 0, 103):
    raise SystemExit('Cargo.lock still contains vulnerable anyhow < 1.0.103')
if version('crossbeam-epoch') < (0, 9, 20):
    raise SystemExit('Cargo.lock still contains vulnerable crossbeam-epoch < 0.9.20')

# Layerfault itself must remain on the maintained indicatif line. Embedded
# inference currently resolves an additional 0.17.x copy through hf-hub /
# tokenizers; RUSTSEC-2025-0119 marks its number_prefix dependency unmaintained,
# not memory-unsafe. Keep that transitive debt visible without pretending the
# lock graph is already clean.
manifest = Path('Cargo.toml').read_text()
if not re.search(r'^indicatif\s*=\s*"0\.18\.6"\s*$', manifest, re.M):
    raise SystemExit('Cargo.toml direct indicatif dependency must remain pinned to 0.18.6')
if max(versions('indicatif')) < (0, 18, 6):
    raise SystemExit('Cargo.lock does not contain maintained indicatif >= 0.18.6')
if re.search(r'\[\[package\]\]\nname = "number_prefix"\n', text):
    print('WARN: Cargo.lock retains transitive number_prefix via embedded-inference dependencies (RUSTSEC-2025-0119 informational/unmaintained)')

# Layerfault standardises native networking/TLS on Rustls so a normal Linux build does
# not require libssl-dev/pkg-config/system OpenSSL. If openssl-sys or native-tls
# re-enter the default dependency graph, fail loudly rather than silently regressing
# portability; approve any genuinely unavoidable exception here explicitly.
APPROVED_OPENSSL_EXCEPTIONS = set()
for name in ('openssl-sys', 'native-tls'):
    if name in APPROVED_OPENSSL_EXCEPTIONS:
        continue
    if re.search(r'\[\[package\]\]\nname = "' + re.escape(name) + r'"\n', text):
        raise SystemExit(
            f'Cargo.lock unexpectedly contains {name}; the normal Linux build must not '
            'require system OpenSSL. Run `cargo tree -i ' + name + '` to find the offending '
            'dependency and standardise it on rustls, or add a documented, reviewed exception.'
        )
PY

if command -v osv-scanner >/dev/null 2>&1; then
  log "OSV-Scanner"
  OSV_REPORT="$(mktemp)"
  if ! osv-scanner scan source --format json --output-file "$OSV_REPORT" .; then
    python3 - "$OSV_REPORT" <<'PY'
import json
from pathlib import Path
import sys

approved_unmaintained = {
    'RUSTSEC-2024-0436',
    'RUSTSEC-2025-0075',
    'RUSTSEC-2025-0080',
    'RUSTSEC-2025-0081',
    'RUSTSEC-2025-0090',
    'RUSTSEC-2025-0098',
    'RUSTSEC-2025-0100',
    'RUSTSEC-2025-0119',
}
report = json.loads(Path(sys.argv[1]).read_text())
observed = {
    vulnerability['id']
    for result in report.get('results', [])
    for package in result.get('packages', [])
    for vulnerability in package.get('vulnerabilities', [])
}
for advisory in sorted(observed & approved_unmaintained):
    print(f'WARN: OSV reports approved unmaintained transitive advisory {advisory}')
blocking = observed - approved_unmaintained
if blocking:
    raise SystemExit(
        'OSV reports unreviewed advisories: ' + ', '.join(sorted(blocking))
    )
PY
  fi
  rm -f "$OSV_REPORT"
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
