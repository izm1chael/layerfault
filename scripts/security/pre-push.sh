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
bash scripts/security/repo-invariants.sh

log "Repository architecture substance gate"
bash scripts/security/architecture-gates.sh "$ROOT"

# Clippy type-checks everything `cargo check` does on top of its own lints,
# so running both back to back pays the compile cost twice for no extra
# coverage; Clippy alone is the exhaustive one.
log "Rust formatting / Clippy"
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features --jobs "$BUILD_JOBS" -- -D warnings

# Full CI (fuzz-smoke.yml) already runs every target for the full 60s on a
# schedule; this local gate only needs to catch a target that's freshly
# broken, not find new crashes, so it runs much shorter and with a fixed
# seed so a failure is reproducible run to run instead of you fighting
# libFuzzer's own randomness on top of debugging the actual failure.
log "All-target fuzz smoke (shortened, deterministic seed)"
FUZZ_SMOKE_SECONDS_PER_TARGET="${FUZZ_SMOKE_SECONDS_PER_TARGET:-8}" \
FUZZ_SMOKE_SEED="${FUZZ_SMOKE_SEED:-1}" \
  bash fuzz/smoke.sh

# Run timing-sensitive regression checks before the exhaustive test suite can
# leave the host under sustained CPU or disk pressure.
log "Layerfault security and performance contracts"
bash scripts/security/gates.sh

log "Exhaustive Rust tests and schema contracts"
cargo test --locked --all-targets --jobs "$BUILD_JOBS"
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
  # `cargo audit` re-fetches the whole RustSec advisory-db git repo on every
  # invocation by default. The advisory set doesn't change push-to-push, so
  # cache it locally and only re-fetch once the cache is older than the TTL
  # (still always re-fetched fresh on a cold cache, e.g. in CI).
  AUDIT_DB_DIR="${CARGO_AUDIT_DB_PATH:-${CARGO_HOME:-$HOME/.cargo}/advisory-db}"
  AUDIT_DB_MARKER="$AUDIT_DB_DIR/.layerfault-last-fetch"
  AUDIT_DB_TTL_SECONDS="${LAYERFAULT_AUDIT_DB_TTL_SECONDS:-86400}"
  if [[ -f "$AUDIT_DB_MARKER" ]] \
    && [[ $(( $(date +%s) - $(date -r "$AUDIT_DB_MARKER" +%s 2>/dev/null || echo 0) )) -lt "$AUDIT_DB_TTL_SECONDS" ]]; then
    log "cargo-audit (advisory DB cached; skipping fetch)"
    cargo audit --no-fetch
  else
    log "cargo-audit (refreshing advisory DB)"
    cargo audit
    touch "$AUDIT_DB_MARKER"
  fi
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
