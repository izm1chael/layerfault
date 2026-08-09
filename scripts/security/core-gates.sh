#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
cd "$ROOT"

for cmd in cargo python3 openssl; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "SKIP: $cmd is required for core-security-gates.sh" >&2; exit 77; }
done

cargo build --locked --quiet
BIN="$ROOT/target/debug/layerfault"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
STORE="$TMP/models"
CFG="$TMP/config"
FAKEBIN="$TMP/bin"
mkdir -p "$STORE/blobs" "$STORE/manifests/registry.ollama.ai/library/fixture" "$CFG" "$FAKEBIN"
export LAYERFAULT_CONFIG_DIR="$CFG"

python3 - "$STORE" <<'PY'
import hashlib, json, pathlib, sys
root=pathlib.Path(sys.argv[1])
blob=b"You are a benign local test fixture."
digest="sha256:"+hashlib.sha256(blob).hexdigest()
(root/"blobs"/digest.replace(":","-")).write_bytes(blob)
manifest={"schemaVersion":2,"layers":[{"mediaType":"application/vnd.ollama.image.template","digest":digest,"size":len(blob)}]}
(root/"manifests/registry.ollama.ai/library/fixture/latest").write_text(json.dumps(manifest,separators=(",",":")))
PY

openssl genpkey -algorithm ED25519 -out "$TMP/private.pem" >/dev/null 2>&1
openssl pkey -in "$TMP/private.pem" -pubout -out "$TMP/public.pem" >/dev/null 2>&1

"$BIN" trust add --name fixture-publisher --public-key "$TMP/public.pem" --namespace 'registry.ollama.ai/library/*'
"$BIN" attest sign fixture --private-key "$TMP/private.pem" --ollama-dir "$STORE"
"$BIN" verify fixture --policy strict --ollama-dir "$STORE" >/dev/null

"$BIN" baseline create --name gate --ollama-dir "$STORE" >/dev/null
"$BIN" baseline verify --name gate --ollama-dir "$STORE" >/dev/null
"$BIN" audit --deep --policy strict --ollama-dir "$STORE" >/dev/null

cat > "$FAKEBIN/ollama" <<'SH'
#!/usr/bin/env bash
if [[ "${1:-}" == "--version" ]]; then echo "ollama version is 0.17.1"; exit 0; fi
printf '%s\n' "$*" > "${LAYERFAULT_FAKE_OLLAMA_LOG:?}"
SH
chmod +x "$FAKEBIN/ollama"
export LAYERFAULT_FAKE_OLLAMA_LOG="$TMP/ollama.log"
PATH="$FAKEBIN:$PATH" "$BIN" run fixture --policy strict --ollama-dir "$STORE" -- hello >/dev/null
[[ "$(cat "$TMP/ollama.log")" == "run fixture hello" ]] || { echo "guarded run did not invoke expected ollama command" >&2; exit 1; }

# Policy-only blocks may be overridden only with a recorded reason. Remove the
# attestation temporarily so strict policy blocks an otherwise benign model.
ATT_PATH="$(find "$STORE/blobs" -maxdepth 1 -name '*.attestation.json' -print -quit)"
[[ -n "$ATT_PATH" ]] || { echo "attestation envelope not found" >&2; exit 1; }
mv "$ATT_PATH" "$TMP/attestation.json"
set +e
PATH="$FAKEBIN:$PATH" "$BIN" run fixture --policy strict --ollama-dir "$STORE" >/dev/null 2>&1
NO_OVERRIDE_RC=$?
set -e
[[ "$NO_OVERRIDE_RC" -eq 4 ]] || { echo "strict unsigned model should be policy-blocked with 4, got $NO_OVERRIDE_RC" >&2; exit 1; }
PATH="$FAKEBIN:$PATH" "$BIN" run fixture --policy strict --ollama-dir "$STORE" --override-reason "Temporary approved offline test" >/dev/null
[[ -s "$CFG/override-audit.jsonl" ]] || { echo "policy override audit record was not written" >&2; exit 1; }
mv "$TMP/attestation.json" "$ATT_PATH"

ID="$($BIN quarantine put fixture --ollama-dir "$STORE" --no-scan | sed -n 's/.* as \([^ ]*\) (.*/\1/p')"
[[ -n "$ID" ]] || { echo "could not capture quarantine id" >&2; exit 1; }
"$BIN" quarantine list --ollama-dir "$STORE" --json | python3 -c 'import json,sys; data=json.load(sys.stdin); assert len(data)==1'
"$BIN" quarantine restore "$ID" --ollama-dir "$STORE" >/dev/null
"$BIN" verify fixture --policy strict --ollama-dir "$STORE" >/dev/null

"$BIN" trust revoke fixture-publisher >/dev/null
set +e
"$BIN" verify fixture --policy strict --ollama-dir "$STORE" >/dev/null 2>&1
REVOKED_RC=$?
set -e
[[ "$REVOKED_RC" -eq 3 ]] || { echo "revoked key should produce blocking provenance failure (3), got $REVOKED_RC" >&2; exit 1; }
"$BIN" trust unrevoke fixture-publisher >/dev/null
"$BIN" verify fixture --policy strict --ollama-dir "$STORE" >/dev/null

echo "PASS: Layerfault synthetic trust/policy/enforcement/baseline/audit/quarantine gate"
