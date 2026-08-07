#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$ROOT"
for cmd in cargo python3 openssl; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "SKIP: $cmd is required" >&2; exit 77; }
done

# Preserve the established Ollama trust/policy/quarantine security contract first.
bash scripts/core-security-gates.sh "$ROOT"
cargo build --locked --quiet
BIN="$ROOT/target/debug/layerfault"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
export LAYERFAULT_CONFIG_DIR="$TMP/config"
mkdir -p "$LAYERFAULT_CONFIG_DIR" "$TMP/bin" "$TMP/artifacts"

python3 - "$TMP/artifacts" <<'PY'
import json,pathlib,struct,sys
root=pathlib.Path(sys.argv[1])
def safe(path, name="w", dtype="U8", n=4):
    header=json.dumps({name:{"dtype":dtype,"shape":[n],"data_offsets":[0,n]}},separators=(",",":"))
    path.write_bytes(struct.pack("<Q",len(header))+header.encode()+bytes(n))
safe(root/"model.safetensors")
safe(root/"model-00001-of-00002.safetensors","a")
safe(root/"model-00002-of-00002.safetensors","b")
(root/"model.safetensors.index.json").write_text(json.dumps({"metadata":{"total_size":8},"weight_map":{"a":"model-00001-of-00002.safetensors","b":"model-00002-of-00002.safetensors"}},separators=(",",":")))
header=json.dumps({"w":{"dtype":"U8","shape":[4],"data_offsets":[1,5]}},separators=(",",":"))
(root/"bad.safetensors").write_bytes(struct.pack("<Q",len(header))+header.encode()+bytes(5))
PY

# Whole-package identity/security is runtime-independent and never executes package code.
mkdir -p "$TMP/package-a" "$TMP/package-b"
cp "$TMP/artifacts/model.safetensors" "$TMP/package-a/model.safetensors"
cp "$TMP/artifacts/model.safetensors" "$TMP/package-b/model.safetensors"
printf '%s
' '{"architectures":["Fixture"],"auto_map":{"AutoModel":"modeling_fixture.Fixture"}}' > "$TMP/package-a/config.json"
cp "$TMP/package-a/config.json" "$TMP/package-b/config.json"
printf '%s
' 'import subprocess
def load(): subprocess.run(["echo","fixture"])' > "$TMP/package-a/modeling_fixture.py"
cp "$TMP/package-a/modeling_fixture.py" "$TMP/package-b/modeling_fixture.py"
FP_A="$($BIN fingerprint "$TMP/package-a" | head -n1)"
FP_B="$($BIN fingerprint "$TMP/package-b" | head -n1)"
[[ "$FP_A" == "$FP_B" && "$FP_A" == lfpkg:sha256:* ]] || { echo "package fingerprint is not location-independent" >&2; exit 1; }
set +e
"$BIN" verify-package "$TMP/package-a" --policy workstation --json > "$TMP/package.json" 2>/dev/null
PACKAGE_RC=$?
set -e
[[ "$PACKAGE_RC" -eq 1 ]] || { echo "custom-code package should warn under workstation policy, got $PACKAGE_RC" >&2; exit 1; }
python3 - "$TMP/package.json" <<'PY2'
import json,sys
x=json.load(open(sys.argv[1])); ids=[m for f in x["package"]["findings"] for m in f.get("matches",[])]
assert any("LF-CODE-AUTO-MAP" in m for m in ids)
assert any("LF-CODE-SUBPROCESS" in m for m in ids)
PY2
printf '\x80\x04malicious-fixture' > "$TMP/package-a/model.pkl"
set +e
"$BIN" inspect "$TMP/package-a" --json >/dev/null 2>&1
PICKLE_RC=$?
set -e
[[ "$PICKLE_RC" -eq 3 ]] || { echo "code-capable serialization should block package inspection, got $PICKLE_RC" >&2; exit 1; }
rm -f "$TMP/package-a/model.pkl"

# Signed scan evidence binds exact results, policy/trust hashes and subject identity.
openssl genpkey -algorithm ED25519 -out "$TMP/evidence.key" >/dev/null 2>&1
openssl pkey -in "$TMP/evidence.key" -pubout -out "$TMP/evidence.pub" >/dev/null 2>&1
"$BIN" trust add --name evidence-gate --public-key "$TMP/evidence.pub" --namespace '*' >/dev/null
"$BIN" verify-file "$TMP/artifacts/model.safetensors" --policy permissive --evidence-out "$TMP/scan-evidence.json" --evidence-key "$TMP/evidence.key" --json >/dev/null || [[ $? -eq 1 ]]
"$BIN" evidence verify "$TMP/scan-evidence.json" >/dev/null
cp "$TMP/scan-evidence.json" "$TMP/tampered-evidence.json"
python3 - "$TMP/tampered-evidence.json" <<'PY2'
import json,sys
p=sys.argv[1]; x=json.load(open(p)); x["payload"]["decision"]="TAMPERED"; open(p,"w").write(json.dumps(x))
PY2
set +e
"$BIN" evidence verify "$TMP/tampered-evidence.json" >/dev/null 2>&1
EVIDENCE_RC=$?
set -e
[[ "$EVIDENCE_RC" -eq 3 ]] || { echo "tampered signed evidence should fail with 3, got $EVIDENCE_RC" >&2; exit 1; }

"$BIN" inspect "$TMP/artifacts/model.safetensors" --json > "$TMP/inspect.json"
python3 - "$TMP/inspect.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1])); assert x["format"]=="safetensors"; assert not any(r["status"]=="Fail" for r in x["results"])
PY
"$BIN" inspect "$TMP/artifacts/model.safetensors.index.json" --json > "$TMP/index.json"
set +e
"$BIN" inspect "$TMP/artifacts/bad.safetensors" --json > "$TMP/bad.json" 2>/dev/null
BAD_RC=$?
set -e
[[ "$BAD_RC" -eq 3 ]] || { echo "malformed Safetensors should block with 3, got $BAD_RC" >&2; exit 1; }

# Source/format policy is independent from structural validity.
cat > "$TMP/lm-policy.json" <<'JSON'
{"version":1,"profile":"workstation","allowed_sources":["lmstudio"],"allowed_formats":["safetensors"]}
JSON
"$BIN" policy lint "$TMP/lm-policy.json" >/dev/null
set +e
"$BIN" verify-file "$TMP/artifacts/model.safetensors" --policy-file "$TMP/lm-policy.json" --source file --json >/dev/null 2>&1
FILE_POLICY_RC=$?
set -e
[[ "$FILE_POLICY_RC" -eq 4 ]] || { echo "source policy should block file source with 4, got $FILE_POLICY_RC" >&2; exit 1; }
"$BIN" verify-file "$TMP/artifacts/model.safetensors" --policy-file "$TMP/lm-policy.json" --source lmstudio --json >/dev/null || [[ $? -eq 1 ]]

# Fake LM Studio adapter: discovery, dry-run import, execute import and guarded load.
cat > "$TMP/bin/lms" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "--version" ]]; then echo "0.3.0"; exit 0; fi
if [[ "${1:-}" == "ls" ]]; then
  printf '[{"modelKey":"fixture-safe","path":"%s","architecture":"test","quantization":"none"}]\n' "${LAYERFAULT_FIXTURE:?}"
  exit 0
fi
printf '%s\n' "$*" >> "${LAYERFAULT_LMS_LOG:?}"
SH
chmod +x "$TMP/bin/lms"
export LAYERFAULT_FIXTURE="$TMP/artifacts/model.safetensors"
export LAYERFAULT_LMS_LOG="$TMP/lms.log"
PATH="$TMP/bin:$PATH" "$BIN" audit --source lmstudio --deep --json >/dev/null
PATH="$TMP/bin:$PATH" "$BIN" import "$LAYERFAULT_FIXTURE" --source lmstudio --policy permissive >/dev/null
PATH="$TMP/bin:$PATH" "$BIN" import "$LAYERFAULT_FIXTURE" --source lmstudio --policy permissive --execute >/dev/null
PATH="$TMP/bin:$PATH" "$BIN" run fixture-safe --source lmstudio --policy permissive -- --ttl 10 >/dev/null

grep -q '^import .*--dry-run' "$TMP/lms.log" || { echo "LM Studio dry-run import was not used" >&2; exit 1; }
grep -q '^import ' "$TMP/lms.log" || { echo "LM Studio import was not exercised" >&2; exit 1; }
grep -q '^load fixture-safe' "$TMP/lms.log" || { echo "LM Studio guarded load was not exercised" >&2; exit 1; }

# Fake llama.cpp adapter: the runtime sees the path only after artifact admission.
cat > "$TMP/bin/llama-cli" <<'SH'
#!/usr/bin/env bash
if [[ "${1:-}" == "--version" ]]; then echo "llama.cpp version: 9637"; exit 0; fi
printf 'cli %s\n' "$*" >> "${LAYERFAULT_LLAMA_LOG:?}"
SH
cat > "$TMP/bin/llama-server" <<'SH'
#!/usr/bin/env bash
if [[ "${1:-}" == "--version" ]]; then echo "llama.cpp version: 9637"; exit 0; fi
printf 'server %s\n' "$*" >> "${LAYERFAULT_LLAMA_LOG:?}"
SH
chmod +x "$TMP/bin/llama-cli" "$TMP/bin/llama-server"
export LAYERFAULT_LLAMA_LOG="$TMP/llama.log"
PATH="$TMP/bin:$PATH" "$BIN" run "$LAYERFAULT_FIXTURE" --source llama-cpp --policy permissive -- --threads 1 >/dev/null
PATH="$TMP/bin:$PATH" "$BIN" serve "$LAYERFAULT_FIXTURE" --policy permissive -- --port 19090 >/dev/null
grep -q 'cli -m .*model.safetensors --threads 1' "$TMP/llama.log" || { echo "llama-cli gate failed" >&2; exit 1; }
grep -q 'server -m .*model.safetensors --port 19090' "$TMP/llama.log" || { echo "llama-server gate failed" >&2; exit 1; }
grep -q 'admission-staging' "$TMP/llama.log" || { echo "llama.cpp did not receive the private staged admission copy" >&2; exit 1; }

# Synthetic Hugging Face cache with a snapshot symlink to a content-addressed local blob.
HF="$TMP/hf"; REPO="$HF/models--example--fixture"; REV=0123456789abcdef
mkdir -p "$REPO/blobs" "$REPO/refs" "$REPO/snapshots/$REV"
cp "$LAYERFAULT_FIXTURE" "$REPO/blobs/safe-blob"
printf '%s\n' "$REV" > "$REPO/refs/main"
ln -s "../../blobs/safe-blob" "$REPO/snapshots/$REV/model.safetensors"
printf '%s
' '{"auto_map":{"AutoModel":"modeling_fixture.Fixture"}}' > "$REPO/blobs/config-blob"
printf '%s
' 'import subprocess
subprocess.run(["echo","fixture"])' > "$REPO/blobs/code-blob"
ln -s "../../blobs/config-blob" "$REPO/snapshots/$REV/config.json"
ln -s "../../blobs/code-blob" "$REPO/snapshots/$REV/modeling_fixture.py"
set +e
"$BIN" audit --source hf-cache --hf-cache "$HF" --deep --json > "$TMP/hf.json"
HF_RC=$?
set -e
[[ "$HF_RC" -eq 1 ]] || { echo "HF custom-code package should warn, got $HF_RC" >&2; exit 1; }
python3 - "$TMP/hf.json" <<'PY2'
import json,sys
x=json.load(open(sys.argv[1])); findings=x["hf_cache"][0]["package_findings"]; ids=[m for f in findings for m in f.get("matches",[])]
assert any("LF-CODE-AUTO-MAP" in m for m in ids)
assert any("LF-CODE-SUBPROCESS" in m for m in ids)
PY2
set +e
"$BIN" audit --source hf-cache --hf-cache "$HF" --deep --mlbom "$TMP/models.cdx.json" >/dev/null
HF_BOM_RC=$?
set -e
[[ "$HF_BOM_RC" -eq 1 ]] || { echo "HF ML-BOM audit should preserve package warning exit, got $HF_BOM_RC" >&2; exit 1; }
python3 - "$TMP/models.cdx.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1])); assert x["bomFormat"]=="CycloneDX" and x["specVersion"]=="1.7"; assert x["components"]
PY

# Offline runtime advisory admission: built-in catalog plus signed external catalogs.
"$BIN" advisories list --json > "$TMP/advisories.json"
python3 - "$TMP/advisories.json" <<'PY2'
import json,sys
x=json.load(open(sys.argv[1])); assert any(a["id"]=="CVE-2026-7482" for a in x["advisories"]); assert any(a["runtime"]=="llama-cpp" for a in x["advisories"])
PY2
cat > "$TMP/bin/ollama" <<'SH'
#!/usr/bin/env bash
if [[ "${1:-}" == "--version" ]]; then echo "ollama version is 0.17.0"; exit 0; fi
exit 0
SH
chmod +x "$TMP/bin/ollama"
set +e
PATH="$TMP/bin:$PATH" "$BIN" advisories check ollama >/dev/null 2>&1
VULN_RUNTIME_RC=$?
set -e
[[ "$VULN_RUNTIME_RC" -eq 3 ]] || { echo "known vulnerable Ollama runtime should block, got $VULN_RUNTIME_RC" >&2; exit 1; }
openssl genpkey -algorithm ED25519 -out "$TMP/advisory.key" >/dev/null 2>&1
openssl pkey -in "$TMP/advisory.key" -pubout -out "$TMP/advisory.pub" >/dev/null 2>&1
openssl pkeyutl -sign -rawin -inkey "$TMP/advisory.key" -in advisories/runtime-advisories.json -out "$TMP/advisory.sig.bin"
python3 - "$TMP/advisory.sig.bin" "$TMP/advisory.sig" <<'PY2'
import pathlib,sys
pathlib.Path(sys.argv[2]).write_text(pathlib.Path(sys.argv[1]).read_bytes().hex()+"\n")
PY2
"$BIN" advisories verify --database advisories/runtime-advisories.json --signature "$TMP/advisory.sig" --public-key "$TMP/advisory.pub" >/dev/null

# Built-in parser/certification and machine-output contracts.
"$BIN" selftest --json > "$TMP/selftest.json"
"$BIN" certify --json > "$TMP/certify.json"
python3 scripts/schema-gates.py --binary "$BIN"
"$BIN" doctor --json >/dev/null
"$BIN" sources --json >/dev/null
"$BIN" version --json >/dev/null
"$BIN" explain LF-SAFE-STRUCT --json >/dev/null

# Trust bundles, key lifetime/rotation metadata, two-signer threshold, signed baselines,
# quarantine evidence and conservative GC use an isolated Ollama store.
STORE="$TMP/store"; mkdir -p "$STORE/blobs" "$STORE/manifests/registry.ollama.ai/library/fixture"
python3 - "$STORE" <<'PY'
import hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1]); blob=b"benign gate fixture"; d="sha256:"+hashlib.sha256(blob).hexdigest(); (root/"blobs"/d.replace(":","-")).write_bytes(blob)
p=root/"manifests/registry.ollama.ai/library/fixture/latest"; p.write_text(json.dumps({"schemaVersion":2,"layers":[{"mediaType":"application/vnd.ollama.image.template","digest":d,"size":len(blob)}]},separators=(",",":")))
PY
for n in one two; do openssl genpkey -algorithm ED25519 -out "$TMP/$n.key" >/dev/null 2>&1; openssl pkey -in "$TMP/$n.key" -pubout -out "$TMP/$n.pub" >/dev/null 2>&1; "$BIN" trust add --name "$n" --public-key "$TMP/$n.pub" --namespace 'registry.ollama.ai/library/*' >/dev/null; done
"$BIN" trust configure one --rotation-group publishers >/dev/null
"$BIN" trust configure two --rotation-group publishers >/dev/null
"$BIN" trust export --output "$TMP/trust.json" >/dev/null
"$BIN" trust import --input "$TMP/trust.json" >/dev/null
"$BIN" attest sign fixture --private-key "$TMP/one.key" --ollama-dir "$STORE" >/dev/null
"$BIN" attest sign fixture --private-key "$TMP/two.key" --ollama-dir "$STORE" >/dev/null
cat > "$TMP/two-signers.json" <<'JSON'
{"version":1,"profile":"strict","minimum_trusted_signatures":2}
JSON
"$BIN" verify fixture --policy-file "$TMP/two-signers.json" --ollama-dir "$STORE" >/dev/null

"$BIN" baseline create --name cert --ollama-dir "$STORE" >/dev/null
"$BIN" baseline sign --name cert --private-key "$TMP/one.key" >/dev/null
"$BIN" baseline verify-signature --name cert >/dev/null
"$BIN" baseline diff --name cert --ollama-dir "$STORE" --json >/dev/null

QID="$($BIN quarantine put fixture --ollama-dir "$STORE" --reason 'Adversarial evidence gate' --no-scan | sed -n 's/.* as \([^ ]*\) (.*/\1/p')"
[[ -n "$QID" ]] || { echo "could not obtain quarantine id" >&2; exit 1; }
"$BIN" quarantine inspect "$QID" --ollama-dir "$STORE" --json >/dev/null
"$BIN" quarantine export "$QID" --ollama-dir "$STORE" --output "$TMP/evidence" --include-blobs --sign-with "$TMP/one.key" >/dev/null
[[ -s "$TMP/evidence/SHA256SUMS" && -s "$TMP/evidence/evidence-signature.json" ]] || { echo "quarantine evidence export incomplete" >&2; exit 1; }
"$BIN" quarantine restore "$QID" --ollama-dir "$STORE" >/dev/null

# Add an orphan and prove dry-run does not delete it, then execute GC.
printf orphan > "$STORE/blobs/sha256-$(printf orphan | sha256sum | awk '{print $1}')"
ORPHAN_PATH="$STORE/blobs/sha256-$(printf orphan | sha256sum | awk '{print $1}')"
"$BIN" gc --ollama-dir "$STORE" --json >/dev/null
[[ -f "$ORPHAN_PATH" ]] || { echo "GC dry-run deleted an orphan" >&2; exit 1; }
"$BIN" gc --ollama-dir "$STORE" --execute >/dev/null
[[ ! -e "$ORPHAN_PATH" ]] || { echo "GC execute did not remove demonstrably orphaned blob" >&2; exit 1; }

# SBOM generation is local and deterministic.
python3 scripts/cargo-sbom.py "$TMP/layerfault-sbom.cdx.json" >/dev/null
python3 - "$TMP/layerfault-sbom.cdx.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1])); assert x["bomFormat"]=="CycloneDX" and x["specVersion"]=="1.7"
PY

echo "PASS: Layerfault development admission/sources/formats/trust/policy/baseline/quarantine/inventory gate"
