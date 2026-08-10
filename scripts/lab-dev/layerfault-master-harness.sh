#!/usr/bin/env bash
# Canonical lab script: 2026-08-09 / multi-source static + active master harness
set -uo pipefail

# Layerfault master corpus harness
#
# Restartable corpus runner for:
#   /lab/samples    original regression corpus
#   /lab/extended   deeper model/package corpus
#   /lab/datasets   poisoning/training-data corpus
#   /lab/large      optional large stress corpus
#   /lab/ollama     real Ollama registry manifests/content-addressed blobs
#   /lab/fixtures   deterministic parser/store security fixtures
#
# Default mode is static/non-executing. It never loads hostile package code.
#
# Optional active mode executes only manifest-selected models via Layerfault's
# strong behavioural sandbox. It supports GGUF/llama.cpp and local
# Transformers/PEFT runtimes. On Linux, Layerfault requires Bubblewrap
# filesystem/network isolation and resource limits before launching models.
#
# Usage:
#   chmod +x layerfault-master-harness.sh
#
#   ./layerfault-master-harness.sh --fresh
#
#   ./layerfault-master-harness.sh --fresh --include-large
#   ./layerfault-master-harness.sh --fresh --broad-static
#   ./layerfault-master-harness.sh --fresh --broad --python-runtime /opt/layerfault/runtimes/python/bin/python
#
#   ./layerfault-master-harness.sh --fresh --active-only \
#       --llama-cpp /path/to/llama-cli \
#       --python-runtime /opt/layerfault/runtimes/python/bin/python
#
#   ./layerfault-master-harness.sh --fresh --include-large --active \
#       --llama-cpp /path/to/llama-cli \
#       --python-runtime /opt/layerfault/runtimes/python/bin/python
#
#   # Optional broad GGUF sweep in addition to the targeted active manifest:
#   ./layerfault-master-harness.sh --active --all-gguf-behaviour
#
#   # Force a specific completed case to re-run and recapture output, even if
#   # its prior result was exit 0 (which --retry-failed alone can never do,
#   # since it only re-runs operations with a non-zero/timeout exit code):
#   ./layerfault-master-harness.sh --active --force-rerun-case qwen3-4b-safety-bypass-diff
#
# Re-run the same command without --fresh to resume. Completed operations are
# skipped. Use --retry-failed to re-run non-zero/timeout operations. Use
# --force-rerun-case NAME (repeatable) to force one or more specific case
# names to re-run regardless of their prior exit code.
#
# Outputs:
#   /lab/runs/current/
#       summary.tsv
#       case-summary.tsv
#       findings.tsv
#       egress-summary.tsv
#       summary.json
#       operations/
#       meta/

LAB_ROOT="${LAB_ROOT:-/lab}"
BIN="${LAYERFAULT_BIN:-$(command -v layerfault 2>/dev/null || true)}"
RUNS="$LAB_ROOT/runs"
CURRENT="$RUNS/current"

INCLUDE_CORE=1
INCLUDE_EXTENDED=1
INCLUDE_DATASETS=1
INCLUDE_LARGE=0
INCLUDE_OLLAMA=0
INCLUDE_FIXTURES=1
BEHAVIOUR=0
ALL_GGUF_BEHAVIOUR=0
LLAMA_CPP=""
PYTHON_RUNTIME=""
ACTIVE_MANIFEST="$LAB_ROOT/active/ACTIVE-MANIFEST.tsv"
OLLAMA_MODELS="$LAB_ROOT/ollama/models"
FIXTURE_PACKAGES="$LAB_ROOT/fixtures/packages"
INVALID_OLLAMA_MODELS="$LAB_ROOT/fixtures/ollama-invalid/models"
CLI_WORKFLOW_FIXTURES="$LAB_ROOT/fixtures/cli-workflow"
PROFILE="standard"
STATIC_TIMEOUT=900
BEHAVIOUR_TIMEOUT=300
FRESH=0
RETRY_FAILED=0
FORCE_RERUN_CASES=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --include-large) INCLUDE_LARGE=1 ;;
    --include-ollama) INCLUDE_OLLAMA=1 ;;
    --no-fixtures) INCLUDE_FIXTURES=0 ;;
    --broad) INCLUDE_LARGE=1; INCLUDE_OLLAMA=1; BEHAVIOUR=1 ;;
    --broad-static) INCLUDE_LARGE=1; INCLUDE_OLLAMA=1; BEHAVIOUR=0 ;;
    --ollama-only) INCLUDE_CORE=0; INCLUDE_EXTENDED=0; INCLUDE_DATASETS=0; INCLUDE_LARGE=0; INCLUDE_OLLAMA=1; INCLUDE_FIXTURES=0; BEHAVIOUR=0 ;;
    --active-only)
      INCLUDE_CORE=0
      INCLUDE_EXTENDED=0
      INCLUDE_DATASETS=0
      INCLUDE_LARGE=0
      INCLUDE_OLLAMA=0
      INCLUDE_FIXTURES=0
      BEHAVIOUR=1
      ;;
    --no-core) INCLUDE_CORE=0 ;;
    --no-extended) INCLUDE_EXTENDED=0 ;;
    --no-datasets) INCLUDE_DATASETS=0 ;;
    --behaviour|--active) BEHAVIOUR=1 ;;
    --all-gguf-behaviour) BEHAVIOUR=1; ALL_GGUF_BEHAVIOUR=1 ;;
    --llama-cpp)
      [[ $# -ge 2 ]] || { echo "--llama-cpp requires a path" >&2; exit 2; }
      LLAMA_CPP="$2"; shift
      ;;
    --python-runtime)
      [[ $# -ge 2 ]] || { echo "--python-runtime requires a path" >&2; exit 2; }
      PYTHON_RUNTIME="$2"; shift
      ;;
    --active-manifest)
      [[ $# -ge 2 ]] || { echo "--active-manifest requires a path" >&2; exit 2; }
      ACTIVE_MANIFEST="$2"; shift
      ;;
    --profile)
      [[ $# -ge 2 ]] || { echo "--profile requires quick|standard|deep|research" >&2; exit 2; }
      PROFILE="$2"; shift
      ;;
    --timeout)
      [[ $# -ge 2 ]] || { echo "--timeout requires seconds" >&2; exit 2; }
      STATIC_TIMEOUT="$2"; shift
      ;;
    --behaviour-timeout)
      [[ $# -ge 2 ]] || { echo "--behaviour-timeout requires seconds" >&2; exit 2; }
      BEHAVIOUR_TIMEOUT="$2"; shift
      ;;
    --fresh) FRESH=1 ;;
    --retry-failed) RETRY_FAILED=1 ;;
    --force-rerun-case)
      [[ $# -ge 2 ]] || { echo "--force-rerun-case requires a case name" >&2; exit 2; }
      FORCE_RERUN_CASES+=("$2"); shift
      ;;
    -h|--help)
      sed -n '1,60p' "$0"
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

case "$PROFILE" in
  quick|standard|deep|research) ;;
  *) echo "Unsupported profile: $PROFILE" >&2; exit 2 ;;
esac

[[ -n "$BIN" && -x "$BIN" ]] || {
  echo "Layerfault binary not found. Set LAYERFAULT_BIN=/path/to/layerfault" >&2
  exit 2
}
command -v timeout >/dev/null 2>&1 || { echo "'timeout' command is required" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 2; }

if [[ "$BEHAVIOUR" -eq 1 ]]; then
  if [[ "$(uname -s)" == "Linux" ]]; then
    command -v bwrap >/dev/null 2>&1 || {
      echo "Active mode on Linux requires bubblewrap (bwrap)." >&2
      echo "Install Layerfault active prerequisites first." >&2
      exit 2
    }
    command -v prlimit >/dev/null 2>&1 || {
      echo "Active mode on Linux requires prlimit (util-linux)." >&2
      exit 2
    }
  fi

  if [[ -z "$LLAMA_CPP" ]]; then
    for candidate in       "$(command -v llama-cli 2>/dev/null || true)"       "/opt/layerfault/runtimes/llama/llama-cli"       "/usr/local/bin/llama-cli"; do
      if [[ -n "$candidate" && -x "$candidate" ]]; then
        LLAMA_CPP="$candidate"
        break
      fi
    done
  fi

  if [[ -z "$PYTHON_RUNTIME" ]]; then
    for candidate in       "/opt/layerfault/runtimes/python/bin/python"       "$(command -v python3 2>/dev/null || true)"; do
      if [[ -n "$candidate" && -x "$candidate" ]]; then
        PYTHON_RUNTIME="$candidate"
        break
      fi
    done
  fi
fi

mkdir -p "$RUNS"

if [[ "$FRESH" -eq 1 || ! -L "$CURRENT" || ! -d "$(readlink -f "$CURRENT" 2>/dev/null || true)" ]]; then
  STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
  OUT="$RUNS/$STAMP"
  mkdir -p "$OUT"
  rm -f "$CURRENT"
  ln -s "$OUT" "$CURRENT"
else
  OUT="$(readlink -f "$CURRENT")"
fi

mkdir -p "$OUT"/{operations,meta}
SUMMARY="$OUT/summary.tsv"
EVENTS="$OUT/events.tsv"
ACTIVE_EXPECT="$OUT/active-expectations.tsv"

if [[ ! -f "$SUMMARY" ]]; then
  printf 'group\tcase\toperation\texit_code\telapsed_ms\tstate\toutput\tstderr\n' > "$SUMMARY"
fi
if [[ ! -f "$EVENTS" ]]; then
  printf 'utc\tevent\tdetail\n' > "$EVENTS"
fi
if [[ ! -f "$ACTIVE_EXPECT" ]]; then
  printf 'name\truntime\tmode\texpected_exit\tactual_exit\tresult\tnotes\n' > "$ACTIVE_EXPECT"
fi

event() {
  local detail="${2//$'\t'/ }"
  detail="${detail//$'\n'/ }"
  printf '%s\t%s\t%s\n' "$(date -u +%FT%TZ)" "$1" "$detail" >> "$EVENTS"
}

sanitize() {
  printf '%s' "$1" | sed 's#[^A-Za-z0-9_.-]#_#g'
}

state_for_rc() {
  case "$1" in
    0) echo PASS ;;
    1) echo WARN ;;
    2) echo INTEGRITY_OR_ERROR ;;
    3) echo BLOCK ;;
    4) echo POLICY_BLOCK ;;
    5) echo DRIFT ;;
    124|137) echo TIMEOUT ;;
    *) echo ERROR ;;
  esac
}

case_force_rerun() {
  local case_name="$1" candidate
  for candidate in "${FORCE_RERUN_CASES[@]:-}"; do
    [[ -n "$candidate" && "$candidate" == "$case_name" ]] && return 0
  done
  return 1
}

run_capture() {
  local group="$1" case_name="$2" operation="$3" timeout_secs="$4"
  shift 4

  local key marker stdout stderr rc start end ms state
  key="$(sanitize "${group}__${case_name}__${operation}")"
  marker="$OUT/operations/$key.done"
  stdout="$OUT/operations/$key.stdout"
  stderr="$OUT/operations/$key.stderr"

  if [[ -f "$marker" ]] && ! case_force_rerun "$case_name"; then
    rc="$(cat "$marker" 2>/dev/null || echo 255)"
    if [[ "$RETRY_FAILED" -eq 0 || "$rc" -eq 0 ]]; then
      printf '  SKIP %-34s rc=%s\n' "$operation" "$rc"
      return 0
    fi
  fi

  printf '  RUN  %-34s ' "$operation"
  start="$(date +%s%N)"
  if timeout --signal=TERM --kill-after=15s "${timeout_secs}s" "$@" >"$stdout" 2>"$stderr"; then
    rc=0
  else
    rc=$?
  fi
  end="$(date +%s%N)"
  ms=$(( (end - start) / 1000000 ))
  state="$(state_for_rc "$rc")"

  printf '%s\n' "$rc" > "$marker"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$group" "$case_name" "$operation" "$rc" "$ms" "$state" \
    "${stdout#$OUT/}" "${stderr#$OUT/}" >> "$SUMMARY"

  printf 'rc=%s  %sms  %s\n' "$rc" "$ms" "$state"
}

artifact_scan() {
  local group="$1" case_name="$2" root="$3"
  local artifact rel op

  while IFS= read -r -d '' artifact; do
    rel="${artifact#$root/}"

    op="artifact-inspect__$(sanitize "$rel")"
    run_capture "$group" "$case_name" "$op" "$STATIC_TIMEOUT" \
      "$BIN" inspect "$artifact" --json

    op="artifact-verify__$(sanitize "$rel")"
    run_capture "$group" "$case_name" "$op" "$STATIC_TIMEOUT" \
      "$BIN" verify-file "$artifact" --policy workstation --json
  done < <(
    find "$root" -type f \( \
      -iname '*.gguf' -o \
      -iname '*.safetensors' -o \
      -iname '*.onnx' -o \
      -iname '*.tflite' -o \
      -iname '*.keras' -o \
      -iname '*.h5' -o \
      -iname '*.hdf5' \
    \) -print0 | sort -z
  )
}

run_package_case() {
  local group="$1" path="$2"
  local case_name
  case_name="$(basename "$path")"

  echo
  echo "================================================================"
  echo "[$group] $case_name"
  echo "Path: $path"
  echo "================================================================"

  run_capture "$group" "$case_name" fingerprint "$STATIC_TIMEOUT" \
    "$BIN" fingerprint "$path" --json

  run_capture "$group" "$case_name" inspect-package "$STATIC_TIMEOUT" \
    "$BIN" inspect "$path" --json

  run_capture "$group" "$case_name" scan-dir "$STATIC_TIMEOUT" \
    "$BIN" scan-dir "$path" --json

  run_capture "$group" "$case_name" verify-package "$STATIC_TIMEOUT" \
    "$BIN" verify-package "$path" --policy workstation --json

  run_capture "$group" "$case_name" pipeline "$STATIC_TIMEOUT" \
    "$BIN" pipeline "$path" --policy workstation --json

  # quick review explicitly skips inference but exercises vNext static/model logic.
  run_capture "$group" "$case_name" review-quick "$STATIC_TIMEOUT" \
    "$BIN" review "$path" --profile quick --json

  artifact_scan "$group" "$case_name" "$path"
}

run_group() {
  local group="$1" root="$2"
  [[ -d "$root" ]] || { event skip "missing group root $root"; return; }

  while IFS= read -r -d '' path; do
    # Ignore incomplete empty directories.
    if find "$path" -type f -print -quit | grep -q .; then
      run_package_case "$group" "$path"
    fi
  done < <(find "$root" -mindepth 1 -maxdepth 1 -type d -print0 | sort -z)
}


run_ollama_store() {
  [[ "$INCLUDE_OLLAMA" -eq 1 ]] || return 0
  [[ -d "$OLLAMA_MODELS/manifests" && -d "$OLLAMA_MODELS/blobs" ]] || {
    event skip "missing Ollama corpus store at $OLLAMA_MODELS"
    return 0
  }

  echo
  echo "================================================================"
  echo "[ollama] real registry store"
  echo "Path: $OLLAMA_MODELS"
  echo "================================================================"

  run_capture ollama registry-store scan-store "$STATIC_TIMEOUT" \
    "$BIN" scan --ollama-dir "$OLLAMA_MODELS" --json

  run_capture ollama registry-store audit-deep "$STATIC_TIMEOUT" \
    "$BIN" audit --source ollama --ollama-dir "$OLLAMA_MODELS" --deep --json
}

run_fixture_corpus() {
  [[ "$INCLUDE_FIXTURES" -eq 1 ]] || return 0

  if [[ -d "$FIXTURE_PACKAGES" ]]; then
    run_group fixture "$FIXTURE_PACKAGES"
  fi

  if [[ -d "$INVALID_OLLAMA_MODELS/manifests" && -d "$INVALID_OLLAMA_MODELS/blobs" ]]; then
    echo
    echo "================================================================"
    echo "[fixture] invalid Ollama store"
    echo "Path: $INVALID_OLLAMA_MODELS"
    echo "================================================================"

    run_capture fixture ollama-invalid-store audit-ollama-invalid "$STATIC_TIMEOUT" \
      "$BIN" audit --source ollama --ollama-dir "$INVALID_OLLAMA_MODELS" --deep --json
  fi
}

run_cli_workflow_fixtures() {
  [[ "$INCLUDE_FIXTURES" -eq 1 ]] || return 0
  local fx="$CLI_WORKFLOW_FIXTURES"
  [[ -d "$fx/keys" ]] || {
    event skip "missing CLI-workflow fixtures at $fx"
    return 0
  }

  # Isolate trust store / baselines under this run's directory so repeated
  # runs never touch the operator's real ~/.config/layerfault state and stay
  # reproducible across --fresh runs.
  local cfg="$OUT/meta/cli-workflow-config"
  mkdir -p "$cfg"
  export LAYERFAULT_CONFIG_DIR="$cfg"

  echo
  echo "================================================================"
  echo "[cli-workflow] trust / attest / baseline / quarantine / policy"
  echo "Config root: $cfg"
  echo "================================================================"

  run_capture cli-workflow trust trust-add "$STATIC_TIMEOUT" \
    "$BIN" trust add --name lab-signer --public-key "$fx/keys/signer.pub.pem" --namespace lab

  run_capture cli-workflow trust trust-list "$STATIC_TIMEOUT" \
    "$BIN" trust list --json

  run_capture cli-workflow baseline baseline-create "$STATIC_TIMEOUT" \
    "$BIN" baseline create --name lab --ollama-dir "$fx/ollama-baseline/models"

  run_capture cli-workflow baseline baseline-verify "$STATIC_TIMEOUT" \
    "$BIN" baseline verify --name lab --ollama-dir "$fx/ollama-baseline/models" --json

  run_capture cli-workflow baseline baseline-diff "$STATIC_TIMEOUT" \
    "$BIN" baseline diff --name lab --ollama-dir "$fx/ollama-baseline/models" --json

  run_capture cli-workflow baseline baseline-sign "$STATIC_TIMEOUT" \
    "$BIN" baseline sign --name lab --private-key "$fx/keys/signer.key.pem"

  run_capture cli-workflow baseline baseline-verify-signature-trusted "$STATIC_TIMEOUT" \
    "$BIN" baseline verify-signature --name lab --json

  # Untrusted-signer rejection path: re-sign with a key never added to the
  # trust store and confirm verify-signature reports it as untrusted, not a
  # crash and not a false "trusted".
  run_capture cli-workflow baseline baseline-sign-untrusted "$STATIC_TIMEOUT" \
    "$BIN" baseline sign --name lab --private-key "$fx/keys/untrusted.key.pem"

  run_capture cli-workflow baseline baseline-verify-signature-untrusted "$STATIC_TIMEOUT" \
    "$BIN" baseline verify-signature --name lab --json

  run_capture cli-workflow attest attest-sign "$STATIC_TIMEOUT" \
    "$BIN" attest sign layerfault-clean-fixture \
      --private-key "$fx/keys/signer.key.pem" \
      --ollama-dir "$fx/ollama-baseline/models" --json

  run_capture cli-workflow quarantine quarantine-put "$STATIC_TIMEOUT" \
    "$BIN" quarantine put layerfault-unsafe-fixture \
      --ollama-dir "$fx/ollama-quarantine/models" --reason "harness lab test"

  run_capture cli-workflow quarantine quarantine-list "$STATIC_TIMEOUT" \
    "$BIN" quarantine list --ollama-dir "$fx/ollama-quarantine/models" --json

  local qid
  qid="$("$BIN" quarantine list --ollama-dir "$fx/ollama-quarantine/models" --json 2>/dev/null |
    python3 -c 'import json,sys
rows = json.load(sys.stdin)
print(rows[0]["id"] if rows else "")' 2>/dev/null || true)"

  if [[ -n "$qid" ]]; then
    run_capture cli-workflow quarantine quarantine-inspect "$STATIC_TIMEOUT" \
      "$BIN" quarantine inspect "$qid" --ollama-dir "$fx/ollama-quarantine/models" --json

    run_capture cli-workflow quarantine quarantine-export "$STATIC_TIMEOUT" \
      "$BIN" quarantine export "$qid" --ollama-dir "$fx/ollama-quarantine/models" \
        --output "$OUT/operations/quarantine-export-$qid.tar" \
        --sign-with "$fx/keys/signer.key.pem"

    run_capture cli-workflow quarantine quarantine-restore "$STATIC_TIMEOUT" \
      "$BIN" quarantine restore "$qid" --ollama-dir "$fx/ollama-quarantine/models"
  else
    event skip "cli-workflow quarantine id not resolved; skipping inspect/export/restore"
  fi

  local policy_file="$OUT/meta/cli-workflow-policy.toml"
  run_capture cli-workflow policy policy-init "$STATIC_TIMEOUT" \
    "$BIN" policy init --profile workstation --output "$policy_file"

  run_capture cli-workflow policy policy-lint "$STATIC_TIMEOUT" \
    "$BIN" policy lint "$policy_file"

  run_capture cli-workflow policy policy-explain "$STATIC_TIMEOUT" \
    "$BIN" policy explain "$policy_file"

  run_capture cli-workflow policy policy-show "$STATIC_TIMEOUT" \
    "$BIN" policy show --file "$policy_file"

  local policy_artifact
  policy_artifact="$(find "$LAB_ROOT/samples" -type f -iname '*.gguf' 2>/dev/null | sort | head -1)"
  if [[ -n "$policy_artifact" ]]; then
    run_capture cli-workflow policy policy-test "$STATIC_TIMEOUT" \
      "$BIN" policy test "$policy_file" "$policy_artifact" --source file --json

    run_capture cli-workflow models models-remember "$STATIC_TIMEOUT" \
      "$BIN" models remember "$policy_artifact" --name lab-model --publisher layerfault-lab --json
    run_capture cli-workflow models models-list "$STATIC_TIMEOUT" \
      "$BIN" models list --json
    run_capture cli-workflow models models-show "$STATIC_TIMEOUT" \
      "$BIN" models show lab-model --json
    run_capture cli-workflow models models-history "$STATIC_TIMEOUT" \
      "$BIN" models history lab-model --json
    run_capture cli-workflow models drift-against "$STATIC_TIMEOUT" \
      "$BIN" drift "$policy_artifact" --against lab-model --json
    local drift_artifact
    drift_artifact="$(find "$LAB_ROOT/samples" -type f -iname '*.gguf' 2>/dev/null | sort | tail -1)"
    if [[ -n "$drift_artifact" && "$drift_artifact" != "$policy_artifact" ]]; then
      run_capture cli-workflow models models-remember-second "$STATIC_TIMEOUT" \
        "$BIN" models remember "$drift_artifact" --name lab-model --publisher layerfault-lab --json
      run_capture cli-workflow models drift-previous "$STATIC_TIMEOUT" \
        "$BIN" drift "$drift_artifact" --previous --json
    else
      event skip "cli-workflow drift --previous: no second GGUF artifact"
    fi
    run_capture cli-workflow research research-campaign "$STATIC_TIMEOUT" \
      "$BIN" research campaign --json
    local evidence_file="$OUT/meta/cli-workflow-evidence.json"
    run_capture cli-workflow evidence evidence-create "$STATIC_TIMEOUT" \
      "$BIN" pipeline "$policy_artifact" --json \
        --evidence-out "$evidence_file" --evidence-key "$fx/keys/signer.key.pem"
    if [[ -f "$evidence_file" ]]; then
      run_capture cli-workflow evidence evidence-verify "$STATIC_TIMEOUT" \
        "$BIN" evidence verify "$evidence_file" --json
    else
      event skip "cli-workflow evidence verify: pipeline did not create evidence"
    fi
  else
    event skip "cli-workflow policy-test: no GGUF artifact found under $LAB_ROOT/samples"
  fi

  run_capture cli-workflow advisory advisory-list "$STATIC_TIMEOUT" \
    "$BIN" advisories list --json
  run_capture cli-workflow advisory advisory-verify "$STATIC_TIMEOUT" \
    "$BIN" advisories verify \
      --database "$fx/advisory-database.json" \
      --signature "$fx/advisory-database.sig" \
      --public-key "$fx/keys/signer.pub.pem"
  run_capture cli-workflow lineage lineage-verify-chain "$STATIC_TIMEOUT" \
    "$BIN" lineage verify-chain "$fx/lineage-chain.json" --json
  run_capture cli-workflow diagnostics capabilities "$STATIC_TIMEOUT" \
    "$BIN" capabilities --json
  run_capture cli-workflow diagnostics sources "$STATIC_TIMEOUT" \
    "$BIN" sources --json
  run_capture cli-workflow diagnostics explain-lineage "$STATIC_TIMEOUT" \
    "$BIN" explain LF-LINEAGE-QUANTIZATION-TEMPLATE --json

  local platform_db="sqlite:$OUT/meta/cli-workflow-platform.db"
  run_capture cli-workflow platform platform-migrate "$STATIC_TIMEOUT" \
    "$BIN" platform migrate --database "$platform_db"
  run_capture cli-workflow platform platform-doctor "$STATIC_TIMEOUT" \
    "$BIN" platform doctor --database "$platform_db" --json
  run_capture cli-workflow platform platform-worker-once "$STATIC_TIMEOUT" \
    "$BIN" platform worker --database "$platform_db" --once
  run_capture cli-workflow platform platform-publish-weekly "$STATIC_TIMEOUT" \
    "$BIN" platform publish-weekly --database "$platform_db" --json
  run_capture cli-workflow platform platform-newsletter-generate "$STATIC_TIMEOUT" \
    "$BIN" platform newsletter generate --database "$platform_db" --format markdown
  run_capture cli-workflow platform platform-newsletter-dry-run "$STATIC_TIMEOUT" \
    "$BIN" platform newsletter send --database "$platform_db" \
      --to lab@example.invalid --from layerfault@example.invalid \
      --smtp-host smtp.example.invalid --dry-run

  # hub: exercise against a repo id already present in this run's downloaded
  # corpus manifest, so the case stays valid as the corpus's case list changes
  # rather than depending on a hardcoded repo name.
  if [[ -f "$LAB_ROOT/SOURCE-MANIFEST.tsv" ]]; then
    local hub_repo
    hub_repo="$(awk -F'\t' 'NR>1 && $3=="model" && $10 ~ /^ok/ {print $4; exit}' \
      "$LAB_ROOT/SOURCE-MANIFEST.tsv")"
    if [[ -n "$hub_repo" ]]; then
      run_capture cli-workflow hub hub-model "$STATIC_TIMEOUT" \
        "$BIN" hub model "$hub_repo" --json

      run_capture cli-workflow hub hub-files "$STATIC_TIMEOUT" \
        "$BIN" hub files "$hub_repo" --json
      run_capture cli-workflow hub hub-crawl "$STATIC_TIMEOUT" \
        "$BIN" hub crawl --limit 1 --json
      run_capture cli-workflow platform platform-crawl "$STATIC_TIMEOUT" \
        "$BIN" platform crawl --database "$platform_db" --limit 1 --json
    else
      event skip "cli-workflow hub: no successfully-downloaded model repo in SOURCE-MANIFEST.tsv"
    fi
  fi

  if [[ -n "${policy_artifact:-}" ]]; then
    run_capture cli-workflow models models-forget "$STATIC_TIMEOUT" \
      "$BIN" models forget lab-model --json
  fi
}

run_dataset_case() {
  local path="$1" case_name
  case_name="$(basename "$path")"

  echo
  echo "================================================================"
  echo "[dataset] $case_name"
  echo "Path: $path"
  echo "================================================================"

  run_capture dataset "$case_name" dataset-inspect "$STATIC_TIMEOUT" \
    "$BIN" dataset inspect "$path" --json

  run_capture dataset "$case_name" dataset-fingerprint "$STATIC_TIMEOUT" \
    "$BIN" dataset fingerprint "$path" --json

  run_capture dataset "$case_name" dataset-poisoning-review "$STATIC_TIMEOUT" \
    "$BIN" dataset poisoning-review "$path" --json
}

run_datasets() {
  local root="$LAB_ROOT/datasets" path
  [[ -d "$root" ]] || return

  while IFS= read -r -d '' path; do
    if find "$path" -type f -print -quit | grep -q .; then
      run_dataset_case "$path"
    fi
  done < <(find "$root" -mindepth 1 -maxdepth 1 -type d -print0 | sort -z)
}

first_gguf() {
  local root="$1" pattern="$2"
  find "$root" -type f -iname "$pattern" -print 2>/dev/null | sort | head -1
}

run_compare() {
  local name="$1" base="$2" derived="$3" claim="${4:-}"

  [[ -e "$base" && -e "$derived" ]] || {
    event compare-skip "$name missing base or derived"
    return
  }

  echo
  echo "================================================================"
  echo "[comparison] $name"
  echo "Base:    $base"
  echo "Derived: $derived"
  echo "================================================================"

  if [[ -n "$claim" ]]; then
    run_capture comparison "$name" "compare-$claim" "$STATIC_TIMEOUT" \
      "$BIN" compare "$base" "$derived" --claim "$claim" --json

    run_capture comparison "$name" "review-quick-$claim" "$STATIC_TIMEOUT" \
      "$BIN" review "$derived" --base "$base" --claim "$claim" --profile quick --json
  else
    run_capture comparison "$name" compare "$STATIC_TIMEOUT" \
      "$BIN" compare "$base" "$derived" --json

    run_capture comparison "$name" review-quick "$STATIC_TIMEOUT" \
      "$BIN" review "$derived" --base "$base" --profile quick --json
  fi
}

run_known_comparisons() {
  local e="$LAB_ROOT/extended"
  local l="$LAB_ROOT/large"
  local malicious="$LAB_ROOT/fixtures/packages/83-generated-quantization-template-tamper"
  local gguf

  if [[ -d "$malicious/base" && -f "$malicious/tampered-q4.gguf" ]]; then
    run_compare \
      generated-quantization-template-tamper \
      "$malicious/base" "$malicious/tampered-q4.gguf" quantization
  fi

  [[ "$INCLUDE_EXTENDED" -eq 1 || "$INCLUDE_LARGE" -eq 1 ]] || return 0

  if [[ -d "$e/27-smollm2-135m-base" && -d "$e/28-smollm2-135m-q4-derived" ]]; then
    gguf="$(first_gguf "$e/28-smollm2-135m-q4-derived" '*Q4_K_M.gguf')"
    [[ -n "$gguf" ]] && run_compare \
      smollm2-135m-base-to-q4 \
      "$e/27-smollm2-135m-base" "$gguf" quantization
  fi

  if [[ -d "$e/29-qwen25-05b-base" && -d "$e/30-qwen25-05b-q4-derived" ]]; then
    gguf="$(first_gguf "$e/30-qwen25-05b-q4-derived" '*.gguf')"
    [[ -n "$gguf" ]] && run_compare \
      qwen25-05b-base-to-q4 \
      "$e/29-qwen25-05b-base" "$gguf" quantization
  fi

  if [[ -d "$e/31-smollm2-360m-base" && -d "$e/32-smollm2-360m-quant-matrix" ]]; then
    for pattern in '*Q2_K.gguf' '*Q4_K_M.gguf' '*Q8_0.gguf'; do
      gguf="$(first_gguf "$e/32-smollm2-360m-quant-matrix" "$pattern")"
      [[ -n "$gguf" ]] || continue
      run_compare \
        "smollm2-360m-$(basename "$gguf" .gguf)" \
        "$e/31-smollm2-360m-base" "$gguf" quantization
    done
  fi

  if [[ "$INCLUDE_LARGE" -eq 1 &&
        -d "$l/44-qwen25-3b-base-sharded" &&
        -d "$l/45-qwen25-3b-q4-gguf" ]]; then
    gguf="$(first_gguf "$l/45-qwen25-3b-q4-gguf" '*.gguf')"
    [[ -n "$gguf" ]] && run_compare \
      qwen25-3b-base-to-q4 \
      "$l/44-qwen25-3b-base-sharded" "$gguf" quantization
  fi
}


run_active_manifest() {
  [[ "$BEHAVIOUR" -eq 1 ]] || return 0
  [[ -f "$ACTIVE_MANIFEST" ]] || {
    event active-skip "active manifest missing: $ACTIVE_MANIFEST"
    echo
    echo "Active manifest not found: $ACTIVE_MANIFEST"
    echo "Run the lab setup with --with-active, or pass --active-manifest."
    return 0
  }

  local name mode runtime model base profile probe_suite flags expected notes
  while IFS=$'\t' read -r name mode runtime model base profile probe_suite flags expected notes; do
    [[ -z "${name:-}" || "$name" == \#* ]] && continue

    if [[ -z "${model:-}" || "$model" == "-" || ! -e "$model" ]]; then
      event active-skip "$name model missing: ${model:-<empty>}"
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$name" "$runtime" "$mode" "${expected:--}" "-" "MISSING_MODEL" "${notes:-}" >> "$ACTIVE_EXPECT"
      continue
    fi
    if [[ "$mode" == "compare" && ( -z "${base:-}" || "$base" == "-" || ! -e "$base" ) ]]; then
      event active-skip "$name base missing: ${base:-<empty>}"
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$name" "$runtime" "$mode" "${expected:--}" "-" "MISSING_BASE" "${notes:-}" >> "$ACTIVE_EXPECT"
      continue
    fi

    local runtime_path=""
    case "$runtime" in
      llama-cpp)
        if [[ -z "$LLAMA_CPP" || ! -x "$LLAMA_CPP" ]]; then
          event active-skip "$name llama-cli unavailable"
          printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$name" "$runtime" "$mode" "${expected:--}" "-" "RUNTIME_UNAVAILABLE" "${notes:-}" >> "$ACTIVE_EXPECT"
          continue
        fi
        runtime_path="$LLAMA_CPP"
        ;;
      transformers|transformers-python)
        if [[ -z "$PYTHON_RUNTIME" || ! -x "$PYTHON_RUNTIME" ]]; then
          event active-skip "$name Python runtime unavailable"
          printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$name" "$runtime" "$mode" "${expected:--}" "-" "RUNTIME_UNAVAILABLE" "${notes:-}" >> "$ACTIVE_EXPECT"
          continue
        fi
        runtime_path="$PYTHON_RUNTIME"
        ;;
      *)
        event active-skip "$name unsupported runtime=$runtime"
        continue
        ;;
    esac

    echo
    echo "================================================================"
    echo "[active] $name"
    echo "Mode:    $mode"
    echo "Runtime: $runtime"
    echo "Model:   $model"
    [[ "$base" != "-" && -n "$base" ]] && echo "Base:    $base"
    [[ "$probe_suite" != "-" && -n "$probe_suite" ]] && echo "Probes:  $probe_suite"
    echo "================================================================"

    local cmd=("$BIN")
    if [[ "$mode" == "compare" ]]; then
      cmd+=(compare-behaviour "$base" "$model")
    else
      cmd+=(behaviour "$model")
      [[ "$base" != "-" && -n "$base" ]] && cmd+=(--base "$base")
    fi
    cmd+=(--runtime "$runtime" --runtime-path "$runtime_path" --profile "${profile:-$PROFILE}")
    cmd+=(--timeout-seconds "$BEHAVIOUR_TIMEOUT" --json)
    if [[ -n "$probe_suite" && "$probe_suite" != "-" && -f "$probe_suite" ]]; then
      cmd+=(--probe-suite "$probe_suite")
    fi

    IFS=',' read -r -a flag_values <<< "${flags:-}"
    local flag
    for flag in "${flag_values[@]}"; do
      case "${flag// /}" in
        ""|-) ;;
        allow-static-blocked) cmd+=(--allow-static-blocked) ;;
        execute-custom-code) cmd+=(--execute-custom-code) ;;
        *) event active-flag "$name unknown flag=$flag" ;;
      esac
    done

    local operation="active-$(sanitize "$name")"
    run_capture active "$name" "$operation" "$BEHAVIOUR_TIMEOUT" "${cmd[@]}"

    local key marker stdout stderr rc result
    key="$(sanitize "active__${name}__${operation}")"
    marker="$OUT/operations/$key.done"
    stdout="$OUT/operations/$key.stdout"
    stderr="$OUT/operations/$key.stderr"
    rc="$(cat "$marker" 2>/dev/null || echo 255)"

    if [[ "$rc" -eq 1 ]] && grep -Eq \
      '^.*active analysis skipped: estimated runtime memory [0-9]+([.][0-9]+)? GiB exceeds safe host budget [0-9]+([.][0-9]+)? GiB' \
      "$stderr" 2>/dev/null; then
      result="RESOURCE_UNAVAILABLE"
    elif [[ -n "${expected:-}" && "$expected" != "-" && "$rc" != "$expected" ]]; then
      if [[ "$expected" -eq 0 && "$rc" -ne 0 ]]; then
        result="FALSE_POSITIVE_REGRESSION"
        event active-false-positive "$name expected=$expected actual=$rc"
      else
        result="DETECTION_REGRESSION"
        event active-regression "$name expected=$expected actual=$rc"
      fi
    else
      result="OK"
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$name" "$runtime" "$mode" "${expected:--}" "$rc" "$result" "${notes:-}" >> "$ACTIVE_EXPECT"
  done < "$ACTIVE_MANIFEST"
}

run_behaviour() {
  if [[ "$BEHAVIOUR" -ne 1 || "$ALL_GGUF_BEHAVIOUR" -ne 1 ]]; then
    return 0
  fi

  [[ -n "$LLAMA_CPP" && -x "$LLAMA_CPP" ]] || {
    event behaviour-skip "broad GGUF sweep requested but llama-cli unavailable"
    return 0
  }

  local roots=()
  [[ "$INCLUDE_EXTENDED" -eq 1 ]] && roots+=("$LAB_ROOT/extended")
  [[ "$INCLUDE_LARGE" -eq 1 ]] && roots+=("$LAB_ROOT/large")

  local root model case_name
  for root in "${roots[@]}"; do
    [[ -d "$root" ]] || continue

    while IFS= read -r -d '' model; do
      case_name="$(basename "$(dirname "$model")")__$(basename "$model")"

      echo
      echo "================================================================"
      echo "[behaviour] $case_name"
      echo "Model: $model"
      echo "================================================================"

      run_capture behaviour "$case_name" "behaviour-$PROFILE" "$BEHAVIOUR_TIMEOUT" \
        "$BIN" behaviour "$model" \
        --runtime llama-cpp \
        --runtime-path "$LLAMA_CPP" \
        --profile "$PROFILE" \
        --timeout-seconds "$BEHAVIOUR_TIMEOUT" \
        --json
    done < <(find "$root" -type f -iname '*.gguf' -print0 | sort -z)
  done
}

generate_reports() {
  python3 - "$OUT" "$LAB_ROOT" "$BIN" <<'PY'
import csv
import json
import pathlib
import subprocess
import sys
from collections import Counter, defaultdict

out = pathlib.Path(sys.argv[1])
lab = pathlib.Path(sys.argv[2])
binary = sys.argv[3]

with (out / "summary.tsv").open(newline="", encoding="utf-8") as fh:
    raw = list(csv.DictReader(fh, delimiter="\t"))

# Last execution of a given operation wins after retries.
latest = {}
for row in raw:
    latest[(row["group"], row["case"], row["operation"])] = row
rows = list(latest.values())

def severity(state):
    return {
        "ERROR": 100,
        "TIMEOUT": 95,
        "BLOCK": 80,
        "POLICY_BLOCK": 75,
        "INTEGRITY_OR_ERROR": 70,
        "DRIFT": 60,
        "WARN": 40,
        "UNAVAILABLE": 20,
        "PASS": 0,
    }.get(state, 50)

states = Counter(r["state"] for r in rows)
groups = Counter(r["group"] for r in rows)
by_case = defaultdict(list)
for row in rows:
    by_case[(row["group"], row["case"])].append(row)

case_rows = []
for (group, case), ops in sorted(by_case.items()):
    worst = max(ops, key=lambda r: severity(r["state"]))
    case_rows.append({
        "group": group,
        "case": case,
        "operations": len(ops),
        "worst_state": worst["state"],
        "worst_exit_code": int(worst["exit_code"]),
        "elapsed_ms": sum(int(op["elapsed_ms"]) for op in ops),
    })

with (out / "case-summary.tsv").open("w", newline="", encoding="utf-8") as fh:
    fields = ["group","case","operations","worst_state","worst_exit_code","elapsed_ms"]
    w = csv.DictWriter(fh, fieldnames=fields, delimiter="\t")
    w.writeheader()
    w.writerows(case_rows)

# Walk JSON output and collect Layerfault findings plus behaviour/runtime evidence.
finding_rows = []
semantic_rows = []
verdict_mismatches = []
egress = defaultdict(lambda: {
    "static_network_indicators": 0,
    "secret_disclosure": 0,
    "tool_exfil_intent": 0,
    "sandbox_network_isolated": "",
    "network_mechanism": "",
    "notes": set(),
})

def case_from_filename(name):
    # operation filenames are group__case__operation.stdout
    stem = name[:-7] if name.endswith(".stdout") else name
    parts = stem.split("__", 2)
    if len(parts) >= 2:
        return parts[0], parts[1]
    return "", stem

def walk(v, group, case, source):
    if isinstance(v, dict):
        status = str(v.get("status",""))
        rule = str(v.get("rule_id",""))
        matches = v.get("matches")
        detail = str(v.get("detail","") or "")

        rules = []
        if rule:
            rules.append(rule)
        rids = v.get("rule_ids")
        if isinstance(rids, list):
            rules.extend(str(x) for x in rids)

        if status.upper() in {"WARN","FAIL"} or rules:
            finding_rows.append({
                "group": group,
                "case": case,
                "source": source,
                "status": status,
                "rule_ids": ";".join(sorted(set(rules))),
                "finding_class": str(v.get("finding_class","") or ""),
                "matches": ";".join(map(str, matches)) if isinstance(matches, list) else str(matches or ""),
                "detail": detail,
            })

        key = (group, case)
        joined_rules = set(rules)

        if "LF-CODE-NETWORK" in joined_rules:
            egress[key]["static_network_indicators"] += 1
        if "LF-BEHAV-SECRET-DISCLOSURE" in joined_rules:
            egress[key]["secret_disclosure"] += 1
        if "LF-BEHAV-TOOL-EXFIL" in joined_rules:
            egress[key]["tool_exfil_intent"] += 1

        # Behaviour reports expose runtime.sandbox.*
        sandbox = v.get("sandbox")
        if isinstance(sandbox, dict) and "network_isolation" in sandbox:
            egress[key]["sandbox_network_isolated"] = str(bool(sandbox.get("network_isolation"))).lower()
            egress[key]["network_mechanism"] = str(sandbox.get("network_mechanism") or "")

        for child in v.values():
            walk(child, group, case, source)
    elif isinstance(v, list):
        for child in v:
            walk(child, group, case, source)

def semantic_verdict(value, group, operation):
    if not isinstance(value, dict):
        return None, None

    final_decision = value.get("final_decision")
    if isinstance(final_decision, str):
        return final_decision.upper(), "final_decision"

    decision = value.get("decision")
    if isinstance(decision, str) and decision.upper() in {"PASS","WARN","BLOCK"}:
        return decision.upper(), "decision"

    if group == "dataset" and "poisoning" in operation:
        state = value.get("state")
        if isinstance(state, str):
            upper = state.upper()
            if upper == "ANOMALOUS":
                return "WARN", f"dataset_state:{upper}"
            if upper == "REVIEW":
                return "WARN", f"dataset_state:{upper}"
            if upper == "NO_SUSPICIOUS_INDICATORS_OBSERVED":
                return "PASS", f"dataset_state:{upper}"
            return "WARN", f"dataset_state:{upper}"

    return None, None

def expected_rc_for_semantic(verdict, value):
    # Commands with a specialized scanner contract emit their selected exit
    # code at the top level (for example pipeline integrity BLOCK=2). Honour
    # that explicit contract while retaining canonical PASS/WARN/BLOCK mapping
    # for composite commands that do not expose a specialized code.
    emitted = value.get("exit_code") if isinstance(value, dict) else None
    if isinstance(emitted, int) and emitted in {0, 1, 2, 3, 4, 5}:
        return emitted
    return {"PASS": 0, "WARN": 1, "BLOCK": 3}.get(verdict)

latest_by_output = {}
for row in rows:
    latest_by_output[pathlib.Path(row["output"]).name] = row

for path in sorted((out / "operations").glob("*.stdout")):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        continue
    group, case = case_from_filename(path.name)
    walk(value, group, case, path.name)

    operation = ""
    operation_row = None
    for row in rows:
        if pathlib.Path(row["output"]).name == path.name:
            operation_row = row
            operation = row["operation"]
            break

    verdict, source = semantic_verdict(value, group, operation)
    if verdict:
        rc = int(operation_row["exit_code"]) if operation_row else None
        semantic_rows.append({
            "group": group,
            "case": case,
            "operation": operation,
            "semantic_verdict": verdict,
            "semantic_source": source,
            "exit_code": "" if rc is None else rc,
        })
        expected = expected_rc_for_semantic(verdict, value)
        if expected is not None and rc is not None and rc != expected:
            verdict_mismatches.append({
                "group": group,
                "case": case,
                "operation": operation,
                "semantic_verdict": verdict,
                "expected_exit_code": expected,
                "actual_exit_code": rc,
                "semantic_source": source,
            })

with (out / "semantic-summary.tsv").open("w", newline="", encoding="utf-8") as fh:
    fields = ["group","case","operation","semantic_verdict","semantic_source","exit_code"]
    w = csv.DictWriter(fh, fieldnames=fields, delimiter="\t")
    w.writeheader()
    w.writerows(semantic_rows)

with (out / "verdict-mismatches.tsv").open("w", newline="", encoding="utf-8") as fh:
    fields = [
        "group","case","operation","semantic_verdict",
        "expected_exit_code","actual_exit_code","semantic_source"
    ]
    w = csv.DictWriter(fh, fieldnames=fields, delimiter="\t")
    w.writeheader()
    w.writerows(verdict_mismatches)

# Deduplicate identical findings.
seen = set()
dedup = []
for row in finding_rows:
    key = tuple(row.items())
    if key not in seen:
        seen.add(key)
        dedup.append(row)

with (out / "findings.tsv").open("w", newline="", encoding="utf-8") as fh:
    fields = ["group","case","source","status","rule_ids","finding_class","matches","detail"]
    w = csv.DictWriter(fh, fieldnames=fields, delimiter="\t")
    w.writeheader()
    w.writerows(dedup)

# Ensure every case is represented in the egress rollup, even if zero signals.
for group, case in by_case:
    egress[(group, case)]

egress_rows = []
for (group, case), values in sorted(egress.items()):
    static = values["static_network_indicators"]
    secret = values["secret_disclosure"]
    intent = values["tool_exfil_intent"]
    isolation = values["sandbox_network_isolated"]
    mechanism = values["network_mechanism"]

    if intent or secret:
        verdict = "HIGH_RISK_EXFIL_BEHAVIOUR"
    elif static:
        verdict = "STATIC_NETWORK_CAPABILITY"
    elif isolation == "true":
        verdict = "NO_EXFIL_SIGNAL_OBSERVED_SANDBOXED"
    else:
        verdict = "NO_EXFIL_SIGNAL_OBSERVED"

    egress_rows.append({
        "group": group,
        "case": case,
        "static_network_indicators": static,
        "secret_disclosure": secret,
        "tool_exfil_intent": intent,
        "sandbox_network_isolated": isolation,
        "network_mechanism": mechanism,
        "egress_verdict": verdict,
    })

with (out / "egress-summary.tsv").open("w", newline="", encoding="utf-8") as fh:
    fields = [
        "group","case","static_network_indicators","secret_disclosure",
        "tool_exfil_intent","sandbox_network_isolated","network_mechanism",
        "egress_verdict",
    ]
    w = csv.DictWriter(fh, fieldnames=fields, delimiter="\t")
    w.writeheader()
    w.writerows(egress_rows)

try:
    version = subprocess.check_output(
        [binary, "--version"], text=True, stderr=subprocess.STDOUT
    ).strip()
except Exception as exc:
    version = f"unknown: {exc}"

meta = {
    "schema_version": "1.0",
    "layerfault": version,
    "run_directory": str(out),
    "operations": len(rows),
    "cases": len(case_rows),
    "states": dict(states),
    "groups": dict(groups),
    "case_results": case_rows,
    "egress_summary": egress_rows,
    "semantic_results": semantic_rows,
    "verdict_mismatches": verdict_mismatches,
    "boundary": (
        "Static findings identify network-capable code/config indicators. "
        "Behavioural findings identify synthetic secret disclosure and fake-tool "
        "exfiltration intent. Strong Linux behavioural runs use Layerfault's "
        "network-isolated sandbox. Absence of findings does not prove arbitrary "
        "unexecuted custom loader code can never attempt network activity."
    ),
}
(out / "summary.json").write_text(
    json.dumps(meta, indent=2) + "\n",
    encoding="utf-8",
)

print()
print("=== MASTER SUMMARY ===")
print(f"Layerfault: {version}")
print(f"Run:        {out}")
print(f"Cases:      {len(case_rows)}")
print(f"Operations: {len(rows)}")
for state, count in sorted(states.items(), key=lambda kv: -severity(kv[0])):
    print(f"{state:20s} {count}")
print()
print(f"Case summary:  {out / 'case-summary.tsv'}")
print(f"Findings:      {out / 'findings.tsv'}")
print(f"Semantic:      {out / 'semantic-summary.tsv'}")
print(f"Mismatches:    {out / 'verdict-mismatches.tsv'}")
print(f"Egress/exfil:  {out / 'egress-summary.tsv'}")
print(f"Full JSON:     {out / 'summary.json'}")
active_expect = out / "active-expectations.tsv"
if active_expect.exists():
    print(f"Active checks: {active_expect}")
PY

  echo
  if command -v column >/dev/null 2>&1; then
    column -t -s $'\t' "$OUT/case-summary.tsv"
    echo
    echo "=== EGRESS / EXFIL SUMMARY ==="
    column -t -s $'\t' "$OUT/egress-summary.tsv"
  else
    cat "$OUT/case-summary.tsv"
    echo
    cat "$OUT/egress-summary.tsv"
  fi
}

# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------

event start "binary=$BIN include_large=$INCLUDE_LARGE include_ollama=$INCLUDE_OLLAMA include_fixtures=$INCLUDE_FIXTURES active=$BEHAVIOUR profile=$PROFILE manifest=$ACTIVE_MANIFEST"

"$BIN" --version > "$OUT/meta/layerfault-version.txt" 2>&1 || true
sha256sum "$BIN" > "$OUT/meta/layerfault-binary.sha256" 2>/dev/null || true
uname -a > "$OUT/meta/uname.txt"
df -h "$LAB_ROOT" > "$OUT/meta/disk.txt"
command -v lscpu >/dev/null 2>&1 && lscpu > "$OUT/meta/lscpu.txt" || true
command -v bwrap >/dev/null 2>&1 && bwrap --version > "$OUT/meta/bwrap-version.txt" 2>&1 || true

if [[ "$BEHAVIOUR" -eq 1 ]]; then
  if [[ -n "$LLAMA_CPP" && -x "$LLAMA_CPP" ]]; then
    sha256sum "$LLAMA_CPP" > "$OUT/meta/llama-cpp.sha256" 2>/dev/null || true
    "$LLAMA_CPP" --version > "$OUT/meta/llama-cpp-version.txt" 2>&1 || true
  fi
  if [[ -n "$PYTHON_RUNTIME" && -x "$PYTHON_RUNTIME" ]]; then
    sha256sum "$PYTHON_RUNTIME" > "$OUT/meta/python-runtime.sha256" 2>/dev/null || true
    "$PYTHON_RUNTIME" --version > "$OUT/meta/python-runtime-version.txt" 2>&1 || true
  fi
  [[ -f "$ACTIVE_MANIFEST" ]] &&
    cp "$ACTIVE_MANIFEST" "$OUT/meta/ACTIVE-MANIFEST.tsv"
  timeout --signal=TERM --kill-after=15s 60s \
    "$BIN" capabilities --json > "$OUT/meta/layerfault-capabilities.json" 2>&1 || true
  timeout --signal=TERM --kill-after=15s 60s \
    "$BIN" doctor --json > "$OUT/meta/layerfault-doctor.json" 2>&1 || true
fi

[[ -f "$LAB_ROOT/SOURCE-MANIFEST.tsv" ]] &&
  cp "$LAB_ROOT/SOURCE-MANIFEST.tsv" "$OUT/meta/SOURCE-MANIFEST.tsv"
[[ -f "$LAB_ROOT/SHA256SUMS" ]] &&
  cp "$LAB_ROOT/SHA256SUMS" "$OUT/meta/CORPUS-SHA256SUMS"
[[ -f "$LAB_ROOT/OLLAMA-SOURCE-MANIFEST.tsv" ]] &&
  cp "$LAB_ROOT/OLLAMA-SOURCE-MANIFEST.tsv" "$OUT/meta/OLLAMA-SOURCE-MANIFEST.tsv"
[[ -f "$LAB_ROOT/fixtures/FIXTURE-MANIFEST.json" ]] &&
  cp "$LAB_ROOT/fixtures/FIXTURE-MANIFEST.json" "$OUT/meta/FIXTURE-MANIFEST.json"
[[ -f "$LAB_ROOT/CORPUS-COVERAGE.tsv" ]] &&
  cp "$LAB_ROOT/CORPUS-COVERAGE.tsv" "$OUT/meta/CORPUS-COVERAGE.tsv"

echo "Layerfault master corpus harness"
echo "Binary:            $BIN"
echo "Run directory:     $OUT"
echo "Static timeout:    ${STATIC_TIMEOUT}s"
echo "Ollama included:   $INCLUDE_OLLAMA"
echo "Fixtures included: $INCLUDE_FIXTURES"
echo "Active enabled:    $BEHAVIOUR"
echo "Active manifest:   $ACTIVE_MANIFEST"
echo "Active profile:    $PROFILE"
[[ -n "$LLAMA_CPP" ]] && echo "llama.cpp:         $LLAMA_CPP"
[[ -n "$PYTHON_RUNTIME" ]] && echo "Python runtime:    $PYTHON_RUNTIME"
echo

# ---------------------------------------------------------------------------
# Execute
# ---------------------------------------------------------------------------

[[ "$INCLUDE_CORE" -eq 1 ]] &&
  run_group core "$LAB_ROOT/samples"

[[ "$INCLUDE_EXTENDED" -eq 1 ]] &&
  run_group extended "$LAB_ROOT/extended"

[[ "$INCLUDE_DATASETS" -eq 1 ]] &&
  run_datasets

[[ "$INCLUDE_LARGE" -eq 1 ]] &&
  run_group large "$LAB_ROOT/large"

run_fixture_corpus
run_cli_workflow_fixtures
run_ollama_store
run_known_comparisons
run_active_manifest
run_behaviour
generate_reports

event finish "completed"

echo
echo "Done."
echo "Results: $OUT"
resume_args=()
[[ "$INCLUDE_LARGE" -eq 1 ]] && resume_args+=(--include-large)
if [[ "$BEHAVIOUR" -eq 1 ]]; then
  resume_args+=(--active)
  [[ -n "$LLAMA_CPP" ]] && resume_args+=(--llama-cpp "$LLAMA_CPP")
  [[ -n "$PYTHON_RUNTIME" ]] && resume_args+=(--python-runtime "$PYTHON_RUNTIME")
  [[ "$ALL_GGUF_BEHAVIOUR" -eq 1 ]] && resume_args+=(--all-gguf-behaviour)
fi
printf 'Resume:  %q' "$0"
printf ' %q' "${resume_args[@]}"
printf '\n'
