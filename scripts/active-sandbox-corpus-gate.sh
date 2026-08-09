#!/usr/bin/env bash
set -euo pipefail

BIN="${LAYERFAULT_BIN:-/usr/local/bin/layerfault}"
MANIFEST="${1:-tests/active-sandbox-corpus-template.tsv}"
OUT_DIR="${LAYERFAULT_ACTIVE_RESULTS_DIR:-./active-sandbox-results}"
LLAMA_RUNTIME="${LAYERFAULT_LLAMA_RUNTIME:-}"
PYTHON_RUNTIME="${LAYERFAULT_PYTHON_RUNTIME:-}"
PROBE_SUITE="${LAYERFAULT_ACTIVE_PROBE_SUITE:-}"

[[ -x "$BIN" ]] || { echo "Layerfault binary not executable: $BIN" >&2; exit 64; }
[[ -f "$MANIFEST" ]] || { echo "Active sandbox manifest not found: $MANIFEST" >&2; exit 64; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required to validate JSON sandbox contracts" >&2; exit 64; }
mkdir -p "$OUT_DIR"

fail=0
while IFS=$'\t' read -r name mode runtime model base profile flags expected_exit notes; do
  [[ -z "${name:-}" || "$name" == \#* ]] && continue
  [[ -e "$model" ]] || { echo "FAIL $name: model missing: $model" >&2; fail=1; continue; }
  if [[ "$mode" == "compare" ]]; then
    [[ -n "${base:-}" && -e "$base" ]] || { echo "FAIL $name: comparison base missing: $base" >&2; fail=1; continue; }
  fi

  case "$runtime" in
    llama-cpp)
      [[ -n "$LLAMA_RUNTIME" && -x "$LLAMA_RUNTIME" ]] || {
        echo "FAIL $name: set LAYERFAULT_LLAMA_RUNTIME to the audited llama.cpp executable" >&2
        fail=1; continue;
      }
      runtime_path="$LLAMA_RUNTIME"
      ;;
    transformers|transformers-python)
      runtime_path="$PYTHON_RUNTIME"
      if [[ -n "$runtime_path" && ! -x "$runtime_path" ]]; then
        echo "FAIL $name: LAYERFAULT_PYTHON_RUNTIME is not executable: $runtime_path" >&2
        fail=1; continue
      fi
      ;;
    *)
      echo "FAIL $name: unsupported active runtime '$runtime'" >&2
      fail=1; continue
      ;;
  esac

  cmd=("$BIN")
  if [[ "$mode" == "compare" ]]; then
    cmd+=(compare-behaviour "$base" "$model")
  elif [[ "$mode" == "behaviour" ]]; then
    cmd+=(behaviour "$model")
    [[ -n "${base:-}" && "$base" != "-" ]] && cmd+=(--base "$base")
  else
    echo "FAIL $name: mode must be behaviour or compare" >&2
    fail=1; continue
  fi
  cmd+=(--runtime "$runtime" --profile "${profile:-standard}" --json)
  [[ -n "$PROBE_SUITE" ]] && cmd+=(--probe-suite "$PROBE_SUITE")
  [[ -n "$runtime_path" ]] && cmd+=(--runtime-path "$runtime_path")

  high_risk=0
  IFS=',' read -r -a flag_values <<< "${flags:-}"
  for flag in "${flag_values[@]}"; do
    case "${flag// /}" in
      "") ;;
      allow-static-blocked)
        cmd+=(--allow-static-blocked); high_risk=1 ;;
      execute-custom-code)
        cmd+=(--execute-custom-code); high_risk=1 ;;
      *)
        echo "FAIL $name: unknown flag '$flag'" >&2
        fail=1; continue 2 ;;
    esac
  done

  safe_name=$(printf '%s' "$name" | tr -c 'A-Za-z0-9._-' '_')
  json_out="$OUT_DIR/${safe_name}.json"
  err_out="$OUT_DIR/${safe_name}.stderr.txt"
  echo "==> $name${notes:+ — $notes}"
  set +e
  "${cmd[@]}" >"$json_out" 2>"$err_out"
  rc=$?
  set -e
  echo "exit=$rc json=$json_out"

  if [[ -n "${expected_exit:-}" && "$expected_exit" != "-" && "$rc" != "$expected_exit" ]]; then
    echo "BEHAVIOUR_REGRESSION $name: expected exit $expected_exit, got $rc" >&2
    fail=1
  fi
  if [[ ! -s "$json_out" ]]; then
    echo "ACTIVE_CONTRACT $name: command emitted no JSON report" >&2
    fail=1
    continue
  fi

  if ! python3 - "$json_out" "$mode" "$high_risk" <<'PY'
import json, sys
path, mode, high_risk = sys.argv[1], sys.argv[2], sys.argv[3] == "1"
with open(path, "r", encoding="utf-8") as fh:
    doc = json.load(fh)
reports = [doc]
if mode == "compare":
    reports = [doc.get("base", {}), doc.get("derived", {})]
errors = []
for index, report in enumerate(reports):
    sandbox = report.get("runtime", {}).get("sandbox", {})
    label = f"report[{index}]"
    for key in (
        "workspace_isolated", "home_isolated", "environment_scrubbed",
        "network_isolation", "host_files_hidden", "real_tools_disabled",
        "process_namespace_isolated", "ipc_namespace_isolated",
        "uts_namespace_isolated", "capabilities_dropped",
    ):
        if sandbox.get(key) is not True:
            errors.append(f"{label}: sandbox.{key} was not true")
    if sandbox.get("resource_limits") is not True:
        errors.append(f"{label}: external active execution lacked resource limits")
    if not sandbox.get("address_space_limit_bytes"):
        errors.append(f"{label}: external active execution lacked address-space limit")
    if high_risk and sandbox.get("syscall_trace") is not True:
        errors.append(f"{label}: high-risk execution lacked syscall tracing")
    if high_risk and report.get("dynamic_observations", {}).get("trace_available") is not True:
        errors.append(f"{label}: high-risk execution did not retain syscall telemetry")
if errors:
    for error in errors:
        print("ACTIVE_CONTRACT", error, file=sys.stderr)
    raise SystemExit(1)
PY
  then
    fail=1
  fi
done < "$MANIFEST"

exit "$fail"
