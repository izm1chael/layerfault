#!/usr/bin/env bash
set -euo pipefail
[[ $# -ge 4 ]] || { echo "Usage: $0 RUN_DIR NAME TIMEOUT_SECONDS command..." >&2; exit 2; }
run="$1" name="$2" timeout_secs="$3"; shift 3
mkdir -p "$run/operations"
stdout="$run/operations/$name.stdout"; stderr="$run/operations/$name.stderr"; marker="$run/operations/$name.inprogress"; donef="$run/operations/$name.done"
[[ -f "$donef" ]] && { echo "[active] $name already complete; skipping"; exit 0; }
printf 'start_utc=%s\npid=%s\ncommand=' "$(date -u +%FT%TZ)" "$$" >"$marker"; printf '%q ' "$@" >>"$marker"; printf '\n' >>"$marker"
cleanup(){ rm -f "$marker"; }
interrupt_cleanup(){
  if [[ -n "${child:-}" ]] && kill -0 "$child" 2>/dev/null; then
    kill -TERM -- "-$child" 2>/dev/null || true
    for _ in 1 2 3 4 5; do
      kill -0 "$child" 2>/dev/null || break
      sleep 1
    done
    kill -KILL -- "-$child" 2>/dev/null || true
    wait "$child" 2>/dev/null || true
  fi
  cleanup
}
trap cleanup EXIT
trap 'interrupt_cleanup; exit 130' INT
trap 'interrupt_cleanup; exit 143' TERM
command -v setsid >/dev/null 2>&1 || { echo "setsid is required for process-tree containment" >&2; exit 2; }
setsid "$@" >"$stdout" 2>"$stderr" & child=$!
started=$SECONDS; timed_out=0
last_heartbeat=-10
while kill -0 "$child" 2>/dev/null; do
  elapsed=$((SECONDS-started))
  if (( elapsed - last_heartbeat >= 10 )); then
    echo "ACTIVE $name elapsed=${elapsed}s pid=$child"
    last_heartbeat=$elapsed
  fi
  if (( elapsed >= timeout_secs )); then
    timed_out=1
    kill -TERM -- "-$child" 2>/dev/null || true
    for _ in $(seq 1 15); do
      kill -0 "$child" 2>/dev/null || break
      sleep 1
    done
    kill -KILL -- "-$child" 2>/dev/null || true
    break
  fi
  sleep 1
done
set +e; wait "$child"; rc=$?; set -e
if (( timed_out )); then printf 'TIMEOUT\n' >"$run/operations/$name.state"; exit 124; fi
printf '%s\n' "$rc" >"$run/operations/$name.rc"
[[ "$rc" -eq 0 ]] && touch "$donef"
exit "$rc"
