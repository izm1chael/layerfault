#!/usr/bin/env bash
set -euo pipefail
[[ $# -ge 1 ]] || { echo "Usage: $0 MODEL_OR_PACKAGE [warm-runs=3] [output.tsv]" >&2; exit 2; }
target="$1"; warm_runs="${2:-3}"; output="${3:-fingerprint-benchmark.tsv}"
[[ "$warm_runs" =~ ^[0-9]+$ && "$warm_runs" -ge 3 ]] || { echo "warm-runs must be >=3" >&2; exit 2; }
command -v layerfault >/dev/null || { echo "layerfault not on PATH" >&2; exit 2; }
bytes="$(python3 - "$target" <<'PY'
from pathlib import Path
import os,sys
p=Path(sys.argv[1]); total=0
if p.is_file(): total=p.stat().st_size
elif p.is_dir():
  for root,ds,fs in os.walk(p, followlinks=False):
    for f in fs:
      q=Path(root)/f
      try:
        if not q.is_symlink(): total+=q.stat().st_size
      except OSError: pass
print(total)
PY
)"
printf 'phase\trun\tbytes\twall_seconds\tcpu_seconds\tpeak_rss_kib\tthroughput_mib_s\n' >"$output"
run_one(){
  local phase="$1" run="$2" tf; tf="$(mktemp)"
  /usr/bin/time -f '%e\t%U\t%S\t%M' -o "$tf" layerfault fingerprint "$target" --json >/dev/null
  IFS=$'\t' read -r wall user sys rss <"$tf"; rm -f "$tf"
  python3 - "$phase" "$run" "$bytes" "$wall" "$user" "$sys" "$rss" >>"$output" <<'PY'
import sys
phase,run,b,w,u,s,r=sys.argv[1:]; b=int(b); w=float(w); cpu=float(u)+float(s)
tp=(b/(1024*1024)/w) if w>0 else 0
print(f"{phase}\t{run}\t{b}\t{w:.6f}\t{cpu:.6f}\t{r}\t{tp:.3f}")
PY
}
# A cold-cache attempt is made only when the operator explicitly permits it.
if [[ "${LAYERFAULT_BENCH_DROP_CACHES:-0}" == 1 && "$(id -u)" -eq 0 && -w /proc/sys/vm/drop_caches ]]; then
  sync; echo 3 >/proc/sys/vm/drop_caches; run_one cold 1
else
  echo "Cold-cache run skipped (set LAYERFAULT_BENCH_DROP_CACHES=1 as root to enable)." >&2
fi
for ((i=1;i<=warm_runs;i++)); do run_one warm "$i"; done
cat "$output"
