#!/usr/bin/env python3
"""Broad ratio-based corpus performance guard; avoids VPS-specific fixed milliseconds."""
from __future__ import annotations
import argparse, csv, json
from pathlib import Path

def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument("run_dir", type=Path)
    ap.add_argument("--rules", type=Path, default=Path("tests/corpus-performance.json"))
    args=ap.parse_args()
    with (args.run_dir/"summary.tsv").open(newline="",encoding="utf-8") as fh:
        rows=list(csv.DictReader(fh,delimiter="\t"))
    elapsed={(r["group"],r["case"],r["operation"]):int(r["elapsed_ms"]) for r in rows}
    rules=json.loads(args.rules.read_text(encoding="utf-8"))["ratio_rules"]
    failures=[]
    for rule in rules:
        cold_key=(rule["group"],rule["case"],rule["cold"])
        cold=elapsed.get(cold_key)
        if cold is None or cold <= 0:
            continue
        for operation in rule["warm"]:
            key=(rule["group"],rule["case"],operation)
            warm=elapsed.get(key)
            if warm is None:
                continue
            ratio=warm/cold
            print(f"{rule['case']} {operation}: {warm}ms / {cold}ms = {ratio:.4f}")
            if ratio > float(rule["max_ratio"]):
                failures.append((key,ratio,rule["max_ratio"]))
    if failures:
        for key,ratio,limit in failures:
            print(f"PERFORMANCE_REGRESSION: {key}: ratio={ratio:.4f} limit={limit}")
        return 1
    print("PASS: corpus warm/cold performance ratios within broad guardrails")
    return 0

if __name__ == "__main__": raise SystemExit(main())
