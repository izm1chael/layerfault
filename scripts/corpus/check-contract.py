#!/usr/bin/env python3
"""Validate expected Layerfault corpus decisions and process-exit semantics."""
from __future__ import annotations
import argparse, csv, json
from pathlib import Path

RANK = {"PASS": 0, "WARN": 1, "BLOCK": 2}

def read_tsv(path: Path):
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh, delimiter="\t"))

def read_operation_output(run_dir: Path, row: dict[str, str]) -> str:
    relative = row.get("output", "")
    if not relative:
        raise ValueError("summary row has no output path")
    root = run_dir.resolve()
    output = (root / relative).resolve()
    try:
        output.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"output path escapes run directory: {relative}") from exc
    if output.stat().st_size > 64 * 1024 * 1024:
        raise ValueError(f"output exceeds 64 MiB contract-check cap: {relative}")
    return output.read_text(encoding="utf-8", errors="replace")

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir", type=Path)
    ap.add_argument("--expectations", type=Path, default=Path("tests/corpus-expectations.json"))
    args = ap.parse_args()
    summary = {(r["group"], r["case"], r["operation"]): r for r in read_tsv(args.run_dir / "summary.tsv")}
    semantic_path = args.run_dir / "semantic-summary.tsv"
    semantic = {}
    if semantic_path.exists():
        rows = read_tsv(semantic_path)
        for r in rows:
            semantic[(r["group"], r["case"], r["operation"])] = r.get("semantic_verdict") or r.get("semantic_decision") or r.get("decision") or r.get("state")
    document = json.loads(args.expectations.read_text(encoding="utf-8"))
    failures = []
    for expected in document["expectations"]:
        key = (expected["group"], expected["case"], expected["operation"])
        row = summary.get(key)
        if row is None:
            failures.append(("MISSING_OPERATION", key, expected, None))
            continue
        actual = semantic.get(key) or row["state"]
        actual_exit = int(row["exit_code"])
        if actual != expected["decision"] or actual_exit != expected["exit_code"]:
            if actual == expected["decision"] and actual_exit != expected["exit_code"]:
                kind = "SEMANTIC_MISMATCH"
            elif RANK.get(actual, -1) < RANK.get(expected["decision"], -1):
                kind = "DETECTION_REGRESSION"
            else:
                kind = "FALSE_POSITIVE_REGRESSION"
            failures.append((kind, key, expected, {"decision": actual, "exit_code": actual_exit}))
        required_prefixes = expected.get("required_rule_prefixes", [])
        if required_prefixes:
            try:
                output = read_operation_output(args.run_dir, row)
                missing = [prefix for prefix in required_prefixes if prefix not in output]
            except (OSError, ValueError) as error:
                failures.append(("EVIDENCE_UNAVAILABLE", key, expected, str(error)))
            else:
                if missing:
                    failures.append(("RULE_EVIDENCE_MISSING", key, expected, {"missing": missing}))
    for kind, key, expected, actual in failures:
        print(f"{kind}: {key}: expected={expected} actual={actual}")
    if failures:
        print(f"FAIL: {len(failures)} corpus contract violation(s)")
        return 1
    print(f"PASS: {len(document['expectations'])} corpus expectations satisfied")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
