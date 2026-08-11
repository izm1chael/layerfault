#!/usr/bin/env python3
"""
Performance and Memory Regression Gate for Pull Requests.

Enforces deterministic wall time, peak RSS, full-file pass count, and temporary disk usage
guardrails for PR-safe scenarios before code changes can be merged.
"""
from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description="Layerfault PR Performance Regression Gate")
    parser.add_argument("--binary", type=pathlib.Path, default=pathlib.Path("target/debug/layerfault"))
    parser.add_argument("--baselines", type=pathlib.Path, default=pathlib.Path("tests/performance-baselines.json"))
    parser.add_argument("--allow-regression", type=str, default=None, help="Explicit justification for intentional performance regression")
    
    args = parser.parse_args()

    harness_script = pathlib.Path(__file__).parent / "benchmark_harness.py"

    cmd = [
        sys.executable,
        str(harness_script),
        "--binary",
        str(args.binary),
        "--baselines",
        str(args.baselines),
        "--tier",
        "pr",
    ]

    if args.allow_regression:
        cmd.extend(["--allow-regression", args.allow_regression])

    print("Running Layerfault Performance Regression Gate...")
    proc = subprocess.run(cmd)

    if proc.returncode == 0:
        print("PASS: Performance, memory, and I/O regression gate satisfied.")
        return 0
    else:
        print("FAIL: Performance regression detected! Review benchmark violations above.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
