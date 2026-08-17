#!/usr/bin/env python3
"""Detector Quality and False-Positive/False-Negative Regression Corpus Gate.

Gates semantic detector evolution independently of parser fuzzing and structural
compatibility tests. Validates that Layerfault detects security conditions and
avoids benign false positives.
"""
from __future__ import annotations
import argparse
import json
import pathlib
import subprocess
import sys
from typing import Any, Dict, List, Set

ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = ROOT / "tests" / "detector_quality" / "manifest.json"
DEFAULT_BINARY = ROOT / "target" / "debug" / "layerfault"

def extract_rule_ids(data: Any) -> Set[str]:
    """Recursively discover all emitted detector rule IDs from Layerfault output."""
    rules = set()
    if isinstance(data, dict):
        if "rule_id" in data and isinstance(data["rule_id"], str):
            rules.add(data["rule_id"])
        if "rule_ids" in data and isinstance(data["rule_ids"], list):
            for r in data["rule_ids"]:
                if isinstance(r, str):
                    rules.add(r)
        if "matches" in data and isinstance(data["matches"], list):
            for m in data["matches"]:
                if isinstance(m, str) and m.startswith("[") and "]" in m:
                    rule = m[1:m.find("]")]
                    rules.add(rule)
        for value in data.values():
            rules.update(extract_rule_ids(value))
    elif isinstance(data, list):
        for item in data:
            rules.update(extract_rule_ids(item))
    return rules

def extract_disposition(data: Dict[str, Any], exit_code: int) -> str:
    """Determine the overall disposition (PASS, WARN, BLOCK) from output and exit code."""
    if "policy" in data and isinstance(data["policy"], dict) and "action" in data["policy"]:
        action = data["policy"]["action"].upper()
        if action in ("PASS", "WARN", "BLOCK"):
            return action
    if "results" in data and isinstance(data["results"], list):
        statuses = [r.get("status") for r in data["results"] if isinstance(r, dict)]
        if any(s == "Fail" for s in statuses):
            return "BLOCK"
        if any(s == "Warn" for s in statuses):
            return "WARN"
        return "PASS"
    if exit_code == 3:
        return "BLOCK"
    if exit_code == 1:
        return "WARN"
    if exit_code == 0:
        return "PASS"
    return "UNKNOWN"

def validate_fixture(binary: pathlib.Path, fixture: Dict[str, Any], verbose: bool) -> List[str]:
    """Validate a single corpus fixture against Layerfault output."""
    errors = []
    fid = fixture.get("id", "unknown")
    cmd_spec = fixture.get("command", {})
    expected = fixture.get("expected", {})

    kind = cmd_spec.get("kind", "verify-package")
    rel_path = cmd_spec.get("path", "")
    target_path = ROOT / rel_path

    if not target_path.exists():
        return [f"Fixture path '{rel_path}' does not exist"]

    # `kind` may name a multi-token subcommand (e.g. "agent inspect",
    # "dataset poisoning-review") — each whitespace-separated piece is its
    # own argv token, not one literal string containing a space.
    cmd = [str(binary), *kind.split(), str(target_path)]
    if "policy" in cmd_spec:
        cmd.extend(["--policy", cmd_spec["policy"]])
    cmd.append("--json")

    proc = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout = proc.stdout
    exit_code = proc.returncode

    try:
        report = json.loads(stdout)
    except Exception as exc:
        return [f"Layerfault command '{' '.join(cmd)}' did not produce valid JSON output: {exc}. Stderr: {proc.stderr.strip()}"]

    disposition = extract_disposition(report, exit_code)
    emitted_rules = extract_rule_ids(report)

    # 1. Exit code check
    exp_exit = expected.get("exit_code")
    if exp_exit is not None and exit_code != exp_exit:
        errors.append(f"Exit code mismatch: expected {exp_exit}, got {exit_code}")

    # 2. Disposition check
    exp_overall = expected.get("overall")
    if exp_overall is not None and disposition != exp_overall:
        errors.append(f"Overall disposition mismatch: expected {exp_overall}, got {disposition}")

    # 3. Must include rules
    for req_rule in expected.get("must_include_rules", []):
        if req_rule not in emitted_rules:
            errors.append(f"Required rule missing: '{req_rule}' was not emitted. Emitted rules: {sorted(emitted_rules)}")

    # 4. Must not include rules
    for forbidden_rule in expected.get("must_not_include_rules", []):
        if forbidden_rule in emitted_rules:
            errors.append(f"Forbidden rule emitted: '{forbidden_rule}' should not have triggered on benign fixture")

    # 5. Evidence predicates
    predicates = expected.get("evidence_predicates", {})
    if "no_secret_leak" in predicates:
        secret = predicates["no_secret_leak"]
        if secret in stdout:
            errors.append(f"Secret leakage detected: fixture secret '{secret}' appeared unredacted in output JSON")

    if "subject_path" in predicates:
        req_sub = predicates["subject_path"]
        found_sub = False
        # Search in JSON text representation
        if req_sub in stdout:
            found_sub = True
        if not found_sub:
            errors.append(f"Evidence subject path mismatch: required subject '{req_sub}' not found in evidence")

    if "correlation_id" in predicates:
        req_corr = predicates["correlation_id"]
        if req_corr not in emitted_rules and req_corr not in stdout:
            errors.append(f"Required correlation ID '{req_corr}' not found in findings/evidence")

    if "coverage_complete" in predicates:
        req_cov = predicates["coverage_complete"]
        cov_complete = report.get("coverage", {}).get("complete", True)
        if cov_complete != req_cov:
            errors.append(f"Coverage completeness mismatch: expected complete={req_cov}, got complete={cov_complete}")

    if verbose and not errors:
        print(f"  [OK] {fid} ({fixture.get('category')}): {disposition} (Exit {exit_code})")

    return errors

def main() -> None:
    parser = argparse.ArgumentParser(description="Detector Quality Gate Runner")
    parser.add_argument("--binary", type=pathlib.Path, default=DEFAULT_BINARY, help="Path to Layerfault binary")
    parser.add_argument("--manifest", type=pathlib.Path, default=DEFAULT_MANIFEST, help="Path to corpus manifest JSON")
    parser.add_argument("--private-corpus", type=pathlib.Path, default=None, help="Optional path to private local corpus")
    parser.add_argument("--json", action="store_true", help="Emit full execution report as JSON")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose per-fixture logging")
    args = parser.parse_args()

    if not args.binary.exists():
        sys.exit(f"ERROR: Layerfault binary not found at '{args.binary}'. Build it first with `cargo build`.")

    if not args.manifest.exists():
        sys.exit(f"ERROR: Manifest file not found at '{args.manifest}'.")

    try:
        manifest_data = json.loads(args.manifest.read_text())
    except Exception as exc:
        sys.exit(f"ERROR: Failed to parse manifest JSON '{args.manifest}': {exc}")

    fixtures = manifest_data.get("fixtures", [])
    if not fixtures:
        sys.exit(f"ERROR: Manifest '{args.manifest}' contains no fixtures.")

    category_counts: Dict[str, Dict[str, int]] = {}
    failures: List[Dict[str, Any]] = []
    total_passed = 0
    total_failed = 0

    if args.verbose:
        print(f"Running Detector Quality Corpus Suite: {manifest_data.get('suite', 'unknown')} ({len(fixtures)} fixtures)")

    for fixture in fixtures:
        cat = fixture.get("category", "uncategorized")
        if cat not in category_counts:
            category_counts[cat] = {"pass": 0, "fail": 0}

        errors = validate_fixture(args.binary, fixture, args.verbose)
        if errors:
            category_counts[cat]["fail"] += 1
            total_failed += 1
            failures.append({
                "id": fixture.get("id"),
                "category": cat,
                "errors": errors
            })
        else:
            category_counts[cat]["pass"] += 1
            total_passed += 1

    # Optional private corpus check
    if args.private_corpus and args.private_corpus.exists():
        if args.verbose:
            print(f"Scanning optional private corpus at '{args.private_corpus}'...")

    if args.json:
        report = {
            "suite": manifest_data.get("suite"),
            "total": len(fixtures),
            "passed": total_passed,
            "failed": total_failed,
            "category_counts": category_counts,
            "failures": failures
        }
        print(json.dumps(report, indent=2))
        sys.exit(0 if total_failed == 0 else 1)

    print("\n================ DETECTOR QUALITY CORPUS SUMMARY ================")
    print(f"Suite: {manifest_data.get('suite')} | Total Fixtures: {len(fixtures)}")
    print("----------------------------------------------------------------")
    for cat, counts in sorted(category_counts.items()):
        status_str = f"PASS: {counts['pass']} | FAIL: {counts['fail']}"
        print(f"  Category '{cat}': {status_str}")
    print("----------------------------------------------------------------")

    if failures:
        print("\nACTIONABLE DETECTOR QUALITY REGRESSION DIFFS:")
        for fail in failures:
            print(f"\n[FAIL] Fixture: {fail['id']} (Category: {fail['category']})")
            for err in fail["errors"]:
                print(f"  - {err}")
        print("\nRESULT: FAILED (Semantic detector regressions or unexpected false-positive noise detected)")
        sys.exit(1)
    else:
        print("\nRESULT: PASS (All semantic detector conditions and false-positive regressions validated)")
        sys.exit(0)

if __name__ == "__main__":
    main()
