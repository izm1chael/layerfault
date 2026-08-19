#!/usr/bin/env python3
"""Detector Quality and False-Positive/False-Negative Regression Corpus Gate.

Gates semantic detector evolution independently of parser fuzzing and structural
compatibility tests. Validates that Layerfault detects security conditions and
avoids benign false positives, and that every registered rule has corpus coverage.
"""
from __future__ import annotations
import argparse
import json
import pathlib
import subprocess
import sys
from typing import Any, Dict, List, Set, Tuple

ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = ROOT / "tests" / "detector_quality" / "manifest.json"
DEFAULT_BINARY = ROOT / "target" / "debug" / "layerfault"

KNOWN_EVIDENCE_PREDICATES = {
    "no_secret_leak",
    "subject_path",
    "correlation_id",
    "coverage_complete",
    "source_sink_type",
}

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

def extract_evidence_kinds(data: Any) -> Set[str]:
    """Recursively collect every evidence[].kind (source/sink type) emitted."""
    kinds = set()
    if isinstance(data, dict):
        if "evidence" in data and isinstance(data["evidence"], list):
            for ev in data["evidence"]:
                if isinstance(ev, dict) and isinstance(ev.get("kind"), str):
                    kinds.add(ev["kind"])
        for value in data.values():
            kinds.update(extract_evidence_kinds(value))
    elif isinstance(data, list):
        for item in data:
            kinds.update(extract_evidence_kinds(item))
    return kinds

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

def get_registered_rule_ids(binary: pathlib.Path) -> Set[str]:
    """Query the binary for the full canonical rule catalogue."""
    proc = subprocess.run(
        [str(binary), "explain", "--list", "--json"],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        rows = json.loads(proc.stdout)
    except Exception as exc:
        sys.exit(
            f"ERROR: Could not parse rule catalogue from `{binary} explain --list --json`: {exc}. "
            f"Stderr: {proc.stderr.strip()}"
        )
    ids = set()
    for row in rows:
        if isinstance(row, dict) and isinstance(row.get("rule_id"), str):
            ids.add(row["rule_id"])
    return ids

def fixture_covered_rule_ids(fixtures: List[Dict[str, Any]]) -> Set[str]:
    """Rule IDs a manifest's fixtures actually assert coverage for.

    A rule is considered covered if it appears in `must_include_rules` (it must
    fire) or as a `correlation_id` evidence predicate (a composite rule proven
    to trigger). `must_not_include_rules` does NOT count as coverage — asserting
    a rule must stay silent on a benign fixture is a negative control, not
    proof the rule can ever fire.
    """
    covered = set()
    for fixture in fixtures:
        expected = fixture.get("expected", {})
        covered.update(expected.get("must_include_rules", []))
        predicates = expected.get("evidence_predicates", {})
        corr = predicates.get("correlation_id")
        if isinstance(corr, str):
            covered.add(corr)
    return covered

def check_rule_coverage(
    binary: pathlib.Path,
    manifests: List[Tuple[str, Dict[str, Any]]],
) -> Tuple[Set[str], Set[str], List[str]]:
    """Compare the registered rule catalogue against corpus coverage + waivers.

    Returns (missing, orphaned, waiver_errors). `missing` is registered rules
    with no fixture and no justified waiver. `orphaned` is rule IDs referenced
    by fixtures/waivers that the registry no longer knows about (stale or
    renamed rules — corpus coverage claims are now lying).
    """
    registered = get_registered_rule_ids(binary)

    covered: Set[str] = set()
    waived: Set[str] = set()
    waiver_errors: List[str] = []
    for suite_name, manifest_data in manifests:
        covered.update(fixture_covered_rule_ids(manifest_data.get("fixtures", [])))
        for waiver in manifest_data.get("waivers", []):
            rule_id = waiver.get("rule_id")
            reason = waiver.get("reason", "")
            if not isinstance(rule_id, str) or not rule_id:
                waiver_errors.append(f"[{suite_name}] waiver entry missing a string 'rule_id': {waiver}")
                continue
            if not isinstance(reason, str) or not reason.strip():
                waiver_errors.append(
                    f"[{suite_name}] waiver for '{rule_id}' has no justification in its 'reason' field"
                )
                continue
            waived.add(rule_id)

    missing = registered - covered - waived
    orphaned = (covered | waived) - registered
    return missing, orphaned, waiver_errors

def validate_fixture(binary: pathlib.Path, fixture: Dict[str, Any], root: pathlib.Path, verbose: bool) -> List[str]:
    """Validate a single corpus fixture against Layerfault output."""
    errors = []
    fid = fixture.get("id", "unknown")
    cmd_spec = fixture.get("command", {})
    expected = fixture.get("expected", {})

    kind = cmd_spec.get("kind", "verify-package")
    rel_path = cmd_spec.get("path", "")
    target_path = root / rel_path

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

    unknown_predicates = set(predicates) - KNOWN_EVIDENCE_PREDICATES
    for unknown in sorted(unknown_predicates):
        errors.append(
            f"Unknown evidence_predicate '{unknown}': the runner does not validate this key, "
            f"so this fixture is not testing what its manifest entry claims. "
            f"Known predicates: {sorted(KNOWN_EVIDENCE_PREDICATES)}"
        )

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

    if "source_sink_type" in predicates:
        req_kind = predicates["source_sink_type"]
        emitted_kinds = extract_evidence_kinds(report)
        if req_kind not in emitted_kinds:
            errors.append(
                f"Evidence source/sink type mismatch: required evidence kind '{req_kind}' "
                f"not found among emitted evidence. Emitted kinds: {sorted(emitted_kinds)}"
            )

    if "coverage_complete" in predicates:
        req_cov = predicates["coverage_complete"]
        coverage = report.get("coverage")
        if not isinstance(coverage, dict) or "complete" not in coverage:
            errors.append(
                f"Coverage completeness unknown: report has no 'coverage.complete' field "
                f"(fixture requires complete={req_cov}). Absent coverage information is never "
                f"treated as complete — it is an unknown, and an unknown fails this check."
            )
        elif coverage["complete"] != req_cov:
            errors.append(f"Coverage completeness mismatch: expected complete={req_cov}, got complete={coverage['complete']}")

    if verbose and not errors:
        print(f"  [OK] {fid} ({fixture.get('category')}): {disposition} (Exit {exit_code})")

    return errors

def run_suite(binary: pathlib.Path, suite_label: str, manifest_data: Dict[str, Any], root: pathlib.Path, verbose: bool) -> Tuple[Dict[str, Dict[str, int]], List[Dict[str, Any]], int, int]:
    fixtures = manifest_data.get("fixtures", [])
    category_counts: Dict[str, Dict[str, int]] = {}
    failures: List[Dict[str, Any]] = []
    total_passed = 0
    total_failed = 0

    if verbose:
        print(f"Running {suite_label}: {manifest_data.get('suite', 'unknown')} ({len(fixtures)} fixtures)")

    for fixture in fixtures:
        cat = fixture.get("category", "uncategorized")
        if cat not in category_counts:
            category_counts[cat] = {"pass": 0, "fail": 0}

        errors = validate_fixture(binary, fixture, root, verbose)
        if errors:
            category_counts[cat]["fail"] += 1
            total_failed += 1
            failures.append({
                "id": fixture.get("id"),
                "suite": suite_label,
                "category": cat,
                "errors": errors,
            })
        else:
            category_counts[cat]["pass"] += 1
            total_passed += 1

    return category_counts, failures, total_passed, total_failed

def merge_counts(dst: Dict[str, Dict[str, int]], src: Dict[str, Dict[str, int]]) -> None:
    for cat, counts in src.items():
        if cat not in dst:
            dst[cat] = {"pass": 0, "fail": 0}
        dst[cat]["pass"] += counts["pass"]
        dst[cat]["fail"] += counts["fail"]

def main() -> None:
    parser = argparse.ArgumentParser(description="Detector Quality Gate Runner")
    parser.add_argument("--binary", type=pathlib.Path, default=DEFAULT_BINARY, help="Path to Layerfault binary")
    parser.add_argument("--manifest", type=pathlib.Path, default=DEFAULT_MANIFEST, help="Path to corpus manifest JSON")
    parser.add_argument("--private-corpus", type=pathlib.Path, default=None, help="Optional path to a private local corpus directory containing its own manifest.json")
    parser.add_argument("--skip-rule-coverage", action="store_true", help="Skip the registered-rule-vs-corpus-coverage gate (diagnostic use only)")
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

    manifests_for_coverage: List[Tuple[str, Dict[str, Any]]] = [("committed_pr", manifest_data)]

    category_counts, failures, total_passed, total_failed = run_suite(
        args.binary, "committed_pr", manifest_data, ROOT, args.verbose
    )

    private_corpus_ran = False
    if args.private_corpus:
        if not args.private_corpus.exists():
            sys.exit(f"ERROR: --private-corpus path '{args.private_corpus}' does not exist.")
        private_manifest_path = args.private_corpus / "manifest.json"
        if not private_manifest_path.exists():
            sys.exit(
                f"ERROR: --private-corpus '{args.private_corpus}' has no manifest.json "
                f"(expected '{private_manifest_path}')."
            )
        try:
            private_manifest_data = json.loads(private_manifest_path.read_text())
        except Exception as exc:
            sys.exit(f"ERROR: Failed to parse private corpus manifest '{private_manifest_path}': {exc}")

        if args.verbose:
            print(f"Scanning private corpus at '{args.private_corpus}'...")

        private_counts, private_failures, private_passed, private_failed = run_suite(
            args.binary, "private_corpus", private_manifest_data, args.private_corpus, args.verbose
        )
        merge_counts(category_counts, private_counts)
        failures.extend(private_failures)
        total_passed += private_passed
        total_failed += private_failed
        manifests_for_coverage.append(("private_corpus", private_manifest_data))
        private_corpus_ran = True

    # Rule-completeness gate: every registered rule must have a fixture or a
    # justified waiver, across whichever manifests were actually run.
    rule_coverage: Dict[str, Any] = {"checked": False}
    if not args.skip_rule_coverage:
        missing, orphaned, waiver_errors = check_rule_coverage(args.binary, manifests_for_coverage)
        rule_coverage = {
            "checked": True,
            "missing": sorted(missing),
            "orphaned": sorted(orphaned),
            "waiver_errors": waiver_errors,
        }
        if missing or orphaned or waiver_errors:
            total_failed += 1
            failures.append({
                "id": "RULE-COVERAGE-GATE",
                "suite": "rule_coverage",
                "category": "rule_coverage",
                "errors": (
                    [f"Registered rule has no fixture and no waiver: '{r}'" for r in sorted(missing)]
                    + [f"Fixture/waiver references unregistered rule ID: '{r}'" for r in sorted(orphaned)]
                    + waiver_errors
                ),
            })
        else:
            total_passed += 1

    if args.json:
        report = {
            "suite": manifest_data.get("suite"),
            "total": len(fixtures) + (len(private_manifest_data.get("fixtures", [])) if private_corpus_ran else 0),
            "passed": total_passed,
            "failed": total_failed,
            "category_counts": category_counts,
            "failures": failures,
            "rule_coverage": rule_coverage,
        }
        print(json.dumps(report, indent=2))
        sys.exit(0 if total_failed == 0 else 1)

    print("\n================ DETECTOR QUALITY CORPUS SUMMARY ================")
    print(f"Suite: {manifest_data.get('suite')} | Total Fixtures: {len(fixtures)}")
    if private_corpus_ran:
        print(f"Private corpus: {args.private_corpus} | Fixtures: {len(private_manifest_data.get('fixtures', []))}")
    print("----------------------------------------------------------------")
    for cat, counts in sorted(category_counts.items()):
        status_str = f"PASS: {counts['pass']} | FAIL: {counts['fail']}"
        print(f"  Category '{cat}': {status_str}")
    print("----------------------------------------------------------------")
    if rule_coverage.get("checked"):
        n_missing = len(rule_coverage["missing"])
        n_orphaned = len(rule_coverage["orphaned"])
        print(f"  Rule coverage: {n_missing} registered rule(s) missing a fixture/waiver, {n_orphaned} orphaned reference(s)")
    print("----------------------------------------------------------------")

    if failures:
        print("\nACTIONABLE DETECTOR QUALITY REGRESSION DIFFS:")
        for fail in failures:
            print(f"\n[FAIL] Fixture: {fail['id']} (Suite: {fail.get('suite', 'committed_pr')}, Category: {fail['category']})")
            for err in fail["errors"]:
                print(f"  - {err}")
        print("\nRESULT: FAILED (Semantic detector regressions, false-positive noise, or rule-coverage gaps detected)")
        sys.exit(1)
    else:
        print("\nRESULT: PASS (All semantic detector conditions, false-positive regressions, and rule coverage validated)")
        sys.exit(0)

if __name__ == "__main__":
    main()
