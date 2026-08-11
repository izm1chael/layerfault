#!/usr/bin/env python3
"""Offline contract smoke checks for Layerfault's shipped JSON schemas.

This intentionally uses only the Python standard library. It validates that every
schema is parseable Draft-2020-12-shaped JSON and checks representative command
outputs for the stable required fields/types used by automation. It is not a
replacement for a full JSON Schema validator; release CI may additionally run one.

`sarif-2.1.0.json` is a verbatim vendored copy of the upstream OASIS SARIF
schema (committed unmodified so re-vendoring stays a clean diff) and predates
Draft 2020-12, so it is exempted from the draft-version check below and
validated structurally instead, against representative SARIF output from the
binary.
"""
from __future__ import annotations
import argparse, json, pathlib, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "schemas"

REQUIRED = {
    "artifact-report.json": {"identity", "source", "report", "trust_state", "trusted_signatures", "signer_fingerprints", "policy"},
    "certification.json": {"tool_version", "passed", "checks"},
}

# Vendored third-party schemas: authoritative as shipped upstream, not
# repo-authored, so the repo's own Draft-2020-12 authoring convention does
# not apply to them.
VENDORED = {"sarif-2.1.0.json"}

SARIF_REQUIRED_TOP = {"$schema", "version", "runs"}
SARIF_REQUIRED_RUN = {"tool", "results"}
SARIF_REQUIRED_RESULT = {"ruleId", "level", "message"}

def load_schemas() -> None:
    failures=[]
    schemas = sorted(SCHEMAS.glob("*.json"))
    if not schemas:
        raise SystemExit(f"no JSON schemas discovered under {SCHEMAS}")
    for path in schemas:
        try: obj=json.loads(path.read_text())
        except Exception as exc: failures.append(f"{path.name}: invalid JSON: {exc}"); continue
        if path.name not in VENDORED and obj.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            failures.append(f"{path.name}: expected Draft 2020-12 $schema")
        if obj.get("type") not in ("object", "array"): failures.append(f"{path.name}: root type must be object or array")
        if path.name in VENDORED and "$defs" not in obj and "definitions" not in obj:
            failures.append(f"{path.name}: vendored schema missing $defs/definitions section")
    if failures: raise SystemExit("\n".join(failures))

def run_json(binary: pathlib.Path, *args: str) -> dict:
    proc=subprocess.run([str(binary), *args], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode not in (0,1,2,3):
        raise SystemExit(f"{' '.join(args)} exited {proc.returncode}: {proc.stderr.strip()}")
    try: return json.loads(proc.stdout)
    except Exception as exc: raise SystemExit(f"{' '.join(args)} did not emit JSON: {exc}")

def require(name: str, obj: dict) -> None:
    missing=REQUIRED[name]-set(obj)
    if missing: raise SystemExit(f"{name}: representative output missing {sorted(missing)}")

def check_sarif(doc: dict) -> None:
    """Hand-rolled structural smoke check, not a full JSON Schema validator.

    Vendoring a `jsonschema`-style validator would be a new dependency; this
    instead asserts the handful of keys the vendored schema itself requires
    at the levels Layerfault actually populates, which is enough to catch a
    gross regression in the typed SARIF emission path.
    """
    missing = SARIF_REQUIRED_TOP - set(doc)
    if missing: raise SystemExit(f"sarif: missing top-level {sorted(missing)}")
    if doc.get("version") != "2.1.0":
        raise SystemExit(f"sarif: version must be '2.1.0', got {doc.get('version')!r}")
    runs = doc.get("runs")
    if not isinstance(runs, list) or not runs:
        raise SystemExit("sarif: 'runs' must be a non-empty array")
    run = runs[0]
    missing = SARIF_REQUIRED_RUN - set(run)
    if missing: raise SystemExit(f"sarif: run missing {sorted(missing)}")
    if not isinstance(run.get("tool", {}).get("driver", {}).get("name"), str):
        raise SystemExit("sarif: tool.driver.name must be a string")
    for i, result in enumerate(run.get("results", [])):
        missing = SARIF_REQUIRED_RESULT - set(result)
        if missing: raise SystemExit(f"sarif: results[{i}] missing {sorted(missing)}")
        if not isinstance(result.get("message", {}).get("text"), str):
            raise SystemExit(f"sarif: results[{i}].message.text must be a string")
        for loc in result.get("locations", []):
            physical = loc.get("physicalLocation", {})
            if "uri" not in physical.get("artifactLocation", {}):
                raise SystemExit(f"sarif: results[{i}] has a location missing artifactLocation.uri")

def run_sarif(binary: pathlib.Path, *args: str) -> dict:
    proc=subprocess.run([str(binary), *args], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode not in (0,1,2,3):
        raise SystemExit(f"{' '.join(args)} exited {proc.returncode}: {proc.stderr.strip()}")
    try: return json.loads(proc.stdout)
    except Exception as exc: raise SystemExit(f"{' '.join(args)} did not emit SARIF JSON: {exc}")

def main() -> None:
    ap=argparse.ArgumentParser(); ap.add_argument("--binary", type=pathlib.Path)
    ap.add_argument("--sarif-fixture", type=pathlib.Path, help="Path scanned to produce representative SARIF output")
    ns=ap.parse_args(); load_schemas()
    if ns.binary:
        cert=run_json(ns.binary, "selftest", "--json"); require("certification.json", cert)
        version=run_json(ns.binary, "version", "--json")
        for key in ("name","version","supported_formats","sources"):
            if key not in version: raise SystemExit(f"version JSON missing {key}")
        if ns.sarif_fixture:
            sarif = run_sarif(ns.binary, "pipeline", str(ns.sarif_fixture), "--sarif")
            check_sarif(sarif)
    print("PASS: JSON schemas and representative machine-output contracts")
if __name__ == "__main__": main()
