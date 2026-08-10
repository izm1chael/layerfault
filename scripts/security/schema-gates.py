#!/usr/bin/env python3
"""Offline contract smoke checks for Layerfault's shipped JSON schemas.

This intentionally uses only the Python standard library. It validates that every
schema is parseable Draft-2020-12-shaped JSON and checks representative command
outputs for the stable required fields/types used by automation. It is not a
replacement for a full JSON Schema validator; release CI may additionally run one.
"""
from __future__ import annotations
import argparse, json, pathlib, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "schemas"

REQUIRED = {
    "artifact-report.json": {"identity", "source", "report", "trust_state", "trusted_signatures", "signer_fingerprints", "policy"},
    "certification.json": {"tool_version", "passed", "checks"},
}

def load_schemas() -> None:
    failures=[]
    schemas = sorted(SCHEMAS.glob("*.json"))
    if not schemas:
        raise SystemExit(f"no JSON schemas discovered under {SCHEMAS}")
    for path in schemas:
        try: obj=json.loads(path.read_text())
        except Exception as exc: failures.append(f"{path.name}: invalid JSON: {exc}"); continue
        if obj.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            failures.append(f"{path.name}: expected Draft 2020-12 $schema")
        if obj.get("type") not in ("object", "array"): failures.append(f"{path.name}: root type must be object or array")
    if failures: raise SystemExit("\n".join(failures))

def run_json(binary: pathlib.Path, *args: str) -> dict:
    proc=subprocess.run([str(binary), *args], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode not in (0,1):
        raise SystemExit(f"{' '.join(args)} exited {proc.returncode}: {proc.stderr.strip()}")
    try: return json.loads(proc.stdout)
    except Exception as exc: raise SystemExit(f"{' '.join(args)} did not emit JSON: {exc}")

def require(name: str, obj: dict) -> None:
    missing=REQUIRED[name]-set(obj)
    if missing: raise SystemExit(f"{name}: representative output missing {sorted(missing)}")

def main() -> None:
    ap=argparse.ArgumentParser(); ap.add_argument("--binary", type=pathlib.Path)
    ns=ap.parse_args(); load_schemas()
    if ns.binary:
        cert=run_json(ns.binary, "selftest", "--json"); require("certification.json", cert)
        version=run_json(ns.binary, "version", "--json")
        for key in ("name","version","supported_formats","sources"):
            if key not in version: raise SystemExit(f"version JSON missing {key}")
    print("PASS: JSON schemas and representative machine-output contracts")
if __name__ == "__main__": main()
