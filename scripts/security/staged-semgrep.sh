#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

mapfile -d '' -t staged < <(git diff --cached --name-only --diff-filter=ACMR -z)
files=()
for path in "${staged[@]}"; do
  [[ -f "$path" ]] || continue
  case "$path" in
    tests/detector_quality/manifest.json|tests/detector_quality/release_manifest.json|tests/detector_quality/fixtures/redaction/secret_in_code/modeling_secret.py)
      # These files deliberately contain the same synthetic credential so the
      # detector-quality gate can prove Layerfault redacts it from output.
      continue
      ;;
  esac
  case "$path" in
    *.rs|*.py|*.sh|*.yml|*.yaml|*.json|Dockerfile)
      files+=("$path")
      ;;
  esac
done

[[ ${#files[@]} -gt 0 ]] || exit 0
semgrep scan --config auto --error "${files[@]}"
