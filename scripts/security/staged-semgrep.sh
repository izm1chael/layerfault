#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

mapfile -d '' -t staged < <(git diff --cached --name-only --diff-filter=ACMR -z)
files=()
for path in "${staged[@]}"; do
  [[ -f "$path" ]] || continue
  case "$path" in
    *.rs|*.py|*.sh|*.yml|*.yaml|*.json|Dockerfile)
      files+=("$path")
      ;;
  esac
done

[[ ${#files[@]} -gt 0 ]] || exit 0
semgrep scan --config auto --error "${files[@]}"
