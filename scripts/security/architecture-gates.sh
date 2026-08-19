#!/usr/bin/env bash
# Guards against the decomposed-module-regrowth failure mode: a subsystem
# directory exists but its child modules are empty stubs while the real
# implementation stays in mod.rs (or a monolithic root file returns).
set -euo pipefail

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
cd "$ROOT"

fail=0
error() {
    printf 'ARCHITECTURE ERROR:\n%s\n' "$*" >&2
    fail=1
}

# Directory -> required child modules (space-separated, no .rs suffix).
declare -A REQUIRED_CHILDREN=(
    [src/binding]="types copy stage manifest revalidate"
    [src/behaviour/sandbox]="types limits process backend command seccomp telemetry"
    [src/platform/db]="connection schema types jobs reviews weekly"
    [src/model/weights]="types discovery statistics compare sampling decode"
    [src/model/dataset]="types readers inventory sampling analysis indicators"
    [src/hub]="types client cache"
    [src/cli]="args dispatch output scan_setup validation"
)

# mod.rs -> max line count.
declare -A MOD_LINE_LIMITS=(
    [src/binding/mod.rs]=300
    [src/behaviour/sandbox/mod.rs]=400
    [src/platform/db/mod.rs]=300
    [src/model/weights/mod.rs]=300
    [src/model/dataset/mod.rs]=300
    [src/hub/mod.rs]=350
    [src/cli/mod.rs]=350
    [src/rules/catalogue/mod.rs]=20
)

# Monolith locations that must not return as substantive files. A file here
# may still exist as a tiny compatibility facade (<= 25 non-comment/non-blank
# lines); it fails only if it grows back into real implementation.
MONOLITH_FACADE_MAX_LINES=25
MONOLITHS=(
    src/binding.rs
    src/rules/catalogue.rs
)

substantive_line_count() {
    # Count lines that are neither blank nor a `//` comment line.
    grep -cve '^[[:space:]]*$' -e '^[[:space:]]*//' "$1" || true
}

for dir in "${!REQUIRED_CHILDREN[@]}"; do
    if [[ ! -d "$dir" ]]; then
        error "$dir is missing. The subsystem decomposition has not happened."
        continue
    fi
    for child in ${REQUIRED_CHILDREN[$dir]}; do
        file="$dir/$child.rs"
        if [[ ! -f "$file" ]]; then
            error "$file does not exist. The decomposition is incomplete."
            continue
        fi
        if [[ ! -s "$file" ]]; then
            error "$file is empty. The decomposition is incomplete."
            continue
        fi
        substantive="$(substantive_line_count "$file")"
        if [[ "$substantive" -eq 0 ]]; then
            error "$file contains only whitespace/comments. The decomposition is incomplete."
        fi
    done
done

for mod_file in "${!MOD_LINE_LIMITS[@]}"; do
    limit="${MOD_LINE_LIMITS[$mod_file]}"
    if [[ ! -f "$mod_file" ]]; then
        error "$mod_file is missing."
        continue
    fi
    lines="$(wc -l < "$mod_file")"
    if [[ "$lines" -gt "$limit" ]]; then
        error "$mod_file is $lines lines, above the $limit line orchestration threshold. Implementation has leaked back into the orchestration file."
    fi
done

for monolith in "${MONOLITHS[@]}"; do
    if [[ -f "$monolith" ]]; then
        substantive="$(substantive_line_count "$monolith")"
        if [[ "$substantive" -gt "$MONOLITH_FACADE_MAX_LINES" ]]; then
            error "$monolith exists with $substantive substantive lines, above the $MONOLITH_FACADE_MAX_LINES line compatibility-facade cap. The old monolith has returned."
        fi
    fi
done

# Empty-file sweep restricted to the decomposed subsystem directories; other
# parts of the tree may have legitimate empty fixtures/generated files.
for dir in "${!REQUIRED_CHILDREN[@]}"; do
    while IFS= read -r -d '' empty_file; do
        error "$empty_file is empty. Decomposed subsystem child modules may not be empty."
    done < <(find "$dir" -type f -name '*.rs' -empty -print0)
done

if [[ "$fail" -ne 0 ]]; then
    printf '\nArchitecture substance gate failed.\n' >&2
    exit 1
fi

echo "Architecture substance gate passed."
