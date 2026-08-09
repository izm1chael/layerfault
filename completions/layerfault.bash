# Generated from Layerfault command surface. Regenerate with scripts/build/cli-assets.sh.
_layerfault() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local commands="scan inspect verify-file scan-dir fingerprint verify-package pipeline verify run import serve trust attest audit baseline quarantine policy gc doctor capabilities sources explain diff compare behaviour compare-behaviour review models drift lineage dataset research hub platform selftest certify advisories evidence version"
    if [[ $COMP_CWORD -eq 1 ]]; then COMPREPLY=( $(compgen -W "$commands" -- "$cur") ); else COMPREPLY=( $(compgen -f -- "$cur") ); fi
}
complete -F _layerfault layerfault
