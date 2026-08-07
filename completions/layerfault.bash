# Layerfault top-level completion. Regenerate with scripts/generate-cli-assets.sh.
_layerfault() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local commands="scan inspect verify-file scan-dir verify run import serve trust attest audit baseline quarantine policy gc doctor sources explain diff selftest certify version"
    if [[ $COMP_CWORD -eq 1 ]]; then COMPREPLY=( $(compgen -W "$commands" -- "$cur") ); else COMPREPLY=( $(compgen -f -- "$cur") ); fi
}
complete -F _layerfault layerfault
