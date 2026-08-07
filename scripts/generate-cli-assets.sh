#!/usr/bin/env bash
set -euo pipefail
ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
BIN="${2:-$ROOT/target/debug/layerfault}"
[[ -x "$BIN" ]] || { echo "layerfault binary not found/executable: $BIN" >&2; exit 1; }
mkdir -p "$ROOT/completions" "$ROOT/docs/man"
HELP="$($BIN --help)"
COMMANDS="$(printf '%s\n' "$HELP" | awk '/^Commands:/{flag=1;next} flag && /^[[:space:]]{2}[A-Za-z0-9_-]+/{print $1} flag && /^Options:/{flag=0}' | tr '\n' ' ')"
cat > "$ROOT/completions/layerfault.bash" <<BASH
# Generated from layerfault --help by scripts/generate-cli-assets.sh
_layerfault() {
    local cur
    cur="\${COMP_WORDS[COMP_CWORD]}"
    if [[ \$COMP_CWORD -eq 1 ]]; then
        COMPREPLY=( \$(compgen -W "$COMMANDS" -- "\$cur") )
    else
        COMPREPLY=( \$(compgen -f -- "\$cur") )
    fi
}
complete -F _layerfault layerfault
BASH
cat > "$ROOT/completions/_layerfault" <<ZSH
#compdef layerfault
# Generated from layerfault --help by scripts/generate-cli-assets.sh
_arguments '1:command:($COMMANDS)' '*:argument:_files'
ZSH
{
  echo '# Generated from layerfault --help by scripts/generate-cli-assets.sh'
  for cmd in $COMMANDS; do
    printf 'complete -c layerfault -n "__fish_use_subcommand" -a "%s"\n' "$cmd"
  done
} > "$ROOT/completions/layerfault.fish"
{
  echo '.TH LAYERFAULT 1'
  echo '.SH NAME'
  echo 'layerfault \- offline-first local AI model admission and supply-chain security'
  echo '.SH SYNOPSIS'
  echo '.nf'
  printf '%s\n' "$HELP" | sed 's/^/  /'
  echo '.fi'
  echo '.SH SECURITY'
  echo 'See THREATS.md and the documentation shipped with Layerfault. Scanner, structural, integrity, and invalid provenance failures are not operator-overridable.'
} > "$ROOT/docs/man/layerfault.1"
echo "Generated completions and docs/man/layerfault.1"
