for cmd in scan inspect verify-file scan-dir verify run import serve trust attest audit baseline quarantine policy gc doctor sources explain diff selftest certify version
    complete -c layerfault -n "__fish_use_subcommand" -a "$cmd"
end
