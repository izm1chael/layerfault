# Security Policy

## Supported releases

The currently supported release line is `1.0.0-rc.1`, which is a feature-frozen release candidate undergoing adversarial and compatibility testing.

## Reporting a vulnerability

Please do not open a public issue containing exploit details for an undisclosed vulnerability.

If GitHub Private Vulnerability Reporting is enabled for this repository, please use it. Otherwise, contact the repository owner privately through GitHub and include enough detail to reproduce and assess the issue. Do not include model weights or private keys unless they are strictly necessary for reproduction.

Security fixes may be released as correctness, hardening, or compatibility updates. No response or remediation timeline is promised.

## Static analysis

Pre-publication static-analysis decisions and reviewed Semgrep suppressions are documented in [`docs/STATIC_ANALYSIS.md`](docs/STATIC_ANALYSIS.md).


## Active model execution

Layerfault can optionally execute models for behavioural analysis. Treat this capability as hostile-code analysis, not as a safe way to run untrusted software on a production workstation.

External active execution requires Layerfault's strong Bubblewrap sandbox. The sandbox disables host networking, uses private process/IPC/UTS namespaces and a private home/workspace, drops capabilities, mounts model inputs read-only, injects only synthetic canary credentials, and applies mandatory external resource limits. Requests to run statically blocked artifacts or Hugging Face custom loader code require Bubblewrap, syscall tracing (`strace`) and resource limiting (`prlimit`) and fail closed if those controls are unavailable.

Layerfault derives a conservative active-memory budget from `/proc/meminfo`, reserves host headroom, and estimates the model/base runtime footprint before launch. Hosts that cannot safely fit a target should refuse active execution rather than swap/OOM the machine; static admission remains available. `LAYERFAULT_BEHAVIOUR_MEMORY_MB` is an explicit administrator override and should not be raised beyond real host capacity. The default `RLIMIT_AS` ceiling is derived from that same admission budget with virtual-address headroom; `LAYERFAULT_BEHAVIOUR_ADDRESS_SPACE_MB` overrides the final ceiling and can deliberately force a lower limit than the admitted runtime needs.

Do not place real secrets in the model package or active-analysis workspace. Run deliberately hostile custom loaders on a disposable or dedicated lab host: Bubblewrap provides namespace/filesystem isolation but shares the host kernel and is not a VM-grade kernel boundary. Transformers/PEFT execution is offline/local-only and Layerfault does not download model/runtime code during an active run.
