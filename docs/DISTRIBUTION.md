# Distribution and release engineering

Layerfault's release pipeline is intentionally **dry-run/manual** during the RC development cycle.

The workflow builds and smoke-tests native artifacts but cannot publish a GitHub Release unless both:

1. the manual workflow input `publish` is true; and
2. the repository variable `LAYERFAULT_RELEASE_PUBLISH_ENABLED` is set to `true`.

Normal pushes and tags do not publish releases.

## Prepared artifacts

- Linux amd64/arm64: DEB and RPM from an AlmaLinux 9 / glibc-compatible build
- Linux amd64/arm64: APK and portable tar.gz from a native musl build
- Arch Linux: native package on x86_64; ARM64 uses the portable Linux archive
- macOS arm64/x86_64: universal tar.gz plus unsigned `.pkg` validation artifact; GA installer package requires signing
- Windows amd64/arm64: native-runner ZIP plus unsigned MSIX validation package; GA MSIX publication requires signing
- release `install.sh`, `install-active-runtime.sh`, `install.ps1`
- SHA256SUMS
- CycloneDX SBOMs
- GitHub artifact provenance attestations
- generated Homebrew formula artifact

Package smoke tests install or execute the produced artifact on the corresponding runner before it is considered releasable.

## GA activation

When release behavior is approved, set `LAYERFAULT_RELEASE_PUBLISH_ENABLED=true` in repository Actions variables and manually dispatch the release workflow with `publish=true` and an explicit release version/tag. Keep the publish gate off during rapid RC pushes.

## Linux compatibility policy

Package extension is not treated as compatibility. The dry-run pipeline builds GNU and musl binaries separately and smoke-tests them inside Ubuntu 22.04, Debian 12, AlmaLinux 9, Alpine and Arch environments. The generic Linux archive uses the musl build so it does not inherit the GitHub runner's glibc floor.

## RC safety

The workflow is `workflow_dispatch` only. Merely pushing commits or tags cannot publish a release. The `publish` job additionally requires the repository Actions variable `LAYERFAULT_RELEASE_PUBLISH_ENABLED=true`, which should remain unset/false during rapid RC development.
