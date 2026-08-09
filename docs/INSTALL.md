# Installing Layerfault

Layerfault is designed to be usable without cloning the repository or installing Rust.

## Core installation

The core CLI performs static artifact/package/dataset admission and does not require ML frameworks.

```bash
curl -fsSL https://github.com/izm1chael/layerfault/releases/latest/download/install.sh | sudo bash
```

For a reviewable install, download `install.sh` and `SHA256SUMS` from the release, verify them, then execute the script locally.

Native release assets are prepared for Debian/Ubuntu (`.deb`), Fedora/RHEL/Rocky/Alma (`.rpm`), Alpine (`.apk`), Arch Linux x86_64 (`.pkg.tar.zst`), generic Linux (`.tar.gz`, musl/portable), macOS (`.tar.gz`; unsigned `.pkg` validation artifact until GA signing) and Windows (`.zip`; unsigned MSIX packages are built for validation until GA signing is configured). Release downloads are verified against `SHA256SUMS` by the installers.

## Active analysis

Linux users can install the sandbox/runtime prerequisites separately:

```bash
sudo ./install.sh --active --device cpu
```

This installs Bubblewrap, `strace`, `prlimit`, Python venv support and, on supported glibc Linux hosts, a managed CPU Transformers/PEFT runtime under `/opt/layerfault/runtimes/python`. Direct runtime versions are pinned by the release. Alpine/musl installs the scanner/sandbox prerequisites but leaves Transformers unavailable unless an administrator supplies a separately validated runtime.

Use `--full` to additionally try the distribution-managed `llama.cpp` package where available:

```bash
sudo ./install.sh --full --device cpu
```

Layerfault does not silently fetch an unpinned upstream llama.cpp binary.

Use:

```bash
layerfault capabilities
layerfault doctor
```

before active analysis.

Active Bubblewrap execution is currently Linux-only. Static scanning remains cross-platform.

## Low-memory hosts

Layerfault derives a safe active-execution budget from host memory instead of assuming a 24 GiB machine. It reserves host headroom, estimates model/base runtime memory before launch and skips active execution when the model is unlikely to fit safely. Static admission still runs.

An administrator can explicitly override the sandbox budget:

```bash
export LAYERFAULT_BEHAVIOUR_MEMORY_MB=8192
```

Only raise this when the host actually has enough memory.

## Build from source

Source builds use the Rust toolchain pinned by `rust-toolchain.toml`:

```bash
git clone https://github.com/izm1chael/layerfault.git
cd layerfault
cargo build --release --locked
```

The vendored `candelabra` patch is intentionally retained until upstream offers the same Rustls-only dependency configuration; removing it today would reintroduce native TLS/OpenSSL build dependencies.
