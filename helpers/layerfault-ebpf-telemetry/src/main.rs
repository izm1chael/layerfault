//! Optional external eBPF telemetry helper for Layerfault's sandboxed
//! active analysis. Runs entirely on the host side (never inside the
//! bwrap/seccomp boundary the sandboxed workload runs under — see the
//! `seccomp_filter_file` denial of `bpf()`/`perf_event_open()` in
//! `src/behaviour/sandbox.rs`), observes one sandbox run, and streams
//! normalized event frames to Layerfault's main process over the wire
//! protocol defined in `layerfault-telemetry-protocol`.
//!
//! This binary is intentionally NOT `forbid(unsafe_code)` — see the comment
//! on that attribute (absent here on purpose) in `Cargo.toml`.

mod probes;
mod protocol;
mod scope;

use anyhow::{Context, Result};
use clap::Parser;
use layerfault_telemetry_protocol::{EbpfEventFrame, EbpfEventType, PROTOCOL_SCHEMA_VERSION};
use protocol::FrameWriter;
use std::fs::File;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "layerfault-ebpf-telemetry",
    version,
    about = "Observes one Layerfault sandbox run via eBPF and streams normalized telemetry frames"
)]
struct Args {
    /// Correlation id for this run. Threaded through every emitted frame so
    /// the main crate's decoder can reject frames from a stale/unrelated
    /// run even if scope filtering here has a bug.
    #[arg(long)]
    run_token: String,

    /// PID of the root sandboxed process to scope observation to (fallback
    /// scope identity when cgroup delegation is unavailable).
    #[arg(long)]
    root_pid: u32,

    /// Delegated cgroup path for the sandboxed run, when available. Not
    /// currently used to filter kernel-side (that requires a cgroup-aware
    /// probe attach point, a follow-up), but recorded for future use and
    /// passed through so the main crate's scope-token derivation stays the
    /// single source of truth for preference order.
    #[arg(long)]
    cgroup_path: Option<String>,

    /// Path to the compiled eBPF probe object (`bpfel-unknown-none` /
    /// `bpfeb-unknown-none`), built out-of-band by the sibling
    /// `layerfault-ebpf-telemetry-ebpf` crate.
    #[arg(long)]
    object: PathBuf,

    /// Where to write the length-prefixed frame stream. The main crate
    /// reads this same path via `FRAMES_FILE_NAME` under the sandbox run's
    /// telemetry root.
    #[arg(long)]
    output: PathBuf,

    /// How long to observe before exiting, regardless of whether the
    /// sandboxed process has exited. The caller (main crate) is expected to
    /// terminate this helper once the sandboxed run completes; this is a
    /// backstop against the helper outliving an already-finished run.
    #[arg(long, default_value_t = 3600)]
    max_seconds: u64,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let pid_namespace_inode = scope::pid_namespace_inode(args.root_pid);
    let process_identity = scope::process_identity(args.root_pid);
    if process_identity.is_none() {
        eprintln!(
            "layerfault-ebpf-telemetry: root_pid {} not observable at startup; scope fallback \
             will rely on run_token/pid_namespace alone",
            args.root_pid
        );
    }

    let mut ebpf =
        probes::load_and_attach(&args.object).context("unable to attach eBPF telemetry probes")?;

    let output = File::create(&args.output)
        .with_context(|| format!("unable to create output file '{}'", args.output.display()))?;
    let mut writer = FrameWriter::new(output);

    // Emit a synthetic startup marker so the main crate can distinguish
    // "helper ran but observed nothing" from "helper never started" purely
    // from the frame stream, without a separate side channel.
    let startup = EbpfEventFrame {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        run_token: args.run_token.clone(),
        event_type: EbpfEventType::Exec,
        pid: i64::from(args.root_pid),
        path: None,
        detail: Some("layerfault-ebpf-telemetry: probes attached".to_owned()),
        exit_code: None,
        pid_namespace_inode,
        write_like: false,
    };
    let _ = writer.write_event(&startup);
    writer.flush().ok();

    // Drain the exec/exit ring buffer until max_seconds elapses or the
    // caller (Layerfault's main process) kills this helper once the
    // sandboxed run completes. See probes.rs's module doc comment: only
    // exec/exit are implemented in the probe object today; the
    // network/filesystem tracepoints remain a follow-up pending a real
    // kernel/root test environment to validate their argument offsets
    // against.
    let deadline = std::time::Instant::now() + Duration::from_secs(args.max_seconds);
    let mut events_map = ebpf
        .take_map("EVENTS")
        .context("probe object has no 'EVENTS' ring buffer map")?;
    let mut ring_buf =
        aya::maps::RingBuf::try_from(&mut events_map).context("'EVENTS' is not a ring buffer")?;
    loop {
        while let Some(item) = ring_buf.next() {
            if let Some(frame) =
                probes::parse_raw_event(&item, &args.run_token, pid_namespace_inode)
            {
                if !writer.write_event(&frame).unwrap_or(false) {
                    writer.flush().ok();
                    drop(ebpf);
                    return Ok(());
                }
            }
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    writer.flush().ok();
    drop(ebpf);

    Ok(())
}
