//! Attaches the compiled eBPF probe programs to their tracepoints.
//!
//! The probe programs themselves (exec/exit/openat/unlink/rename/connect,
//! written against `aya-ebpf` for a `bpfel-unknown-none`/`bpfeb-unknown-none`
//! target) are a separate, out-of-band build artifact: a `no_std` BPF
//! program crate compiled with a `bpf-linker`-equipped nightly toolchain,
//! not something this host-side crate builds itself. This function loads
//! that pre-built object file (path supplied by the caller, normally
//! resolved next to this helper binary and hash/version-verified by the
//! main crate before this helper is ever spawned — see
//! `src/behaviour/ebpf_verify.rs`) and attaches each program by name.
//!
//! CURRENT SCOPE: the sibling `layerfault-ebpf-telemetry-ebpf` `no_std`
//! crate builds (via `bpf-linker`, confirmed producing a valid `ELF 64-bit
//! ..., eBPF` relocatable object with `on_exec`/`on_exit` tracepoint
//! programs and an `EVENTS` ring buffer map) but currently only implements
//! the `on_exec`/`on_exit` programs, sourced from the self-contained
//! `bpf_get_current_pid_tgid`/`bpf_get_current_comm` helpers. The
//! `on_connect`/`on_openat`/`on_unlinkat`/`on_renameat2` programs listed in
//! `TRACEPOINTS` below are not yet defined in the probe object: reading
//! syscall arguments at those tracepoints correctly requires offsets from
//! each event's live `format` file
//! (`/sys/kernel/debug/tracing/events/.../format`), which this development
//! environment cannot generate/verify against (no root, no debugfs tracing
//! access, `unprivileged_bpf_disabled=2` on this host). Attaching a program
//! name the object doesn't define is a normal, already-handled partial
//! failure below (reported, not fatal) — so this list stays complete as a
//! forward-looking target rather than being trimmed to match today's
//! object.
//!
//! Attachment itself (as opposed to compilation) has not been exercised on
//! a live kernel in this environment for the same root/BTF-availability
//! reasons — the host-side loader code is written and type-checked against
//! the real `aya` 0.14 API, but "loads and the kernel accepts the verifier"
//! remains unverified pending a suitable test host.

use anyhow::{Context, Result};
use aya::programs::TracePoint;
use aya::Ebpf;
use layerfault_telemetry_protocol::{EbpfEventFrame, EbpfEventType, PROTOCOL_SCHEMA_VERSION};

/// Tracepoints backing the event-parity target (process exec/exit, network
/// connect attempts, filesystem create/write/delete/rename). Program names
/// must match the `#[tracepoint(name = "...")]` attributes in the probe
/// object.
const TRACEPOINTS: &[(&str, &str, &str)] = &[
    ("on_exec", "sched", "sched_process_exec"),
    ("on_exit", "sched", "sched_process_exit"),
    ("on_connect", "syscalls", "sys_enter_connect"),
    ("on_openat", "syscalls", "sys_enter_openat"),
    ("on_unlinkat", "syscalls", "sys_enter_unlinkat"),
    ("on_renameat2", "syscalls", "sys_enter_renameat2"),
];

/// Load the probe object and attach every tracepoint in `TRACEPOINTS`.
/// Returns the loaded `Ebpf` handle, which must be kept alive for the
/// lifetime of the run: dropping it detaches the programs.
pub fn load_and_attach(object_path: &std::path::Path) -> Result<Ebpf> {
    let mut ebpf = Ebpf::load_file(object_path)
        .with_context(|| format!("unable to load eBPF object '{}'", object_path.display()))?;

    let mut failures = Vec::new();
    for (program_name, category, name) in TRACEPOINTS {
        if let Err(err) = attach_tracepoint(&mut ebpf, program_name, category, name) {
            failures.push(format!("{program_name}: {err}"));
        }
    }

    if failures.len() == TRACEPOINTS.len() {
        anyhow::bail!(
            "no eBPF tracepoints attached, all {} probe(s) failed: {}",
            TRACEPOINTS.len(),
            failures.join("; ")
        );
    }
    if !failures.is_empty() {
        // Partial attachment is a degraded-but-usable run: the main crate
        // surfaces this via `SandboxTelemetry.backend_degraded`, it is
        // never silently treated as full coverage.
        eprintln!(
            "layerfault-ebpf-telemetry: {} of {} probes failed to attach: {}",
            failures.len(),
            TRACEPOINTS.len(),
            failures.join("; ")
        );
    }

    Ok(ebpf)
}

/// Byte layout produced by `RawEvent` in
/// `helpers/layerfault-ebpf-telemetry-ebpf/src/main.rs` (hand-synced with
/// that `repr(C)` struct, documented there as the seam between the two
/// crates): `event_type: u8` at offset 0, 7 reserved/padding bytes, `pid:
/// u64` (native-endian, matching the target the probe was built for) at
/// offset 8, `comm: [u8; 16]` at offset 16. 32 bytes total.
const RAW_EVENT_LEN: usize = 32;
const RAW_EVENT_TYPE_EXEC: u8 = 0;
const RAW_EVENT_TYPE_EXIT: u8 = 5;

/// Normalize one raw ring-buffer record into a wire-protocol frame. Returns
/// `None` for a record that is too short or carries an event type this
/// host build does not (yet) understand — dropped here rather than at the
/// main crate's decoder only because there is no reason to spend a wire
/// frame on something never going to decode meaningfully; the main crate's
/// decoder still independently validates and bounds everything it
/// receives regardless.
pub fn parse_raw_event(
    raw: &[u8],
    run_token: &str,
    pid_namespace_inode: Option<u64>,
) -> Option<EbpfEventFrame> {
    if raw.len() < RAW_EVENT_LEN {
        return None;
    }
    let event_type = match raw[0] {
        RAW_EVENT_TYPE_EXEC => EbpfEventType::Exec,
        RAW_EVENT_TYPE_EXIT => EbpfEventType::Exit,
        _ => return None,
    };
    let pid = u64::from_ne_bytes(raw[8..16].try_into().ok()?);
    let comm_bytes = &raw[16..32];
    let comm_len = comm_bytes.iter().position(|&b| b == 0).unwrap_or(16);
    let comm = String::from_utf8_lossy(&comm_bytes[..comm_len]).into_owned();

    Some(EbpfEventFrame {
        schema_version: PROTOCOL_SCHEMA_VERSION,
        run_token: run_token.to_owned(),
        event_type,
        pid: i64::try_from(pid).unwrap_or(i64::MAX),
        path: None,
        detail: Some(comm),
        exit_code: None,
        pid_namespace_inode,
        write_like: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_bytes(event_type: u8, pid: u64, comm: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; RAW_EVENT_LEN];
        bytes[0] = event_type;
        bytes[8..16].copy_from_slice(&pid.to_ne_bytes());
        let len = comm.len().min(16);
        bytes[16..16 + len].copy_from_slice(&comm[..len]);
        bytes
    }

    #[test]
    fn parses_exec_event() {
        let bytes = raw_bytes(RAW_EVENT_TYPE_EXEC, 42, b"sh");
        let frame = parse_raw_event(&bytes, "run-1", None).unwrap();
        assert_eq!(frame.event_type, EbpfEventType::Exec);
        assert_eq!(frame.pid, 42);
        assert_eq!(frame.detail.as_deref(), Some("sh"));
        assert_eq!(frame.run_token, "run-1");
    }

    #[test]
    fn parses_exit_event() {
        let bytes = raw_bytes(RAW_EVENT_TYPE_EXIT, 7, b"python3");
        let frame = parse_raw_event(&bytes, "run-1", Some(99)).unwrap();
        assert_eq!(frame.event_type, EbpfEventType::Exit);
        assert_eq!(frame.pid_namespace_inode, Some(99));
    }

    #[test]
    fn rejects_unknown_event_type() {
        let bytes = raw_bytes(3, 7, b"x");
        assert!(parse_raw_event(&bytes, "run-1", None).is_none());
    }

    #[test]
    fn rejects_short_record() {
        assert!(parse_raw_event(&[0u8; 4], "run-1", None).is_none());
    }
}

fn attach_tracepoint(
    ebpf: &mut Ebpf,
    program_name: &str,
    category: &str,
    name: &str,
) -> Result<()> {
    let program: &mut TracePoint = ebpf
        .program_mut(program_name)
        .with_context(|| format!("probe object has no program named '{program_name}'"))?
        .try_into()
        .with_context(|| format!("program '{program_name}' is not a tracepoint"))?;
    program
        .load()
        .with_context(|| format!("unable to load program '{program_name}'"))?;
    program
        .attach(category, name)
        .with_context(|| format!("unable to attach '{program_name}' to {category}:{name}"))?;
    Ok(())
}
