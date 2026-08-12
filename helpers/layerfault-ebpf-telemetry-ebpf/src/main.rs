//! eBPF probe programs for the Layerfault telemetry helper.
//!
//! `#![no_std]`/`#![no_main]`, compiled to `bpfel-unknown-none` /
//! `bpfeb-unknown-none` via `bpf-linker` (see `.cargo/config.toml` and
//! `rust-toolchain.toml` in this crate). This crate is intentionally its
//! own standalone workspace (`[workspace]` in `Cargo.toml`), separate from
//! both the main `forbid(unsafe_code)` crate and the host-side
//! `layerfault-ebpf-telemetry` helper — its target and build-std
//! requirements are incompatible with a normal host build.
//!
//! CURRENT SCOPE: exec/exit tracepoints only. `bpf_get_current_pid_tgid`
//! and `bpf_get_current_comm` are self-contained BPF helper functions with
//! no tracepoint-specific argument layout to get right, so they can be
//! implemented and built correctly without a live kernel to validate
//! against. The network/filesystem tracepoints
//! (`sys_enter_connect`/`sys_enter_openat`/`sys_enter_unlinkat`/
//! `sys_enter_renameat2`) additionally need to read syscall arguments at
//! tracepoint-specific offsets (from each event's `format` file under
//! `/sys/kernel/debug/tracing/events/...`); producing that safely requires
//! a real kernel to generate and check bindings against (`aya-tool
//! generate`), which this development environment cannot do (no root, no
//! debugfs tracing access — `unprivileged_bpf_disabled=2` on this host).
//! Implementing those from memory without verification would be exactly
//! the kind of unverifiable guesswork this project avoids; they remain a
//! follow-up once a suitable kernel/root test environment is available.
//! `helpers/layerfault-ebpf-telemetry/src/probes.rs` still declares and
//! attempts to attach all six tracepoints — attaching a program name this
//! object does not yet define is a normal partial-attach failure, already
//! handled there as a non-fatal, reported degradation.

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid},
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};

/// Fixed-layout event record shared (by hand-synced convention, documented
/// here and in the host-side reader) with
/// `helpers/layerfault-ebpf-telemetry/src/probes.rs`. No `serde`/`alloc` is
/// available in this `no_std` context, so this is a plain `repr(C)` struct
/// rather than the JSON `EbpfEventFrame` the host later encodes into the
/// wire protocol — normalization into that JSON frame happens entirely in
/// the (already-verified, host-side, non-`unsafe`) userspace loader.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawEvent {
    /// 0 = exec, 5 = exit (matches `EbpfEventType`'s discriminant order in
    /// `layerfault-telemetry-protocol`; only these two are emitted today).
    pub event_type: u8,
    pub _reserved: [u8; 7],
    pub pid: u64,
    pub comm: [u8; 16],
}

#[map(name = "EVENTS")]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

const EVENT_TYPE_EXEC: u8 = 0;
const EVENT_TYPE_EXIT: u8 = 5;

fn submit_event(event_type: u8) {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid >> 32;
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    let event = RawEvent {
        event_type,
        _reserved: [0u8; 7],
        pid,
        comm,
    };
    if let Some(mut entry) = EVENTS.reserve::<RawEvent>(0) {
        entry.write(event);
        entry.submit(0);
    }
}

#[tracepoint]
pub fn on_exec(_ctx: TracePointContext) -> u32 {
    submit_event(EVENT_TYPE_EXEC);
    0
}

#[tracepoint]
pub fn on_exit(_ctx: TracePointContext) -> u32 {
    submit_event(EVENT_TYPE_EXIT);
    0
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
