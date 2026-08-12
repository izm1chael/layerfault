//! Wire protocol decoder for the optional eBPF telemetry helper.
//!
//! The helper (a separately built, non-`forbid(unsafe_code)` component; see
//! `helpers/layerfault-ebpf-telemetry`) observes a sandboxed run from the
//! host side and streams length-prefixed JSON event frames into a file under
//! the workspace telemetry root. Everything in this module treats that
//! stream as fully untrusted attacker-influenced input: bounded frame sizes,
//! a closed event-type enum, an explicit schema version, and per-run byte
//! ceilings, mirroring the bounding already applied to strace evidence in
//! `sandbox.rs` (`MAX_TRACE_BYTES`, `MAX_TELEMETRY_ROWS`, `excerpt`).
//!
//! Scope filtering is defense in depth: the helper is expected to only
//! observe the sandboxed run, but every frame is re-validated against the
//! run's `ScopeToken` here regardless, so a buggy or compromised helper
//! cannot inject evidence about an unrelated host process by simply omitting
//! its own filtering.

use crate::behaviour::sandbox::{
    excerpt, is_canary_evidence, is_sensitive_evidence, SandboxTelemetry, TelemetryBackend,
    TelemetryBackendKind, MAX_TELEMETRY_ROWS,
};
use anyhow::Result;
pub use layerfault_telemetry_protocol::{
    EbpfEventFrame, EbpfEventType, FRAMES_FILE_NAME, MAX_FRAME_BYTES, MAX_TOTAL_STREAM_BYTES,
    PROTOCOL_SCHEMA_VERSION,
};
use std::io::Read;
use std::path::Path;

/// Evidence strings (paths/argv/detail) are capped at the same length as
/// strace excerpts so bounding stays consistent across backends.
const MAX_STRING_LEN: usize = layerfault_telemetry_protocol::MAX_STRING_LEN;

/// Scope identity for a single sandbox run. The decoder always checks the
/// run token and additionally checks PID-namespace identity when both sides
/// provide it. Cgroup and root-process identity are carried here for the
/// collector integration that will derive and enforce kernel-side scope;
/// frames do not currently contain enough information to re-check those two
/// identities in the decoder.
#[derive(Debug, Clone, Default)]
pub struct ScopeToken {
    pub run_token: String,
    pub cgroup_path: Option<String>,
    pub root_pid: Option<u32>,
    pub pid_namespace_inode: Option<u64>,
}

impl ScopeToken {
    fn frame_in_scope(&self, frame: &EbpfEventFrame) -> bool {
        if frame.run_token != self.run_token {
            return false;
        }
        if let (Some(expected), Some(actual)) =
            (self.pid_namespace_inode, frame.pid_namespace_inode)
        {
            if expected != actual {
                return false;
            }
        }
        true
    }
}

/// eBPF-backed implementation of `TelemetryBackend`. Reads the helper's
/// frame stream from `<telemetry_root>/ebpf.frames`; a missing file (helper
/// never ran, or produced no events) is not itself an error.
pub struct EbpfTelemetryBackend {
    pub scope: ScopeToken,
}

impl TelemetryBackend for EbpfTelemetryBackend {
    fn kind(&self) -> TelemetryBackendKind {
        TelemetryBackendKind::Ebpf
    }

    fn collect(&self, telemetry_root: &Path, telemetry: &mut SandboxTelemetry) -> Result<()> {
        let frames_path = telemetry_root.join(FRAMES_FILE_NAME);
        let file = match crate::safeio::open_readonly_nofollow(&frames_path) {
            Ok(file) => file,
            Err(_) => return Ok(()),
        };
        decode_frames(file, &self.scope, telemetry)
    }
}

/// Decode a length-prefixed JSON frame stream: each frame is a little-
/// endian `u32` byte length followed by that many bytes of JSON. Bounded on
/// every axis (per-frame size, total stream size, per-category evidence
/// rows); malformed or out-of-scope frames are dropped and counted, never
/// silently ignored without a trace and never allowed to panic or hang on
/// hostile input.
pub fn decode_frames<R: Read>(
    mut reader: R,
    scope: &ScopeToken,
    telemetry: &mut SandboxTelemetry,
) -> Result<()> {
    let mut total_bytes: u64 = 0;
    loop {
        let mut len_buf = [0u8; 4];
        if let Err(err) = reader.read_exact(&mut len_buf) {
            if err.kind() == std::io::ErrorKind::UnexpectedEof {
                break;
            }
            return Err(err.into());
        }
        let frame_len = u32::from_le_bytes(len_buf);

        // Include the framing prefix in the run-wide ceiling. In
        // particular, zero-length frames must not provide a cheap way to
        // force millions of decoder iterations without consuming the byte
        // budget. Check the declared length before reading or skipping the
        // payload so an attacker cannot make us drain a multi-gigabyte
        // oversized frame first.
        total_bytes = total_bytes.saturating_add(4);
        total_bytes = total_bytes.saturating_add(u64::from(frame_len));
        if total_bytes > MAX_TOTAL_STREAM_BYTES {
            telemetry.buffer_overflow = true;
            telemetry.events_dropped = telemetry.events_dropped.saturating_add(1);
            break;
        }

        if frame_len > MAX_FRAME_BYTES {
            telemetry.events_dropped = telemetry.events_dropped.saturating_add(1);
            let mut sink = std::io::sink();
            let mut bounded = (&mut reader).take(u64::from(frame_len));
            if std::io::copy(&mut bounded, &mut sink).is_err() {
                // Stream ended mid-skip; nothing more to decode.
                break;
            }
            continue;
        }

        if frame_len == 0 {
            // Zero-length frame carries no information; treat as malformed
            // rather than a silent no-op so a flood of empty frames is
            // still visible via events_dropped.
            telemetry.events_dropped = telemetry.events_dropped.saturating_add(1);
            continue;
        }

        let mut buf = vec![0u8; frame_len as usize];
        if reader.read_exact(&mut buf).is_err() {
            // Truncated final frame: count it and stop, don't guess content.
            telemetry.events_dropped = telemetry.events_dropped.saturating_add(1);
            break;
        }

        match serde_json::from_slice::<EbpfEventFrame>(&buf) {
            Ok(frame) if frame.schema_version != PROTOCOL_SCHEMA_VERSION => {
                telemetry.events_dropped = telemetry.events_dropped.saturating_add(1);
            }
            Ok(frame) if !scope.frame_in_scope(&frame) => {
                telemetry.events_dropped = telemetry.events_dropped.saturating_add(1);
            }
            Ok(frame) => record_event(&frame, telemetry),
            Err(_) => {
                telemetry.events_dropped = telemetry.events_dropped.saturating_add(1);
            }
        }
    }
    Ok(())
}

fn record_event(frame: &EbpfEventFrame, telemetry: &mut SandboxTelemetry) {
    *telemetry
        .events_seen
        .entry(frame.event_type.category().to_owned())
        .or_insert(0) += 1;

    let evidence = sanitize_evidence(frame);
    let lower = evidence.to_ascii_lowercase();

    match frame.event_type {
        EbpfEventType::Connect => push_bounded(&mut telemetry.network_attempts, evidence),
        EbpfEventType::Exec => push_bounded(&mut telemetry.process_exec_attempts, evidence),
        EbpfEventType::Exit => push_bounded(&mut telemetry.process_exit_events, evidence),
        EbpfEventType::Unlink | EbpfEventType::Rename => {
            push_bounded(&mut telemetry.filesystem_write_attempts, evidence);
        }
        EbpfEventType::Open => {
            if frame.write_like {
                push_bounded(&mut telemetry.filesystem_write_attempts, evidence.clone());
            }
            if is_canary_evidence(&lower) {
                push_bounded(&mut telemetry.canary_accesses, evidence.clone());
            }
            if is_sensitive_evidence(&lower) {
                push_bounded(&mut telemetry.sensitive_path_accesses, evidence);
            }
        }
    }
}

fn push_bounded(rows: &mut Vec<String>, value: String) {
    if rows.len() < MAX_TELEMETRY_ROWS {
        rows.push(value);
    }
}

/// Strip control characters and cap length, matching the strace `excerpt()`
/// bounding so evidence strings are consistently sized regardless of
/// backend. Control characters are removed rather than escaped: this data
/// only ever reaches evidence/report output, never a shell or terminal
/// re-interpretation, so removal is sufficient and keeps the string simple.
fn sanitize_evidence(frame: &EbpfEventFrame) -> String {
    let raw = frame
        .detail
        .as_deref()
        .or(frame.path.as_deref())
        .unwrap_or("");
    let cleaned: String = raw.chars().filter(|ch| !ch.is_control()).collect();
    let mut truncated: String = cleaned.chars().take(MAX_STRING_LEN).collect();
    if cleaned.chars().count() > MAX_STRING_LEN {
        truncated.push('…');
    }
    if truncated.is_empty() {
        excerpt(&format!("{:?}", frame.event_type))
    } else {
        truncated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame_bytes(frame: &EbpfEventFrame) -> Vec<u8> {
        let json = serde_json::to_vec(frame).unwrap();
        let mut out = Vec::with_capacity(4 + json.len());
        out.extend_from_slice(&(json.len() as u32).to_le_bytes());
        out.extend_from_slice(&json);
        out
    }

    fn base_frame(event_type: EbpfEventType) -> EbpfEventFrame {
        EbpfEventFrame {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            run_token: "run-abc".to_owned(),
            event_type,
            pid: 42,
            path: Some("/workspace/workspace/secrets/api_token.txt".to_owned()),
            detail: None,
            exit_code: None,
            pid_namespace_inode: None,
            write_like: true,
        }
    }

    fn scope() -> ScopeToken {
        ScopeToken {
            run_token: "run-abc".to_owned(),
            cgroup_path: None,
            root_pid: None,
            pid_namespace_inode: None,
        }
    }

    #[test]
    fn valid_frame_populates_expected_vector_and_aggregate_count() {
        let frame = base_frame(EbpfEventType::Connect);
        let bytes = frame_bytes(&frame);
        let mut telemetry = SandboxTelemetry::default();
        decode_frames(std::io::Cursor::new(bytes), &scope(), &mut telemetry).unwrap();
        assert_eq!(telemetry.network_attempts.len(), 1);
        assert_eq!(telemetry.events_seen.get("connect"), Some(&1));
        assert_eq!(telemetry.events_dropped, 0);
    }

    #[test]
    fn open_event_classifies_write_canary_and_sensitive() {
        let mut frame = base_frame(EbpfEventType::Open);
        frame.path = Some("/workspace/home/.ssh/id_ed25519".to_owned());
        let bytes = frame_bytes(&frame);
        let mut telemetry = SandboxTelemetry::default();
        decode_frames(std::io::Cursor::new(bytes), &scope(), &mut telemetry).unwrap();
        assert_eq!(telemetry.filesystem_write_attempts.len(), 1);
        assert_eq!(telemetry.canary_accesses.len(), 1);
    }

    #[test]
    fn exit_event_populates_process_exit_events() {
        let mut frame = base_frame(EbpfEventType::Exit);
        frame.detail = Some("exit_group(0)".to_owned());
        frame.exit_code = Some(0);
        let bytes = frame_bytes(&frame);
        let mut telemetry = SandboxTelemetry::default();
        decode_frames(std::io::Cursor::new(bytes), &scope(), &mut telemetry).unwrap();
        assert_eq!(telemetry.process_exit_events, vec!["exit_group(0)"]);
    }

    #[test]
    fn wrong_schema_version_is_dropped_not_reinterpreted() {
        let mut frame = base_frame(EbpfEventType::Exec);
        frame.schema_version = PROTOCOL_SCHEMA_VERSION + 1;
        let bytes = frame_bytes(&frame);
        let mut telemetry = SandboxTelemetry::default();
        decode_frames(std::io::Cursor::new(bytes), &scope(), &mut telemetry).unwrap();
        assert!(telemetry.process_exec_attempts.is_empty());
        assert_eq!(telemetry.events_dropped, 1);
    }

    #[test]
    fn mismatched_run_token_is_dropped_defense_in_depth() {
        let mut frame = base_frame(EbpfEventType::Exec);
        frame.run_token = "someone-elses-run".to_owned();
        let bytes = frame_bytes(&frame);
        let mut telemetry = SandboxTelemetry::default();
        decode_frames(std::io::Cursor::new(bytes), &scope(), &mut telemetry).unwrap();
        assert!(telemetry.process_exec_attempts.is_empty());
        assert_eq!(telemetry.events_dropped, 1);
    }

    #[test]
    fn mismatched_pid_namespace_is_dropped_even_with_matching_run_token() {
        let mut frame = base_frame(EbpfEventType::Exec);
        frame.pid_namespace_inode = Some(999);
        let mut scoped = scope();
        scoped.pid_namespace_inode = Some(111);
        let bytes = frame_bytes(&frame);
        let mut telemetry = SandboxTelemetry::default();
        decode_frames(std::io::Cursor::new(bytes), &scoped, &mut telemetry).unwrap();
        assert!(telemetry.process_exec_attempts.is_empty());
        assert_eq!(telemetry.events_dropped, 1);
    }

    #[test]
    fn declared_giant_frame_stops_without_draining_its_payload() {
        let bytes = u32::MAX.to_le_bytes();
        let mut telemetry = SandboxTelemetry::default();
        decode_frames(std::io::Cursor::new(bytes), &scope(), &mut telemetry).unwrap();
        assert!(telemetry.buffer_overflow);
        assert_eq!(telemetry.events_dropped, 1);
    }

    #[test]
    fn malformed_json_is_dropped_and_stream_recovers_for_next_frame() {
        let mut bytes = Vec::new();
        let garbage = b"not json at all {{{";
        bytes.extend_from_slice(&(garbage.len() as u32).to_le_bytes());
        bytes.extend_from_slice(garbage);
        bytes.extend_from_slice(&frame_bytes(&base_frame(EbpfEventType::Exec)));
        let mut telemetry = SandboxTelemetry::default();
        decode_frames(std::io::Cursor::new(bytes), &scope(), &mut telemetry).unwrap();
        assert_eq!(telemetry.events_dropped, 1);
        assert_eq!(telemetry.process_exec_attempts.len(), 1);
    }

    #[test]
    fn oversized_frame_is_dropped_and_stream_stays_aligned() {
        let mut bytes = Vec::new();
        let oversized_len = MAX_FRAME_BYTES + 1;
        bytes.extend_from_slice(&oversized_len.to_le_bytes());
        bytes.extend(std::iter::repeat_n(b'x', oversized_len as usize));
        bytes.extend_from_slice(&frame_bytes(&base_frame(EbpfEventType::Connect)));
        let mut telemetry = SandboxTelemetry::default();
        decode_frames(std::io::Cursor::new(bytes), &scope(), &mut telemetry).unwrap();
        assert_eq!(telemetry.events_dropped, 1);
        assert_eq!(telemetry.network_attempts.len(), 1);
    }

    #[test]
    fn truncated_final_frame_does_not_panic_or_hang() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&100u32.to_le_bytes());
        bytes.extend_from_slice(b"short");
        let mut telemetry = SandboxTelemetry::default();
        decode_frames(std::io::Cursor::new(bytes), &scope(), &mut telemetry).unwrap();
        assert_eq!(telemetry.events_dropped, 1);
    }

    #[test]
    fn zero_length_frame_is_dropped_not_a_silent_noop() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u32.to_le_bytes());
        let mut telemetry = SandboxTelemetry::default();
        decode_frames(std::io::Cursor::new(bytes), &scope(), &mut telemetry).unwrap();
        assert_eq!(telemetry.events_dropped, 1);
    }

    #[test]
    fn total_stream_ceiling_sets_buffer_overflow_and_stops_reading() {
        let frame = base_frame(EbpfEventType::Connect);
        let one = frame_bytes(&frame);
        // Overshoot generously: total_bytes only counts each frame's JSON
        // payload (not its 4-byte length prefix), so sizing purely off the
        // prefixed frame length must leave enough margin to still cross the
        // ceiling after that per-frame undercount.
        let repeats = (MAX_TOTAL_STREAM_BYTES / one.len() as u64) * 2 + 16;
        let mut bytes = Vec::new();
        for _ in 0..repeats {
            bytes.extend_from_slice(&one);
        }
        let mut telemetry = SandboxTelemetry::default();
        decode_frames(std::io::Cursor::new(bytes), &scope(), &mut telemetry).unwrap();
        assert!(telemetry.buffer_overflow);
    }

    #[test]
    fn per_category_row_cap_truncates_vector_but_aggregate_count_survives() {
        let mut bytes = Vec::new();
        let total = MAX_TELEMETRY_ROWS + 25;
        for i in 0..total {
            let mut frame = base_frame(EbpfEventType::Connect);
            frame.detail = Some(format!("connect#{i}"));
            bytes.extend_from_slice(&frame_bytes(&frame));
        }
        let mut telemetry = SandboxTelemetry::default();
        decode_frames(std::io::Cursor::new(bytes), &scope(), &mut telemetry).unwrap();
        assert_eq!(telemetry.network_attempts.len(), MAX_TELEMETRY_ROWS);
        assert_eq!(telemetry.events_seen.get("connect"), Some(&(total as u64)));
    }

    #[test]
    fn control_characters_are_stripped_from_evidence() {
        let mut frame = base_frame(EbpfEventType::Exec);
        frame.detail = Some("execve(\"/bin/sh\x07\x1b[31m\")".to_owned());
        let bytes = frame_bytes(&frame);
        let mut telemetry = SandboxTelemetry::default();
        decode_frames(std::io::Cursor::new(bytes), &scope(), &mut telemetry).unwrap();
        assert!(!telemetry.process_exec_attempts[0].contains('\x07'));
        assert!(!telemetry.process_exec_attempts[0].contains('\x1b'));
    }

    #[test]
    fn hostile_random_bytes_never_panic() {
        // Not a substitute for the dedicated fuzz target, but a fast smoke
        // check that arbitrary byte soup decodes without panicking.
        let patterns: &[&[u8]] = &[
            &[],
            &[0xff; 3],
            &[0x00, 0x00, 0x00, 0x00],
            &[0xff, 0xff, 0xff, 0xff],
            b"\x05\x00\x00\x00{\"a\":1}",
        ];
        for pattern in patterns {
            let mut telemetry = SandboxTelemetry::default();
            let _ = decode_frames(std::io::Cursor::new(*pattern), &scope(), &mut telemetry);
        }
    }
}
