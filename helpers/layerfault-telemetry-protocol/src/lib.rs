//! Wire-protocol types shared between Layerfault's main crate (the untrusted
//! decoder, in `src/behaviour/ebpf_telemetry.rs`, which must stay under
//! `forbid(unsafe_code)`) and the optional eBPF telemetry helper (the
//! encoder, in `helpers/layerfault-ebpf-telemetry`, which needs `unsafe` for
//! Aya). Keeping the schema in one hand-synced crate avoids the encoder and
//! decoder drifting apart.
//!
//! This crate itself carries no unsafe code and no telemetry-collection
//! logic — only the framing/schema definitions and a pure encode helper.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// The only schema version a build understands. A frame declaring a
/// different version must be rejected by the decoder, not reinterpreted.
pub const PROTOCOL_SCHEMA_VERSION: u16 = 1;

/// Per-frame byte ceiling, enforced by both the encoder (never emit an
/// oversized frame) and the decoder (never trust the encoder to have
/// enforced it).
pub const MAX_FRAME_BYTES: u32 = 64 * 1024;

/// Total bytes a decoder should read from a single run's frame stream
/// before stopping early and marking observation as possibly incomplete.
pub const MAX_TOTAL_STREAM_BYTES: u64 = 16 * 1024 * 1024;

/// Evidence strings (paths/argv/detail) are capped at this length,
/// consistent with the strace-evidence excerpt length in the main crate.
pub const MAX_STRING_LEN: usize = 512;

/// The filename the helper writes its length-prefixed frame stream to,
/// under the sandbox run's telemetry root (sibling of the strace trace
/// prefix file).
pub const FRAMES_FILE_NAME: &str = "ebpf.frames";

/// Closed set of event kinds the protocol carries. An unrecognized
/// discriminant fails JSON deserialization rather than being guessed or
/// coerced into a known kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EbpfEventType {
    Exec,
    Connect,
    Open,
    Unlink,
    Rename,
    Exit,
}

impl EbpfEventType {
    pub fn category(self) -> &'static str {
        match self {
            Self::Exec => "exec",
            Self::Connect => "connect",
            Self::Open => "open",
            Self::Unlink => "unlink",
            Self::Rename => "rename",
            Self::Exit => "exit",
        }
    }
}

/// One event frame. Every field is attacker-influenced once it crosses the
/// helper/main-crate boundary; the decoder excerpts/sanitizes string fields
/// and range-checks numeric fields before any of this reaches evidence
/// output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EbpfEventFrame {
    pub schema_version: u16,
    /// Correlation id the helper was launched with for this run. Used both
    /// as the ultimate scope-fallback identity and as a replay/cross-run
    /// mixing guard even when cgroup/pid/namespace scoping is also used.
    pub run_token: String,
    pub event_type: EbpfEventType,
    pub pid: i64,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub pid_namespace_inode: Option<u64>,
    #[serde(default)]
    pub write_like: bool,
}

/// Encode one frame as `u32` little-endian byte length + JSON payload.
/// Truncates `path`/`detail` to `MAX_STRING_LEN` chars before encoding (the
/// encoder side of the same bound the decoder re-enforces independently),
/// and refuses to emit a frame that would still exceed `MAX_FRAME_BYTES`.
pub fn encode_frame(frame: &EbpfEventFrame) -> Result<Vec<u8>, EncodeError> {
    let mut bounded = frame.clone();
    if let Some(path) = bounded.path.as_mut() {
        truncate_in_place(path);
    }
    if let Some(detail) = bounded.detail.as_mut() {
        truncate_in_place(detail);
    }
    let payload = serde_json::to_vec(&bounded)?;
    if payload.len() > MAX_FRAME_BYTES as usize {
        return Err(EncodeError::FrameTooLarge(payload.len()));
    }
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

fn truncate_in_place(value: &mut String) {
    if value.chars().count() > MAX_STRING_LEN {
        let mut truncated: String = value.chars().take(MAX_STRING_LEN).collect();
        truncated.push('…');
        *value = truncated;
    }
}

#[derive(Debug)]
pub enum EncodeError {
    Json(serde_json::Error),
    FrameTooLarge(usize),
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json(err) => write!(f, "unable to serialize telemetry frame: {err}"),
            Self::FrameTooLarge(len) => {
                write!(f, "encoded frame ({len} bytes) exceeds MAX_FRAME_BYTES")
            }
        }
    }
}

impl std::error::Error for EncodeError {}

impl From<serde_json::Error> for EncodeError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_length_prefixed_json() {
        let frame = EbpfEventFrame {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            run_token: "run-1".to_owned(),
            event_type: EbpfEventType::Exec,
            pid: 7,
            path: Some("/bin/sh".to_owned()),
            detail: None,
            exit_code: None,
            pid_namespace_inode: None,
            write_like: false,
        };
        let bytes = encode_frame(&frame).unwrap();
        let len = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
        let decoded: EbpfEventFrame = serde_json::from_slice(&bytes[4..4 + len]).unwrap();
        assert_eq!(decoded.run_token, "run-1");
        assert_eq!(decoded.event_type, EbpfEventType::Exec);
    }

    #[test]
    fn oversized_string_fields_are_truncated_before_encoding() {
        let frame = EbpfEventFrame {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            run_token: "run-1".to_owned(),
            event_type: EbpfEventType::Open,
            pid: 7,
            path: Some("a".repeat(10_000)),
            detail: None,
            exit_code: None,
            pid_namespace_inode: None,
            write_like: true,
        };
        let bytes = encode_frame(&frame).unwrap();
        assert!(bytes.len() < 10_000);
    }
}
