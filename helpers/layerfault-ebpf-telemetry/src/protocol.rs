//! Thin encoder-side wrapper around `layerfault_telemetry_protocol`. Bounds
//! total emitted bytes to `MAX_TOTAL_STREAM_BYTES` on the sender side too —
//! defense in depth alongside the decoder's own independent enforcement of
//! the same ceiling in the main crate.

use layerfault_telemetry_protocol::{encode_frame, EbpfEventFrame, MAX_TOTAL_STREAM_BYTES};
use std::io::Write;

pub struct FrameWriter<W: Write> {
    sink: W,
    total_bytes_sent: u64,
    stopped: bool,
}

impl<W: Write> FrameWriter<W> {
    pub fn new(sink: W) -> Self {
        Self {
            sink,
            total_bytes_sent: 0,
            stopped: false,
        }
    }

    /// Encode and write one frame. Returns `Ok(false)` once the sender-side
    /// stream ceiling has been reached (all further calls are no-ops), so
    /// the caller can stop polling for events and exit cleanly rather than
    /// growing an unbounded queue waiting to be flushed.
    pub fn write_event(&mut self, frame: &EbpfEventFrame) -> anyhow::Result<bool> {
        if self.stopped {
            return Ok(false);
        }
        let bytes = encode_frame(frame).map_err(|err| anyhow::anyhow!(err.to_string()))?;
        let next_total = self.total_bytes_sent.saturating_add(bytes.len() as u64);
        if next_total > MAX_TOTAL_STREAM_BYTES {
            self.stopped = true;
            return Ok(false);
        }
        self.sink.write_all(&bytes)?;
        self.total_bytes_sent = next_total;
        Ok(true)
    }

    pub fn flush(&mut self) -> anyhow::Result<()> {
        self.sink.flush()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use layerfault_telemetry_protocol::{EbpfEventType, PROTOCOL_SCHEMA_VERSION};

    fn frame() -> EbpfEventFrame {
        EbpfEventFrame {
            schema_version: PROTOCOL_SCHEMA_VERSION,
            run_token: "run".to_owned(),
            event_type: EbpfEventType::Exec,
            pid: 1,
            path: Some("/bin/sh".to_owned()),
            detail: None,
            exit_code: None,
            pid_namespace_inode: None,
            write_like: false,
        }
    }

    #[test]
    fn writes_length_prefixed_frames() {
        let mut writer = FrameWriter::new(Vec::new());
        assert!(writer.write_event(&frame()).unwrap());
        assert!(writer.write_event(&frame()).unwrap());
        assert!(!writer.sink.is_empty());
    }

    #[test]
    fn stops_once_stream_ceiling_reached() {
        let mut writer = FrameWriter::new(Vec::new());
        writer.total_bytes_sent = MAX_TOTAL_STREAM_BYTES;
        assert!(!writer.write_event(&frame()).unwrap());
        assert!(!writer.write_event(&frame()).unwrap());
    }
}
