//! Bounded TensorFlow SavedModel/checkpoint inspection without graph execution.

use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

const MAX_PB_SCAN: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct TensorFlowSummary {
    pub kind: String,
    pub bytes: u64,
    pub suspicious_markers: Vec<String>,
    pub blocking_markers: Vec<String>,
    pub capability: String,
}

pub fn inspect_saved_model(file: &File, len: u64) -> Result<TensorFlowSummary> {
    if len == 0 {
        bail!("SavedModel protobuf is empty");
    }

    let scan = len.min(MAX_PB_SCAN);
    let mut cloned = file.try_clone()?;
    cloned.seek(SeekFrom::Start(0))?;
    let mut bytes = vec![0u8; usize::try_from(scan).context("SavedModel scan length too large")?];
    cloned.read_exact(&mut bytes)?;

    let mut suspicious = Vec::new();
    for needle in [
        b"PyFunc".as_slice(),
        b"EagerPyFunc".as_slice(),
        b"XlaCallModule".as_slice(),
        b"ReadFile".as_slice(),
        b"WriteFile".as_slice(),
        b"PrintV2".as_slice(),
        b"SaveV2".as_slice(),
        b"MatchingFiles".as_slice(),
        b"WholeFileReader".as_slice(),
        b"TextLineReader".as_slice(),
        b"FixedLengthRecordReader".as_slice(),
    ] {
        if find_bytes(&bytes, needle) {
            suspicious.push(String::from_utf8_lossy(needle).into_owned());
        }
    }

    let mut blocking = Vec::new();
    // PrintV2 becomes an arbitrary file-write primitive when output_stream is a file URI.
    // Other filesystem-related op names remain review evidence until Layerfault can bind
    // them to a concrete destination/attribute rather than blocking on the op name alone.
    if find_bytes(&bytes, b"PrintV2") && find_bytes(&bytes, b"file://") {
        blocking.push("PrintV2:file://".to_owned());
    }

    suspicious.sort();
    suspicious.dedup();
    blocking.sort();
    blocking.dedup();

    Ok(TensorFlowSummary {
        kind: "saved_model".into(),
        bytes: len,
        suspicious_markers: suspicious,
        blocking_markers: blocking,
        capability: if len > MAX_PB_SCAN {
            "bounded protobuf marker/inventory scan; full graph exceeds scan cap".into()
        } else {
            "bounded protobuf structural/marker scan".into()
        },
    })
}

pub fn inspect_checkpoint(path: &Path, _file: &File, len: u64) -> Result<TensorFlowSummary> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("checkpoint index has no parent"))?;
    let stem = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .strip_suffix(".index")
        .unwrap_or("");
    if stem.is_empty() {
        bail!("invalid TensorFlow checkpoint index filename");
    }

    let prefix = format!("{stem}.data-");
    let mut shards = 0usize;
    for entry in std::fs::read_dir(parent)? {
        let entry = entry?;
        let meta = entry.file_type()?;
        if meta.is_symlink() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if meta.is_file() && name.starts_with(&prefix) {
            shards += 1;
        }
    }
    if shards == 0 {
        bail!("TensorFlow checkpoint index has no matching data shard");
    }

    Ok(TensorFlowSummary {
        kind: "checkpoint".into(),
        bytes: len,
        suspicious_markers: Vec::new(),
        blocking_markers: Vec::new(),
        capability: format!(
            "checkpoint shard/package integrity validated; {shards} data shard(s); tensor value decoding is not required for static admission"
        ),
    })
}

pub fn scan_saved_model(
    file: &File,
    len: u64,
    digest: &str,
    media: &str,
) -> Result<crate::scanner::LayerScanResult> {
    let started = std::time::Instant::now();
    match inspect_saved_model(file, len) {
        Ok(summary) if !summary.blocking_markers.is_empty() => Ok(mk(
            digest,
            media,
            crate::scanner::ScanStatus::Fail,
            crate::scanner::FindingClass::ContentIndicator,
            format!("TensorFlow SavedModel inspected: {}", summary.capability),
            vec![format!(
                "[LF-TF-FILESYSTEM-WRITE] graph contains file-write capability marker(s): {}",
                summary.blocking_markers.join(", ")
            )],
            started,
        )),
        Ok(summary) if !summary.suspicious_markers.is_empty() => Ok(mk(
            digest,
            media,
            crate::scanner::ScanStatus::Warn,
            crate::scanner::FindingClass::ContentIndicator,
            format!("TensorFlow SavedModel inspected: {}", summary.capability),
            vec![format!(
                "[LF-TF-EXECUTION-OP] graph contains execution/file-related op markers: {}",
                summary.suspicious_markers.join(", ")
            )],
            started,
        )),
        Ok(summary) if len > MAX_PB_SCAN => Ok(mk(
            digest,
            media,
            crate::scanner::ScanStatus::Warn,
            crate::scanner::FindingClass::Compatibility,
            format!("TensorFlow SavedModel inspected: {}", summary.capability),
            vec![
                "[LF-TF-SCAN-LIMIT] SavedModel exceeded the bounded protobuf marker scan cap"
                    .to_owned(),
            ],
            started,
        )),
        Ok(summary) => Ok(mk(
            digest,
            media,
            crate::scanner::ScanStatus::Pass,
            crate::scanner::FindingClass::Structural,
            format!("TensorFlow SavedModel inspected: {}", summary.capability),
            Vec::new(),
            started,
        )),
        Err(error) => Ok(mk(
            digest,
            media,
            crate::scanner::ScanStatus::Fail,
            crate::scanner::FindingClass::Structural,
            format!("Invalid TensorFlow SavedModel: {error}"),
            vec!["[LF-TF-STRUCT] SavedModel structural validation failed".into()],
            started,
        )),
    }
}

pub fn scan_checkpoint(
    path: &Path,
    file: &File,
    len: u64,
    digest: &str,
    media: &str,
) -> Result<crate::scanner::LayerScanResult> {
    let started = std::time::Instant::now();
    match inspect_checkpoint(path, file, len) {
        Ok(summary) => Ok(mk(
            digest,
            media,
            crate::scanner::ScanStatus::Warn,
            crate::scanner::FindingClass::Compatibility,
            summary.capability,
            vec![
                "[LF-TF-CHECKPOINT-LIMIT] checkpoint package/shards validated; full TensorBundle tensor decoding is capability-limited"
                    .into(),
            ],
            started,
        )),
        Err(error) => Ok(mk(
            digest,
            media,
            crate::scanner::ScanStatus::Fail,
            crate::scanner::FindingClass::Structural,
            format!("Invalid TensorFlow checkpoint: {error}"),
            vec!["[LF-TF-CHECKPOINT-STRUCT] checkpoint validation failed".into()],
            started,
        )),
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn mk(
    digest: &str,
    media: &str,
    status: crate::scanner::ScanStatus,
    class: crate::scanner::FindingClass,
    detail: String,
    matches: Vec<String>,
    started: std::time::Instant,
) -> crate::scanner::LayerScanResult {
    crate::scanner::LayerScanResult {
        layer_digest: digest.into(),
        media_type: media.into(),
        check_type: crate::scanner::CheckType::TensorFlowStructure,
        status,
        finding_class: class,
        confidence: crate::scanner::Confidence::High,
        detail: Some(detail),
        matches,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::ScanStatus;
    use std::fs;

    fn fixture(label: &str, bytes: &[u8]) -> (std::path::PathBuf, File) {
        let path = std::env::temp_dir().join(format!(
            "layerfault-tensorflow-{label}-{}",
            std::process::id()
        ));
        fs::write(&path, bytes).expect("write TensorFlow fixture");
        let file = File::open(&path).expect("open TensorFlow fixture");
        (path, file)
    }

    #[test]
    fn printv2_file_uri_is_blocking_file_write_capability() {
        let bytes = b"SavedModel PrintV2 output_stream file:///tmp/LAYERFAULT_TEST";
        let (path, file) = fixture("printv2-file", bytes);
        let result = scan_saved_model(
            &file,
            bytes.len() as u64,
            "sha256:fixture",
            "application/x-tensorflow-savedmodel",
        )
        .expect("scan TensorFlow fixture");
        assert_eq!(result.status, ScanStatus::Fail);
        assert!(result
            .matches
            .iter()
            .any(|value| value.contains("LF-TF-FILESYSTEM-WRITE")));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn printv2_without_file_uri_is_warning_only() {
        let bytes = b"SavedModel PrintV2 stderr";
        let (path, file) = fixture("printv2-stderr", bytes);
        let result = scan_saved_model(
            &file,
            bytes.len() as u64,
            "sha256:fixture",
            "application/x-tensorflow-savedmodel",
        )
        .expect("scan TensorFlow fixture");
        assert_eq!(result.status, ScanStatus::Warn);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn benign_savedmodel_marker_scan_passes() {
        let bytes = b"SavedModel MatMul Relu Identity";
        let (path, file) = fixture("benign", bytes);
        let result = scan_saved_model(
            &file,
            bytes.len() as u64,
            "sha256:fixture",
            "application/x-tensorflow-savedmodel",
        )
        .expect("scan TensorFlow fixture");
        assert_eq!(result.status, ScanStatus::Pass);
        let _ = fs::remove_file(path);
    }
}
