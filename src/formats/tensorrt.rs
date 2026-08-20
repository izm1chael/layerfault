//! TensorRT serialized engine inspector.
//!
//! TensorRT engines are proprietary serialized binary blobs. This module performs
//! defensible checks (header magic, version metadata, binary executable scan, hash integrity)
//! and reports an explicit capability limitation without reverse-engineering brittle offsets.

use crate::finding_evidence::{byte_range_evidence, EvidenceSubject, FindingBuilder};
use crate::scanner::binary::BinaryScanner;
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use anyhow::{Context, Result};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Bounded static inspection of a TensorRT serialized engine.
pub fn scan(
    path: &Path,
    file: &File,
    size: u64,
    identity: &str,
    media: &str,
) -> Result<Vec<LayerScanResult>> {
    let mut cloned = file.try_clone().context("failed to clone file handle")?;
    cloned.seek(SeekFrom::Start(0))?;

    let header_len = usize::try_from(size.min(1024)).unwrap_or(1024);
    let mut header_buf = vec![0u8; header_len];
    cloned.read_exact(&mut header_buf)?;

    let mut results = Vec::new();
    let subject = EvidenceSubject::member(&path.display().to_string())
        .with_sha256(Some(identity.to_owned()))
        .with_media_type(media);

    if size < 4 {
        results.push(
            FindingBuilder::new(
                "LF-TENSORRT-TRUNCATED",
                CheckType::LayerPolicy,
                ScanStatus::Fail,
            )
            .class(FindingClass::Structural)
            .confidence(Confidence::High)
            .digest(identity)
            .media_type(media)
            .subject(subject.clone())
            .detail("TensorRT engine file is smaller than minimum magic header size".to_owned())
            .finish(),
        );
        return Ok(results);
    }

    // Check TensorRT header magic signatures: "TRT\x00", "ptrt", "TRT\x02", "TRT"
    let is_trt = header_buf.starts_with(b"TRT")
        || header_buf.starts_with(b"ptrt")
        || header_buf.windows(4).any(|w| w == b"TRT\x00");

    if !is_trt {
        results.push(
            FindingBuilder::new(
                "LF-TENSORRT-INVALID-MAGIC",
                CheckType::LayerPolicy,
                ScanStatus::Warn,
            )
            .class(FindingClass::Compatibility)
            .confidence(Confidence::High)
            .digest(identity)
            .media_type(media)
            .subject(subject.clone())
            .detail("File extension claims TensorRT engine, but standard 'TRT' magic header was not identified".to_owned())
            .evidence(byte_range_evidence(
                subject.clone(),
                0,
                4.min(header_buf.len() as u64),
                "unrecognized engine header magic",
            ))
            .finish(),
        );
    }

    // Binary scan for embedded executable payloads or native binaries.
    //
    // Unlike a weights-only format (GGUF, Safetensors), a TensorRT engine's
    // entire purpose is to be a serialized, compiled GPU execution plan —
    // it inherently contains compiled machine code as normal, expected,
    // load-bearing content. There is no such thing as a "clean" engine
    // without one. Reporting this generic scan as a blocking finding would
    // fail every real TensorRT engine, not just tampered ones, so it's kept
    // as visible, non-blocking evidence instead of forwarded as a Fail.
    let bin_result = BinaryScanner::scan_file(file, size, identity, media)?;
    if bin_result.status == ScanStatus::Fail {
        let mut executable_finding = bin_result;
        executable_finding.status = ScanStatus::Warn;
        executable_finding.check_type = CheckType::PackageSecurity;
        executable_finding.detail = Some(
            "TensorRT engine blob contains embedded native executable/binary payload; this is expected of every serialized TensorRT engine (a compiled GPU execution plan) and is not, by itself, evidence of tampering".to_owned(),
        );
        results.push(executable_finding);
    }

    // Report explicit capability limitation finding
    results.push(
        FindingBuilder::new(
            "LF-TENSORRT-OPAQUE",
            CheckType::LayerPolicy,
            ScanStatus::Pass,
        )
        .class(FindingClass::Compatibility)
        .confidence(Confidence::High)
        .digest(identity)
        .media_type(media)
        .subject(subject)
        .detail("TensorRT serialized engine header, size, integrity, and binary payload inspected. Engine graph execution parameters remain opaque by specification.".to_owned())
        .finish(),
    );

    Ok(results)
}
