//! Bounded structural inspection for ExecuTorch `.pte` artifacts.
//!
//! ExecuTorch models use FlatBuffer binary schemas. This module performs pure-Rust
//! bounded parsing of segment bounds, table offsets, trailing data, and embedded
//! delegate binaries without executing any model operations or loading C++ runtimes.

use crate::finding_evidence::{
    byte_range_evidence, structural_invariant, EvidenceSubject, FindingBuilder,
};
use crate::scanner::binary::BinaryScanner;
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use anyhow::{Context, Result};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Bounded static scan for ExecuTorch artifacts.
pub fn scan(
    path: &Path,
    file: &File,
    size: u64,
    identity: &str,
    media: &str,
) -> Result<Vec<LayerScanResult>> {
    let mut cloned = file.try_clone().context("failed to clone file handle")?;
    cloned.seek(SeekFrom::Start(0))?;

    let header_read_len = usize::try_from(size.min(4096)).unwrap_or(4096);
    let mut header_buf = vec![0u8; header_read_len];
    cloned.read_exact(&mut header_buf)?;

    let mut results = Vec::new();
    let subject = EvidenceSubject::member(&path.display().to_string())
        .with_sha256(Some(identity.to_owned()))
        .with_media_type(media);

    // ExecuTorch magic validation: FlatBuffer file identifier "ET12", "ET11", "ET01".."ET99" or "ET" prefix
    if size < 8 {
        results.push(
            FindingBuilder::new(
                "LF-EXECUTORCH-TRUNCATED",
                CheckType::LayerPolicy,
                ScanStatus::Fail,
            )
            .class(FindingClass::Structural)
            .confidence(Confidence::High)
            .digest(identity)
            .media_type(media)
            .subject(subject.clone())
            .detail("ExecuTorch model file is smaller than minimum header size".to_owned())
            .evidence(structural_invariant(
                subject.clone(),
                "file size smaller than ExecuTorch header",
                serde_json::json!({ "size": size, "min_required": 8 }),
            ))
            .finish(),
        );
        return Ok(results);
    }

    let is_et_magic = (header_buf.len() >= 8 && &header_buf[4..6] == b"ET")
        || header_buf.starts_with(b"ET12")
        || header_buf.starts_with(b"ET11");

    if !is_et_magic {
        results.push(
            FindingBuilder::new(
                "LF-EXECUTORCH-INVALID-MAGIC",
                CheckType::LayerPolicy,
                ScanStatus::Fail,
            )
            .class(FindingClass::Structural)
            .confidence(Confidence::High)
            .digest(identity)
            .media_type(media)
            .subject(subject.clone())
            .detail("ExecuTorch artifact lacks valid 'ET' FlatBuffer file identifier".to_owned())
            .evidence(byte_range_evidence(
                subject.clone(),
                0,
                8.min(header_buf.len() as u64),
                "invalid ExecuTorch header magic",
            ))
            .finish(),
        );
        return Ok(results);
    }

    // FlatBuffer root table offset check
    if header_buf.len() >= 4 {
        let root_table_offset = u32::from_le_bytes(header_buf[..4].try_into().unwrap()) as u64;
        if root_table_offset >= size {
            results.push(
                FindingBuilder::new(
                    "LF-EXECUTORCH-BOUNDS",
                    CheckType::LayerPolicy,
                    ScanStatus::Fail,
                )
                .class(FindingClass::Structural)
                .confidence(Confidence::High)
                .digest(identity)
                .media_type(media)
                .subject(subject.clone())
                .detail(format!(
                    "ExecuTorch root table offset ({root_table_offset}) exceeds file size ({size})"
                ))
                .evidence(structural_invariant(
                    subject.clone(),
                    "FlatBuffer root table offset out of bounds",
                    serde_json::json!({ "offset": root_table_offset, "file_size": size }),
                ))
                .finish(),
            );
            return Ok(results);
        }
    }

    // ExecuTorch extended header truncation check. `.pte` files produced with
    // a segment/delegate layout embed an optional "eh00" extended header at
    // a fixed offset (see ExecuTorch's `schema/extended_header.h`) declaring
    // the program's true total size; comparing that against the file's
    // actual size on disk catches truncation the earlier bounds-only check
    // cannot, since a truncated tail can still leave the root table (which
    // lives near the head) internally consistent.
    const EH_OFFSET: usize = 8;
    const EH_MAGIC: &[u8; 4] = b"eh00";
    const EH_LENGTH_OFF: usize = EH_OFFSET + 4;
    const EH_PROGRAM_SIZE_OFF: usize = EH_LENGTH_OFF + 4;
    const EH_SEGMENT_BASE_OFFSET_OFF: usize = EH_PROGRAM_SIZE_OFF + 8;
    const EH_SEGMENT_DATA_SIZE_OFF: usize = EH_SEGMENT_BASE_OFFSET_OFF + 8;
    const EH_MIN_HEADER_LENGTH: u32 = 24;
    const EH_LENGTH_WITH_SEGMENT_DATA_SIZE: u32 = 32;

    if header_buf.len() >= EH_SEGMENT_DATA_SIZE_OFF + 8
        && header_buf[EH_OFFSET..EH_OFFSET + 4] == *EH_MAGIC
    {
        let header_length = u32::from_le_bytes(
            header_buf[EH_LENGTH_OFF..EH_LENGTH_OFF + 4]
                .try_into()
                .unwrap(),
        );
        if header_length >= EH_MIN_HEADER_LENGTH {
            let program_size = u64::from_le_bytes(
                header_buf[EH_PROGRAM_SIZE_OFF..EH_PROGRAM_SIZE_OFF + 8]
                    .try_into()
                    .unwrap(),
            );
            let segment_base_offset = u64::from_le_bytes(
                header_buf[EH_SEGMENT_BASE_OFFSET_OFF..EH_SEGMENT_BASE_OFFSET_OFF + 8]
                    .try_into()
                    .unwrap(),
            );
            let segment_data_size = if header_length >= EH_LENGTH_WITH_SEGMENT_DATA_SIZE {
                u64::from_le_bytes(
                    header_buf[EH_SEGMENT_DATA_SIZE_OFF..EH_SEGMENT_DATA_SIZE_OFF + 8]
                        .try_into()
                        .unwrap(),
                )
            } else {
                0
            };
            // The extended header comes in two forms: a 32+ byte form that
            // includes `segment_data_size`, and a short 24-byte form that
            // doesn't. When segments are present (`segment_base_offset != 0`)
            // but this file uses the short form, `segment_data_size` is
            // unknown — not "zero segment bytes". Treating it as zero would
            // silently collapse `expected_size` down to just the offset
            // where segments *begin*, giving false confidence that a file
            // truncated partway through the segment/delegate region would
            // be caught, when it structurally cannot be: this matches
            // ExecuTorch's own reference runtime, which computes the same
            // `expected_size` formula and has the same blind spot for this
            // header form. Report the limitation explicitly instead of
            // silently falling through to a clean Pass.
            let segment_size_unknown =
                segment_base_offset != 0 && header_length < EH_LENGTH_WITH_SEGMENT_DATA_SIZE;
            let expected_size = if segment_base_offset == 0 {
                program_size
            } else {
                segment_base_offset.saturating_add(segment_data_size)
            };

            if segment_size_unknown {
                results.push(
                    FindingBuilder::new(
                        "LF-EXECUTORCH-SEGMENT-SIZE-UNKNOWN",
                        CheckType::LayerPolicy,
                        ScanStatus::Warn,
                    )
                    .class(FindingClass::Compatibility)
                    .confidence(Confidence::High)
                    .digest(identity)
                    .media_type(media)
                    .subject(subject.clone())
                    .detail(format!(
                        "ExecuTorch extended header declares segments starting at byte {segment_base_offset} but uses the short header form, which does not declare the segments' total size; truncation within the segment/delegate region cannot be verified"
                    ))
                    .evidence(structural_invariant(
                        subject.clone(),
                        "extended header omits segment_data_size",
                        serde_json::json!({ "segment_base_offset": segment_base_offset, "header_length": header_length }),
                    ))
                    .finish(),
                );
            } else if expected_size > 0 && size < expected_size {
                results.push(
                    FindingBuilder::new(
                        "LF-EXECUTORCH-TRUNCATED",
                        CheckType::LayerPolicy,
                        ScanStatus::Fail,
                    )
                    .class(FindingClass::Structural)
                    .confidence(Confidence::High)
                    .digest(identity)
                    .media_type(media)
                    .subject(subject.clone())
                    .detail(format!(
                        "ExecuTorch extended header declares a total size of {expected_size} bytes but the file is only {size} bytes"
                    ))
                    .evidence(structural_invariant(
                        subject.clone(),
                        "file size smaller than extended-header-declared program size",
                        serde_json::json!({ "size": size, "expected_size": expected_size }),
                    ))
                    .finish(),
                );
                return Ok(results);
            }
        }
    }

    // Binary scan for embedded executable payloads or delegates
    let bin_result = BinaryScanner::scan_file(file, size, identity, media)?;
    if bin_result.status == ScanStatus::Fail {
        let mut delegate_finding = bin_result;
        delegate_finding.check_type = CheckType::PackageSecurity;
        delegate_finding.detail = Some(
            "ExecuTorch model contains embedded native binary delegate / executable payload"
                .to_owned(),
        );
        results.push(delegate_finding);
    }

    results.push(
        FindingBuilder::new(
            "LF-EXECUTORCH-STRUCTURAL",
            CheckType::LayerPolicy,
            ScanStatus::Pass,
        )
        .class(FindingClass::Structural)
        .confidence(Confidence::High)
        .digest(identity)
        .media_type(media)
        .subject(subject)
        .detail("ExecuTorch model header and FlatBuffer bounds verified statically (capability-limited structural parser)".to_owned())
        .finish(),
    );

    Ok(results)
}
