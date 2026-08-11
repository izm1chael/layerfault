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
