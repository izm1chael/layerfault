//! Extent and trailing-data inspection for parsed artifact formats.

use crate::finding_evidence::{
    binary_object, structural_invariant, EvidenceSubject, FindingBuilder,
};
use crate::scanner::{
    BinaryScanner, CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus,
};
use anyhow::Result;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ParsedExtent {
    pub logical_end: u64,
    pub file_len: u64,
}

impl ParsedExtent {
    pub fn new(logical_end: u64, file_len: u64) -> Self {
        Self {
            logical_end: logical_end.min(file_len),
            file_len,
        }
    }

    pub fn has_trailing_data(&self) -> bool {
        self.file_len > self.logical_end
    }

    pub fn trailing_bytes_count(&self) -> u64 {
        self.file_len.saturating_sub(self.logical_end)
    }
}

/// Inspect trailing data after `extent.logical_end`.
pub fn inspect_trailing_data(
    file: &File,
    extent: ParsedExtent,
    subject: &EvidenceSubject,
    layer_digest: &str,
    media_type: &str,
) -> Result<Option<LayerScanResult>> {
    if !extent.has_trailing_data() {
        return Ok(None);
    }

    let trailing_len = extent.trailing_bytes_count();
    let mut cloned = file.try_clone()?;
    cloned.seek(SeekFrom::Start(extent.logical_end))?;

    // Read initial 512 bytes of trailing region to classify signatures
    let mut prefix_buf = [0_u8; 512];
    let n = cloned.read(&mut prefix_buf)?;
    let prefix = &prefix_buf[..n];

    // Check if trailing bytes are all zeros (legitimate alignment/padding)
    if is_all_zeros(file, extent.logical_end, trailing_len)? {
        return Ok(None);
    }

    let trailing_offset = extent.logical_end;

    // 1. Appended Pickle check
    if prefix.len() >= 2 && prefix[0] == 0x80 && (2..=5).contains(&prefix[1]) {
        return Ok(Some(
            FindingBuilder::new(
                "LF-FORMAT-APPENDED-SERIALIZATION",
                CheckType::LayerPolicy,
                ScanStatus::Fail,
            )
            .class(FindingClass::ContentIndicator)
            .confidence(Confidence::High)
            .subject(subject.clone())
            .detail(format!(
                "Appended Pickle serialization stream detected at trailing offset 0x{trailing_offset:x} ({trailing_len} trailing bytes)"
            ))
            .evidence(structural_invariant(
                subject.clone(),
                "appended pickle stream after primary format end",
                serde_json::json!({
                    "logical_end": extent.logical_end,
                    "file_len": extent.file_len,
                    "trailing_bytes": trailing_len,
                    "trailing_magic": "pickle",
                }),
            ))
            .finish(),
        ));
    }

    // 2. Appended Archive check (ZIP/TAR)
    if prefix.starts_with(b"PK\x03\x04") || prefix.starts_with(b"PK\x05\x06") {
        return Ok(Some(
            FindingBuilder::new(
                "LF-FORMAT-APPENDED-ARCHIVE",
                CheckType::LayerPolicy,
                ScanStatus::Fail,
            )
            .class(FindingClass::ContentIndicator)
            .confidence(Confidence::High)
            .subject(subject.clone())
            .detail(format!(
                "Appended ZIP archive detected at trailing offset 0x{trailing_offset:x} ({trailing_len} trailing bytes)"
            ))
            .evidence(structural_invariant(
                subject.clone(),
                "appended archive container after primary format end",
                serde_json::json!({
                    "logical_end": extent.logical_end,
                    "file_len": extent.file_len,
                    "trailing_bytes": trailing_len,
                    "trailing_magic": "zip",
                }),
            ))
            .finish(),
        ));
    }

    // 3. Appended Executable check (ELF, PE, Mach-O, WASM)
    if BinaryScanner::looks_executable_prefix(prefix) {
        let bin_res = BinaryScanner::scan_file(file, extent.file_len, layer_digest, media_type)?;
        if bin_res.status == ScanStatus::Fail {
            // Binary scanner found a structurally valid embedded/appended executable!
            return Ok(Some(
                FindingBuilder::new(
                    "LF-FORMAT-POLYGLOT",
                    CheckType::BinarySteganography,
                    ScanStatus::Fail,
                )
                .class(FindingClass::ContentIndicator)
                .confidence(Confidence::High)
                .subject(subject.clone())
                .detail(format!(
                    "Structurally valid polyglot executable payload detected at trailing offset 0x{trailing_offset:x}"
                ))
                .evidence(binary_object(
                    subject.clone(),
                    trailing_offset,
                    trailing_len,
                    serde_json::json!({
                        "logical_end": extent.logical_end,
                        "file_len": extent.file_len,
                        "trailing_bytes": trailing_len,
                    }),
                ))
                .finish(),
            ));
        }
    }

    // 4. Arbitrary non-padding trailing payload
    Ok(Some(
        FindingBuilder::new(
            "LF-FORMAT-TRAILING-DATA",
            CheckType::LayerPolicy,
            ScanStatus::Warn,
        )
        .class(FindingClass::Structural)
        .confidence(Confidence::High)
        .subject(subject.clone())
        .detail(format!(
            "Unmodeled non-zero trailing payload of {trailing_len} bytes detected after logical end at 0x{trailing_offset:x}"
        ))
        .evidence(structural_invariant(
            subject.clone(),
            "unmodeled non-zero bytes after primary format logical end",
            serde_json::json!({
                "logical_end": extent.logical_end,
                "file_len": extent.file_len,
                "trailing_bytes": trailing_len,
            }),
        ))
        .finish(),
    ))
}

fn is_all_zeros(file: &File, offset: u64, len: u64) -> Result<bool> {
    let mut cloned = file.try_clone()?;
    cloned.seek(SeekFrom::Start(offset))?;
    let mut buf = [0_u8; 4096];
    let mut remaining = len;
    while remaining > 0 {
        let to_read = (remaining as usize).min(buf.len());
        let n = cloned.read(&mut buf[..to_read])?;
        if n == 0 {
            break;
        }
        if buf[..n].iter().any(|&b| b != 0) {
            return Ok(false);
        }
        remaining = remaining.saturating_sub(n as u64);
    }
    Ok(true)
}
