pub mod elf;
pub mod macho;
pub mod pe;
pub mod types;
pub mod wasm;

pub use types::*;

use crate::finding_evidence::{binary_object, EvidenceSubject, FindingBuilder};
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use anyhow::Result;
use std::collections::BTreeSet;
use std::fs::File;
use std::time::Instant;

const CHUNK_BYTES: usize = 1024 * 1024;
const OVERLAP_BYTES: usize = 512;
const MAX_FINDINGS: usize = 8;

pub struct BinaryScanner;

pub(crate) struct BinaryStreamScanner {
    carry: Vec<u8>,
    absolute_read: u64,
    findings: Vec<String>,
    pending_evidence: Vec<(String, u64, String, Option<BinaryMetadata>)>,
    seen: BTreeSet<(u8, u64)>,
    started: Instant,
}

impl BinaryStreamScanner {
    pub(crate) fn new() -> Self {
        Self {
            carry: Vec::new(),
            absolute_read: 0,
            findings: Vec::new(),
            pending_evidence: Vec::new(),
            seen: BTreeSet::new(),
            started: Instant::now(),
        }
    }

    pub(crate) fn observe_at_offset(&mut self, offset: u64, bytes: &[u8]) -> Result<()> {
        self.observe_with_file(None, offset, bytes)
    }

    pub(crate) fn observe(&mut self, file: &File, file_len: u64, bytes: &[u8]) -> Result<()> {
        let offset = self.absolute_read;
        self.observe_with_file(Some((file, file_len)), offset, bytes)
    }

    pub(crate) fn observe_with_file(
        &mut self,
        file_info: Option<(&File, u64)>,
        offset: u64,
        bytes: &[u8],
    ) -> Result<()> {
        if bytes.is_empty() || self.findings.len() >= MAX_FINDINGS {
            self.absolute_read = offset.saturating_add(bytes.len() as u64);
            return Ok(());
        }

        self.absolute_read = offset.saturating_add(bytes.len() as u64);
        let mut window = Vec::with_capacity(self.carry.len() + bytes.len());
        window.extend_from_slice(&self.carry);
        window.extend_from_slice(bytes);
        let window_start = offset.saturating_sub(self.carry.len() as u64);

        for (offset_in_win, magic) in window.windows(4).enumerate() {
            if self.findings.len() >= MAX_FINDINGS {
                break;
            }
            let absolute = window_start.saturating_add(offset_in_win as u64);
            if magic == b"\x7fELF" {
                let valid = if let Some((file, file_len)) = file_info {
                    looks_like_elf_header(&window[offset_in_win..])
                        && validate_elf(file, file_len, absolute)?
                } else {
                    looks_like_elf_header(&window[offset_in_win..])
                };
                if valid {
                    let metadata = file_info.and_then(|(file, file_len)| {
                        elf::parse_elf(file, file_len, absolute).ok().flatten()
                    });
                    self.push(
                        1,
                        absolute,
                        "T12-001",
                        "ELF",
                        format!(
                            "[T12-001] Structurally valid embedded ELF object at file offset 0x{absolute:x}"
                        ),
                        metadata,
                    );
                }
                continue;
            }
            if magic == b"\0asm" {
                let valid = if let Some((file, file_len)) = file_info {
                    validate_wasm(file, file_len, absolute)?
                } else {
                    true
                };
                if valid {
                    let metadata = file_info.and_then(|(file, file_len)| {
                        wasm::parse_wasm(file, file_len, absolute).ok().flatten()
                    });
                    self.push(
                        4,
                        absolute,
                        "T12-004",
                        "WASM",
                        format!(
                            "[T12-004] Structurally valid WebAssembly module header at file offset 0x{absolute:x}"
                        ),
                        metadata,
                    );
                }
                continue;
            }
            let maybe_macho = matches!(magic[0], 0xfe | 0xce | 0xca | 0xbe | 0xbf | 0xcf)
                && MACHO_MAGICS.iter().any(|candidate| magic == *candidate);
            if maybe_macho {
                let valid = if let Some((file, file_len)) = file_info {
                    validate_macho(file, file_len, absolute)?
                } else {
                    true
                };
                if valid {
                    let metadata = file_info.and_then(|(file, file_len)| {
                        macho::parse_macho(file, file_len, absolute).ok().flatten()
                    });
                    self.push(
                        3,
                        absolute,
                        "T12-003",
                        "Mach-O",
                        format!(
                            "[T12-003] Structurally valid embedded Mach-O object at file offset 0x{absolute:x}"
                        ),
                        metadata,
                    );
                }
            }
        }

        if self.findings.len() < MAX_FINDINGS {
            for offset_in_win in find_all(&window, b"MZ") {
                if self.findings.len() >= MAX_FINDINGS {
                    break;
                }
                if !looks_like_dos_header(&window[offset_in_win..]) {
                    continue;
                }
                let absolute = window_start.saturating_add(offset_in_win as u64);
                let valid = if let Some((file, file_len)) = file_info {
                    validate_pe(file, file_len, absolute)?
                } else {
                    true
                };
                if valid {
                    let metadata = file_info.and_then(|(file, file_len)| {
                        pe::parse_pe(file, file_len, absolute).ok().flatten()
                    });
                    self.push(
                        2,
                        absolute,
                        "T12-002",
                        "PE",
                        format!(
                            "[T12-002] Structurally valid embedded PE object at file offset 0x{absolute:x}"
                        ),
                        metadata,
                    );
                }
            }
        }

        let keep = window.len().min(OVERLAP_BYTES);
        self.carry.clear();
        self.carry.extend_from_slice(&window[window.len() - keep..]);
        Ok(())
    }

    fn push(
        &mut self,
        kind: u8,
        offset: u64,
        rule_id: &str,
        format_name: &str,
        finding: String,
        metadata: Option<BinaryMetadata>,
    ) {
        if self.seen.insert((kind, offset)) && self.findings.len() < MAX_FINDINGS {
            self.findings.push(finding);
            self.pending_evidence.push((
                rule_id.to_owned(),
                offset,
                format_name.to_owned(),
                metadata,
            ));
        }
    }

    pub(crate) fn finish(self, layer_digest: &str, media_type: &str) -> LayerScanResult {
        let subject = EvidenceSubject::identity(layer_digest, media_type)
            .with_sha256(Some(layer_digest.to_owned()));
        if self.findings.is_empty() {
            return FindingBuilder::new(
                "T12-CLEAR",
                CheckType::BinarySteganography,
                ScanStatus::Pass,
            )
            .class(FindingClass::ContentIndicator)
            .confidence(Confidence::High)
            .digest(layer_digest)
            .media_type(media_type)
            .subject(subject)
            .evidence_not_applicable()
            .duration_ms(crate::scanner::duration_ms(self.started))
            .finish();
        }

        let rule_id = self
            .pending_evidence
            .first()
            .map(|(rule, ..)| rule.clone())
            .unwrap_or_else(|| "T12-001".to_owned());

        let mut builder =
            FindingBuilder::new(&rule_id, CheckType::BinarySteganography, ScanStatus::Fail)
                .class(FindingClass::ContentIndicator)
                .confidence(Confidence::High)
                .digest(layer_digest)
                .media_type(media_type)
                .subject(subject.clone())
                .detail(format!(
                    "{} structurally plausible embedded executable/module object(s) detected",
                    self.findings.len()
                ))
                .duration_ms(crate::scanner::duration_ms(self.started));

        for (rule, offset, format_name, metadata) in &self.pending_evidence {
            let facts = if let Some(meta) = metadata {
                serde_json::to_value(meta).unwrap_or_else(
                    |_| serde_json::json!({ "format": format_name, "rule_id": rule }),
                )
            } else {
                serde_json::json!({ "format": format_name, "rule_id": rule })
            };

            builder = builder.evidence(binary_object(subject.clone(), *offset, 4, facts));
        }

        let mut result = builder.finish();
        result.matches = self.findings;
        result
    }
}

impl BinaryScanner {
    pub fn parse_metadata(file: &File, file_len: u64) -> Result<Option<BinaryMetadata>> {
        let prefix = match read_at(file, 0, 8)? {
            Some(b) => b,
            None => return Ok(None),
        };

        if prefix.starts_with(b"\x7fELF") {
            return elf::parse_elf(file, file_len, 0);
        }
        if prefix.starts_with(b"MZ") {
            return pe::parse_pe(file, file_len, 0);
        }
        if prefix.starts_with(b"\0asm\x01\0\0\0") {
            return wasm::parse_wasm(file, file_len, 0);
        }
        if MACHO_MAGICS
            .iter()
            .any(|magic| prefix.starts_with(&magic[..]))
        {
            return macho::parse_macho(file, file_len, 0);
        }

        Ok(None)
    }

    pub fn inspect_file_capabilities(
        file: &File,
        file_len: u64,
        layer_digest: &str,
        package_relative_path: &str,
    ) -> Result<(Option<BinaryMetadata>, Vec<LayerScanResult>)> {
        let metadata = match Self::parse_metadata(file, file_len)? {
            Some(meta) => meta,
            None => return Ok((None, Vec::new())),
        };

        let mut findings = Vec::new();
        let subject = EvidenceSubject::member(package_relative_path)
            .with_sha256(Some(layer_digest.to_owned()))
            .with_size(Some(file_len));

        if metadata.flags.wx_sections || metadata.flags.gnu_stack_wx == Some(true) {
            let detail = format!(
                "Native binary '{package_relative_path}' has writable and executable (WX) memory permissions"
            );
            findings.push(
                FindingBuilder::new(
                    "LF-NATIVE-WX-SECTION",
                    CheckType::PackageSecurity,
                    ScanStatus::Warn,
                )
                .class(FindingClass::ContentIndicator)
                .confidence(Confidence::High)
                .digest(layer_digest)
                .subject(subject.clone())
                .detail(detail)
                .evidence(
                    crate::finding_evidence::FindingEvidence::new(
                        crate::finding_evidence::EvidenceKind::BinaryObject,
                        subject.clone(),
                        "Native binary memory permissions include writable and executable sections",
                    )
                    .structured(serde_json::json!({
                        "wx_sections": metadata.flags.wx_sections,
                        "gnu_stack_wx": metadata.flags.gnu_stack_wx,
                        "format": format!("{:?}", metadata.format),
                    })),
                )
                .finish(),
            );
        }

        if !metadata.rpaths.is_empty() {
            let detail = format!(
                "Native binary '{package_relative_path}' specifies RPATH/RUNPATH search paths: {}",
                metadata.rpaths.join(", ")
            );
            findings.push(
                FindingBuilder::new("LF-NATIVE-RPATH", CheckType::PackageSecurity, ScanStatus::Warn)
                    .class(FindingClass::ContentIndicator)
                    .confidence(Confidence::High)
                    .digest(layer_digest)
                    .subject(subject.clone())
                    .detail(detail)
                    .evidence(crate::finding_evidence::FindingEvidence::new(
                        crate::finding_evidence::EvidenceKind::BinaryObject,
                        subject.clone(),
                        "Native binary contains explicit dynamic library search paths (RPATH/RUNPATH)",
                    ).structured(serde_json::json!({
                        "rpaths": metadata.rpaths,
                        "format": format!("{:?}", metadata.format),
                    })))
                    .finish()
            );
        }

        let exec_imports: Vec<_> = metadata
            .imports
            .iter()
            .filter(|i| i.category == Some(BinarySymbolCategory::Process))
            .map(|i| i.name.as_str())
            .collect();
        if !exec_imports.is_empty() {
            let detail = format!(
                "Native binary '{package_relative_path}' imports process execution capability symbols: {}",
                exec_imports.join(", ")
            );
            findings.push(
                FindingBuilder::new(
                    "LF-NATIVE-EXEC-CAPABILITY",
                    CheckType::PackageSecurity,
                    ScanStatus::Warn,
                )
                .class(FindingClass::ContentIndicator)
                .confidence(Confidence::High)
                .digest(layer_digest)
                .subject(subject.clone())
                .detail(detail)
                .evidence(
                    crate::finding_evidence::FindingEvidence::new(
                        crate::finding_evidence::EvidenceKind::BinaryObject,
                        subject.clone(),
                        "Native binary imports process execution function symbols",
                    )
                    .structured(serde_json::json!({
                        "imported_process_symbols": exec_imports,
                        "format": format!("{:?}", metadata.format),
                    })),
                )
                .finish(),
            );
        }

        let net_imports: Vec<_> = metadata
            .imports
            .iter()
            .filter(|i| i.category == Some(BinarySymbolCategory::Network))
            .map(|i| i.name.as_str())
            .collect();
        if !net_imports.is_empty() {
            let detail = format!(
                "Native binary '{package_relative_path}' imports network capability symbols: {}",
                net_imports.join(", ")
            );
            findings.push(
                FindingBuilder::new(
                    "LF-NATIVE-NETWORK-CAPABILITY",
                    CheckType::PackageSecurity,
                    ScanStatus::Warn,
                )
                .class(FindingClass::ContentIndicator)
                .confidence(Confidence::High)
                .digest(layer_digest)
                .subject(subject.clone())
                .detail(detail)
                .evidence(
                    crate::finding_evidence::FindingEvidence::new(
                        crate::finding_evidence::EvidenceKind::BinaryObject,
                        subject.clone(),
                        "Native binary imports network function symbols",
                    )
                    .structured(serde_json::json!({
                        "imported_network_symbols": net_imports,
                        "format": format!("{:?}", metadata.format),
                    })),
                )
                .finish(),
            );
        }

        let dl_imports: Vec<_> = metadata
            .imports
            .iter()
            .filter(|i| i.category == Some(BinarySymbolCategory::DynamicLoad))
            .map(|i| i.name.as_str())
            .collect();
        if !dl_imports.is_empty() {
            let detail = format!(
                "Native binary '{package_relative_path}' imports dynamic loader capability symbols: {}",
                dl_imports.join(", ")
            );
            findings.push(
                FindingBuilder::new(
                    "LF-NATIVE-DYNAMIC-LOAD",
                    CheckType::PackageSecurity,
                    ScanStatus::Warn,
                )
                .class(FindingClass::ContentIndicator)
                .confidence(Confidence::High)
                .digest(layer_digest)
                .subject(subject.clone())
                .detail(detail)
                .evidence(
                    crate::finding_evidence::FindingEvidence::new(
                        crate::finding_evidence::EvidenceKind::BinaryObject,
                        subject.clone(),
                        "Native binary imports dynamic loader function symbols",
                    )
                    .structured(serde_json::json!({
                        "imported_dynamic_load_symbols": dl_imports,
                        "format": format!("{:?}", metadata.format),
                    })),
                )
                .finish(),
            );
        }

        Ok((Some(metadata), findings))
    }

    pub fn scan_file(
        file: &File,
        file_len: u64,
        layer_digest: &str,
        media_type: &str,
    ) -> Result<LayerScanResult> {
        let mut read_buf = vec![0_u8; CHUNK_BYTES];
        let mut scanner = BinaryStreamScanner::new();
        let mut offset = 0_u64;
        while offset < file_len {
            let count = read_into_at(file, offset, &mut read_buf)?;
            if count == 0 {
                break;
            }
            scanner.observe(file, file_len, &read_buf[..count])?;
            offset = offset.saturating_add(count as u64);
        }
        Ok(scanner.finish(layer_digest, media_type))
    }

    pub fn looks_executable_prefix(prefix: &[u8]) -> bool {
        prefix.starts_with(b"\x7fELF")
            || prefix.starts_with(b"MZ")
            || prefix.starts_with(b"\0asm\x01\0\0\0")
            || MACHO_MAGICS
                .iter()
                .any(|magic| prefix.starts_with(&magic[..]))
    }
}

const MACHO_MAGICS: &[&[u8; 4]] = &[
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
];

fn looks_like_elf_header(bytes: &[u8]) -> bool {
    if bytes.len() < 20 || bytes.get(0..4) != Some(b"\x7fELF") {
        return false;
    }
    matches!(bytes[4], 1 | 2) && matches!(bytes[5], 1 | 2) && bytes[6] == 1
}

fn looks_like_dos_header(bytes: &[u8]) -> bool {
    if bytes.len() < 64 || bytes.get(0..2) != Some(b"MZ") {
        return false;
    }
    let pe_rel = u32::from_le_bytes(bytes[0x3c..0x40].try_into().expect("fixed slice")) as u64;
    (64..=1024 * 1024).contains(&pe_rel)
}

fn find_all<'a>(haystack: &'a [u8], needle: &'a [u8]) -> impl Iterator<Item = usize> + 'a {
    haystack
        .windows(needle.len())
        .enumerate()
        .filter_map(move |(index, window)| (window == needle).then_some(index))
}

pub(crate) fn table_in_bounds(offset: u64, entry_size: u64, count: u64, available: u64) -> bool {
    if count == 0 {
        return offset == 0 || offset <= available;
    }
    if offset == 0 || entry_size == 0 {
        return false;
    }
    entry_size
        .checked_mul(count)
        .and_then(|bytes| offset.checked_add(bytes))
        .is_some_and(|end| end <= available)
}

fn validate_elf(file: &File, file_len: u64, offset: u64) -> Result<bool> {
    elf::parse_elf(file, file_len, offset).map(|res| res.is_some())
}

fn validate_pe(file: &File, file_len: u64, offset: u64) -> Result<bool> {
    pe::parse_pe(file, file_len, offset).map(|res| res.is_some())
}

fn validate_macho(file: &File, file_len: u64, offset: u64) -> Result<bool> {
    macho::parse_macho(file, file_len, offset).map(|res| res.is_some())
}

fn validate_wasm(file: &File, file_len: u64, offset: u64) -> Result<bool> {
    wasm::parse_wasm(file, file_len, offset).map(|res| res.is_some())
}

pub(crate) fn read_at(file: &File, offset: u64, len: usize) -> Result<Option<Vec<u8>>> {
    let mut bytes = vec![0_u8; len];
    let mut read = 0usize;
    while read < len {
        let count = read_into_at(file, offset.saturating_add(read as u64), &mut bytes[read..])?;
        if count == 0 {
            return Ok(None);
        }
        read += count;
    }
    Ok(Some(bytes))
}

#[cfg(unix)]
fn read_into_at(file: &File, offset: u64, bytes: &mut [u8]) -> Result<usize> {
    use std::os::unix::fs::FileExt;
    Ok(file.read_at(bytes, offset)?)
}

#[cfg(windows)]
fn read_into_at(file: &File, offset: u64, bytes: &mut [u8]) -> Result<usize> {
    use std::os::windows::fs::FileExt;
    Ok(file.seek_read(bytes, offset)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn minimal_elf64() -> Vec<u8> {
        let mut bytes = vec![0_u8; 128];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
        bytes[40..48].copy_from_slice(&64_u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        bytes[58..60].copy_from_slice(&64_u16.to_le_bytes());
        bytes[60..62].copy_from_slice(&1_u16.to_le_bytes());
        bytes
    }

    fn minimal_pe64() -> Vec<u8> {
        let mut bytes = vec![0_u8; 272];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&64_u32.to_le_bytes());
        let pe = 64_usize;
        bytes[pe..pe + 4].copy_from_slice(b"PE\0\0");
        bytes[pe + 4..pe + 6].copy_from_slice(&0x8664_u16.to_le_bytes());
        bytes[pe + 6..pe + 8].copy_from_slice(&1_u16.to_le_bytes());
        bytes[pe + 20..pe + 22].copy_from_slice(&112_u16.to_le_bytes());
        bytes[pe + 24..pe + 26].copy_from_slice(&0x020b_u16.to_le_bytes());
        let section = pe + 24 + 112;
        bytes[section + 16..section + 20].copy_from_slice(&16_u32.to_le_bytes());
        bytes[section + 20..section + 24].copy_from_slice(&256_u32.to_le_bytes());
        bytes
    }

    fn minimal_macho64() -> Vec<u8> {
        // Mach-O 64-bit header (32 bytes) + one valid LC_SEGMENT_64 (72-byte
        // header + 80-byte section) with one real section. A segment with
        // zero sections is not treated as substantive evidence (see
        // `has_substantive_command` in macho.rs), so a genuine positive
        // fixture needs an actual declared section.
        let header_size = 32u32;
        let seg_header_size = 72u32;
        let sect_size = 80u32;
        let seg_size = seg_header_size + sect_size;
        let cmd_size = header_size + seg_size;
        let mut bytes = vec![0_u8; cmd_size as usize];
        bytes[0..4].copy_from_slice(b"\xcf\xfa\xed\xfe");
        bytes[4..8].copy_from_slice(&0x01000007_u32.to_le_bytes());
        bytes[8..12].copy_from_slice(&3_u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&2_u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&1_u32.to_le_bytes()); // ncmds = 1
        bytes[20..24].copy_from_slice(&seg_size.to_le_bytes()); // sizeofcmds
                                                                // LC_SEGMENT_64 at offset 32
        let seg = header_size as usize;
        bytes[seg..seg + 4].copy_from_slice(&0x19_u32.to_le_bytes()); // cmd = LC_SEGMENT_64
        bytes[seg + 4..seg + 8].copy_from_slice(&seg_size.to_le_bytes()); // cmdsize
                                                                          // segname[16] = all zeros (OK)
                                                                          // vmaddr = 0, vmsize = 0, fileoff = 0, filesize = 0
                                                                          // initprot = 3, maxprot = 7, nsects = 1, flags = 0
        bytes[seg + 56..seg + 60].copy_from_slice(&3u32.to_le_bytes()); // initprot
        bytes[seg + 60..seg + 64].copy_from_slice(&7u32.to_le_bytes()); // maxprot
        bytes[seg + 64..seg + 68].copy_from_slice(&1u32.to_le_bytes()); // nsects = 1
                                                                        // One 64-bit section struct immediately after the segment header.
        let sect = seg + seg_header_size as usize;
        bytes[sect..sect + 4].copy_from_slice(b"__text\0\0"[..4].as_ref()); // sectname prefix
        bytes[sect + 40..sect + 48].copy_from_slice(&64u64.to_le_bytes()); // size = 64
        bytes
    }

    fn scan_fixture(label: &str, bytes: &[u8]) -> Result<LayerScanResult> {
        let path =
            std::env::temp_dir().join(format!("layerfault-binary-{label}-{}", std::process::id()));
        fs::write(&path, bytes)?;
        let file = File::open(&path)?;
        let result =
            BinaryScanner::scan_file(&file, file.metadata()?.len(), "sha256:test", "model")?;
        let _ = fs::remove_file(path);
        Ok(result)
    }

    #[test]
    fn structurally_valid_elf_is_detected() -> Result<()> {
        let result = scan_fixture("elf", &minimal_elf64())?;
        assert_eq!(result.status, ScanStatus::Fail);
        assert!(result.matches.iter().any(|m| m.contains("T12-001")));
        assert_eq!(crate::policy::rule_id(&result), "T12-001");
        let record = result.evidence.first().expect("binary evidence");
        assert_eq!(
            record.kind,
            crate::finding_evidence::EvidenceKind::BinaryObject
        );
        assert!(matches!(
            record.location,
            Some(crate::finding_evidence::EvidenceLocation::ByteRange { offset: 0, .. })
        ));
        assert_eq!(
            record
                .structured
                .as_ref()
                .and_then(|v| v["format"].as_str()),
            Some("ELF")
        );
        assert_eq!(
            result.evidence_state,
            Some(crate::finding_evidence::EvidenceState::Available)
        );
        Ok(())
    }

    #[test]
    fn structurally_valid_pe_is_detected() -> Result<()> {
        let result = scan_fixture("pe", &minimal_pe64())?;
        assert_eq!(result.status, ScanStatus::Fail);
        assert!(result.matches.iter().any(|m| m.contains("T12-002")));
        Ok(())
    }

    #[test]
    fn pe_mz_alone_plus_garbage_is_not_detected() -> Result<()> {
        let mut bytes = vec![0_u8; 128];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[2..].copy_from_slice(&[0x41_u8; 126]);
        let result = scan_fixture("pe-mz-only", &bytes)?;
        assert_eq!(result.status, ScanStatus::Pass);
        Ok(())
    }

    #[test]
    fn pe_truncated_dos_header_is_not_detected() -> Result<()> {
        // Fewer than the 64 bytes needed to read e_lfanew.
        let mut bytes = vec![0_u8; 40];
        bytes[0..2].copy_from_slice(b"MZ");
        let result = scan_fixture("pe-truncated-dos", &bytes)?;
        assert_eq!(result.status, ScanStatus::Pass);
        Ok(())
    }

    #[test]
    fn pe_e_lfanew_outside_data_is_not_detected() -> Result<()> {
        let mut bytes = minimal_pe64();
        // Point e_lfanew far outside the 1 MiB sanity bound.
        bytes[0x3c..0x40].copy_from_slice(&0xffff_ffff_u32.to_le_bytes());
        let result = scan_fixture("pe-bad-lfanew", &bytes)?;
        assert_eq!(result.status, ScanStatus::Pass);
        Ok(())
    }

    #[test]
    fn pe_missing_signature_is_not_detected() -> Result<()> {
        let mut bytes = minimal_pe64();
        bytes[64..68].copy_from_slice(b"XXXX");
        let result = scan_fixture("pe-bad-sig", &bytes)?;
        assert_eq!(result.status, ScanStatus::Pass);
        Ok(())
    }

    #[test]
    fn pe_truncated_coff_header_is_not_detected() -> Result<()> {
        // Cut the file off right after the PE signature, before the
        // 24-byte COFF header can be fully read.
        let full = minimal_pe64();
        let bytes = full[..70].to_vec();
        let result = scan_fixture("pe-truncated-coff", &bytes)?;
        assert_eq!(result.status, ScanStatus::Pass);
        Ok(())
    }

    #[test]
    fn pe_impossible_section_count_is_not_detected() -> Result<()> {
        let mut bytes = minimal_pe64();
        let pe = 64_usize;
        // num_sections must be within 1..=96.
        bytes[pe + 6..pe + 8].copy_from_slice(&0_u16.to_le_bytes());
        let result = scan_fixture("pe-zero-sections", &bytes)?;
        assert_eq!(result.status, ScanStatus::Pass);
        Ok(())
    }

    #[test]
    fn pe_optional_header_bad_magic_is_not_detected() -> Result<()> {
        let mut bytes = minimal_pe64();
        let pe = 64_usize;
        bytes[pe + 24..pe + 26].copy_from_slice(&0x1234_u16.to_le_bytes());
        let result = scan_fixture("pe-bad-optional-magic", &bytes)?;
        assert_eq!(result.status, ScanStatus::Pass);
        Ok(())
    }

    #[test]
    fn structurally_valid_macho_is_detected() -> Result<()> {
        let result = scan_fixture("macho", &minimal_macho64())?;
        assert_eq!(result.status, ScanStatus::Fail);
        assert!(result.matches.iter().any(|m| m.contains("T12-003")));
        Ok(())
    }

    #[test]
    fn macho_segment_with_zero_sections_is_not_detected() -> Result<()> {
        // Regression: a lone LC_SEGMENT_64 that declares zero sections (or
        // claims sections it doesn't actually back with in-bounds section
        // data) is not, by itself, substantive evidence of a genuine
        // embedded Mach-O object — the same weak "one plausible header,
        // nothing corroborating it" shape a coincidental magic-byte
        // collision in a large binary weight file can produce.
        let mut bytes = minimal_macho64();
        // nsects lives at seg(32) + 64..68 in the 64-bit segment header.
        bytes[32 + 64..32 + 68].copy_from_slice(&0u32.to_le_bytes());
        let result = scan_fixture("macho-zero-sections", &bytes)?;
        assert_eq!(
            result.status,
            ScanStatus::Pass,
            "a segment with zero sections must not be substantive evidence on its own"
        );
        Ok(())
    }

    #[test]
    fn macho_magic_alone_is_not_detected() -> Result<()> {
        let bytes = b"\xcf\xfa\xed\xfe".to_vec();
        let result = scan_fixture("macho-magic-only", &bytes)?;
        assert_eq!(result.status, ScanStatus::Pass);
        Ok(())
    }

    #[test]
    fn macho_truncated_header_is_not_detected() -> Result<()> {
        // Fewer than the 32 bytes needed for a 64-bit Mach-O header.
        let mut bytes = vec![0_u8; 20];
        bytes[0..4].copy_from_slice(b"\xcf\xfa\xed\xfe");
        let result = scan_fixture("macho-truncated-header", &bytes)?;
        assert_eq!(result.status, ScanStatus::Pass);
        Ok(())
    }

    #[test]
    fn macho_impossible_sizeofcmds_is_not_detected() -> Result<()> {
        let mut bytes = minimal_macho64();
        // ncmds says 1 command but sizeofcmds claims far more data than the
        // file actually has after the header.
        bytes[20..24].copy_from_slice(&1_000_000_u32.to_le_bytes());
        let result = scan_fixture("macho-impossible-sizeofcmds", &bytes)?;
        assert_eq!(result.status, ScanStatus::Pass);
        Ok(())
    }

    #[test]
    fn macho_cmdsize_smaller_than_command_header_is_not_detected() -> Result<()> {
        let mut bytes = minimal_macho64();
        // cmdsize (bytes 4..8 of the load command at offset 32) below the
        // 8-byte minimum load-command header.
        bytes[32 + 4..32 + 8].copy_from_slice(&4_u32.to_le_bytes());
        let result = scan_fixture("macho-cmdsize-too-small", &bytes)?;
        assert_eq!(result.status, ScanStatus::Pass);
        Ok(())
    }

    #[test]
    fn macho_command_beyond_eof_is_not_detected() -> Result<()> {
        let mut bytes = minimal_macho64();
        // sizeofcmds still claims the full 72 bytes, but the command's own
        // cmdsize now runs past the declared load-command region.
        bytes[32 + 4..32 + 8].copy_from_slice(&1000_u32.to_le_bytes());
        let result = scan_fixture("macho-command-beyond-eof", &bytes)?;
        assert_eq!(result.status, ScanStatus::Pass);
        Ok(())
    }

    fn fat_wrapping(thin: &[u8]) -> Vec<u8> {
        // Big-endian FAT header (magic 0xcafebabe) with one 32-bit fat_arch
        // entry pointing at `thin`, laid out immediately after the table.
        let table_start = 8_u32;
        let entry_size = 20_u32;
        let arch_offset = table_start + entry_size;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"\xca\xfe\xba\xbe");
        bytes.extend_from_slice(&1_u32.to_be_bytes()); // nfat_arch
        bytes.extend_from_slice(&0x0100_0007_u32.to_be_bytes()); // cputype x86_64
        bytes.extend_from_slice(&3_u32.to_be_bytes()); // cpusubtype
        bytes.extend_from_slice(&arch_offset.to_be_bytes()); // offset
        bytes.extend_from_slice(&(thin.len() as u32).to_be_bytes()); // size
        bytes.extend_from_slice(&0_u32.to_be_bytes()); // align
        bytes.extend_from_slice(thin);
        bytes
    }

    #[test]
    fn structurally_valid_fat_macho_is_detected() -> Result<()> {
        let bytes = fat_wrapping(&minimal_macho64());
        let result = scan_fixture("macho-fat", &bytes)?;
        assert_eq!(result.status, ScanStatus::Fail);
        assert!(result.matches.iter().any(|m| m.contains("T12-003")));
        Ok(())
    }

    fn minimal_wasm_with_section() -> Vec<u8> {
        // Magic + version + a Type section (ID=1, one `() -> ()` function
        // type) + a Function section (ID=3, declaring one function of that
        // type). Two validly-ordered, non-empty non-custom sections is
        // substantive structural evidence, unlike a single bare/empty
        // section.
        let mut bytes = b"\0asm\x01\0\0\0".to_vec();
        bytes.push(1u8); // section ID = 1 (Type)
        bytes.push(4u8); // payload length = 4
        bytes.push(1u8); // type count = 1
        bytes.extend_from_slice(&[0x60, 0x00, 0x00]); // func type, 0 params, 0 results
        bytes.push(3u8); // section ID = 3 (Function)
        bytes.push(2u8); // payload length = 2
        bytes.push(1u8); // function count = 1
        bytes.push(0u8); // type index 0
        bytes
    }

    #[test]
    fn wasm_header_is_detected() -> Result<()> {
        let result = scan_fixture("wasm", &minimal_wasm_with_section())?;
        assert_eq!(result.status, ScanStatus::Fail);
        assert!(result.matches.iter().any(|m| m.contains("T12-004")));
        Ok(())
    }

    #[test]
    fn wasm_magic_alone_is_not_detected() -> Result<()> {
        // Bare magic + version bytes with no sections should be rejected.
        let result = scan_fixture("wasm-bare", b"\0asm\x01\0\0\0")?;
        assert_eq!(result.status, ScanStatus::Pass);
        Ok(())
    }

    #[test]
    fn wasm_only_custom_sections_are_not_detected() -> Result<()> {
        // A WASM with only custom sections (ID=0) should be rejected.
        let mut bytes = b"\0asm\x01\0\0\0".to_vec();
        // Custom section (ID=0) with name "name" + 0 extra payload
        bytes.push(0u8); // section ID = 0 (Custom)
        bytes.push(6u8); // payload length = 6
        bytes.push(4u8); // name length = 4
        bytes.extend_from_slice(b"name"); // name = "name"
        bytes.push(0u8); // no extra data
        let result = scan_fixture("wasm-custom", &bytes)?;
        assert_eq!(result.status, ScanStatus::Pass);
        Ok(())
    }

    #[test]
    fn wasm_section_payload_beyond_eof_is_not_detected() -> Result<()> {
        let mut bytes = b"\0asm\x01\0\0\0".to_vec();
        bytes.push(1u8); // section ID = 1 (Type)
        bytes.push(200u8); // payload length claims 200 bytes; file has none
        let result = scan_fixture("wasm-section-oob", &bytes)?;
        assert_eq!(result.status, ScanStatus::Pass);
        Ok(())
    }

    #[test]
    fn wasm_malformed_leb128_section_size_is_not_detected() -> Result<()> {
        let mut bytes = b"\0asm\x01\0\0\0".to_vec();
        bytes.push(1u8); // section ID = 1 (Type)
                         // Five continuation bytes with no terminator: an unterminated
                         // LEB128 varint.
        bytes.extend_from_slice(&[0x80, 0x80, 0x80, 0x80, 0x80]);
        let result = scan_fixture("wasm-bad-leb128", &bytes)?;
        assert_eq!(result.status, ScanStatus::Pass);
        Ok(())
    }

    #[test]
    fn wasm_magic_inside_junk_without_a_complete_module_is_not_detected() -> Result<()> {
        let mut bytes = b"random prefix bytes ".to_vec();
        bytes.extend_from_slice(b"\0asm\x01\0\0\0");
        bytes.extend_from_slice(
            b"more junk after magic that is not a valid section stream \xff\xff",
        );
        let result = scan_fixture("wasm-embedded-magic", &bytes)?;
        assert_eq!(result.status, ScanStatus::Pass);
        Ok(())
    }

    #[test]
    fn short_magic_coincidences_are_not_failures() -> Result<()> {
        let result = scan_fixture("false", b"noise\x7fELFnoiseMZ\x90\x00")?;
        assert_eq!(result.status, ScanStatus::Pass);
        Ok(())
    }

    #[test]
    fn wasm_single_isolated_empty_section_deep_in_a_large_buffer_is_not_detected() -> Result<()> {
        // Regression: a magic-byte collision followed by exactly one
        // structurally-parseable-but-empty section (a Type section
        // declaring zero function types) must not be enough for a strong
        // positive, even though it satisfies "at least one non-custom
        // section parsed without error". This is the realistic shape of a
        // coincidental match deep inside a large binary weight file: one
        // isolated section, no imports/exports/code, nothing corroborating
        // it as a genuine embedded module.
        let mut bytes = vec![0_u8; 4096];
        let offset = 2048;
        bytes[offset..offset + 8].copy_from_slice(b"\0asm\x01\0\0\0");
        bytes[offset + 8] = 1u8; // section ID = 1 (Type)
        bytes[offset + 9] = 1u8; // payload length = 1
        bytes[offset + 10] = 0u8; // type count = 0
        let result = scan_fixture("wasm-isolated-empty-section", &bytes)?;
        assert_eq!(
            result.status,
            ScanStatus::Pass,
            "a single empty section must not be substantive evidence of an embedded module"
        );
        Ok(())
    }

    #[test]
    fn wasm_two_validly_ordered_nonempty_sections_are_substantive() -> Result<()> {
        // The positive counterpart: two real, correctly-ordered sections
        // (not just one) is enough structural corroboration.
        let result = scan_fixture("wasm-two-sections", &minimal_wasm_with_section())?;
        assert_eq!(result.status, ScanStatus::Fail);
        assert!(result.matches.iter().any(|m| m.contains("T12-004")));
        Ok(())
    }

    #[test]
    fn wasm_out_of_order_non_custom_sections_are_not_detected() -> Result<()> {
        // Real WASM modules always emit non-custom sections in strictly
        // increasing id order. A Function section (3) before a Type
        // section (1) cannot occur in a genuine module, so this stream is
        // rejected as malformed rather than treated as two corroborating
        // sections.
        let mut bytes = b"\0asm\x01\0\0\0".to_vec();
        bytes.push(3u8); // section ID = 3 (Function) — out of order first
        bytes.push(2u8);
        bytes.push(1u8);
        bytes.push(0u8);
        bytes.push(1u8); // section ID = 1 (Type) — decreasing, invalid order
        bytes.push(4u8);
        bytes.push(1u8);
        bytes.extend_from_slice(&[0x60, 0x00, 0x00]);
        let result = scan_fixture("wasm-out-of-order-sections", &bytes)?;
        assert_eq!(result.status, ScanStatus::Pass);
        Ok(())
    }

    #[test]
    fn wasm_unknown_section_id_is_not_detected() -> Result<()> {
        // Section ids above 11 do not exist in the core WASM binary format;
        // treating one as valid structural evidence would make random
        // bytes far too easy to satisfy.
        let mut bytes = b"\0asm\x01\0\0\0".to_vec();
        bytes.push(200u8); // not a valid WASM section id
        bytes.push(1u8);
        bytes.push(0u8);
        let result = scan_fixture("wasm-unknown-section-id", &bytes)?;
        assert_eq!(result.status, ScanStatus::Pass);
        Ok(())
    }
}
