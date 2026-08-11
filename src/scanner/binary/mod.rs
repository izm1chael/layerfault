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
        let mut bytes = vec![0_u8; 40];
        bytes[0..4].copy_from_slice(b"\xcf\xfa\xed\xfe");
        bytes[4..8].copy_from_slice(&0x01000007_u32.to_le_bytes());
        bytes[8..12].copy_from_slice(&3_u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&2_u32.to_le_bytes());
        bytes[16..20].copy_from_slice(&1_u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&8_u32.to_le_bytes());
        bytes[32..36].copy_from_slice(&1_u32.to_le_bytes());
        bytes[36..40].copy_from_slice(&8_u32.to_le_bytes());
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
    fn structurally_valid_macho_is_detected() -> Result<()> {
        let result = scan_fixture("macho", &minimal_macho64())?;
        assert_eq!(result.status, ScanStatus::Fail);
        assert!(result.matches.iter().any(|m| m.contains("T12-003")));
        Ok(())
    }

    #[test]
    fn wasm_header_is_detected() -> Result<()> {
        let result = scan_fixture("wasm", b"\0asm\x01\0\0\0")?;
        assert_eq!(result.status, ScanStatus::Fail);
        assert!(result.matches.iter().any(|m| m.contains("T12-004")));
        Ok(())
    }

    #[test]
    fn short_magic_coincidences_are_not_failures() -> Result<()> {
        let result = scan_fixture("false", b"noise\x7fELFnoiseMZ\x90\x00")?;
        assert_eq!(result.status, ScanStatus::Pass);
        Ok(())
    }
}
