use crate::scanner::{
    duration_ms, CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus,
};
use anyhow::Result;
use std::collections::BTreeSet;
use std::fs::File;
use std::time::Instant;

const CHUNK_BYTES: usize = 1024 * 1024;
const OVERLAP_BYTES: usize = 512;
const MAX_FINDINGS: usize = 8;
const MAX_MACHO_COMMAND_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FAT_ARCHES: u64 = 64;

pub struct BinaryScanner;

/// Incremental executable-object detector used by both the standalone binary
/// scan and the integrity hash pass. Structural validation always reads from
/// the already-open descriptor; chunks are only used to discover candidates.
pub(crate) struct BinaryStreamScanner {
    carry: Vec<u8>,
    absolute_read: u64,
    findings: Vec<String>,
    seen: BTreeSet<(u8, u64)>,
    started: Instant,
}

impl BinaryStreamScanner {
    pub(crate) fn new() -> Self {
        Self {
            carry: Vec::new(),
            absolute_read: 0,
            findings: Vec::new(),
            seen: BTreeSet::new(),
            started: Instant::now(),
        }
    }

    pub(crate) fn observe(&mut self, file: &File, file_len: u64, bytes: &[u8]) -> Result<()> {
        if bytes.is_empty() || self.findings.len() >= MAX_FINDINGS {
            self.absolute_read = self.absolute_read.saturating_add(bytes.len() as u64);
            return Ok(());
        }

        let chunk_start = self.absolute_read;
        self.absolute_read = self.absolute_read.saturating_add(bytes.len() as u64);
        let mut window = Vec::with_capacity(self.carry.len() + bytes.len());
        window.extend_from_slice(&self.carry);
        window.extend_from_slice(bytes);
        let window_start = chunk_start.saturating_sub(self.carry.len() as u64);

        // Scan four-byte object magics in one pass. The earlier ELF-only scanner
        // already had to touch every byte; folding Mach-O and WASM into the same
        // walk avoids eight extra full-buffer passes for the Mach-O variants.
        for (offset, magic) in window.windows(4).enumerate() {
            if self.findings.len() >= MAX_FINDINGS {
                break;
            }
            let absolute = window_start.saturating_add(offset as u64);
            if magic == b"\x7fELF" {
                if looks_like_elf_header(&window[offset..])
                    && validate_elf(file, file_len, absolute)?
                {
                    self.push(
                        1,
                        absolute,
                        format!(
                            "[T12-001] Structurally valid embedded ELF object at file offset 0x{absolute:x}"
                        ),
                    );
                }
                continue;
            }
            if magic == b"\0asm" {
                if validate_wasm(file, file_len, absolute)? {
                    self.push(
                        4,
                        absolute,
                        format!(
                            "[T12-004] Structurally valid WebAssembly module header at file offset 0x{absolute:x}"
                        ),
                    );
                }
                continue;
            }
            let maybe_macho = matches!(magic[0], 0xfe | 0xce | 0xca | 0xbe | 0xbf | 0xcf)
                && MACHO_MAGICS.iter().any(|candidate| magic == *candidate);
            if maybe_macho && validate_macho(file, file_len, absolute)? {
                self.push(
                    3,
                    absolute,
                    format!(
                        "[T12-003] Structurally valid embedded Mach-O object at file offset 0x{absolute:x}"
                    ),
                );
            }
        }

        if self.findings.len() < MAX_FINDINGS {
            for offset in find_all(&window, b"MZ") {
                if self.findings.len() >= MAX_FINDINGS {
                    break;
                }
                if !looks_like_dos_header(&window[offset..]) {
                    continue;
                }
                let absolute = window_start.saturating_add(offset as u64);
                if validate_pe(file, file_len, absolute)? {
                    self.push(
                        2,
                        absolute,
                        format!(
                            "[T12-002] Structurally valid embedded PE object at file offset 0x{absolute:x}"
                        ),
                    );
                }
            }
        }

        let keep = window.len().min(OVERLAP_BYTES);
        self.carry.clear();
        self.carry.extend_from_slice(&window[window.len() - keep..]);
        Ok(())
    }

    fn push(&mut self, kind: u8, offset: u64, finding: String) {
        if self.seen.insert((kind, offset)) && self.findings.len() < MAX_FINDINGS {
            self.findings.push(finding);
        }
    }

    pub(crate) fn finish(self, layer_digest: &str, media_type: &str) -> LayerScanResult {
        let (status, detail) = if self.findings.is_empty() {
            (ScanStatus::Pass, None)
        } else {
            (
                ScanStatus::Fail,
                Some(format!(
                    "{} structurally plausible embedded executable/module object(s) detected",
                    self.findings.len()
                )),
            )
        };
        LayerScanResult {
            layer_digest: layer_digest.to_owned(),
            media_type: media_type.to_owned(),
            check_type: CheckType::BinarySteganography,
            status,
            finding_class: FindingClass::ContentIndicator,
            confidence: Confidence::High,
            detail,
            matches: self.findings,
            duration_ms: duration_ms(self.started),
        }
    }
}

impl BinaryScanner {
    /// Search for complete, structurally plausible ELF/PE/Mach-O/WASM objects
    /// rather than treating short magic-byte coincidences as executable evidence.
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

    /// Cheap package gate for renamed standalone executables. Full structural
    /// validation still happens in `scan_file` before a finding is emitted.
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
    b"\xfe\xed\xfa\xce", // MH_MAGIC
    b"\xce\xfa\xed\xfe", // MH_CIGAM
    b"\xfe\xed\xfa\xcf", // MH_MAGIC_64
    b"\xcf\xfa\xed\xfe", // MH_CIGAM_64
    b"\xca\xfe\xba\xbe", // FAT_MAGIC
    b"\xbe\xba\xfe\xca", // FAT_CIGAM
    b"\xca\xfe\xba\xbf", // FAT_MAGIC_64
    b"\xbf\xba\xfe\xca", // FAT_CIGAM_64
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

fn validate_elf(file: &File, file_len: u64, offset: u64) -> Result<bool> {
    let header = match read_at(file, offset, 64)? {
        Some(header) => header,
        None => return Ok(false),
    };
    if header.get(0..4) != Some(b"\x7fELF") {
        return Ok(false);
    }

    let class = header[4];
    let endian = header[5];
    if !matches!(class, 1 | 2) || !matches!(endian, 1 | 2) || header[6] != 1 {
        return Ok(false);
    }

    let is_le = endian == 1;
    let object_type = read_u16(&header[16..18], is_le);
    let machine = read_u16(&header[18..20], is_le);
    if !(1..=4).contains(&object_type) || machine == 0 {
        return Ok(false);
    }

    let remaining = file_len.saturating_sub(offset);
    if class == 1 {
        let ehsize = read_u16(&header[40..42], is_le) as u64;
        let phoff = read_u32(&header[28..32], is_le) as u64;
        let shoff = read_u32(&header[32..36], is_le) as u64;
        let phentsize = read_u16(&header[42..44], is_le) as u64;
        let phnum = read_u16(&header[44..46], is_le) as u64;
        let shentsize = read_u16(&header[46..48], is_le) as u64;
        let shnum = read_u16(&header[48..50], is_le) as u64;
        if ehsize != 52 {
            return Ok(false);
        }
        Ok(table_in_bounds(phoff, phentsize, phnum, remaining)
            && table_in_bounds(shoff, shentsize, shnum, remaining)
            && (phnum > 0 || shnum > 0))
    } else {
        let ehsize = read_u16(&header[52..54], is_le) as u64;
        let phoff = read_u64(&header[32..40], is_le);
        let shoff = read_u64(&header[40..48], is_le);
        let phentsize = read_u16(&header[54..56], is_le) as u64;
        let phnum = read_u16(&header[56..58], is_le) as u64;
        let shentsize = read_u16(&header[58..60], is_le) as u64;
        let shnum = read_u16(&header[60..62], is_le) as u64;
        if ehsize != 64 {
            return Ok(false);
        }
        Ok(table_in_bounds(phoff, phentsize, phnum, remaining)
            && table_in_bounds(shoff, shentsize, shnum, remaining)
            && (phnum > 0 || shnum > 0))
    }
}

fn table_in_bounds(offset: u64, entry_size: u64, count: u64, available: u64) -> bool {
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

fn validate_pe(file: &File, file_len: u64, offset: u64) -> Result<bool> {
    let dos = match read_at(file, offset, 64)? {
        Some(bytes) => bytes,
        None => return Ok(false),
    };
    if dos.get(0..2) != Some(b"MZ") {
        return Ok(false);
    }

    let pe_rel = u32::from_le_bytes(dos[0x3c..0x40].try_into().expect("fixed slice")) as u64;
    if !(64..=1024 * 1024).contains(&pe_rel) {
        return Ok(false);
    }
    let pe_offset = match offset.checked_add(pe_rel) {
        Some(value) => value,
        None => return Ok(false),
    };
    let coff = match read_at(file, pe_offset, 24)? {
        Some(bytes) => bytes,
        None => return Ok(false),
    };
    if coff.get(0..4) != Some(b"PE\0\0") {
        return Ok(false);
    }

    let machine = u16::from_le_bytes(coff[4..6].try_into().expect("fixed slice"));
    let sections = u16::from_le_bytes(coff[6..8].try_into().expect("fixed slice")) as u64;
    let optional_size = u16::from_le_bytes(coff[20..22].try_into().expect("fixed slice")) as u64;
    if !matches!(machine, 0x014c | 0x8664 | 0x01c0 | 0x01c4 | 0xaa64)
        || !(1..=96).contains(&sections)
        || optional_size > 4096
    {
        return Ok(false);
    }
    if optional_size == 0 {
        return Ok(false);
    }
    let optional = match read_at(file, pe_offset + 24, 2)? {
        Some(bytes) => bytes,
        None => return Ok(false),
    };
    let magic = u16::from_le_bytes(optional[..2].try_into().expect("fixed slice"));
    let min_optional_size = match magic {
        0x010b => 96_u64,
        0x020b => 112_u64,
        _ => return Ok(false),
    };
    if optional_size < min_optional_size {
        return Ok(false);
    }

    let section_table = match pe_offset
        .checked_add(24)
        .and_then(|value| value.checked_add(optional_size))
    {
        Some(value) => value,
        None => return Ok(false),
    };
    let table_size = match sections.checked_mul(40) {
        Some(value) => value,
        None => return Ok(false),
    };
    let section_table_end = match section_table.checked_add(table_size) {
        Some(value) if value <= file_len => value,
        _ => return Ok(false),
    };
    let table = match read_at(
        file,
        section_table,
        usize::try_from(table_size).unwrap_or(usize::MAX),
    )? {
        Some(bytes) => bytes,
        None => return Ok(false),
    };
    let mut bounded_section = false;
    for section in table.chunks_exact(40) {
        let raw_size = u32::from_le_bytes(section[16..20].try_into().expect("fixed slice")) as u64;
        let raw_offset =
            u32::from_le_bytes(section[20..24].try_into().expect("fixed slice")) as u64;
        if raw_size == 0 {
            continue;
        }
        let raw_end = match raw_offset.checked_add(raw_size) {
            Some(value) => value,
            None => return Ok(false),
        };
        let absolute_raw_end = match offset.checked_add(raw_end) {
            Some(value) => value,
            None => return Ok(false),
        };
        if absolute_raw_end > file_len {
            return Ok(false);
        }
        bounded_section = true;
    }
    Ok(bounded_section && section_table_end <= file_len)
}

fn validate_macho(file: &File, file_len: u64, offset: u64) -> Result<bool> {
    let magic = match read_at(file, offset, 4)? {
        Some(bytes) => bytes,
        None => return Ok(false),
    };
    match magic.as_slice() {
        b"\xfe\xed\xfa\xce" => validate_macho_thin(file, file_len, offset, false, false),
        b"\xce\xfa\xed\xfe" => validate_macho_thin(file, file_len, offset, true, false),
        b"\xfe\xed\xfa\xcf" => validate_macho_thin(file, file_len, offset, false, true),
        b"\xcf\xfa\xed\xfe" => validate_macho_thin(file, file_len, offset, true, true),
        b"\xca\xfe\xba\xbe" => validate_macho_fat(file, file_len, offset, false, false),
        b"\xbe\xba\xfe\xca" => validate_macho_fat(file, file_len, offset, true, false),
        b"\xca\xfe\xba\xbf" => validate_macho_fat(file, file_len, offset, false, true),
        b"\xbf\xba\xfe\xca" => validate_macho_fat(file, file_len, offset, true, true),
        _ => Ok(false),
    }
}

fn validate_macho_thin(
    file: &File,
    file_len: u64,
    offset: u64,
    little: bool,
    is_64: bool,
) -> Result<bool> {
    let header_size = if is_64 { 32 } else { 28 };
    let header = match read_at(file, offset, header_size)? {
        Some(bytes) => bytes,
        None => return Ok(false),
    };
    let cpu_type = read_u32(&header[4..8], little);
    let file_type = read_u32(&header[12..16], little);
    let ncmds = read_u32(&header[16..20], little) as u64;
    let sizeofcmds = read_u32(&header[20..24], little) as u64;
    if cpu_type == 0
        || !(1..=12).contains(&file_type)
        || ncmds == 0
        || ncmds > 65_535
        || sizeofcmds < ncmds.saturating_mul(8)
        || sizeofcmds > MAX_MACHO_COMMAND_BYTES
    {
        return Ok(false);
    }
    let commands_start = match offset.checked_add(header_size as u64) {
        Some(value) => value,
        None => return Ok(false),
    };
    let commands_end = match commands_start.checked_add(sizeofcmds) {
        Some(value) if value <= file_len => value,
        _ => return Ok(false),
    };
    let mut cursor = commands_start;
    for _ in 0..ncmds {
        let command = match read_at(file, cursor, 8)? {
            Some(bytes) => bytes,
            None => return Ok(false),
        };
        let cmd = read_u32(&command[0..4], little);
        let cmdsize = read_u32(&command[4..8], little) as u64;
        if cmd == 0 || cmdsize < 8 || !cmdsize.is_multiple_of(4) {
            return Ok(false);
        }
        cursor = match cursor.checked_add(cmdsize) {
            Some(value) if value <= commands_end => value,
            _ => return Ok(false),
        };
    }
    Ok(cursor == commands_end)
}

fn validate_macho_fat(
    file: &File,
    file_len: u64,
    offset: u64,
    little: bool,
    is_64: bool,
) -> Result<bool> {
    let header = match read_at(file, offset, 8)? {
        Some(bytes) => bytes,
        None => return Ok(false),
    };
    let arches = read_u32(&header[4..8], little) as u64;
    if arches == 0 || arches > MAX_FAT_ARCHES {
        return Ok(false);
    }
    let entry_size = if is_64 { 32_u64 } else { 20_u64 };
    let table_size = match arches.checked_mul(entry_size) {
        Some(value) => value,
        None => return Ok(false),
    };
    let table_start = match offset.checked_add(8) {
        Some(value) => value,
        None => return Ok(false),
    };
    let table_end = match table_start.checked_add(table_size) {
        Some(value) if value <= file_len => value,
        _ => return Ok(false),
    };
    let table = match read_at(file, table_start, table_size as usize)? {
        Some(bytes) => bytes,
        None => return Ok(false),
    };
    let mut valid_arch = false;
    for entry in table.chunks_exact(entry_size as usize) {
        let cpu_type = read_u32(&entry[0..4], little);
        if cpu_type == 0 {
            return Ok(false);
        }
        let (relative_offset, size) = if is_64 {
            (
                read_u64(&entry[8..16], little),
                read_u64(&entry[16..24], little),
            )
        } else {
            (
                read_u32(&entry[8..12], little) as u64,
                read_u32(&entry[12..16], little) as u64,
            )
        };
        if size == 0 {
            return Ok(false);
        }
        let arch_start = match offset.checked_add(relative_offset) {
            Some(value) if value >= table_end => value,
            _ => return Ok(false),
        };
        let arch_end = match arch_start.checked_add(size) {
            Some(value) if value <= file_len => value,
            _ => return Ok(false),
        };
        if arch_end <= arch_start {
            return Ok(false);
        }
        if !valid_arch {
            let magic = read_at(file, arch_start, 4)?.unwrap_or_default();
            valid_arch = matches!(
                magic.as_slice(),
                b"\xfe\xed\xfa\xce"
                    | b"\xce\xfa\xed\xfe"
                    | b"\xfe\xed\xfa\xcf"
                    | b"\xcf\xfa\xed\xfe"
            );
        }
    }
    Ok(valid_arch)
}

fn validate_wasm(file: &File, file_len: u64, offset: u64) -> Result<bool> {
    let header = match read_at(file, offset, 8)? {
        Some(bytes) => bytes,
        None => return Ok(false),
    };
    Ok(header == b"\0asm\x01\0\0\0" && offset.saturating_add(8) <= file_len)
}

fn read_at(file: &File, offset: u64, len: usize) -> Result<Option<Vec<u8>>> {
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

#[cfg(not(any(unix, windows)))]
compile_error!("Layerfault binary scanning requires positional file reads on this platform");

fn read_u16(bytes: &[u8], little: bool) -> u16 {
    let bytes: [u8; 2] = bytes.try_into().expect("two bytes");
    if little {
        u16::from_le_bytes(bytes)
    } else {
        u16::from_be_bytes(bytes)
    }
}

fn read_u32(bytes: &[u8], little: bool) -> u32 {
    let bytes: [u8; 4] = bytes.try_into().expect("four bytes");
    if little {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    }
}

fn read_u64(bytes: &[u8], little: bool) -> u64 {
    let bytes: [u8; 8] = bytes.try_into().expect("eight bytes");
    if little {
        u64::from_le_bytes(bytes)
    } else {
        u64::from_be_bytes(bytes)
    }
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
