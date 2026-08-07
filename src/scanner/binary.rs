use crate::scanner::{
    duration_ms, CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus,
};
use anyhow::Result;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::time::Instant;

const CHUNK_BYTES: usize = 1024 * 1024;
const OVERLAP_BYTES: usize = 512;
const MAX_FINDINGS: usize = 8;

pub struct BinaryScanner;

impl BinaryScanner {
    /// Search for complete, structurally plausible ELF/PE objects rather than
    /// treating a four-byte coincidence as evidence of an embedded executable.
    pub fn scan_file(
        file: &File,
        file_len: u64,
        layer_digest: &str,
        media_type: &str,
    ) -> Result<LayerScanResult> {
        let started = Instant::now();
        let mut reader = file.try_clone()?;
        reader.seek(SeekFrom::Start(0))?;

        let mut read_buf = vec![0_u8; CHUNK_BYTES];
        let mut carry = Vec::<u8>::new();
        let mut absolute_read = 0_u64;
        let mut findings = Vec::new();

        loop {
            let count = reader.read(&mut read_buf)?;
            if count == 0 {
                break;
            }

            let chunk_start = absolute_read;
            absolute_read = absolute_read.saturating_add(count as u64);

            let mut window = Vec::with_capacity(carry.len() + count);
            window.extend_from_slice(&carry);
            window.extend_from_slice(&read_buf[..count]);
            let window_start = chunk_start.saturating_sub(carry.len() as u64);

            for offset in find_all(&window, b"\x7fELF") {
                if !looks_like_elf_header(&window[offset..]) {
                    continue;
                }
                let absolute = window_start.saturating_add(offset as u64);
                if validate_elf(file, file_len, absolute)?
                    && !findings
                        .iter()
                        .any(|finding: &String| finding.contains(&format!("0x{absolute:x}")))
                {
                    findings.push(format!(
                        "[T12-001] Structurally valid embedded ELF object at file offset 0x{absolute:x}"
                    ));
                }
                if findings.len() >= MAX_FINDINGS {
                    break;
                }
            }

            if findings.len() < MAX_FINDINGS {
                for offset in find_all(&window, b"MZ") {
                    // Random model weights can contain many two-byte "MZ"
                    // coincidences. Check the DOS header fields in-memory before
                    // doing any random file I/O for the PE signature.
                    if !looks_like_dos_header(&window[offset..]) {
                        continue;
                    }
                    let absolute = window_start.saturating_add(offset as u64);
                    if validate_pe(file, file_len, absolute)?
                        && !findings
                            .iter()
                            .any(|finding| finding.contains(&format!("0x{absolute:x}")))
                    {
                        findings.push(format!(
                            "[T12-002] Structurally valid embedded PE object at file offset 0x{absolute:x}"
                        ));
                    }
                    if findings.len() >= MAX_FINDINGS {
                        break;
                    }
                }
            }

            let keep = window.len().min(OVERLAP_BYTES);
            carry.clear();
            carry.extend_from_slice(&window[window.len() - keep..]);
        }

        let (status, detail) = if findings.is_empty() {
            (ScanStatus::Pass, None)
        } else {
            (
                ScanStatus::Fail,
                Some(format!(
                    "{} structurally plausible embedded executable object(s) detected",
                    findings.len()
                )),
            )
        };

        Ok(LayerScanResult {
            layer_digest: layer_digest.to_owned(),
            media_type: media_type.to_owned(),
            check_type: CheckType::BinarySteganography,
            status,
            finding_class: FindingClass::ContentIndicator,
            confidence: Confidence::High,
            detail,
            matches: findings,
            duration_ms: duration_ms(started),
        })
    }
}

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

fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return Vec::new();
    }
    haystack
        .windows(needle.len())
        .enumerate()
        .filter_map(|(index, window)| (window == needle).then_some(index))
        .collect()
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
        0x010b => 96_u64,  // PE32 fixed fields through NumberOfRvaAndSizes
        0x020b => 112_u64, // PE32+ fixed fields through NumberOfRvaAndSizes
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

    // At least one section must have a bounded raw-data range. This prevents a
    // random DOS+PE header coincidence from being treated as an executable.
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

fn read_at(file: &File, offset: u64, len: usize) -> Result<Option<Vec<u8>>> {
    let mut cloned = file.try_clone()?;
    cloned.seek(SeekFrom::Start(offset))?;
    let mut bytes = vec![0_u8; len];
    match cloned.read_exact(&mut bytes) {
        Ok(()) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
        Err(error) => Err(error.into()),
    }
}

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
        bytes[4] = 2; // 64-bit
        bytes[5] = 1; // little-endian
        bytes[6] = 1; // ELF version
        bytes[16..18].copy_from_slice(&2_u16.to_le_bytes()); // ET_EXEC
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes()); // x86-64
        bytes[40..48].copy_from_slice(&64_u64.to_le_bytes()); // section table offset
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes()); // ELF header size
        bytes[58..60].copy_from_slice(&64_u16.to_le_bytes()); // section header size
        bytes[60..62].copy_from_slice(&1_u16.to_le_bytes()); // one section
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

    #[test]
    fn structurally_valid_elf_is_detected() -> Result<()> {
        let path = std::env::temp_dir().join("layerfault_binary_real_elf");
        fs::write(&path, minimal_elf64())?;
        let file = File::open(&path)?;
        let result =
            BinaryScanner::scan_file(&file, file.metadata()?.len(), "sha256:test", "model")?;
        assert_eq!(result.status, ScanStatus::Fail);
        assert!(result.matches.iter().any(|m| m.contains("T12-001")));
        let _ = fs::remove_file(path);
        Ok(())
    }

    #[test]
    fn structurally_valid_pe_is_detected() -> Result<()> {
        let path = std::env::temp_dir().join("layerfault_binary_real_pe");
        fs::write(&path, minimal_pe64())?;
        let file = File::open(&path)?;
        let result =
            BinaryScanner::scan_file(&file, file.metadata()?.len(), "sha256:test", "model")?;
        assert_eq!(result.status, ScanStatus::Fail);
        assert!(result.matches.iter().any(|m| m.contains("T12-002")));
        let _ = fs::remove_file(path);
        Ok(())
    }

    #[test]
    fn four_byte_elf_coincidence_is_not_a_failure() -> Result<()> {
        let path = std::env::temp_dir().join("layerfault_binary_false_elf");
        fs::write(&path, b"noise\x7fELFnoise")?;
        let file = File::open(&path)?;
        let result =
            BinaryScanner::scan_file(&file, file.metadata()?.len(), "sha256:test", "model")?;
        assert_eq!(result.status, ScanStatus::Pass);
        let _ = fs::remove_file(path);
        Ok(())
    }

    #[test]
    fn four_byte_mz_coincidence_is_not_a_failure() -> Result<()> {
        let path = std::env::temp_dir().join("layerfault_binary_false_mz");
        fs::write(&path, b"MZ\x90\x00 but not a PE")?;
        let file = File::open(&path)?;
        let result =
            BinaryScanner::scan_file(&file, file.metadata()?.len(), "sha256:test", "model")?;
        assert_eq!(result.status, ScanStatus::Pass);
        let _ = fs::remove_file(path);
        Ok(())
    }
}
