use super::types::*;
use anyhow::Result;
use std::fs::File;

pub fn parse_macho(file: &File, file_len: u64, offset: u64) -> Result<Option<BinaryMetadata>> {
    let magic_bytes = match super::read_at(file, offset, 4)? {
        Some(b) if b.len() == 4 => b,
        _ => return Ok(None),
    };

    match magic_bytes.as_slice() {
        b"\xfe\xed\xfa\xce" => parse_macho_thin(file, file_len, offset, false, false),
        b"\xce\xfa\xed\xfe" => parse_macho_thin(file, file_len, offset, true, false),
        b"\xfe\xed\xfa\xcf" => parse_macho_thin(file, file_len, offset, false, true),
        b"\xcf\xfa\xed\xfe" => parse_macho_thin(file, file_len, offset, true, true),
        b"\xca\xfe\xba\xbe" => parse_macho_fat(file, file_len, offset, false, false),
        b"\xbe\xba\xfe\xca" => parse_macho_fat(file, file_len, offset, true, false),
        b"\xca\xfe\xba\xbf" => parse_macho_fat(file, file_len, offset, false, true),
        b"\xbf\xba\xfe\xca" => parse_macho_fat(file, file_len, offset, true, true),
        _ => Ok(None),
    }
}

fn parse_macho_fat(
    file: &File,
    file_len: u64,
    offset: u64,
    little: bool,
    is_64: bool,
) -> Result<Option<BinaryMetadata>> {
    let header = match super::read_at(file, offset, 8)? {
        Some(b) if b.len() == 8 => b,
        _ => return Ok(None),
    };

    let arches = read_u32(&header[4..8], little) as u64;
    if arches == 0 || arches > MAX_FAT_ARCHES {
        return Ok(None);
    }

    let entry_size = if is_64 { 32_u64 } else { 20_u64 };
    let table_size = arches * entry_size;
    let table_start = offset + 8;

    let table = match super::read_at(file, table_start, table_size as usize)? {
        Some(b) => b,
        None => return Ok(None),
    };

    let mut best_slice = None;

    for chunk in table.chunks_exact(entry_size as usize) {
        let cpu_type = read_u32(&chunk[0..4], little);
        let (rel_off, size) = if is_64 {
            (
                read_u64(&chunk[8..16], little),
                read_u64(&chunk[16..24], little),
            )
        } else {
            (
                read_u32(&chunk[8..12], little) as u64,
                read_u32(&chunk[12..16], little) as u64,
            )
        };

        if size == 0 || offset.saturating_add(rel_off).saturating_add(size) > file_len {
            continue;
        }

        let slice_offset = offset + rel_off;
        // Prefer 64-bit slices (x86_64 = 0x01000007, arm64 = 0x0100000c)
        if cpu_type == 0x0100000c || cpu_type == 0x01000007 || best_slice.is_none() {
            best_slice = Some(slice_offset);
        }
    }

    if let Some(slice_off) = best_slice {
        parse_fat_slice(file, file_len, slice_off)
    } else {
        Ok(None)
    }
}

fn parse_fat_slice(file: &File, file_len: u64, offset: u64) -> Result<Option<BinaryMetadata>> {
    let magic_bytes = match super::read_at(file, offset, 4)? {
        Some(bytes) if bytes.len() == 4 => bytes,
        _ => return Ok(None),
    };

    // A universal Mach-O architecture entry contains a thin Mach-O image.
    // Reject another universal header instead of recursively following
    // attacker-controlled slice offsets, which can point back to themselves.
    match magic_bytes.as_slice() {
        b"\xfe\xed\xfa\xce" => parse_macho_thin(file, file_len, offset, false, false),
        b"\xce\xfa\xed\xfe" => parse_macho_thin(file, file_len, offset, true, false),
        b"\xfe\xed\xfa\xcf" => parse_macho_thin(file, file_len, offset, false, true),
        b"\xcf\xfa\xed\xfe" => parse_macho_thin(file, file_len, offset, true, true),
        _ => Ok(None),
    }
}

fn parse_macho_thin(
    file: &File,
    _file_len: u64,
    offset: u64,
    little: bool,
    is_64: bool,
) -> Result<Option<BinaryMetadata>> {
    let header_size = if is_64 { 32 } else { 28 };
    let header = match super::read_at(file, offset, header_size)? {
        Some(b) if b.len() == header_size => b,
        _ => return Ok(None),
    };

    let cpu_type = read_u32(&header[4..8], little);
    let file_type = read_u32(&header[12..16], little);
    let ncmds = read_u32(&header[16..20], little) as u64;
    let sizeofcmds = read_u32(&header[20..24], little) as u64;

    if cpu_type == 0 || ncmds == 0 || ncmds > MAX_LOAD_COMMANDS as u64 || sizeofcmds < ncmds * 8 {
        return Ok(None);
    }

    let arch = match cpu_type {
        7 => Some("x86".to_string()),
        0x01000007 => Some("x86_64".to_string()),
        12 => Some("arm".to_string()),
        0x0100000c => Some("aarch64".to_string()),
        _ => Some(format!("cputype_0x{cpu_type:x}")),
    };

    let kind = match file_type {
        1 => Some(BinaryKind::Relocatable),
        2 => Some(BinaryKind::Executable),
        6 | 8 => Some(BinaryKind::SharedObject),
        _ => Some(BinaryKind::Unknown),
    };

    let commands_start = offset + header_size as u64;
    let commands_bytes = match super::read_at(file, commands_start, sizeofcmds as usize)? {
        Some(b) if b.len() == sizeofcmds as usize => b,
        _ => return Ok(None),
    };

    let mut cursor = 0usize;
    let mut sections = Vec::new();
    let mut linked_libraries = Vec::new();
    let mut rpaths = Vec::new();
    let mut imports = Vec::new();
    let mut exports = Vec::new();
    let mut code_signature = false;
    let mut wx_sections = false;
    let mut entry_point = None;
    let mut symtab_info = None;

    let mut sections_truncated = false;
    let mut imports_truncated = false;
    let mut exports_truncated = false;

    for _ in 0..ncmds {
        if cursor + 8 > commands_bytes.len() {
            break;
        }
        let cmd = read_u32(&commands_bytes[cursor..cursor + 4], little);
        let cmdsize = read_u32(&commands_bytes[cursor + 4..cursor + 8], little) as usize;
        if cmdsize < 8 || cursor + cmdsize > commands_bytes.len() {
            break;
        }

        let cmd_data = &commands_bytes[cursor..cursor + cmdsize];
        let req_cmd = cmd & !0x8000_0000;

        match req_cmd {
            0x1 | 0x19 => {
                // LC_SEGMENT (0x1) / LC_SEGMENT_64 (0x19)
                let is_seg64 = req_cmd == 0x19;
                let min_len = if is_seg64 { 72 } else { 56 };
                if cmd_data.len() >= min_len {
                    let seg_name_raw = &cmd_data[8..24];
                    let seg_end = seg_name_raw.iter().position(|&b| b == 0).unwrap_or(16);
                    let _seg_name = String::from_utf8_lossy(&seg_name_raw[..seg_end]).to_string();

                    let (initprot, maxprot, nsects, sect_offset) = if is_seg64 {
                        let init = read_u32(&cmd_data[56..60], little);
                        let max = read_u32(&cmd_data[60..64], little);
                        let n = read_u32(&cmd_data[64..68], little);
                        (init, max, n, 72)
                    } else {
                        let init = read_u32(&cmd_data[40..44], little);
                        let max = read_u32(&cmd_data[44..48], little);
                        let n = read_u32(&cmd_data[48..52], little);
                        (init, max, n, 56)
                    };

                    let vm_prot_write = 0x2;
                    let vm_prot_exec = 0x4;
                    if (initprot & (vm_prot_write | vm_prot_exec)) == (vm_prot_write | vm_prot_exec)
                        || (maxprot & (vm_prot_write | vm_prot_exec))
                            == (vm_prot_write | vm_prot_exec)
                    {
                        wx_sections = true;
                    }

                    let sect_size = if is_seg64 { 80 } else { 68 };
                    let mut sect_cursor = sect_offset;
                    for _ in 0..nsects {
                        if sect_cursor + sect_size > cmd_data.len() {
                            break;
                        }
                        if sections.len() >= MAX_SECTIONS {
                            sections_truncated = true;
                            break;
                        }
                        let s_data = &cmd_data[sect_cursor..sect_cursor + sect_size];
                        let s_name_raw = &s_data[0..16];
                        let s_end = s_name_raw.iter().position(|&b| b == 0).unwrap_or(16);
                        let s_name = String::from_utf8_lossy(&s_name_raw[..s_end]).to_string();

                        let (addr, size, fileoff, flags) = if is_seg64 {
                            (
                                read_u64(&s_data[32..40], little),
                                read_u64(&s_data[40..48], little),
                                read_u32(&s_data[48..52], little) as u64,
                                read_u32(&s_data[64..68], little),
                            )
                        } else {
                            (
                                read_u32(&s_data[32..36], little) as u64,
                                read_u32(&s_data[36..40], little) as u64,
                                read_u32(&s_data[40..44], little) as u64,
                                read_u32(&s_data[56..60], little),
                            )
                        };

                        let s_type = flags & 0xff;
                        let executable = (initprot & vm_prot_exec) != 0 || s_type == 0x8; // S_ATTR_SOME_INSTRUCTIONS
                        let writable = (initprot & vm_prot_write) != 0;

                        sections.push(SectionSummary {
                            name: s_name,
                            virtual_address: (addr > 0).then_some(addr),
                            size,
                            offset: fileoff,
                            executable,
                            writable,
                            readable: true,
                        });

                        sect_cursor += sect_size;
                    }
                }
            }
            0xc | 0x18 | 0x1f => {
                // LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB
                if cmd_data.len() >= 24 {
                    let str_off = read_u32(&cmd_data[8..12], little) as usize;
                    if str_off < cmd_data.len() {
                        let dylib_name = extract_cstr(&cmd_data[str_off..]);
                        if !dylib_name.is_empty()
                            && !linked_libraries.contains(&dylib_name)
                            && linked_libraries.len() < MAX_IMPORT_LIBRARIES
                        {
                            linked_libraries.push(dylib_name);
                        }
                    }
                }
            }
            0x1c => {
                // LC_RPATH
                if cmd_data.len() >= 12 {
                    let str_off = read_u32(&cmd_data[8..12], little) as usize;
                    if str_off < cmd_data.len() {
                        let rpath = extract_cstr(&cmd_data[str_off..]);
                        if !rpath.is_empty() && !rpaths.contains(&rpath) {
                            rpaths.push(rpath);
                        }
                    }
                }
            }
            0x1d => {
                // LC_CODE_SIGNATURE
                code_signature = true;
            }
            0x8000_0028 => {
                // LC_MAIN
                if cmd_data.len() >= 16 {
                    entry_point = Some(read_u64(&cmd_data[8..16], little));
                }
            }
            0x2 if cmd_data.len() >= 24 => {
                // LC_SYMTAB
                let symoff = read_u32(&cmd_data[8..12], little) as u64;
                let nsyms = read_u32(&cmd_data[12..16], little) as u64;
                let stroff = read_u32(&cmd_data[16..20], little) as u64;
                let strsize = read_u32(&cmd_data[20..24], little) as u64;
                symtab_info = Some((symoff, nsyms, stroff, strsize));
            }
            _ => {}
        }

        cursor += cmdsize;
    }

    if let Some((symoff, nsyms, stroff, strsize)) = symtab_info {
        if nsyms > 0 && strsize > 0 {
            let str_bytes = super::read_at(
                file,
                offset + stroff,
                (strsize as usize).min(MAX_STRING_BYTES),
            )?
            .unwrap_or_default();
            let nlist_size = if is_64 { 16 } else { 12 };
            let scan_nsyms = nsyms.min((MAX_IMPORT_SYMBOLS + MAX_EXPORT_SYMBOLS) as u64);

            if let Some(nlist_data) =
                super::read_at(file, offset + symoff, (scan_nsyms * nlist_size) as usize)?
            {
                for chunk in nlist_data.chunks_exact(nlist_size as usize) {
                    let strx = read_u32(&chunk[0..4], little) as usize;
                    let n_type = chunk[4];
                    let n_sect = chunk[5];
                    let n_val = if is_64 {
                        read_u64(&chunk[8..16], little)
                    } else {
                        read_u32(&chunk[8..12], little) as u64
                    };

                    let name = extract_cstr_at(&str_bytes, strx);
                    if name.is_empty() {
                        continue;
                    }

                    let is_ext = (n_type & 0x01) != 0; // N_EXT
                    let type_mask = n_type & 0x0e;

                    if type_mask == 0x00 {
                        // N_UNDF -> Import
                        if is_ext && imports.len() < MAX_IMPORT_SYMBOLS {
                            let category = classify_symbol_name(&name);
                            imports.push(ImportSymbol {
                                name,
                                library: None,
                                category,
                            });
                        } else if imports.len() >= MAX_IMPORT_SYMBOLS {
                            imports_truncated = true;
                        }
                    } else if type_mask == 0x0e && n_sect > 0 {
                        // N_SECT -> Export
                        if is_ext && exports.len() < MAX_EXPORT_SYMBOLS {
                            exports.push(ExportSymbol {
                                name,
                                address: (n_val > 0).then_some(n_val),
                            });
                        } else if exports.len() >= MAX_EXPORT_SYMBOLS {
                            exports_truncated = true;
                        }
                    }
                }
            }
        }
    }

    Ok(Some(BinaryMetadata {
        format: BinaryFormat::MachO,
        architecture: arch,
        kind,
        entry_point,
        sections,
        imports,
        exports,
        linked_libraries,
        interpreter: None,
        rpaths,
        flags: BinarySecurityFlags {
            wx_sections,
            gnu_stack_wx: None,
            relro: None,
            pie: (file_type == 2).then_some(true),
            nx_compat: Some(true),
            dynamic_base: Some(true),
            code_signature,
            clr_dotnet: false,
            tls_callbacks: false,
        },
        coverage: BinaryAnalysisCoverage {
            complete: !sections_truncated && !imports_truncated && !exports_truncated,
            incomplete_reason: None,
            sections_truncated,
            imports_truncated,
            exports_truncated,
        },
    }))
}

fn extract_cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).to_string()
}

fn extract_cstr_at(bytes: &[u8], offset: usize) -> String {
    if offset >= bytes.len() {
        return String::new();
    }
    extract_cstr(&bytes[offset..])
}

fn read_u32(bytes: &[u8], little: bool) -> u32 {
    let arr: [u8; 4] = bytes.try_into().unwrap_or([0; 4]);
    if little {
        u32::from_le_bytes(arr)
    } else {
        u32::from_be_bytes(arr)
    }
}

fn read_u64(bytes: &[u8], little: bool) -> u64 {
    let arr: [u8; 8] = bytes.try_into().unwrap_or([0; 8]);
    if little {
        u64::from_le_bytes(arr)
    } else {
        u64::from_be_bytes(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn self_referential_fat_macho_is_rejected_without_recursion() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"\xca\xfe\xba\xbe");
        bytes.extend_from_slice(&1_u32.to_be_bytes());
        bytes.extend_from_slice(&0x0100_0007_u32.to_be_bytes());
        bytes.extend_from_slice(&0_u32.to_be_bytes());
        bytes.extend_from_slice(&0_u32.to_be_bytes());
        bytes.extend_from_slice(&48_u32.to_be_bytes());
        bytes.extend_from_slice(&0_u32.to_be_bytes());
        bytes.resize(48, 0);

        let mut fixture = tempfile::NamedTempFile::new().expect("create Mach-O fixture");
        fixture
            .write_all(&bytes)
            .expect("write self-referential Mach-O fixture");
        let file = fixture.reopen().expect("reopen Mach-O fixture");

        assert!(parse_macho(&file, bytes.len() as u64, 0)
            .expect("parse self-referential Mach-O")
            .is_none());
    }
}
