use super::types::*;
use anyhow::Result;
use std::fs::File;

pub fn parse_elf(file: &File, file_len: u64, offset: u64) -> Result<Option<BinaryMetadata>> {
    let header_bytes = match super::read_at(file, offset, 64)? {
        Some(bytes) if bytes.len() >= 52 => bytes,
        _ => return Ok(None),
    };

    if header_bytes.get(0..4) != Some(b"\x7fELF") {
        return Ok(None);
    }

    let class = header_bytes[4];
    let endian = header_bytes[5];
    if !matches!(class, 1 | 2) || !matches!(endian, 1 | 2) || header_bytes[6] != 1 {
        return Ok(None);
    }
    let is_64 = class == 2;
    let is_le = endian == 1;

    let e_type = read_u16(&header_bytes[16..18], is_le);
    let e_machine = read_u16(&header_bytes[18..20], is_le);

    let kind = match e_type {
        1 => Some(BinaryKind::Relocatable),
        2 => Some(BinaryKind::Executable),
        3 => Some(BinaryKind::SharedObject),
        4 => Some(BinaryKind::Core),
        _ => Some(BinaryKind::Unknown),
    };

    let arch = match e_machine {
        3 => Some("x86".to_owned()),
        62 => Some("x86_64".to_owned()),
        40 => Some("arm".to_owned()),
        183 => Some("aarch64".to_owned()),
        243 => Some("riscv64".to_owned()),
        _ => Some(format!("machine_0x{e_machine:x}")),
    };

    let remaining = file_len.saturating_sub(offset);
    let (entry_point, phoff, shoff, phentsize, phnum, shentsize, shnum, shstrndx) = if !is_64 {
        if header_bytes.len() < 52 {
            return Ok(None);
        }
        let entry = read_u32(&header_bytes[24..28], is_le) as u64;
        let phoff = read_u32(&header_bytes[28..32], is_le) as u64;
        let shoff = read_u32(&header_bytes[32..36], is_le) as u64;
        let phentsize = read_u16(&header_bytes[42..44], is_le) as u64;
        let phnum = read_u16(&header_bytes[44..46], is_le) as u64;
        let shentsize = read_u16(&header_bytes[46..48], is_le) as u64;
        let shnum = read_u16(&header_bytes[48..50], is_le) as u64;
        let shstrndx = read_u16(&header_bytes[50..52], is_le) as u64;
        (
            entry, phoff, shoff, phentsize, phnum, shentsize, shnum, shstrndx,
        )
    } else {
        if header_bytes.len() < 64 {
            return Ok(None);
        }
        let entry = read_u64(&header_bytes[24..32], is_le);
        let phoff = read_u64(&header_bytes[32..40], is_le);
        let shoff = read_u64(&header_bytes[40..48], is_le);
        let phentsize = read_u16(&header_bytes[54..56], is_le) as u64;
        let phnum = read_u16(&header_bytes[56..58], is_le) as u64;
        let shentsize = read_u16(&header_bytes[58..60], is_le) as u64;
        let shnum = read_u16(&header_bytes[60..62], is_le) as u64;
        let shstrndx = read_u16(&header_bytes[62..64], is_le) as u64;
        (
            entry, phoff, shoff, phentsize, phnum, shentsize, shnum, shstrndx,
        )
    };

    let ph_valid = phnum == 0 || super::table_in_bounds(phoff, phentsize, phnum, remaining);
    let sh_valid = shnum == 0 || super::table_in_bounds(shoff, shentsize, shnum, remaining);
    if !ph_valid || !sh_valid {
        return Ok(None);
    }

    let mut interpreter = None;
    let mut gnu_stack_wx = None;
    let mut relro = None;
    let mut dynamic_phdr = None;
    let mut program_headers = Vec::new();

    if phnum > 0 && phentsize >= if is_64 { 56 } else { 32 } {
        let ph_count = phnum.min(MAX_PROGRAM_HEADERS as u64);
        let ph_table_bytes = (ph_count * phentsize) as usize;
        let Some(ph_absolute) = absolute_offset(offset, phoff, file_len) else {
            return Ok(None);
        };
        if let Some(ph_data) = super::read_at(file, ph_absolute, ph_table_bytes)? {
            for chunk in ph_data.chunks_exact(phentsize as usize) {
                let p_type = read_u32(&chunk[0..4], is_le);
                let (p_offset, p_vaddr, p_filesz, p_memsz, p_flags) = if !is_64 {
                    (
                        read_u32(&chunk[4..8], is_le) as u64,
                        read_u32(&chunk[8..12], is_le) as u64,
                        read_u32(&chunk[16..20], is_le) as u64,
                        read_u32(&chunk[20..24], is_le) as u64,
                        read_u32(&chunk[24..28], is_le),
                    )
                } else {
                    (
                        read_u64(&chunk[8..16], is_le),
                        read_u64(&chunk[16..24], is_le),
                        read_u64(&chunk[32..40], is_le),
                        read_u64(&chunk[40..48], is_le),
                        read_u32(&chunk[4..8], is_le),
                    )
                };

                program_headers.push((p_type, p_offset, p_vaddr, p_filesz, p_memsz, p_flags));

                if p_type == 3 && interpreter.is_none() && p_filesz > 0 && p_filesz <= 4096 {
                    // PT_INTERP
                    if let Some(interp_absolute) = absolute_offset(offset, p_offset, file_len) {
                        if let Some(interp_bytes) =
                            super::read_at(file, interp_absolute, p_filesz as usize)?
                        {
                            let path = String::from_utf8_lossy(&interp_bytes)
                                .trim_matches('\0')
                                .to_string();
                            if !path.is_empty() {
                                interpreter = Some(path);
                            }
                        }
                    }
                } else if p_type == 2 {
                    // PT_DYNAMIC
                    dynamic_phdr = Some((p_offset, p_filesz));
                } else if p_type == 0x6474e551 {
                    // PT_GNU_STACK
                    gnu_stack_wx = Some((p_flags & 1) != 0); // PF_X
                } else if p_type == 0x6474e552 {
                    // PT_GNU_RELRO
                    relro = Some("Partial".to_string());
                }
            }
        }
    }

    let mut sections = Vec::new();
    let mut sections_truncated = false;
    let mut wx_sections = false;

    if shnum > 0 && shentsize >= if is_64 { 64 } else { 40 } {
        let shstr_offset = if shstrndx < shnum {
            let Some(shstr_relative) = shstrndx
                .checked_mul(shentsize)
                .and_then(|entry| shoff.checked_add(entry))
            else {
                return Ok(None);
            };
            let Some(shstr_entry_offset) = absolute_offset(offset, shstr_relative, file_len) else {
                return Ok(None);
            };
            if let Some(shstr_bytes) = super::read_at(file, shstr_entry_offset, shentsize as usize)?
            {
                if !is_64 {
                    read_u32(&shstr_bytes[16..20], is_le) as u64
                } else {
                    read_u64(&shstr_bytes[24..32], is_le)
                }
            } else {
                0
            }
        } else {
            0
        };

        let shstr_table = if shstr_offset > 0 {
            if let Some(absolute) = absolute_offset(offset, shstr_offset, file_len) {
                super::read_at(file, absolute, MAX_STRING_BYTES)?.unwrap_or_default()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        let scan_shnum = shnum.min(MAX_SECTIONS as u64);
        if shnum > MAX_SECTIONS as u64 {
            sections_truncated = true;
        }

        let Some(sh_absolute) = absolute_offset(offset, shoff, file_len) else {
            return Ok(None);
        };
        if let Some(sh_data) = super::read_at(file, sh_absolute, (scan_shnum * shentsize) as usize)?
        {
            for chunk in sh_data.chunks_exact(shentsize as usize) {
                let sh_name_idx = read_u32(&chunk[0..4], is_le) as usize;
                let (sh_type, sh_flags, sh_addr, sh_offset, sh_size) = if !is_64 {
                    (
                        read_u32(&chunk[4..8], is_le),
                        read_u32(&chunk[8..12], is_le) as u64,
                        read_u32(&chunk[12..16], is_le) as u64,
                        read_u32(&chunk[16..20], is_le) as u64,
                        read_u32(&chunk[20..24], is_le) as u64,
                    )
                } else {
                    (
                        read_u32(&chunk[4..8], is_le),
                        read_u64(&chunk[8..16], is_le),
                        read_u64(&chunk[16..24], is_le),
                        read_u64(&chunk[24..32], is_le),
                        read_u64(&chunk[32..40], is_le),
                    )
                };

                let _ = sh_type;
                let name = extract_string(&shstr_table, sh_name_idx);
                let writable = (sh_flags & 0x1) != 0; // SHF_WRITE
                let readable = (sh_flags & 0x2) != 0; // SHF_ALLOC
                let executable = (sh_flags & 0x4) != 0; // SHF_EXECINSTR

                if writable && executable && sh_size > 0 {
                    wx_sections = true;
                }

                sections.push(SectionSummary {
                    name,
                    virtual_address: (sh_addr > 0).then_some(sh_addr),
                    size: sh_size,
                    offset: sh_offset,
                    executable,
                    writable,
                    readable,
                });
            }
        }
    }

    let mut linked_libraries = Vec::new();
    let mut rpaths = Vec::new();
    let mut imports = Vec::new();
    let mut exports = Vec::new();
    let mut imports_truncated = false;
    let mut exports_truncated = false;

    if let Some((dyn_off, dyn_sz)) = dynamic_phdr {
        let entry_sz = if is_64 { 16 } else { 8 };
        let _dyn_entries = dyn_sz / entry_sz as u64;
        if let Some(dyn_absolute) = absolute_offset(offset, dyn_off, file_len) {
            let dyn_read_len = file_len
                .saturating_sub(dyn_absolute)
                .min(dyn_sz)
                .min(64 * 1024) as usize;
            if let Some(dyn_bytes) = super::read_at(file, dyn_absolute, dyn_read_len)? {
                let mut strtab_vaddr = None;
                let mut symtab_vaddr = None;
                let mut syment_size = if is_64 { 24_u64 } else { 16_u64 };
                let mut dt_needed_offsets = Vec::new();
                let mut dt_rpath_offsets = Vec::new();
                let mut is_bind_now = false;

                for chunk in dyn_bytes.chunks_exact(entry_sz) {
                    let (tag, val) = if !is_64 {
                        (
                            read_u32(&chunk[0..4], is_le) as i64,
                            read_u32(&chunk[4..8], is_le) as u64,
                        )
                    } else {
                        (
                            read_u64(&chunk[0..8], is_le) as i64,
                            read_u64(&chunk[8..16], is_le),
                        )
                    };

                    if tag == 0 {
                        break;
                    } // DT_NULL
                    match tag {
                        1 => dt_needed_offsets.push(val),      // DT_NEEDED
                        5 => strtab_vaddr = Some(val),         // DT_STRTAB
                        6 => symtab_vaddr = Some(val),         // DT_SYMTAB
                        11 => syment_size = val.max(1),        // DT_SYMENT
                        15 | 29 => dt_rpath_offsets.push(val), // DT_RPATH / DT_RUNPATH
                        24 if (val & 0x8) != 0 => {
                            is_bind_now = true;
                        } // DT_FLAGS
                        0x6ffffffb if (val & 0x1) != 0 => {
                            is_bind_now = true;
                        } // DT_FLAGS_1
                        _ => {}
                    }
                }

                if is_bind_now && relro.is_some() {
                    relro = Some("Full".to_string());
                }

                let strtab_offset =
                    strtab_vaddr.and_then(|vaddr| map_vaddr_to_offset(&program_headers, vaddr));
                let strtab_bytes = if let Some(off) = strtab_offset {
                    let absolute = offset.saturating_add(off);
                    let available = file_len.saturating_sub(absolute) as usize;
                    super::read_at(file, absolute, MAX_STRING_BYTES.min(available))?
                        .unwrap_or_default()
                } else {
                    Vec::new()
                };

                for off in dt_needed_offsets {
                    if linked_libraries.len() >= MAX_IMPORT_LIBRARIES {
                        break;
                    }
                    let lib = extract_string(&strtab_bytes, off as usize);
                    if !lib.is_empty() && !linked_libraries.contains(&lib) {
                        linked_libraries.push(lib);
                    }
                }

                for off in dt_rpath_offsets {
                    let rpath = extract_string(&strtab_bytes, off as usize);
                    if !rpath.is_empty() && !rpaths.contains(&rpath) {
                        rpaths.push(rpath);
                    }
                }

                let symtab_offset =
                    symtab_vaddr.and_then(|vaddr| map_vaddr_to_offset(&program_headers, vaddr));
                if let Some(sym_off) = symtab_offset {
                    let max_syms = (MAX_IMPORT_SYMBOLS + MAX_EXPORT_SYMBOLS) as u64;
                    let absolute = offset.saturating_add(sym_off);
                    let available = file_len.saturating_sub(absolute) as usize;
                    let requested = (max_syms.saturating_mul(syment_size)) as usize;
                    if let Some(sym_data) =
                        super::read_at(file, absolute, requested.min(available))?
                    {
                        for chunk in sym_data.chunks_exact(syment_size as usize) {
                            let (name_idx, shndx, value) = if !is_64 {
                                (
                                    read_u32(&chunk[0..4], is_le) as usize,
                                    read_u16(&chunk[14..16], is_le),
                                    read_u32(&chunk[4..8], is_le) as u64,
                                )
                            } else {
                                (
                                    read_u32(&chunk[0..4], is_le) as usize,
                                    read_u16(&chunk[6..8], is_le),
                                    read_u64(&chunk[8..16], is_le),
                                )
                            };

                            let sym_name = extract_string(&strtab_bytes, name_idx);
                            if sym_name.is_empty() {
                                continue;
                            }

                            if shndx == 0 {
                                // Undefined symbol -> Import
                                if imports.len() < MAX_IMPORT_SYMBOLS {
                                    let category = classify_symbol_name(&sym_name);
                                    imports.push(ImportSymbol {
                                        name: sym_name,
                                        library: None,
                                        category,
                                    });
                                } else {
                                    imports_truncated = true;
                                }
                            } else {
                                // Defined symbol -> Export
                                if exports.len() < MAX_EXPORT_SYMBOLS {
                                    exports.push(ExportSymbol {
                                        name: sym_name,
                                        address: (value > 0).then_some(value),
                                    });
                                } else {
                                    exports_truncated = true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(Some(BinaryMetadata {
        format: BinaryFormat::Elf,
        architecture: arch,
        kind,
        entry_point: (entry_point > 0).then_some(entry_point),
        sections,
        imports,
        exports,
        linked_libraries,
        interpreter,
        rpaths,
        flags: BinarySecurityFlags {
            wx_sections,
            gnu_stack_wx,
            relro,
            pie: (e_type == 3).then_some(true), // ET_DYN is PIE-compatible
            nx_compat: gnu_stack_wx.map(|wx| !wx),
            dynamic_base: (e_type == 3).then_some(true),
            code_signature: false,
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

fn map_vaddr_to_offset(phdrs: &[(u32, u64, u64, u64, u64, u32)], vaddr: u64) -> Option<u64> {
    for &(p_type, p_offset, p_vaddr, p_filesz, p_memsz, _) in phdrs {
        let mapped_len = p_filesz.max(p_memsz);
        if p_type == 1 && vaddr >= p_vaddr && vaddr < p_vaddr.saturating_add(mapped_len) {
            return Some(p_offset.saturating_add(vaddr.saturating_sub(p_vaddr)));
        }
    }
    None
}

fn absolute_offset(base: u64, relative: u64, file_len: u64) -> Option<u64> {
    base.checked_add(relative)
        .filter(|absolute| *absolute <= file_len)
}

fn extract_string(bytes: &[u8], offset: usize) -> String {
    if offset >= bytes.len() {
        return String::new();
    }
    let slice = &bytes[offset..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..end]).to_string()
}

fn read_u16(bytes: &[u8], little: bool) -> u16 {
    let arr: [u8; 2] = bytes.try_into().unwrap_or([0, 0]);
    if little {
        u16::from_le_bytes(arr)
    } else {
        u16::from_be_bytes(arr)
    }
}

fn read_u32(bytes: &[u8], little: bool) -> u32 {
    let arr: [u8; 4] = bytes.try_into().unwrap_or([0, 0, 0, 0]);
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
    fn embedded_elf_with_overflowing_string_table_offset_is_bounded() {
        let base = 7usize;
        let mut bytes = vec![0; base + 128];
        let header = &mut bytes[base..base + 64];
        header[..4].copy_from_slice(b"\x7fELF");
        header[4] = 2;
        header[5] = 1;
        header[6] = 1;
        header[16..18].copy_from_slice(&2_u16.to_le_bytes());
        header[18..20].copy_from_slice(&62_u16.to_le_bytes());
        header[40..48].copy_from_slice(&64_u64.to_le_bytes());
        header[58..60].copy_from_slice(&64_u16.to_le_bytes());
        header[60..62].copy_from_slice(&1_u16.to_le_bytes());
        let section = &mut bytes[base + 64..base + 128];
        section[24..32].copy_from_slice(&u64::MAX.to_le_bytes());

        let mut fixture = tempfile::NamedTempFile::new().expect("create ELF fixture");
        fixture.write_all(&bytes).expect("write ELF fixture");
        let file = fixture.reopen().expect("reopen ELF fixture");

        assert!(parse_elf(&file, bytes.len() as u64, base as u64)
            .expect("parse overflow ELF fixture")
            .is_some());
    }
}
