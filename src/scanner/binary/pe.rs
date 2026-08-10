use super::types::*;
use anyhow::Result;
use std::fs::File;

pub fn parse_pe(file: &File, _file_len: u64, offset: u64) -> Result<Option<BinaryMetadata>> {
    let dos_bytes = match super::read_at(file, offset, 64)? {
        Some(bytes) if bytes.len() >= 64 => bytes,
        _ => return Ok(None),
    };

    if dos_bytes.get(0..2) != Some(b"MZ") {
        return Ok(None);
    }

    let pe_rel = u32::from_le_bytes(dos_bytes[0x3c..0x40].try_into().unwrap_or([0; 4])) as u64;
    if !(64..=1024 * 1024).contains(&pe_rel) {
        return Ok(None);
    }
    let pe_offset = offset.saturating_add(pe_rel);

    let coff_bytes = match super::read_at(file, pe_offset, 24)? {
        Some(bytes) if bytes.len() >= 24 => bytes,
        _ => return Ok(None),
    };

    if coff_bytes.get(0..4) != Some(b"PE\0\0") {
        return Ok(None);
    }

    let machine = u16::from_le_bytes(coff_bytes[4..6].try_into().unwrap_or([0, 0]));
    let num_sections = u16::from_le_bytes(coff_bytes[6..8].try_into().unwrap_or([0, 0])) as u64;
    let optional_size = u16::from_le_bytes(coff_bytes[20..22].try_into().unwrap_or([0, 0])) as u64;
    let characteristics = u16::from_le_bytes(coff_bytes[22..24].try_into().unwrap_or([0, 0]));

    if !(1..=96).contains(&num_sections) || optional_size == 0 || optional_size > 4096 {
        return Ok(None);
    }

    let arch = match machine {
        0x014c => Some("x86".to_string()),
        0x8664 => Some("x86_64".to_string()),
        0x01c0 | 0x01c4 => Some("arm".to_string()),
        0xaa64 => Some("aarch64".to_string()),
        _ => Some(format!("machine_0x{machine:x}")),
    };

    let kind = if (characteristics & 0x2000) != 0 {
        Some(BinaryKind::SharedObject)
    } else {
        Some(BinaryKind::Executable)
    };

    let opt_bytes = match super::read_at(file, pe_offset + 24, optional_size as usize)? {
        Some(bytes) => bytes,
        None => return Ok(None),
    };

    if opt_bytes.len() < 24 {
        return Ok(None);
    }

    let magic = u16::from_le_bytes(opt_bytes[0..2].try_into().unwrap_or([0, 0]));
    let is_pe32_plus = magic == 0x020b;
    if !matches!(magic, 0x010b | 0x020b) {
        return Ok(None);
    }

    let entry_point = u32::from_le_bytes(opt_bytes[16..20].try_into().unwrap_or([0; 4])) as u64;

    let (dll_char_offset, rva_count_offset) = if is_pe32_plus { (70, 108) } else { (58, 92) };

    let dll_characteristics = if opt_bytes.len() >= dll_char_offset + 2 {
        u16::from_le_bytes(
            opt_bytes[dll_char_offset..dll_char_offset + 2]
                .try_into()
                .unwrap_or([0, 0]),
        )
    } else {
        0
    };

    let nx_compat = (dll_characteristics & 0x0100) != 0;
    let dynamic_base = (dll_characteristics & 0x0040) != 0;

    let num_rvas = if opt_bytes.len() >= rva_count_offset + 4 {
        u32::from_le_bytes(
            opt_bytes[rva_count_offset..rva_count_offset + 4]
                .try_into()
                .unwrap_or([0; 4]),
        ) as usize
    } else {
        0
    };

    let dirs_start = rva_count_offset + 4;
    let mut data_dirs = Vec::new();
    for i in 0..num_rvas.min(16) {
        let off = dirs_start + (i * 8);
        if opt_bytes.len() >= off + 8 {
            let rva =
                u32::from_le_bytes(opt_bytes[off..off + 4].try_into().unwrap_or([0; 4])) as u64;
            let sz =
                u32::from_le_bytes(opt_bytes[off + 4..off + 8].try_into().unwrap_or([0; 4])) as u64;
            data_dirs.push((rva, sz));
        }
    }

    let export_dir = data_dirs.first().copied().unwrap_or((0, 0));
    let import_dir = data_dirs.get(1).copied().unwrap_or((0, 0));
    let security_dir = data_dirs.get(4).copied().unwrap_or((0, 0));
    let tls_dir = data_dirs.get(9).copied().unwrap_or((0, 0));
    let clr_dir = data_dirs.get(14).copied().unwrap_or((0, 0));

    let section_table_offset = pe_offset + 24 + optional_size;
    let scan_sections = num_sections.min(MAX_SECTIONS as u64);
    let mut sections = Vec::new();
    let sections_truncated = num_sections > MAX_SECTIONS as u64;
    let mut wx_sections = false;

    let section_bytes =
        match super::read_at(file, section_table_offset, (scan_sections * 40) as usize)? {
            Some(bytes) => bytes,
            None => return Ok(None),
        };

    let mut section_mappings = Vec::new();

    for chunk in section_bytes.chunks_exact(40) {
        let name_raw = &chunk[0..8];
        let name_end = name_raw.iter().position(|&b| b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&name_raw[..name_end]).to_string();

        let virt_size = u32::from_le_bytes(chunk[8..12].try_into().unwrap_or([0; 4])) as u64;
        let virt_addr = u32::from_le_bytes(chunk[12..16].try_into().unwrap_or([0; 4])) as u64;
        let raw_size = u32::from_le_bytes(chunk[16..20].try_into().unwrap_or([0; 4])) as u64;
        let raw_offset = u32::from_le_bytes(chunk[20..24].try_into().unwrap_or([0; 4])) as u64;
        let characteristics = u32::from_le_bytes(chunk[36..40].try_into().unwrap_or([0; 4]));

        let executable = (characteristics & 0x20000000) != 0; // IMAGE_SCN_MEM_EXECUTE
        let readable = (characteristics & 0x40000000) != 0; // IMAGE_SCN_MEM_READ
        let writable = (characteristics & 0x80000000) != 0; // IMAGE_SCN_MEM_WRITE

        if executable && writable && raw_size > 0 {
            wx_sections = true;
        }

        let map_size = virt_size.max(raw_size);
        if virt_addr > 0 && map_size > 0 {
            section_mappings.push((virt_addr, map_size, raw_offset));
        }

        sections.push(SectionSummary {
            name,
            virtual_address: (virt_addr > 0).then_some(virt_addr),
            size: raw_size,
            offset: raw_offset,
            executable,
            writable,
            readable,
        });
    }

    let mut linked_libraries = Vec::new();
    let mut imports = Vec::new();
    let mut exports = Vec::new();
    let mut imports_truncated = false;
    let mut exports_truncated = false;

    // Parse Import Directory
    if import_dir.0 > 0 {
        if let Some(import_offset) = map_rva_to_offset(&section_mappings, import_dir.0) {
            let mut desc_cursor = offset + import_offset;
            while linked_libraries.len() < MAX_IMPORT_LIBRARIES {
                let desc_bytes = match super::read_at(file, desc_cursor, 20)? {
                    Some(b) if b.len() == 20 => b,
                    _ => break,
                };

                let original_first_thunk =
                    u32::from_le_bytes(desc_bytes[0..4].try_into().unwrap_or([0; 4])) as u64;
                let name_rva =
                    u32::from_le_bytes(desc_bytes[12..16].try_into().unwrap_or([0; 4])) as u64;
                let first_thunk =
                    u32::from_le_bytes(desc_bytes[16..20].try_into().unwrap_or([0; 4])) as u64;

                if name_rva == 0 && first_thunk == 0 {
                    break;
                }

                let dll_name =
                    if let Some(name_off) = map_rva_to_offset(&section_mappings, name_rva) {
                        read_cstr(file, offset + name_off, 256)?.unwrap_or_default()
                    } else {
                        String::new()
                    };

                if !dll_name.is_empty() && !linked_libraries.contains(&dll_name) {
                    linked_libraries.push(dll_name.clone());
                }

                let thunk_rva = if original_first_thunk > 0 {
                    original_first_thunk
                } else {
                    first_thunk
                };
                if let Some(thunk_off) = map_rva_to_offset(&section_mappings, thunk_rva) {
                    let mut entry_cursor = offset + thunk_off;
                    let step = if is_pe32_plus { 8 } else { 4 };
                    while imports.len() < MAX_IMPORT_SYMBOLS {
                        let entry_bytes = match super::read_at(file, entry_cursor, step)? {
                            Some(b) if b.len() == step => b,
                            _ => break,
                        };

                        let val = if is_pe32_plus {
                            u64::from_le_bytes(entry_bytes.try_into().unwrap_or([0; 8]))
                        } else {
                            u32::from_le_bytes(entry_bytes.try_into().unwrap_or([0; 4])) as u64
                        };

                        if val == 0 {
                            break;
                        }
                        let ordinal_mask = if is_pe32_plus { 1 << 63 } else { 1 << 31 };
                        if (val & ordinal_mask) == 0 {
                            // Import by name (RVA points to Hint/Name table)
                            let hint_rva = val & 0x7fff_ffff;
                            if let Some(hint_off) = map_rva_to_offset(&section_mappings, hint_rva) {
                                if let Some(func_name) =
                                    read_cstr(file, offset + hint_off + 2, 256)?
                                {
                                    if !func_name.is_empty() {
                                        let category = classify_symbol_name(&func_name);
                                        imports.push(ImportSymbol {
                                            name: func_name,
                                            library: (!dll_name.is_empty())
                                                .then_some(dll_name.clone()),
                                            category,
                                        });
                                    }
                                }
                            }
                        }
                        entry_cursor += step as u64;
                    }
                    if imports.len() >= MAX_IMPORT_SYMBOLS {
                        imports_truncated = true;
                    }
                }

                desc_cursor += 20;
            }
        }
    }

    // Parse Export Directory
    if export_dir.0 > 0 {
        if let Some(export_offset) = map_rva_to_offset(&section_mappings, export_dir.0) {
            if let Some(exp_bytes) = super::read_at(file, offset + export_offset, 40)? {
                let num_names =
                    u32::from_le_bytes(exp_bytes[24..28].try_into().unwrap_or([0; 4])) as usize;
                let names_rva =
                    u32::from_le_bytes(exp_bytes[32..36].try_into().unwrap_or([0; 4])) as u64;

                if names_rva > 0 && num_names > 0 {
                    if let Some(names_off) = map_rva_to_offset(&section_mappings, names_rva) {
                        let count = num_names.min(MAX_EXPORT_SYMBOLS);
                        if num_names > MAX_EXPORT_SYMBOLS {
                            exports_truncated = true;
                        }
                        if let Some(rva_table) =
                            super::read_at(file, offset + names_off, count * 4)?
                        {
                            for chunk in rva_table.chunks_exact(4) {
                                let name_rva =
                                    u32::from_le_bytes(chunk.try_into().unwrap_or([0; 4])) as u64;
                                if let Some(str_off) =
                                    map_rva_to_offset(&section_mappings, name_rva)
                                {
                                    if let Some(exp_name) = read_cstr(file, offset + str_off, 256)?
                                    {
                                        if !exp_name.is_empty() {
                                            exports.push(ExportSymbol {
                                                name: exp_name,
                                                address: None,
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(Some(BinaryMetadata {
        format: BinaryFormat::Pe,
        architecture: arch,
        kind,
        entry_point: (entry_point > 0).then_some(entry_point),
        sections,
        imports,
        exports,
        linked_libraries,
        interpreter: None,
        rpaths: Vec::new(),
        flags: BinarySecurityFlags {
            wx_sections,
            gnu_stack_wx: None,
            relro: None,
            pie: None,
            nx_compat: Some(nx_compat),
            dynamic_base: Some(dynamic_base),
            code_signature: security_dir.1 > 0,
            clr_dotnet: clr_dir.1 > 0,
            tls_callbacks: tls_dir.1 > 0,
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

fn map_rva_to_offset(mappings: &[(u64, u64, u64)], rva: u64) -> Option<u64> {
    for &(virt_addr, virt_size, raw_offset) in mappings {
        if rva >= virt_addr && rva < virt_addr.saturating_add(virt_size) {
            return Some(raw_offset.saturating_add(rva.saturating_sub(virt_addr)));
        }
    }
    None
}

fn read_cstr(file: &File, offset: u64, max_len: usize) -> Result<Option<String>> {
    if let Some(bytes) = super::read_at(file, offset, max_len)? {
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        Ok(Some(String::from_utf8_lossy(&bytes[..end]).to_string()))
    } else {
        Ok(None)
    }
}
