use super::types::*;
use anyhow::Result;
use std::fs::File;

pub fn parse_wasm(file: &File, file_len: u64, offset: u64) -> Result<Option<BinaryMetadata>> {
    let header = match super::read_at(file, offset, 8)? {
        Some(b) if b.len() == 8 => b,
        _ => return Ok(None),
    };

    if header != b"\0asm\x01\0\0\0" {
        return Ok(None);
    }

    let mut cursor = offset + 8;
    let mut sections = Vec::new();
    let mut imports = Vec::new();
    let mut exports = Vec::new();
    let mut linked_libraries = Vec::new();
    let mut imports_truncated = false;
    let mut exports_truncated = false;
    let mut sections_truncated = false;
    let mut has_non_custom_section = false;

    while cursor < file_len {
        let id_bytes = match super::read_at(file, cursor, 1)? {
            Some(b) if b.len() == 1 => b,
            _ => break,
        };
        let section_id = id_bytes[0];
        cursor += 1;

        let (payload_len, leb_bytes) = match read_leb128_u32(file, cursor, file_len)? {
            Some(res) => res,
            None => break,
        };
        cursor += leb_bytes as u64;

        let payload_start = cursor;
        let payload_end = cursor.saturating_add(payload_len as u64);
        if payload_end > file_len {
            break;
        }

        if sections.len() < MAX_SECTIONS {
            sections.push(SectionSummary {
                name: section_id_name(section_id).to_string(),
                virtual_address: None,
                size: payload_len as u64,
                offset: payload_start,
                executable: section_id == 10, // Code section
                writable: section_id == 11,   // Data section
                readable: true,
            });
        } else {
            sections_truncated = true;
        }

        if section_id != 0 {
            has_non_custom_section = true;
        }

        match section_id {
            2 => {
                // Import Section
                if let Some(payload) = super::read_at(
                    file,
                    payload_start,
                    (payload_len as usize).min(MAX_STRING_BYTES * 4),
                )? {
                    let mut p_cursor = 0usize;
                    if let Some((count, count_leb)) = decode_leb128_u32_slice(&payload[p_cursor..])
                    {
                        p_cursor += count_leb;
                        for _ in 0..count {
                            if p_cursor >= payload.len() {
                                break;
                            }
                            let (mod_name, mod_bytes) = match read_wasm_string(&payload[p_cursor..])
                            {
                                Some(res) => res,
                                None => break,
                            };
                            p_cursor += mod_bytes;

                            let (field_name, field_bytes) =
                                match read_wasm_string(&payload[p_cursor..]) {
                                    Some(res) => res,
                                    None => break,
                                };
                            p_cursor += field_bytes;

                            if p_cursor >= payload.len() {
                                break;
                            }
                            let import_kind = payload[p_cursor];
                            p_cursor += 1;

                            match import_kind {
                                0 => {
                                    p_cursor += decode_leb128_u32_slice(&payload[p_cursor..])
                                        .map(|(_, l)| l)
                                        .unwrap_or(0)
                                } // Function type index
                                1 | 2 => {
                                    // Table or Memory limits
                                    if p_cursor < payload.len() {
                                        let flags = payload[p_cursor];
                                        p_cursor += 1;
                                        p_cursor += decode_leb128_u32_slice(&payload[p_cursor..])
                                            .map(|(_, l)| l)
                                            .unwrap_or(0);
                                        if (flags & 1) != 0 {
                                            p_cursor +=
                                                decode_leb128_u32_slice(&payload[p_cursor..])
                                                    .map(|(_, l)| l)
                                                    .unwrap_or(0);
                                        }
                                    }
                                }
                                3 => p_cursor += 2, // Global type (content_type + mutability)
                                _ => break,
                            }

                            if !mod_name.is_empty()
                                && !linked_libraries.contains(&mod_name)
                                && linked_libraries.len() < MAX_IMPORT_LIBRARIES
                            {
                                linked_libraries.push(mod_name.clone());
                            }

                            let full_symbol = format!("{mod_name}::{field_name}");
                            let category = classify_wasm_import(&mod_name, &field_name);

                            if imports.len() < MAX_IMPORT_SYMBOLS {
                                imports.push(ImportSymbol {
                                    name: full_symbol,
                                    library: Some(mod_name),
                                    category,
                                });
                            } else {
                                imports_truncated = true;
                            }
                        }
                    }
                }
            }
            7 => {
                // Export Section
                if let Some(payload) = super::read_at(
                    file,
                    payload_start,
                    (payload_len as usize).min(MAX_STRING_BYTES * 4),
                )? {
                    let mut p_cursor = 0usize;
                    if let Some((count, count_leb)) = decode_leb128_u32_slice(&payload[p_cursor..])
                    {
                        p_cursor += count_leb;
                        for _ in 0..count {
                            if p_cursor >= payload.len() {
                                break;
                            }
                            let (exp_name, name_bytes) =
                                match read_wasm_string(&payload[p_cursor..]) {
                                    Some(res) => res,
                                    None => break,
                                };
                            p_cursor += name_bytes;

                            if p_cursor >= payload.len() {
                                break;
                            }
                            p_cursor += 1; // export kind
                            let (_exp_idx, idx_leb) =
                                match decode_leb128_u32_slice(&payload[p_cursor..]) {
                                    Some(res) => res,
                                    None => break,
                                };
                            p_cursor += idx_leb;

                            if exports.len() < MAX_EXPORT_SYMBOLS {
                                exports.push(ExportSymbol {
                                    name: exp_name,
                                    address: None,
                                });
                            } else {
                                exports_truncated = true;
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        cursor = payload_end;
    }

    // Reject WASM binaries that only contain custom sections (section ID 0)
    // or no sections at all – magic + version bytes alone are not enough.
    if !has_non_custom_section {
        return Ok(None);
    }

    Ok(Some(BinaryMetadata {
        format: BinaryFormat::Wasm,
        architecture: Some("wasm32".to_string()),
        kind: Some(BinaryKind::WasmModule),
        entry_point: None,
        sections,
        imports,
        exports,
        linked_libraries,
        interpreter: None,
        rpaths: Vec::new(),
        flags: BinarySecurityFlags {
            wx_sections: false,
            gnu_stack_wx: None,
            relro: None,
            pie: None,
            nx_compat: Some(true),
            dynamic_base: None,
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

fn classify_wasm_import(module: &str, field: &str) -> Option<BinarySymbolCategory> {
    if module.starts_with("wasi_") || module == "wasi" {
        let lower = field.to_ascii_lowercase();
        if lower.contains("proc_spawn") || lower.contains("proc_exec") || lower.contains("sys_exec")
        {
            return Some(BinarySymbolCategory::Process);
        }
        if lower.contains("sock") || lower.contains("net") || lower.contains("connect") {
            return Some(BinarySymbolCategory::Network);
        }
        if lower.contains("fd_") || lower.contains("path_") {
            return Some(BinarySymbolCategory::Filesystem);
        }
    }

    classify_symbol_name(field)
}

fn section_id_name(id: u8) -> &'static str {
    match id {
        0 => "custom",
        1 => "type",
        2 => "import",
        3 => "function",
        4 => "table",
        5 => "memory",
        6 => "global",
        7 => "export",
        8 => "start",
        9 => "element",
        10 => "code",
        11 => "data",
        12 => "datacount",
        _ => "unknown",
    }
}

fn read_leb128_u32(file: &File, mut offset: u64, file_len: u64) -> Result<Option<(u32, usize)>> {
    let mut result: u32 = 0;
    let mut shift = 0;
    let mut bytes_read = 0;

    while offset < file_len && bytes_read < 5 {
        let b = match super::read_at(file, offset, 1)? {
            Some(bytes) if bytes.len() == 1 => bytes[0],
            _ => return Ok(None),
        };
        offset += 1;
        bytes_read += 1;

        result |= ((b & 0x7f) as u32) << shift;
        if (b & 0x80) == 0 {
            return Ok(Some((result, bytes_read)));
        }
        shift += 7;
    }
    Ok(None)
}

fn decode_leb128_u32_slice(slice: &[u8]) -> Option<(u32, usize)> {
    let mut result: u32 = 0;
    let mut shift = 0;
    let mut bytes_read = 0;

    for &b in slice.iter().take(5) {
        bytes_read += 1;
        result |= ((b & 0x7f) as u32) << shift;
        if (b & 0x80) == 0 {
            return Some((result, bytes_read));
        }
        shift += 7;
    }
    None
}

fn read_wasm_string(slice: &[u8]) -> Option<(String, usize)> {
    let (len, leb_len) = decode_leb128_u32_slice(slice)?;
    let start = leb_len;
    let end = start.checked_add(len as usize)?;
    if end <= slice.len() {
        let str_val = String::from_utf8_lossy(&slice[start..end]).to_string();
        Some((str_val, end))
    } else {
        None
    }
}
