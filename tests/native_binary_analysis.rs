use anyhow::Result;
use layerfault::scanner::binary::{BinaryFormat, BinaryScanner, BinarySymbolCategory};
use std::fs::{self, File};

fn temp_file(name: &str, bytes: &[u8]) -> (std::path::PathBuf, File) {
    let dir = std::env::temp_dir().join(format!("layerfault-test-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    fs::write(&path, bytes).unwrap();
    let file = File::open(&path).unwrap();
    (path, file)
}

#[test]
fn elf_capability_parsing() -> Result<()> {
    let mut bytes = vec![0_u8; 512];
    // Header
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2; // ELF64
    bytes[5] = 1; // Little endian
    bytes[6] = 1; // Version
    bytes[16..18].copy_from_slice(&3_u16.to_le_bytes()); // ET_DYN (Shared object)
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes()); // x86_64

    // phoff = 64
    bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
    bytes[54..56].copy_from_slice(&56_u16.to_le_bytes()); // phentsize
    bytes[56..58].copy_from_slice(&2_u16.to_le_bytes()); // phnum

    // Program headers
    // PH 0: PT_LOAD (1)
    bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
    bytes[72..80].copy_from_slice(&0_u64.to_le_bytes()); // offset 0
    bytes[80..88].copy_from_slice(&0_u64.to_le_bytes()); // vaddr 0
    bytes[96..104].copy_from_slice(&512_u64.to_le_bytes()); // filesz

    // PH 1: PT_DYNAMIC (2)
    let ph1 = 64 + 56;
    bytes[ph1..ph1 + 4].copy_from_slice(&2_u32.to_le_bytes());
    bytes[ph1 + 8..ph1 + 16].copy_from_slice(&200_u64.to_le_bytes()); // offset 200
    bytes[ph1 + 16..ph1 + 24].copy_from_slice(&200_u64.to_le_bytes()); // vaddr 200
    bytes[ph1 + 32..ph1 + 40].copy_from_slice(&128_u64.to_le_bytes()); // filesz 128

    // Dynamic section at offset 200
    // DT_STRTAB (5) -> vaddr 350
    bytes[200..208].copy_from_slice(&5_i64.to_le_bytes());
    bytes[208..216].copy_from_slice(&350_u64.to_le_bytes());

    // DT_SYMTAB (6) -> vaddr 400
    bytes[216..224].copy_from_slice(&6_i64.to_le_bytes());
    bytes[224..232].copy_from_slice(&400_u64.to_le_bytes());

    // DT_SYMENT (11) -> 24
    bytes[232..240].copy_from_slice(&11_i64.to_le_bytes());
    bytes[240..248].copy_from_slice(&24_u64.to_le_bytes());

    // DT_RPATH (15) -> string offset 1
    bytes[248..256].copy_from_slice(&15_i64.to_le_bytes());
    bytes[256..264].copy_from_slice(&1_u64.to_le_bytes());

    // DT_NULL (0)
    bytes[264..272].copy_from_slice(&0_i64.to_le_bytes());

    // String table at offset 350
    // "\0/usr/local/lib\0execve\0connect\0dlopen\0"
    let strtab = b"\0/usr/local/lib\0execve\0connect\0dlopen\0";
    bytes[350..350 + strtab.len()].copy_from_slice(strtab);

    // Symtab at offset 400 (24 bytes per Elf64_Sym)
    // Symbol 0: dummy null
    // Symbol 1: "execve" (str offset 16), shndx = 0 (UNDEF)
    bytes[400 + 24..400 + 28].copy_from_slice(&16_u32.to_le_bytes());
    bytes[400 + 38..400 + 40].copy_from_slice(&0_u16.to_le_bytes());

    // Symbol 2: "connect" (str offset 23), shndx = 0 (UNDEF)
    bytes[400 + 48..400 + 52].copy_from_slice(&23_u32.to_le_bytes());
    bytes[400 + 62..400 + 64].copy_from_slice(&0_u16.to_le_bytes());

    // Symbol 3: "dlopen" (str offset 31), shndx = 0 (UNDEF)
    bytes[400 + 72..400 + 76].copy_from_slice(&31_u32.to_le_bytes());
    bytes[400 + 86..400 + 88].copy_from_slice(&0_u16.to_le_bytes());

    let (path, file) = temp_file("libcustom.so", &bytes);
    let (metadata, findings) = BinaryScanner::inspect_file_capabilities(
        &file,
        bytes.len() as u64,
        "sha256:test",
        "libcustom.so",
    )?;

    let meta = metadata.expect("ELF metadata parsed");
    assert_eq!(meta.format, BinaryFormat::Elf);
    assert_eq!(meta.architecture.as_deref(), Some("x86_64"));
    assert_eq!(meta.rpaths, vec!["/usr/local/lib"]);

    let exec_sym = meta.imports.iter().find(|i| i.name == "execve").unwrap();
    assert_eq!(exec_sym.category, Some(BinarySymbolCategory::Process));

    let net_sym = meta.imports.iter().find(|i| i.name == "connect").unwrap();
    assert_eq!(net_sym.category, Some(BinarySymbolCategory::Network));

    let dl_sym = meta.imports.iter().find(|i| i.name == "dlopen").unwrap();
    assert_eq!(dl_sym.category, Some(BinarySymbolCategory::DynamicLoad));

    assert!(findings
        .iter()
        .any(|f| f.matches.iter().any(|m| m.contains("LF-NATIVE-RPATH"))));
    assert!(findings.iter().any(|f| f
        .matches
        .iter()
        .any(|m| m.contains("LF-NATIVE-EXEC-CAPABILITY"))));
    assert!(findings.iter().any(|f| f
        .matches
        .iter()
        .any(|m| m.contains("LF-NATIVE-NETWORK-CAPABILITY"))));
    assert!(findings.iter().any(|f| f
        .matches
        .iter()
        .any(|m| m.contains("LF-NATIVE-DYNAMIC-LOAD"))));

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn elf_malformed_dynamic_table_fails_safely() -> Result<()> {
    let mut bytes = vec![0_u8; 128];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
    // Out of bounds phoff
    bytes[32..40].copy_from_slice(&0xffff_ffff_u64.to_le_bytes());
    bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&10_u16.to_le_bytes());

    let (path, file) = temp_file("bad.elf", &bytes);
    let (metadata, findings) = BinaryScanner::inspect_file_capabilities(
        &file,
        bytes.len() as u64,
        "sha256:test",
        "bad.elf",
    )?;

    assert!(metadata.is_none());
    assert!(findings.is_empty());

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn pe_imports_and_wx_section() -> Result<()> {
    let mut bytes = vec![0_u8; 512];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&64_u32.to_le_bytes());
    let pe = 64_usize;
    bytes[pe..pe + 4].copy_from_slice(b"PE\0\0");
    bytes[pe + 4..pe + 6].copy_from_slice(&0x8664_u16.to_le_bytes()); // x86_64
    bytes[pe + 6..pe + 8].copy_from_slice(&1_u16.to_le_bytes()); // 1 section
    bytes[pe + 20..pe + 22].copy_from_slice(&112_u16.to_le_bytes()); // optional size
    bytes[pe + 24..pe + 26].copy_from_slice(&0x020b_u16.to_le_bytes()); // PE32+

    // Section 1 at pe + 24 + 112 = 200
    let sec = pe + 24 + 112;
    bytes[sec..sec + 8].copy_from_slice(b".textwx\0");
    bytes[sec + 8..sec + 12].copy_from_slice(&64_u32.to_le_bytes()); // virt size
    bytes[sec + 12..sec + 16].copy_from_slice(&256_u32.to_le_bytes()); // virt addr
    bytes[sec + 16..sec + 20].copy_from_slice(&64_u32.to_le_bytes()); // raw size
    bytes[sec + 20..sec + 24].copy_from_slice(&256_u32.to_le_bytes()); // raw offset
                                                                       // IMAGE_SCN_MEM_EXECUTE (0x20000000) | IMAGE_SCN_MEM_WRITE (0x80000000)
    bytes[sec + 36..sec + 40].copy_from_slice(&0xa0000000_u32.to_le_bytes());

    let (path, file) = temp_file("custom.exe", &bytes);
    let (metadata, findings) = BinaryScanner::inspect_file_capabilities(
        &file,
        bytes.len() as u64,
        "sha256:test",
        "custom.exe",
    )?;

    let meta = metadata.expect("PE metadata parsed");
    assert_eq!(meta.format, BinaryFormat::Pe);
    assert!(meta.flags.wx_sections);

    assert!(findings
        .iter()
        .any(|f| f.matches.iter().any(|m| m.contains("LF-NATIVE-WX-SECTION"))));

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn macho_dylib_and_rpath() -> Result<()> {
    let mut bytes = vec![0_u8; 128];
    bytes[0..4].copy_from_slice(b"\xcf\xfa\xed\xfe"); // MH_MAGIC_64
    bytes[4..8].copy_from_slice(&0x01000007_u32.to_le_bytes()); // x86_64
    bytes[8..12].copy_from_slice(&3_u32.to_le_bytes());
    bytes[12..16].copy_from_slice(&6_u32.to_le_bytes()); // MH_DYLIB
    bytes[16..20].copy_from_slice(&1_u32.to_le_bytes()); // 1 command
    bytes[20..24].copy_from_slice(&24_u32.to_le_bytes()); // sizeofcmds

    // Load command 1: LC_RPATH (0x1c)
    let lc1 = 32_usize;
    bytes[lc1..lc1 + 4].copy_from_slice(&0x1c_u32.to_le_bytes());
    bytes[lc1 + 4..lc1 + 8].copy_from_slice(&24_u32.to_le_bytes());
    bytes[lc1 + 8..lc1 + 12].copy_from_slice(&12_u32.to_le_bytes());
    bytes[lc1 + 12..lc1 + 24].copy_from_slice(b"@rpath/lib\0\0");

    let (path, file) = temp_file("custom.dylib", &bytes);
    let (metadata, findings) = BinaryScanner::inspect_file_capabilities(
        &file,
        bytes.len() as u64,
        "sha256:test",
        "custom.dylib",
    )?;

    let meta = metadata.expect("Mach-O metadata parsed");
    assert_eq!(meta.format, BinaryFormat::MachO);
    assert_eq!(meta.rpaths, vec!["@rpath/lib"]);

    assert!(findings
        .iter()
        .any(|f| f.matches.iter().any(|m| m.contains("LF-NATIVE-RPATH"))));

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn wasm_imports_and_wasi() -> Result<()> {
    let mut bytes = vec![0_u8; 64];
    bytes[0..8].copy_from_slice(b"\0asm\x01\0\0\0");

    // Section 2 (Import): id=2, len=20
    bytes[8] = 2;
    bytes[9] = 20; // LEB128 len
                   // 1 import
    bytes[10] = 1;
    // module "wasi_snapshot_preview1" (len 22 -> but let's use "wasi" len 4)
    bytes[11] = 4;
    bytes[12..16].copy_from_slice(b"wasi");
    // field "fd_write" len 8
    bytes[16] = 8;
    bytes[17..25].copy_from_slice(b"fd_write");
    bytes[25] = 0; // func import
    bytes[26] = 0; // type index 0

    let (path, file) = temp_file("module.wasm", &bytes);
    let (metadata, _findings) = BinaryScanner::inspect_file_capabilities(
        &file,
        bytes.len() as u64,
        "sha256:test",
        "module.wasm",
    )?;

    let meta = metadata.expect("WASM metadata parsed");
    assert_eq!(meta.format, BinaryFormat::Wasm);
    assert_eq!(meta.linked_libraries, vec!["wasi"]);
    assert!(meta.imports.iter().any(|i| i.name == "wasi::fd_write"));

    let _ = fs::remove_file(path);
    Ok(())
}

#[test]
fn torch_ops_load_library_correlation() -> Result<()> {
    let dir = std::env::temp_dir().join(format!("layerfault-pkg-{}", std::process::id()));
    fs::create_dir_all(&dir)?;

    let py_content = r#"
import torch
torch.ops.load_library("custom_ops.so")
"#;
    fs::write(dir.join("modeling_custom.py"), py_content)?;

    let mut bytes = vec![0_u8; 512];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[16..18].copy_from_slice(&3_u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
    bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
    bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&2_u16.to_le_bytes());
    bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
    bytes[72..80].copy_from_slice(&0_u64.to_le_bytes());
    bytes[80..88].copy_from_slice(&0_u64.to_le_bytes());
    bytes[96..104].copy_from_slice(&512_u64.to_le_bytes());
    let ph1 = 64 + 56;
    bytes[ph1..ph1 + 4].copy_from_slice(&2_u32.to_le_bytes());
    bytes[ph1 + 8..ph1 + 16].copy_from_slice(&200_u64.to_le_bytes());
    bytes[ph1 + 16..ph1 + 24].copy_from_slice(&200_u64.to_le_bytes());
    bytes[ph1 + 32..ph1 + 40].copy_from_slice(&128_u64.to_le_bytes());
    bytes[200..208].copy_from_slice(&5_i64.to_le_bytes());
    bytes[208..216].copy_from_slice(&350_u64.to_le_bytes());
    bytes[216..224].copy_from_slice(&6_i64.to_le_bytes());
    bytes[224..232].copy_from_slice(&400_u64.to_le_bytes());
    bytes[232..240].copy_from_slice(&11_i64.to_le_bytes());
    bytes[240..248].copy_from_slice(&24_u64.to_le_bytes());
    bytes[248..256].copy_from_slice(&0_i64.to_le_bytes());

    let strtab = b"\0execve\0";
    bytes[350..350 + strtab.len()].copy_from_slice(strtab);
    bytes[400 + 24..400 + 28].copy_from_slice(&1_u32.to_le_bytes());
    bytes[400 + 38..400 + 40].copy_from_slice(&0_u16.to_le_bytes());

    fs::write(dir.join("custom_ops.so"), &bytes)?;

    let report = layerfault::package::inspect(&dir)?;
    assert!(report.findings.iter().any(|f| f
        .matches
        .iter()
        .any(|m| m.contains("LF-CORR-CUSTOM-LOADER-NATIVE"))));

    let _ = fs::remove_dir_all(dir);
    Ok(())
}

#[test]
fn ctypes_cdll_alias_correlation() -> Result<()> {
    let dir = std::env::temp_dir().join(format!("layerfault-pkg2-{}", std::process::id()));
    fs::create_dir_all(&dir)?;

    let py_content = r#"
import ctypes
lib = ctypes.CDLL("./custom.so")
"#;
    fs::write(dir.join("loader.py"), py_content)?;

    let mut bytes = vec![0_u8; 128];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[16..18].copy_from_slice(&3_u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
    fs::write(dir.join("custom.so"), &bytes)?;

    let report = layerfault::package::inspect(&dir)?;
    assert!(report.findings.iter().any(|f| f
        .matches
        .iter()
        .any(|m| m.contains("LF-CORR-CUSTOM-LOADER-NATIVE"))));

    let _ = fs::remove_dir_all(dir);
    Ok(())
}
