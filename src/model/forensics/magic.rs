#[derive(Debug, Clone, Copy)]
pub struct Magic {
    pub name: &'static str,
    pub executable: bool,
    #[allow(dead_code)]
    pub archive: bool,
}
pub fn detect(bytes: &[u8]) -> Option<Magic> {
    if bytes.starts_with(b"\x7fELF") {
        Some(Magic {
            name: "ELF",
            executable: true,
            archive: false,
        })
    } else if bytes.starts_with(b"MZ") && bytes.len() >= 64 {
        Some(Magic {
            name: "PE",
            executable: true,
            archive: false,
        })
    } else if bytes.starts_with(b"PK\x03\x04") {
        Some(Magic {
            name: "ZIP",
            executable: false,
            archive: true,
        })
    } else if bytes.starts_with(b"\x1f\x8b") {
        Some(Magic {
            name: "GZIP",
            executable: false,
            archive: true,
        })
    } else if bytes.starts_with(b"7z\xbc\xaf'\x1c") {
        Some(Magic {
            name: "7z",
            executable: false,
            archive: true,
        })
    } else if bytes.starts_with(b"Rar!") {
        Some(Magic {
            name: "RAR",
            executable: false,
            archive: true,
        })
    } else if bytes.starts_with(b"\xcf\xfa\xed\xfe") || bytes.starts_with(b"\xfe\xed\xfa\xcf") {
        Some(Magic {
            name: "Mach-O",
            executable: true,
            archive: false,
        })
    } else if bytes.starts_with(b"SQLite format 3\0") {
        Some(Magic {
            name: "SQLite",
            executable: false,
            archive: false,
        })
    } else if bytes.starts_with(b"%PDF-") {
        Some(Magic {
            name: "PDF",
            executable: false,
            archive: false,
        })
    } else if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some(Magic {
            name: "PNG",
            executable: false,
            archive: false,
        })
    } else {
        None
    }
}
