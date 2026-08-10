use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BinaryFormat {
    Elf,
    Pe,
    MachO,
    Wasm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BinaryKind {
    Executable,
    SharedObject,
    Relocatable,
    Core,
    WasmModule,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BinarySymbolCategory {
    Process,
    Network,
    DynamicLoad,
    Filesystem,
    Credential,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SectionSummary {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub virtual_address: Option<u64>,
    pub size: u64,
    pub offset: u64,
    pub executable: bool,
    pub writable: bool,
    pub readable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ImportSymbol {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub library: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<BinarySymbolCategory>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ExportSymbol {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BinarySecurityFlags {
    pub wx_sections: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gnu_stack_wx: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relro: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pie: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nx_compat: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dynamic_base: Option<bool>,
    pub code_signature: bool,
    pub clr_dotnet: bool,
    pub tls_callbacks: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BinaryAnalysisCoverage {
    pub complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incomplete_reason: Option<String>,
    pub sections_truncated: bool,
    pub imports_truncated: bool,
    pub exports_truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryMetadata {
    pub format: BinaryFormat,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<BinaryKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_point: Option<u64>,
    pub sections: Vec<SectionSummary>,
    pub imports: Vec<ImportSymbol>,
    pub exports: Vec<ExportSymbol>,
    pub linked_libraries: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interpreter: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rpaths: Vec<String>,
    pub flags: BinarySecurityFlags,
    pub coverage: BinaryAnalysisCoverage,
}

pub const MAX_SECTIONS: usize = 128;
pub const MAX_PROGRAM_HEADERS: usize = 128;
pub const MAX_IMPORT_LIBRARIES: usize = 64;
pub const MAX_IMPORT_SYMBOLS: usize = 256;
pub const MAX_EXPORT_SYMBOLS: usize = 256;
pub const MAX_STRING_BYTES: usize = 4096;
pub const MAX_LOAD_COMMANDS: usize = 256;
pub const MAX_FAT_ARCHES: u64 = 64;

pub fn classify_symbol_name(name: &str) -> Option<BinarySymbolCategory> {
    let lower = name.trim().trim_start_matches('_').to_ascii_lowercase();

    if matches!(
        lower.as_str(),
        "execve"
            | "execv"
            | "execvp"
            | "execvpe"
            | "execl"
            | "execlp"
            | "execle"
            | "posix_spawn"
            | "posix_spawnp"
            | "system"
            | "popen"
            | "fork"
            | "vfork"
            | "clone"
            | "createprocessa"
            | "createprocessw"
            | "winexec"
            | "shellexecutea"
            | "shellexecutew"
            | "shellexecuteexa"
            | "shellexecutexw"
    ) {
        return Some(BinarySymbolCategory::Process);
    }

    if matches!(
        lower.as_str(),
        "socket"
            | "connect"
            | "send"
            | "sendto"
            | "recv"
            | "recvfrom"
            | "getaddrinfo"
            | "gethostbyname"
            | "wsastartup"
            | "wsaconnect"
            | "urldownloadtofilea"
            | "urldownloadtofilew"
            | "winhttpopen"
            | "winhttpconnect"
            | "internetopena"
            | "internetopenw"
    ) {
        return Some(BinarySymbolCategory::Network);
    }

    if matches!(
        lower.as_str(),
        "dlopen"
            | "dlsym"
            | "dlmopen"
            | "loadlibrarya"
            | "loadlibraryw"
            | "loadlibraryexa"
            | "loadlibraryexw"
            | "getprocaddress"
    ) {
        return Some(BinarySymbolCategory::DynamicLoad);
    }

    if matches!(
        lower.as_str(),
        "open"
            | "openat"
            | "unlink"
            | "unlinkat"
            | "rename"
            | "renameat"
            | "chmod"
            | "fchmod"
            | "chown"
    ) {
        return Some(BinarySymbolCategory::Filesystem);
    }

    if matches!(
        lower.as_str(),
        "credreada" | "credreadw" | "lsaretrieveprivatedata"
    ) {
        return Some(BinarySymbolCategory::Credential);
    }

    None
}
