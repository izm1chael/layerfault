use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveFormat {
    Zip,
    Wheel,
    Tar,
    TarGz,
    Unknown,
}

impl ArchiveFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Zip => "zip",
            Self::Wheel => "wheel",
            Self::Tar => "tar",
            Self::TarGz => "tar.gz",
            Self::Unknown => "unknown",
        }
    }
}

pub struct DetectionResult {
    pub format: ArchiveFormat,
    pub claimed_format: ArchiveFormat,
    pub mismatch: bool,
}

pub fn detect_archive_format(path: &Path, prefix: &[u8]) -> DetectionResult {
    detect_archive_format_name(&path.to_string_lossy(), prefix)
}

/// Detect an archive using a logical member name and in-memory prefix. This
/// variant performs no filesystem access.
pub fn detect_archive_format_name(name: &str, prefix: &[u8]) -> DetectionResult {
    let filename = crate::safeio::portable_file_name(name).to_ascii_lowercase();

    let claimed = if filename.ends_with(".whl") {
        ArchiveFormat::Wheel
    } else if filename.ends_with(".zip") || filename.ends_with(".npz") {
        ArchiveFormat::Zip
    } else if filename.ends_with(".tar.gz") || filename.ends_with(".tgz") {
        ArchiveFormat::TarGz
    } else if filename.ends_with(".tar") {
        ArchiveFormat::Tar
    } else {
        ArchiveFormat::Unknown
    };

    let detected_by_magic = if prefix.len() >= 4 && prefix.starts_with(b"PK\x03\x04") {
        if claimed == ArchiveFormat::Wheel {
            ArchiveFormat::Wheel
        } else {
            ArchiveFormat::Zip
        }
    } else if prefix.len() >= 2 && prefix.starts_with(&[0x1f, 0x8b]) {
        ArchiveFormat::TarGz
    } else if is_tar_header_prefix(prefix) {
        ArchiveFormat::Tar
    } else {
        ArchiveFormat::Unknown
    };

    let actual_format = if detected_by_magic != ArchiveFormat::Unknown {
        detected_by_magic
    } else {
        claimed
    };

    let mismatch = match (claimed, detected_by_magic) {
        (ArchiveFormat::Unknown, _) => false,
        (_, ArchiveFormat::Unknown) => false,
        (c, d) => !matches!(
            (c, d),
            (ArchiveFormat::Zip, ArchiveFormat::Zip)
                | (ArchiveFormat::Wheel, ArchiveFormat::Wheel)
                | (ArchiveFormat::Zip, ArchiveFormat::Wheel)
                | (ArchiveFormat::Wheel, ArchiveFormat::Zip)
                | (ArchiveFormat::Tar, ArchiveFormat::Tar)
                | (ArchiveFormat::TarGz, ArchiveFormat::TarGz)
        ),
    };

    DetectionResult {
        format: actual_format,
        claimed_format: claimed,
        mismatch,
    }
}

fn is_tar_header_prefix(prefix: &[u8]) -> bool {
    if prefix.len() >= 262 && &prefix[257..262] == b"ustar" {
        return true;
    }
    // TAR checksum validation if full header is available (512 bytes)
    if prefix.len() >= 512 {
        let checksum_bytes = &prefix[148..156];
        if checksum_bytes
            .iter()
            .all(|&b| b.is_ascii_digit() || b == b' ' || b == 0)
        {
            let mut sum: u32 = 0;
            for (i, &b) in prefix[..512].iter().enumerate() {
                if (148..156).contains(&i) {
                    sum += b' ' as u32;
                } else {
                    sum += b as u32;
                }
            }
            let parsed_sum = std::str::from_utf8(checksum_bytes).ok().and_then(|s| {
                u32::from_str_radix(s.trim_matches(|c| c == ' ' || c == '\0'), 8).ok()
            });
            if let Some(expected) = parsed_sum {
                return expected == sum && sum > 0;
            }
        }
    }
    false
}
