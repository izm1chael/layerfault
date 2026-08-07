pub mod artifact;
pub mod safetensors;

use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactFormat {
    Gguf,
    Safetensors,
    SafetensorsIndex,
    Unknown,
}

impl ArtifactFormat {
    pub fn detect(path: &Path, prefix: &[u8]) -> Self {
        if prefix.starts_with(b"GGUF")
            || path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("gguf"))
        {
            Self::Gguf
        } else if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                name.to_ascii_lowercase()
                    .ends_with(".safetensors.index.json")
            })
        {
            Self::SafetensorsIndex
        } else if path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("safetensors"))
        {
            Self::Safetensors
        } else {
            Self::Unknown
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gguf => "gguf",
            Self::Safetensors => "safetensors",
            Self::SafetensorsIndex => "safetensors-index",
            Self::Unknown => "unknown",
        }
    }
}
