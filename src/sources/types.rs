use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceKind {
    Ollama,
    LmStudio,
    LlamaCpp,
    HfCache,
    Directory,
    File,
}

impl SourceKind {
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "ollama" => Ok(Self::Ollama),
            "lmstudio" | "lm-studio" | "lms" => Ok(Self::LmStudio),
            "llama-cpp" | "llamacpp" => Ok(Self::LlamaCpp),
            "hf-cache" | "huggingface" | "hugging-face" => Ok(Self::HfCache),
            "directory" | "dir" => Ok(Self::Directory),
            "file" => Ok(Self::File),
            other => Err(anyhow!("Unknown source '{other}'")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ollama => "ollama",
            Self::LmStudio => "lmstudio",
            Self::LlamaCpp => "llama-cpp",
            Self::HfCache => "hf-cache",
            Self::Directory => "directory",
            Self::File => "file",
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SourceArtifact {
    pub source: SourceKind,
    pub identity: String,
    pub path: PathBuf,
    pub display_path: String,
    pub format: ArtifactFormat,
    pub size: u64,
    pub architecture: Option<String>,
    pub quantization: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct HfRepoAudit {
    pub repository: String,
    pub root: String,
    pub refs: BTreeMap<String, String>,
    pub snapshots: Vec<String>,
    pub detached_snapshots: Vec<String>,
    pub missing_ref_snapshots: Vec<String>,
    pub invalid_links: Vec<String>,
    pub orphaned_blobs: Vec<String>,
    pub artifacts: Vec<SourceArtifact>,
    pub package_findings: Vec<crate::scanner::LayerScanResult>,
}
