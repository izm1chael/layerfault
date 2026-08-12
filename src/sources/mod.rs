use crate::formats::ArtifactFormat;
use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use walkdir::WalkDir;

pub mod directory;
pub mod executable;
pub mod hf_cache;
pub mod llama;
pub mod lmstudio;
pub mod ollama;

mod types;

pub use directory::discover_directory;
pub use executable::{find_executable, format_from_path};
pub use hf_cache::{audit_hf_cache, hf_cache_root};
pub use llama::{run_llama, run_llama_with};
pub use llama::{
    run_lmstudio_import, run_lmstudio_import_with, run_lmstudio_load, run_lmstudio_load_with,
};
pub use lmstudio::{discover_lmstudio, parse_lmstudio_inventory_bytes};
pub use types::{HfRepoAudit, SourceArtifact, SourceKind};
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_names_parse() {
        assert_eq!(
            SourceKind::parse("lm-studio").unwrap(),
            SourceKind::LmStudio
        );
        assert_eq!(SourceKind::parse("hf-cache").unwrap(), SourceKind::HfCache);
    }

    #[test]
    fn lmstudio_inventory_bytes_use_the_same_parser_as_cli_discovery() -> Result<()> {
        let root =
            std::env::temp_dir().join(format!("layerfault-lmstudio-parser-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root)?;
        let model = root.join("fixture.gguf");
        std::fs::write(&model, b"GGUF\x03\0\0\0")?;
        let payload = serde_json::json!({
            "models": [{
                "filePath": model,
                "modelKey": "fixture/model",
                "architecture": "llama",
                "quantizationType": "Q4_K"
            }]
        });
        let rows = parse_lmstudio_inventory_bytes(&serde_json::to_vec(&payload)?)?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].identity, "fixture/model");
        assert_eq!(rows[0].format, ArtifactFormat::Gguf);
        let _ = std::fs::remove_dir_all(&root);
        Ok(())
    }
}
