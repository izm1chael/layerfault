use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};

pub fn resolve_models_dir() -> Result<PathBuf> {
    if let Ok(value) = std::env::var("OLLAMA_MODELS") {
        if !value.trim().is_empty() {
            let path = PathBuf::from(value);
            validate_models_dir(&path)?;
            return Ok(path);
        }
    }

    let candidate = default_models_dir()?;
    validate_models_dir(&candidate)?;
    Ok(candidate)
}

fn default_models_dir() -> Result<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var("USERPROFILE")
            .map(PathBuf::from)
            .map(|home| home.join(".ollama").join("models"))
            .map_err(|_| anyhow!("Cannot determine home directory"))
    }

    #[cfg(not(windows))]
    {
        let mut candidates = Vec::new();
        if let Ok(home) = std::env::var("HOME") {
            candidates.push(PathBuf::from(home).join(".ollama").join("models"));
        }
        candidates.push(PathBuf::from("/usr/share/ollama/.ollama/models"));

        if let Some(existing) = candidates
            .iter()
            .find(|path| path.join("manifests").is_dir() && path.join("blobs").is_dir())
        {
            return Ok(existing.clone());
        }

        candidates
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("Cannot determine Ollama models directory"))
    }
}

pub fn validate_models_dir(path: &Path) -> Result<()> {
    let manifests = path.join("manifests");
    let blobs = path.join("blobs");

    if path.exists() && manifests.is_dir() && blobs.is_dir() {
        return Ok(());
    }

    Err(anyhow!(
        "Ollama models directory not found at '{}'. \nSet OLLAMA_MODELS or verify your Ollama installation.",
        path.display()
    ))
}
