use super::*;
pub fn find_executable(name: &str) -> Option<PathBuf> {
    let override_name = match name {
        "ollama" => Some("LAYERFAULT_OLLAMA_RUNTIME"),
        "lms" => Some("LAYERFAULT_LMSTUDIO_RUNTIME"),
        "llama-cli" | "llama-server" | "main" => Some("LAYERFAULT_LLAMA_RUNTIME"),
        _ => None,
    };
    if let Some(candidate) = override_name
        .and_then(std::env::var_os)
        .map(PathBuf::from)
        .filter(|path| path.is_file())
        .and_then(|path| std::fs::canonicalize(path).ok())
    {
        return Some(candidate);
    }
    let path: OsString = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            if let Ok(resolved) = std::fs::canonicalize(candidate) {
                return Some(resolved);
            }
        }
        #[cfg(windows)]
        {
            let exe = dir.join(format!("{name}.exe"));
            if exe.is_file() {
                if let Ok(resolved) = std::fs::canonicalize(exe) {
                    return Some(resolved);
                }
            }
        }
    }
    None
}

pub fn format_from_path(path: &Path) -> ArtifactFormat {
    if path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            name.to_ascii_lowercase()
                .ends_with(".safetensors.index.json")
        })
    {
        return ArtifactFormat::SafetensorsIndex;
    }
    match path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "gguf" => ArtifactFormat::Gguf,
        "safetensors" => ArtifactFormat::Safetensors,
        "pkl" | "pickle" | "joblib" | "pt" | "pth" | "ckpt" => ArtifactFormat::Pickle,
        _ => ArtifactFormat::Unknown,
    }
}

pub(super) fn infer_quantization(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy().to_ascii_uppercase();
    for marker in [
        "Q2_K", "Q3_K", "Q4_K", "Q5_K", "Q6_K", "Q8_0", "Q4_0", "Q5_0", "IQ", "F16", "BF16",
    ] {
        if name.contains(marker) {
            return Some(marker.to_owned());
        }
    }
    None
}
