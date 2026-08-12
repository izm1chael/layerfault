use super::*;

pub(crate) fn is_tokenizer_vocabulary_path(rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel).to_ascii_lowercase();
    matches!(
        name.as_str(),
        "tokenizer.json" | "vocab.json" | "merges.txt" | "added_tokens.json"
    ) || name.starts_with("vocab.")
}

pub(crate) fn is_documentation_path(rel: &str) -> bool {
    let lower = rel.to_ascii_lowercase();
    lower.split('/').any(|part| part == "docs")
        || lower.ends_with(".md")
        || lower.ends_with(".rst")
        || lower
            .rsplit('/')
            .next()
            .is_some_and(|name| name.starts_with("readme"))
}

pub(super) fn unsafe_serialization_name(lower: &str) -> bool {
    let filename = lower.rsplit('/').next().unwrap_or(lower);
    let mut candidate = filename;
    for _ in 0..8 {
        if matches!(
            Path::new(candidate)
                .extension()
                .and_then(|value| value.to_str())
                .unwrap_or(""),
            "pkl" | "pickle" | "joblib" | "pt" | "pth" | "ckpt"
        ) {
            return true;
        }
        let Some(stripped) = strip_compression_suffix(candidate) else {
            break;
        };
        candidate = stripped;
    }
    false
}

pub(super) fn strip_compression_suffix(value: &str) -> Option<&str> {
    for suffix in [
        ".gz", ".bz2", ".xz", ".lzma", ".z", ".zlib", ".deflate", ".zst",
    ] {
        if let Some(stripped) = value.strip_suffix(suffix) {
            return Some(stripped);
        }
    }
    None
}

pub(super) fn is_native_or_script(ext: &str, lower: &str) -> bool {
    matches!(
        ext,
        "py" | "sh"
            | "bash"
            | "zsh"
            | "ps1"
            | "psm1"
            | "psd1"
            | "bat"
            | "cmd"
            | "exe"
            | "dll"
            | "so"
            | "dylib"
            | "node"
            | "jar"
            | "js"
            | "mjs"
            | "cjs"
            | "ts"
            | "tsx"
            | "jsx"
    ) || lower.ends_with("setup.py")
}

pub(super) fn is_text_candidate(ext: &str, lower: &str) -> bool {
    matches!(
        ext,
        "json"
            | "txt"
            | "md"
            | "py"
            | "sh"
            | "bash"
            | "zsh"
            | "ps1"
            | "psm1"
            | "psd1"
            | "js"
            | "mjs"
            | "cjs"
            | "ts"
            | "tsx"
            | "jsx"
            | "toml"
            | "yaml"
            | "yml"
            | "jinja"
            | "jinja2"
            | "tmpl"
    ) || lower.ends_with("requirements.txt")
        || lower.ends_with("modelfile")
}

pub(super) fn classify(path: &Path) -> &'static str {
    let lower = path
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let ext = path
        .extension()
        .and_then(|v| v.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if ArtifactFormat::detect(path, &[]) != ArtifactFormat::Unknown {
        "model-artifact"
    } else if matches!(ext.as_str(), "py" | "sh" | "ps1" | "bat" | "cmd") {
        "code"
    } else if matches!(ext.as_str(), "so" | "dll" | "dylib" | "exe") {
        "native"
    } else if unsafe_serialization_name(&lower) || lower.ends_with("pytorch_model.bin") {
        "serialization"
    } else if crate::dependencies::classify_manifest(&lower, &ext).is_some() {
        "dependency-manifest"
    } else if matches!(ext.as_str(), "json" | "toml" | "yaml" | "yml") {
        "config"
    } else {
        "other"
    }
}
