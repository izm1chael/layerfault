use crate::formats::ArtifactFormat;
use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use walkdir::WalkDir;

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

pub fn discover_lmstudio() -> Result<Vec<SourceArtifact>> {
    let binary = find_executable("lms")
        .ok_or_else(|| anyhow!("LM Studio CLI 'lms' was not found in PATH"))?;
    let output = Command::new(&binary)
        .args(["ls", "--json", "--detailed"])
        .output()
        .context("Unable to execute 'lms ls --json --detailed'")?;
    if !output.status.success() {
        return Err(anyhow!(
            "lms ls failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let rows = parse_lmstudio_inventory_bytes(&output.stdout)?;
    if rows.is_empty() {
        return Err(anyhow!("LM Studio returned JSON but Layerfault could not identify any local model paths; use 'layerfault inspect <file>' for this LM Studio release"));
    }
    Ok(rows)
}

pub fn parse_lmstudio_inventory_bytes(bytes: &[u8]) -> Result<Vec<SourceArtifact>> {
    let value: Value = serde_json::from_slice(bytes).context("lms ls did not return valid JSON")?;
    let mut rows = Vec::new();
    collect_lms_objects(&value, &mut rows);
    rows.sort_by(|a, b| a.identity.cmp(&b.identity));
    rows.dedup_by(|a, b| a.identity == b.identity && a.path == b.path);
    Ok(rows)
}

fn collect_lms_objects(value: &Value, out: &mut Vec<SourceArtifact>) {
    match value {
        Value::Array(values) => values
            .iter()
            .for_each(|value| collect_lms_objects(value, out)),
        Value::Object(object) => {
            let path = ["path", "filePath", "file_path", "modelPath", "model_path"]
                .iter()
                .find_map(|key| object.get(*key).and_then(Value::as_str));
            if let Some(path) = path {
                let pathbuf = PathBuf::from(path);
                if pathbuf.is_file() {
                    let identity = [
                        "modelKey",
                        "model_key",
                        "key",
                        "identifier",
                        "name",
                        "displayName",
                    ]
                    .iter()
                    .find_map(|key| object.get(*key).and_then(Value::as_str))
                    .unwrap_or(path)
                    .to_owned();
                    let format = format_from_path(&pathbuf);
                    let size = fs::metadata(&pathbuf).map(|m| m.len()).unwrap_or(0);
                    let architecture = ["architecture", "arch"]
                        .iter()
                        .find_map(|key| object.get(*key).and_then(Value::as_str))
                        .map(ToOwned::to_owned);
                    let quantization = ["quantization", "quantizationType", "quantization_type"]
                        .iter()
                        .find_map(|key| object.get(*key).and_then(Value::as_str))
                        .map(ToOwned::to_owned);
                    out.push(SourceArtifact {
                        source: SourceKind::LmStudio,
                        identity,
                        path: pathbuf.clone(),
                        display_path: pathbuf.display().to_string(),
                        format,
                        size,
                        architecture,
                        quantization,
                    });
                }
            }
            object
                .values()
                .for_each(|value| collect_lms_objects(value, out));
        }
        _ => {}
    }
}

pub fn hf_cache_root(override_path: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = override_path {
        return Ok(path.to_path_buf());
    }
    if let Ok(value) = std::env::var("HF_HUB_CACHE") {
        if !value.trim().is_empty() {
            return Ok(PathBuf::from(value));
        }
    }
    if let Ok(value) = std::env::var("HF_HOME") {
        if !value.trim().is_empty() {
            return Ok(PathBuf::from(value).join("hub"));
        }
    }
    let home = std::env::var("HOME")
        .map_err(|_| anyhow!("Cannot determine Hugging Face cache root; set HF_HUB_CACHE"))?;
    Ok(PathBuf::from(home).join(".cache/huggingface/hub"))
}

pub fn audit_hf_cache(override_path: Option<&Path>) -> Result<Vec<HfRepoAudit>> {
    let root = hf_cache_root(override_path)?;
    if !root.is_dir() {
        return Err(anyhow!(
            "Hugging Face cache '{}' does not exist",
            root.display()
        ));
    }
    let mut reports = Vec::new();
    let entries =
        fs::read_dir(&root).with_context(|| format!("Unable to read '{}'", root.display()))?; // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with("models--") {
            continue;
        }
        reports.push(audit_hf_repo(&entry.path(), &name)?);
    }
    reports.sort_by(|a, b| a.repository.cmp(&b.repository));
    Ok(reports)
}

fn audit_hf_repo(root: &Path, folder_name: &str) -> Result<HfRepoAudit> {
    let repository = folder_name
        .strip_prefix("models--")
        .unwrap_or(folder_name)
        .replace("--", "/");
    let refs_root = root.join("refs");
    let snapshots_root = root.join("snapshots");
    let blobs_root = root.join("blobs");
    let mut refs = BTreeMap::new();
    if refs_root.is_dir() {
        for entry in WalkDir::new(&refs_root).follow_links(false) {
            let entry = entry?;
            if entry.file_type().is_file() {
                let value = fs::read_to_string(entry.path())
                    .unwrap_or_default()
                    .trim()
                    .to_owned();
                let rel = entry
                    .path()
                    .strip_prefix(&refs_root)
                    .unwrap_or(entry.path())
                    .display()
                    .to_string();
                refs.insert(rel, value);
            }
        }
    }
    let referenced_snapshots = refs.values().cloned().collect::<BTreeSet<_>>();
    let mut snapshots = Vec::new();
    let mut invalid_links = Vec::new();
    let mut artifacts = Vec::new();
    let mut package_findings = Vec::new();
    let mut package_cache =
        BTreeMap::<(PathBuf, String), Vec<crate::scanner::LayerScanResult>>::new();
    let mut referenced_blobs = BTreeSet::<PathBuf>::new();
    if snapshots_root.is_dir() {
        let revisions = fs::read_dir(&snapshots_root)?; // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
        for revision in revisions {
            let revision = revision?;
            if !revision.file_type()?.is_dir() {
                continue;
            }
            let revision_name = revision.file_name().to_string_lossy().into_owned();
            snapshots.push(revision_name.clone());
            for entry in WalkDir::new(revision.path()).follow_links(false) {
                let entry = entry?;
                if !entry.file_type().is_symlink() {
                    continue;
                }
                let link_path = entry.path();
                let target = match fs::read_link(link_path) {
                    Ok(target) => target,
                    Err(error) => {
                        invalid_links.push(format!("{}: {error}", link_path.display()));
                        continue;
                    }
                };
                let resolved = if target.is_absolute() {
                    target
                } else {
                    link_path.parent().unwrap_or(root).join(target)
                };
                let canonical = match fs::canonicalize(&resolved) {
                    Ok(value) => value,
                    Err(error) => {
                        invalid_links.push(format!(
                            "{} -> {}: {error}",
                            link_path.display(),
                            resolved.display()
                        ));
                        continue;
                    }
                };
                let canonical_blobs =
                    fs::canonicalize(&blobs_root).unwrap_or_else(|_| blobs_root.clone());
                if !canonical.starts_with(&canonical_blobs) || !canonical.is_file() {
                    invalid_links.push(format!(
                        "{} -> {} escapes repository blobs",
                        link_path.display(),
                        canonical.display()
                    ));
                    continue;
                }
                referenced_blobs.insert(canonical.clone());
                let format = format_from_path(link_path);
                if format == ArtifactFormat::Unknown {
                    // Package scanning is path-role sensitive: the same content-addressed blob can be
                    // linked under different filenames/extensions inside snapshots. Cache only when
                    // both the blob and its presented role match.
                    let role = link_path
                        .file_name()
                        .and_then(|v| v.to_str())
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    let cache_key = (canonical.clone(), role);
                    if let Some(cached) = package_cache.get(&cache_key) {
                        package_findings.extend(cached.clone());
                    } else {
                        match crate::package::inspect_member(link_path, &canonical) {
                            Ok(findings) => {
                                package_cache.insert(cache_key, findings.clone());
                                package_findings.extend(findings);
                            }
                            Err(error) => invalid_links.push(format!(
                                "{} package scan failed safely: {error}",
                                link_path.display()
                            )),
                        }
                    }
                }
                if format == ArtifactFormat::SafetensorsIndex {
                    if let Err(error) = validate_hf_safetensors_index(
                        link_path,
                        &canonical,
                        &revision.path(),
                        &canonical_blobs,
                    ) {
                        invalid_links.push(format!("{}: {error}", link_path.display()));
                    }
                    continue;
                }
                if format != ArtifactFormat::Unknown {
                    let rel = link_path
                        .strip_prefix(revision.path())
                        .unwrap_or(link_path)
                        .display()
                        .to_string();
                    let identity = format!("hf://{repository}@{revision_name}/{rel}");
                    let size = fs::metadata(&canonical).map(|m| m.len()).unwrap_or(0);
                    artifacts.push(SourceArtifact {
                        source: SourceKind::HfCache,
                        identity,
                        path: canonical,
                        display_path: link_path.display().to_string(),
                        format,
                        size,
                        architecture: None,
                        quantization: infer_quantization(link_path),
                    });
                }
            }
        }
    }
    snapshots.sort();
    let snapshot_set = snapshots.iter().cloned().collect::<BTreeSet<_>>();
    let detached_snapshots = snapshot_set
        .difference(&referenced_snapshots)
        .cloned()
        .collect();
    let missing_ref_snapshots = referenced_snapshots
        .difference(&snapshot_set)
        .cloned()
        .collect();
    let mut orphaned_blobs = Vec::new();
    if blobs_root.is_dir() {
        let entries = fs::read_dir(&blobs_root)?; // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
        for entry in entries {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let canonical = fs::canonicalize(entry.path()).unwrap_or_else(|_| entry.path());
                if !referenced_blobs.contains(&canonical) {
                    orphaned_blobs.push(entry.file_name().to_string_lossy().into_owned());
                }
            }
        }
    }
    orphaned_blobs.sort();
    artifacts.sort_by(|a, b| a.identity.cmp(&b.identity));
    Ok(HfRepoAudit {
        repository,
        root: root.display().to_string(),
        refs,
        snapshots,
        detached_snapshots,
        missing_ref_snapshots,
        invalid_links,
        orphaned_blobs,
        artifacts,
        package_findings,
    })
}

fn validate_hf_safetensors_index(
    display_path: &Path,
    blob_path: &Path,
    snapshot_root: &Path,
    canonical_blobs: &Path,
) -> Result<()> {
    let file = crate::safeio::open_readonly_nofollow(blob_path)?;
    let bytes = crate::safeio::read_all_from_file(&file, 100 * 1024 * 1024)?;
    let map = crate::formats::safetensors::parse_index_weight_map(&bytes)?;
    if map.is_empty() || map.len() > 1_000_000 {
        return Err(anyhow!(
            "Safetensors weight_map is empty or exceeds the safety limit"
        ));
    }
    let mut shards = BTreeSet::new();
    for shard in map.values() {
        let relative = Path::new(shard); // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path -- constrained to relative Normal components before joining to the snapshot root
        if relative.is_absolute()
            || relative.as_os_str().is_empty()
            || relative
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return Err(anyhow!("unsafe Safetensors shard path '{shard}'"));
        }
        if !shard.to_ascii_lowercase().ends_with(".safetensors") {
            return Err(anyhow!(
                "Safetensors index references non-Safetensors shard '{shard}'"
            ));
        }
        shards.insert(shard.to_owned());
    }
    for shard in shards {
        let link = snapshot_root.join(&shard);
        let metadata = fs::symlink_metadata(&link).with_context(|| {
            format!(
                "index '{}' references missing shard '{shard}'",
                display_path.display()
            )
        })?;
        if !metadata.file_type().is_symlink() {
            return Err(anyhow!(
                "referenced shard '{shard}' is not a Hugging Face snapshot symlink"
            ));
        }
        let target = fs::read_link(&link)?; // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path -- link target is canonicalized and required to remain inside canonical_blobs before opening
        let resolved = if target.is_absolute() {
            target
        } else {
            link.parent().unwrap_or(snapshot_root).join(target)
        };
        let canonical = fs::canonicalize(&resolved)?;
        if !canonical.starts_with(canonical_blobs) || !canonical.is_file() {
            return Err(anyhow!(
                "referenced shard '{shard}' resolves outside repository blobs"
            ));
        }
        let shard_file = crate::safeio::open_readonly_nofollow(&canonical)?;
        crate::formats::safetensors::validate_file(&shard_file, shard_file.metadata()?.len())
            .with_context(|| format!("referenced shard '{shard}' is structurally invalid"))?;
    }
    Ok(())
}

pub fn discover_directory(root: &Path, source: SourceKind) -> Result<Vec<SourceArtifact>> {
    if !root.is_dir() {
        return Err(anyhow!("'{}' is not a directory", root.display()));
    }
    let mut out = Vec::new();
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry?;
        if entry.file_type().is_file() {
            let format = format_from_path(entry.path());
            if format == ArtifactFormat::Unknown {
                continue;
            }
            let path = entry.path().to_path_buf();
            out.push(SourceArtifact {
                source,
                identity: path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .display()
                    .to_string(),
                display_path: path.display().to_string(),
                size: entry.metadata()?.len(),
                format,
                architecture: None,
                quantization: infer_quantization(&path),
                path,
            });
        }
    }
    out.sort_by(|a, b| a.identity.cmp(&b.identity));
    Ok(out)
}

pub fn run_lmstudio_load(model_key: &str, args: &[String]) -> Result<i32> {
    let binary = find_executable("lms")
        .ok_or_else(|| anyhow!("Runtime executable 'lms' was not found in PATH"))?;
    run_lmstudio_load_with(&binary, model_key, args)
}

pub fn run_lmstudio_load_with(binary: &Path, model_key: &str, args: &[String]) -> Result<i32> {
    let status = Command::new(binary) // nosemgrep: rust.actix.command-injection.rust-actix-command-injection.rust-actix-command-injection -- shell-free argv execution of an explicitly resolved runtime binary
        .arg("load")
        .arg(model_key)
        .args(args)
        .status()
        .with_context(|| format!("Unable to execute '{} load'", binary.display()))?;
    Ok(status.code().unwrap_or(1))
}

pub fn run_lmstudio_import(path: &Path, execute: bool, args: &[String]) -> Result<i32> {
    let binary = find_executable("lms")
        .ok_or_else(|| anyhow!("Runtime executable 'lms' was not found in PATH"))?;
    run_lmstudio_import_with(&binary, path, execute, args)
}

pub fn run_lmstudio_import_with(
    binary: &Path,
    path: &Path,
    execute: bool,
    args: &[String],
) -> Result<i32> {
    let mut command = Command::new(binary); // nosemgrep: rust.actix.command-injection.rust-actix-command-injection.rust-actix-command-injection -- shell-free argv execution of an explicitly resolved runtime binary
    command.arg("import").arg(path);
    if !execute {
        command.arg("--dry-run");
    }
    command.args(args);
    let status = command
        .status()
        .with_context(|| format!("Unable to execute '{} import'", binary.display()))?;
    Ok(status.code().unwrap_or(1))
}

pub fn run_llama(path: &Path, serve: bool, args: &[String]) -> Result<i32> {
    let binary_name = if serve { "llama-server" } else { "llama-cli" };
    let binary = find_executable(binary_name)
        .ok_or_else(|| anyhow!("Runtime executable '{binary_name}' was not found in PATH"))?;
    run_llama_with(&binary, path, args)
}

pub fn run_llama_with(binary: &Path, path: &Path, args: &[String]) -> Result<i32> {
    let status = Command::new(binary) // nosemgrep: rust.actix.command-injection.rust-actix-command-injection.rust-actix-command-injection -- shell-free argv execution of an explicitly resolved runtime binary
        .arg("-m")
        .arg(path)
        .args(args)
        .status()
        .with_context(|| format!("Unable to execute '{}'", binary.display()))?;
    Ok(status.code().unwrap_or(1))
}

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

fn infer_quantization(path: &Path) -> Option<String> {
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
