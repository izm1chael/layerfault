use crate::safeio::{open_readonly_nofollow, read_all_from_file};
use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};
use walkdir::WalkDir;

const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
const KNOWN_DIGESTS: &[(&str, usize)] = &[("sha256", 64), ("sha512", 128)];

#[derive(Debug, Deserialize, Clone)]
pub struct Manifest {
    #[serde(rename = "schemaVersion", default)]
    pub schema_version: Option<u32>,
    #[serde(rename = "mediaType", default)]
    pub media_type: Option<String>,
    /// OCI-style manifests use a top-level config descriptor. Newer Ollama
    /// documentation also describes layer-only manifests, so this is optional.
    #[serde(default)]
    pub config: Option<Layer>,
    #[serde(default)]
    pub layers: Vec<Layer>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Layer {
    #[serde(rename = "mediaType", default)]
    pub media_type: String,
    pub digest: String,
    pub size: u64,
}

impl Layer {
    pub fn base_media_type(&self) -> &str {
        self.media_type
            .split_once(';')
            .map(|(base, _)| base.trim())
            .unwrap_or_else(|| self.media_type.trim())
    }
}

#[derive(Debug, Clone)]
pub struct ModelRef {
    pub name: String,
    pub manifest_path: PathBuf,
}

pub struct ResolvedModel {
    pub name: String,
    pub manifest: Manifest,
    pub manifest_bytes: Vec<u8>,
    pub digest: String,
}

impl ResolvedModel {
    pub fn descriptors(&self) -> impl Iterator<Item = &Layer> {
        self.manifest
            .config
            .iter()
            .chain(self.manifest.layers.iter())
    }
}

pub fn resolve_blob_path(base_dir: &Path, digest: &str) -> Result<PathBuf> {
    validate_digest(digest)?;
    Ok(base_dir.join("blobs").join(digest.replace(':', "-")))
}

pub fn validate_digest(digest: &str) -> Result<()> {
    let (algorithm, encoded) = digest
        .split_once(':')
        .ok_or_else(|| anyhow!("Digest '{digest}' is missing algorithm prefix"))?;

    let expected_len = KNOWN_DIGESTS
        .iter()
        .find(|(candidate, _)| *candidate == algorithm)
        .map(|(_, len)| *len)
        .ok_or_else(|| anyhow!("Unknown digest algorithm '{algorithm}'"))?;

    if encoded.len() != expected_len || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(anyhow!(
            "Digest payload for '{algorithm}' must be exactly {expected_len} hexadecimal characters"
        ));
    }

    Ok(())
}

pub fn discover_all_models(base_dir: &Path) -> Result<Vec<ModelRef>> {
    let manifests_root = base_dir.join("manifests");
    if !manifests_root.is_dir() {
        return Err(anyhow!(
            "Manifest directory '{}' does not exist",
            manifests_root.display()
        ));
    }

    let mut models = Vec::new();
    for entry in WalkDir::new(&manifests_root).follow_links(false) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                eprintln!("warning: unable to inspect manifest path: {error}");
                continue;
            }
        };
        if !entry.file_type().is_file() {
            continue;
        }

        let path = entry.path();
        let relative = path.strip_prefix(&manifests_root).with_context(|| {
            format!(
                "Manifest path '{}' is not under '{}'",
                path.display(),
                manifests_root.display()
            )
        })?;

        let name = match canonical_model_name(relative) {
            Ok(name) => name,
            Err(error) => {
                eprintln!("warning: skipping '{}': {error}", path.display());
                continue;
            }
        };

        models.push(ModelRef {
            name,
            manifest_path: path.to_path_buf(),
        });
    }

    models.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(models)
}

pub fn find_model(base_dir: &Path, selector: &str) -> Result<ModelRef> {
    validate_selector(selector)?;
    let wanted = normalize_selector(selector);
    let models = discover_all_models(base_dir)?;

    let mut matches: Vec<ModelRef> = models
        .into_iter()
        .filter(|model| model_matches(&model.name, &wanted))
        .collect();

    match matches.len() {
        0 => Err(anyhow!(
            "Model '{selector}' not found. Use the canonical registry/namespace/model:tag name when necessary."
        )),
        1 => Ok(matches.remove(0)),
        _ => {
            let candidates = matches
                .iter()
                .map(|model| model.name.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            Err(anyhow!(
                "Model selector '{selector}' is ambiguous; use one of: {candidates}"
            ))
        }
    }
}

pub fn parse_manifest_bytes(bytes: &[u8]) -> Result<Manifest> {
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(anyhow!(
            "Manifest exceeds {} byte safety limit",
            MAX_MANIFEST_BYTES
        ));
    }

    let manifest: Manifest =
        serde_json::from_slice(bytes).context("Manifest is not valid supported JSON")?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

fn validate_manifest(manifest: &Manifest) -> Result<()> {
    if manifest.layers.is_empty() && manifest.config.is_none() {
        return Err(anyhow!("Manifest contains no descriptors"));
    }

    for descriptor in manifest.config.iter().chain(manifest.layers.iter()) {
        validate_digest(&descriptor.digest)
            .with_context(|| format!("Invalid descriptor digest '{}'", descriptor.digest))?;
        if descriptor.media_type.trim().is_empty() {
            return Err(anyhow!(
                "Descriptor '{}' has an empty mediaType",
                descriptor.digest
            ));
        }
    }
    Ok(())
}

pub fn load_model(model: &ModelRef) -> Result<ResolvedModel> {
    let file = open_readonly_nofollow(&model.manifest_path)?;
    let manifest_bytes = read_all_from_file(&file, MAX_MANIFEST_BYTES)?;
    let manifest = parse_manifest_bytes(&manifest_bytes)
        .with_context(|| format!("Manifest '{}' is invalid", model.manifest_path.display()))?;

    let digest = format!("sha256:{}", hex::encode(Sha256::digest(&manifest_bytes)));
    Ok(ResolvedModel {
        name: model.name.clone(),
        manifest,
        manifest_bytes,
        digest,
    })
}

fn canonical_model_name(relative: &Path) -> Result<String> {
    let components: Vec<String> = relative
        .components()
        .map(|component| match component {
            Component::Normal(value) => value
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow!("Manifest path contains non-UTF-8 components")),
            _ => Err(anyhow!("Manifest path contains an unsafe component")),
        })
        .collect::<Result<Vec<_>>>()?;

    // <registry>/<namespace...>/<model>/<tag>
    if components.len() < 3 {
        return Err(anyhow!(
            "Expected manifest path <registry>/<repository>/<tag>, got {} component(s)",
            components.len()
        ));
    }

    let registry = &components[0];
    let tag = components.last().expect("length checked");
    let repository = components[1..components.len() - 1].join("/");
    validate_path_component(registry, "registry")?;
    validate_path_component(tag, "tag")?;
    for part in &components[1..components.len() - 1] {
        validate_path_component(part, "repository")?;
    }

    Ok(format!("{registry}/{repository}:{tag}"))
}

fn validate_selector(selector: &str) -> Result<()> {
    if selector.trim().is_empty() || selector.contains('\\') {
        return Err(anyhow!(
            "Model selector is empty or contains an invalid separator"
        ));
    }
    for part in selector.split('/') {
        let name_part = part.split(':').next().unwrap_or_default();
        if name_part == "." || name_part == ".." || name_part.is_empty() {
            return Err(anyhow!("Model selector contains an unsafe path component"));
        }
    }
    Ok(())
}

fn validate_path_component(component: &str, label: &str) -> Result<()> {
    if component.is_empty() || component == "." || component == ".." {
        return Err(anyhow!("Model {label} component '{component}' is invalid"));
    }
    if component.contains('/') || component.contains('\\') {
        return Err(anyhow!(
            "Model {label} component '{component}' contains a path separator"
        ));
    }
    Ok(())
}

fn normalize_selector(selector: &str) -> String {
    let selector = selector.trim();
    let last_slash = selector.rfind('/');
    let last_colon = selector.rfind(':');
    let has_tag = matches!((last_slash, last_colon), (_, Some(colon)) if last_slash.is_none_or(|slash| colon > slash));
    if has_tag {
        selector.to_owned()
    } else {
        format!("{selector}:latest")
    }
}

fn model_matches(canonical: &str, selector: &str) -> bool {
    if canonical == selector {
        return true;
    }

    let canonical_without_registry = canonical
        .split_once('/')
        .map(|(_, rest)| rest)
        .unwrap_or(canonical);
    if canonical_without_registry == selector {
        return true;
    }

    let short = canonical_without_registry
        .rsplit_once('/')
        .map(|(_, rest)| rest)
        .unwrap_or(canonical_without_registry);
    short == selector
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const DIGEST: &str = "sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abc1";

    #[test]
    fn resolve_blob_path_rewrites_digest_separator() {
        assert_eq!(
            resolve_blob_path(Path::new("/tmp/models"), DIGEST).unwrap(),
            PathBuf::from(format!("/tmp/models/blobs/{}", DIGEST.replace(':', "-")))
        );
    }

    #[test]
    fn resolve_blob_path_rejects_traversal_in_digest() {
        assert!(resolve_blob_path(Path::new("/tmp/models"), "sha256:../../etc/passwd").is_err());
    }

    #[test]
    fn canonical_name_preserves_registry_and_namespace() {
        let name = canonical_model_name(Path::new("registry.example/team/sub/model/v1")).unwrap();
        assert_eq!(name, "registry.example/team/sub/model:v1");
    }

    #[test]
    fn short_selector_matches_canonical_name() {
        assert!(model_matches(
            "registry.ollama.ai/library/llama3:8b",
            "llama3:8b"
        ));
        assert!(model_matches(
            "registry.ollama.ai/acme/llama3:8b",
            "acme/llama3:8b"
        ));
    }

    #[test]
    fn selector_defaults_to_latest_and_allows_namespaces() {
        assert_eq!(normalize_selector("acme/model"), "acme/model:latest");
        assert_eq!(
            normalize_selector("localhost:5000/acme/model"),
            "localhost:5000/acme/model:latest"
        );
        assert_eq!(normalize_selector("acme/model:v2"), "acme/model:v2");
    }

    #[test]
    fn parser_rejects_empty_and_malformed_manifests() {
        assert!(parse_manifest_bytes(br#"{}"#).is_err());
        assert!(parse_manifest_bytes(br#"{not-json}"#).is_err());
        assert!(parse_manifest_bytes(
            br#"{"layers":[{"mediaType":"x","digest":"sha256:nope","size":1}]}"#
        )
        .is_err());
    }

    #[test]
    fn loads_layer_only_manifest() -> Result<()> {
        let root = std::env::temp_dir().join("layerfault_manifest_layer_only");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        let path = root.join("manifest");
        fs::write(
            &path,
            format!(
                r#"{{"layers":[{{"mediaType":"application/vnd.ollama.image.tensor; name=x","digest":"{DIGEST}","size":1}}]}}"#
            ),
        )?;
        let model = load_model(&ModelRef {
            name: "registry/acme/model:latest".to_owned(),
            manifest_path: path,
        })?;
        assert!(model.manifest.config.is_none());
        assert_eq!(
            model.manifest.layers[0].base_media_type(),
            "application/vnd.ollama.image.tensor"
        );
        let _ = fs::remove_dir_all(root);
        Ok(())
    }
}
