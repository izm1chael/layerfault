//! Explicit networked Hugging Face Hub ingestion.
//!
//! No local scan/review command calls this module implicitly.

use anyhow::{anyhow, bail, Context, Result};
use reqwest::blocking::{Client, Response};
use reqwest::header::{AUTHORIZATION, LOCATION, RETRY_AFTER, USER_AGENT};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::{IpAddr, ToSocketAddrs};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};
use url::Url;

const API_BASE: &str = "https://huggingface.co";
const MAX_METADATA_BYTES: usize = 32 * 1024 * 1024;
const MAX_REDIRECTS: usize = 6;
const MAX_FILES: usize = 200_000;
const MAX_DOWNLOAD_BYTES: u64 = 200 * 1024 * 1024 * 1024;
const MAX_RETRIES: usize = 5;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HubLfsMetadata {
    pub oid: String,
    pub size: u64,
    #[serde(default, rename = "pointerSize")]
    pub pointer_size: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IntegrityExpectationSource {
    GitLfs,
    GitBlob,
    None,
    UnsupportedAlgorithm,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoteObjectExpectation {
    pub sha256: Option<String>,
    pub size: Option<u64>,
    pub source: IntegrityExpectationSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IntegrityResult {
    Match,
    Mismatch,
    #[default]
    ExpectationUnavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubFile {
    #[serde(rename = "rfilename")]
    pub path: String,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default, rename = "blobId")]
    pub blob_id: Option<String>,
    #[serde(default)]
    pub lfs: Option<serde_json::Value>,
}

impl HubFile {
    pub fn lfs_metadata(&self) -> Result<Option<HubLfsMetadata>> {
        let Some(val) = &self.lfs else {
            return Ok(None);
        };
        if val.is_null() {
            return Ok(None);
        }
        let meta: HubLfsMetadata = serde_json::from_value(val.clone())
            .context("invalid LFS metadata structure in Hub file record")?;
        Ok(Some(meta))
    }

    pub fn expectation(&self) -> Result<RemoteObjectExpectation> {
        if let Some(lfs) = self.lfs_metadata()? {
            let raw_oid = lfs.oid.trim();
            if raw_oid.is_empty() {
                bail!("LFS metadata carries an empty OID string");
            }
            let (alg, hex_part) = if let Some(stripped) = raw_oid.strip_prefix("sha256:") {
                ("sha256", stripped)
            } else if raw_oid.contains(':') {
                return Ok(RemoteObjectExpectation {
                    sha256: None,
                    size: Some(lfs.size),
                    source: IntegrityExpectationSource::UnsupportedAlgorithm,
                });
            } else {
                ("sha256", raw_oid)
            };

            if alg != "sha256" {
                return Ok(RemoteObjectExpectation {
                    sha256: None,
                    size: Some(lfs.size),
                    source: IntegrityExpectationSource::UnsupportedAlgorithm,
                });
            }

            if hex_part.len() != 64 || !hex_part.bytes().all(|b| b.is_ascii_hexdigit()) {
                bail!("LFS OID '{raw_oid}' is not a valid 64-character hexadecimal SHA-256 digest");
            }

            if lfs.size > MAX_DOWNLOAD_BYTES {
                bail!(
                    "LFS declared size {} exceeds maximum configured download cap {}",
                    lfs.size,
                    MAX_DOWNLOAD_BYTES
                );
            }

            if let Some(file_size) = self.size {
                if file_size != lfs.size {
                    bail!(
                        "API file size ({file_size}) conflicts with LFS declared size ({})",
                        lfs.size
                    );
                }
            }

            if let Some(pointer_size) = lfs.pointer_size {
                if pointer_size == 0 || pointer_size > 4096 {
                    bail!("LFS pointer_size {pointer_size} is outside safe bounds");
                }
            }

            let normalized_sha = format!("sha256:{}", hex_part.to_ascii_lowercase());
            return Ok(RemoteObjectExpectation {
                sha256: Some(normalized_sha),
                size: Some(lfs.size),
                source: IntegrityExpectationSource::GitLfs,
            });
        }

        Ok(RemoteObjectExpectation {
            sha256: None,
            size: self.size,
            source: IntegrityExpectationSource::None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubModel {
    #[serde(alias = "modelId", alias = "id")]
    pub id: String,
    #[serde(default)]
    pub sha: Option<String>,
    #[serde(default)]
    pub private: bool,
    #[serde(default)]
    pub gated: serde_json::Value,
    #[serde(default)]
    pub siblings: Vec<HubFile>,
    #[serde(default, rename = "lastModified")]
    pub last_modified: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub pipeline_tag: Option<String>,
    #[serde(default)]
    pub library_name: Option<String>,
    #[serde(default)]
    pub card_data: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubRevision {
    pub repo: String,
    pub requested_revision: String,
    pub commit_sha: String,
    pub observed_unix: u64,
    pub files: Vec<HubFile>,
    pub claims: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadResult {
    pub repo: String,
    pub revision: String,
    pub file: String,
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
    pub elapsed_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_bytes: Option<u64>,
    #[serde(default)]
    pub integrity_result: IntegrityResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlPage {
    pub models: Vec<HubModel>,
    pub next: Option<String>,
}

/// True when a Hugging Face repository member can materially affect model
/// loading, execution, structure, tokenizer/template behaviour, or package
/// admission. Hosted/direct reviews must share this selector so a PASS never
/// means "only weight/config suffixes happened to be downloaded".
pub fn is_security_relevant_member(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    [
        ".gguf",
        ".safetensors",
        ".safetensors.index.json",
        ".onnx",
        ".tflite",
        ".keras",
        ".h5",
        ".hdf5",
        ".pb",
        ".pkl",
        ".pickle",
        ".joblib",
        ".pt",
        ".pth",
        ".ckpt",
        ".bin",
        ".py",
        ".pyi",
        ".sh",
        ".ps1",
        ".bat",
        ".cmd",
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".node",
        ".jar",
        ".json",
        ".toml",
        ".yaml",
        ".yml",
        ".jinja",
        ".j2",
    ]
    .iter()
    .any(|suffix| lower.ends_with(suffix))
        || matches!(
            name,
            "setup.py"
                | "pyproject.toml"
                | "requirements.txt"
                | "requirements-dev.txt"
                | "environment.yml"
                | "environment.yaml"
                | "model_index.json"
                | "configuration.json"
        )
}

pub struct HubClient {
    client: Client,
    token: Option<String>,
    user_agent: String,
}

impl HubClient {
    pub fn new(token: Option<String>) -> Result<Self> {
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(120))
            .build()?;
        Ok(Self {
            client,
            token,
            user_agent: format!("layerfault/{}", env!("CARGO_PKG_VERSION")),
        })
    }

    pub fn model(&self, repo: &str, revision: Option<&str>) -> Result<HubRevision> {
        validate_repo_id(repo)?;
        let requested = revision.unwrap_or("main");
        validate_revision(requested)?;
        let mut url = Url::parse(API_BASE)?;
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| anyhow!("invalid API base URL"))?;
            segments.push("api").push("models");
            for component in repo.split('/') {
                segments.push(component);
            }
            segments.push("revision").push(requested);
        }
        let response = self.get_following(url, MAX_METADATA_BYTES as u64)?;
        let bytes = read_response_capped(response, MAX_METADATA_BYTES)?;
        let model: HubModel =
            serde_json::from_slice(&bytes).context("invalid Hub model metadata response")?;
        let sha = model
            .sha
            .as_deref()
            .ok_or_else(|| anyhow!("Hub response did not include an immutable commit SHA"))?;
        validate_commit_sha(sha)?;
        if model.siblings.len() > MAX_FILES {
            bail!("Hub model contains more than {MAX_FILES} files");
        }
        for file in &model.siblings {
            validate_member_path(&file.path)?;
        }
        Ok(HubRevision {
            repo: repo.to_owned(),
            requested_revision: requested.to_owned(),
            commit_sha: sha.to_owned(),
            observed_unix: crate::paths::now_unix(),
            files: model.siblings,
            claims: serde_json::json!({
                "tags":model.tags,
                "pipeline_tag":model.pipeline_tag,
                "library_name":model.library_name,
                "card_data":model.card_data,
                "private":model.private,
                "gated":model.gated
            }),
        })
    }

    pub fn list_models(&self, limit: usize, next: Option<&str>) -> Result<CrawlPage> {
        let limit = limit.clamp(1, 1000);
        let url = match next {
            Some(next) => {
                let url = Url::parse(next).context("invalid Hub crawl cursor URL")?;
                validate_url(&url)?;
                if url.host_str() != Some("huggingface.co")
                    || !url.path().starts_with("/api/models")
                {
                    bail!("crawl cursor points outside the Hugging Face models API");
                }
                url
            }
            None => {
                let mut url = Url::parse("https://huggingface.co/api/models")?;
                url.query_pairs_mut()
                    .append_pair("limit", &limit.to_string())
                    .append_pair("full", "true")
                    .append_pair("sort", "lastModified")
                    .append_pair("direction", "-1");
                url
            }
        };
        let response = self.get_following(url, MAX_METADATA_BYTES as u64)?;
        let next = parse_next_link(
            response
                .headers()
                .get("link")
                .and_then(|value| value.to_str().ok()),
        );
        let bytes = read_response_capped(response, MAX_METADATA_BYTES)?;
        let mut models: Vec<HubModel> =
            serde_json::from_slice(&bytes).context("invalid Hub model-list response")?;
        if models.len() > limit {
            models.truncate(limit);
        }
        Ok(CrawlPage { models, next })
    }

    pub fn download_verified(
        &self,
        repo: &str,
        revision: &str,
        file: &HubFile,
        staging: &Path,
        max_bytes: Option<u64>,
    ) -> Result<DownloadResult> {
        validate_repo_id(repo)?;
        validate_commit_sha(revision)?;
        validate_member_path(&file.path)?;
        crate::paths::ensure_private_dir(staging)?;

        let expectation = file.expectation().map_err(|err| {
            anyhow!(
                "LF-HF-LFS-METADATA-INVALID: member '{}' carries invalid LFS metadata: {err}",
                file.path
            )
        })?;

        let configured_cap = max_bytes
            .unwrap_or(MAX_DOWNLOAD_BYTES)
            .min(MAX_DOWNLOAD_BYTES);

        if let Some(expected_size) = expectation.size {
            if expected_size > configured_cap {
                bail!(
                    "LF-HF-LFS-SIZE-MISMATCH: member '{}' declared size ({expected_size} bytes) exceeds configured maximum ({configured_cap} bytes)",
                    file.path
                );
            }
        }

        let destination = safe_destination(staging, &file.path)?;
        ensure_safe_staging_parent(staging, &file.path)?;

        if crate::object_cache::enabled() {
            if let (Some(expected_oid), Some(expected_size)) =
                (expectation.sha256.as_deref(), expectation.size)
            {
                if let Ok(Some(cached)) = crate::object_cache::lookup_and_stage(
                    expected_oid,
                    expected_size,
                    repo,
                    revision,
                    &file.path,
                    &destination,
                ) {
                    return Ok(cached);
                }
            }
        }

        let partial = destination.with_extension(format!(
            "{}.layerfault-part",
            destination
                .extension()
                .and_then(|v| v.to_str())
                .unwrap_or("download")
        ));
        let _ = std::fs::remove_file(&partial);

        let mut url = Url::parse(API_BASE)?;
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| anyhow!("invalid Hub base URL"))?;
            for component in repo.split('/') {
                segments.push(component);
            }
            segments.push("resolve").push(revision);
            // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
            for component in Path::new(&file.path).components() {
                if let Component::Normal(value) = component {
                    // `file.path` passed validate_member_path before URL construction.
                    // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
                    segments.push(&value.to_string_lossy());
                }
            }
        }
        let started = Instant::now();
        let mut response = self.get_following(url, configured_cap)?;
        if let Some(content_length) = response.content_length() {
            if content_length > configured_cap {
                bail!(
                    "Hub download is {content_length} bytes, above configured cap {configured_cap}"
                );
            }
            if let Some(expected_size) = expectation.size {
                if content_length != expected_size {
                    bail!(
                        "LF-HF-LFS-SIZE-MISMATCH: member '{}' HTTP Content-Length header ({content_length}) differs from Hub declared size ({expected_size})",
                        file.path
                    );
                }
            }
        }
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&partial)
            .with_context(|| {
                format!(
                    "unable to create private staging file '{}'",
                    partial.display()
                )
            })?;
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 1024 * 1024];
        let mut total = 0_u64;
        let download_res: Result<()> = (|| {
            loop {
                let read = response.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                total = total
                    .checked_add(read as u64)
                    .ok_or_else(|| anyhow!("download byte count overflow"))?;
                if total > configured_cap {
                    bail!("Hub download exceeded configured byte cap {configured_cap}");
                }
                output.write_all(&buffer[..read])?;
                hasher.update(&buffer[..read]);
            }
            output.sync_all()?;
            Ok(())
        })();
        if let Err(error) = download_res {
            let _ = std::fs::remove_file(&partial);
            return Err(error);
        }

        // Size expectation check
        if let Some(expected_size) = expectation.size {
            if total != expected_size {
                let _ = std::fs::remove_file(&partial);
                bail!(
                    "LF-HF-LFS-SIZE-MISMATCH: member '{}' observed download size ({total} bytes) differs from Hub declared size ({expected_size} bytes)",
                    file.path
                );
            }
        }

        let observed_sha256 = format!("sha256:{}", hex::encode(hasher.finalize()));

        // Digest OID expectation check
        if let Some(ref expected_oid) = expectation.sha256 {
            if !constant_time_eq(observed_sha256.as_bytes(), expected_oid.as_bytes()) {
                let _ = std::fs::remove_file(&partial);
                bail!(
                    "LF-HF-LFS-DIGEST-MISMATCH: member '{}' observed SHA-256 ({observed_sha256}) differs from Hub LFS OID ({expected_oid})",
                    file.path
                );
            }
        }

        if crate::object_cache::enabled() {
            if let (Some(expected_oid), Some(expected_size)) =
                (expectation.sha256.as_deref(), expectation.size)
            {
                if observed_sha256 == expected_oid {
                    let _ = crate::object_cache::insert_verified_object(
                        &partial,
                        expected_oid,
                        expected_size,
                        repo,
                        revision,
                        &file.path,
                        &destination,
                    );
                }
            }
        }

        if !destination.exists() {
            if let Err(err) = std::fs::rename(&partial, &destination) {
                let _ = std::fs::remove_file(&partial);
                return Err(err)
                    .context("unable to promote partial file to final staging destination");
            }
        }

        let integrity_result = if expectation.sha256.is_some() || expectation.size.is_some() {
            IntegrityResult::Match
        } else {
            IntegrityResult::ExpectationUnavailable
        };

        Ok(DownloadResult {
            repo: repo.to_owned(),
            revision: revision.to_owned(),
            file: file.path.clone(),
            path: destination.display().to_string(),
            bytes: total,
            sha256: observed_sha256,
            elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            expected_sha256: expectation.sha256,
            expected_bytes: expectation.size,
            integrity_result,
        })
    }

    pub fn download(
        &self,
        repo: &str,
        revision: &str,
        file: &str,
        staging: &Path,
        max_bytes: Option<u64>,
    ) -> Result<DownloadResult> {
        let hub_file = HubFile {
            path: file.to_owned(),
            size: None,
            blob_id: None,
            lfs: None,
        };
        self.download_verified(repo, revision, &hub_file, staging, max_bytes)
    }

    fn get_following(&self, mut url: Url, max_response_bytes: u64) -> Result<Response> {
        for redirect_index in 0..=MAX_REDIRECTS {
            validate_url(&url)?;
            let mut attempts = 0;
            loop {
                let mut request = self
                    .client
                    .get(url.clone())
                    .header(USER_AGENT, &self.user_agent);
                if url.host_str() == Some("huggingface.co") {
                    if let Some(token) = &self.token {
                        request = request.header(AUTHORIZATION, format!("Bearer {token}"));
                    }
                }
                let response = request
                    .send()
                    .with_context(|| format!("Hub request failed for {url}"))?;
                if response.status().as_u16() == 429 || response.status().is_server_error() {
                    attempts += 1;
                    if attempts >= MAX_RETRIES {
                        return Err(anyhow!(
                            "Hub request failed after {attempts} attempts with {}",
                            response.status()
                        ));
                    }
                    let delay = retry_delay(&response, attempts);
                    std::thread::sleep(delay);
                    continue;
                }
                if response.status().is_redirection() {
                    if redirect_index == MAX_REDIRECTS {
                        bail!("Hub redirect limit exceeded");
                    }
                    let location = response
                        .headers()
                        .get(LOCATION)
                        .ok_or_else(|| anyhow!("Hub redirect lacks Location header"))?
                        .to_str()?;
                    url = url.join(location)?;
                    break;
                }
                if !response.status().is_success() {
                    bail!("Hub request returned HTTP {} for {url}", response.status());
                }
                if let Some(length) = response.content_length() {
                    if length > max_response_bytes {
                        bail!("Hub response exceeds configured byte cap");
                    }
                }
                return Ok(response);
            }
        }
        bail!("Hub redirect processing failed")
    }
}

pub fn token_from_env() -> Option<String> {
    crate::paths::secret_from_env("HF_TOKEN").ok().flatten()
}

pub fn verify_webhook_secret(received: Option<&str>, expected: &str) -> bool {
    let Some(received) = received else {
        return false;
    };
    constant_time_eq(received.as_bytes(), expected.as_bytes())
}

fn read_response_capped(mut response: Response, cap: usize) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = response.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        if output.len().saturating_add(read) > cap {
            bail!("HTTP response exceeds {cap} byte cap");
        }
        output.extend_from_slice(&buffer[..read]);
    }
    Ok(output)
}

fn retry_delay(response: &Response, attempt: usize) -> Duration {
    if let Some(seconds) = response
        .headers()
        .get(RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
    {
        return Duration::from_secs(seconds.min(60));
    }
    let millis = (250_u64.saturating_mul(1_u64 << attempt.min(7))).min(10_000);
    Duration::from_millis(millis)
}

fn validate_url(url: &Url) -> Result<()> {
    if url.scheme() != "https" {
        bail!("Hub networking requires HTTPS");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("URL userinfo is forbidden");
    }
    let host = url.host_str().ok_or_else(|| anyhow!("URL has no host"))?;
    if !allowed_hub_host(host) {
        bail!("redirect host '{host}' is not in the Layerfault Hugging Face allow policy");
    }
    reject_private_resolution(host, url.port_or_known_default().unwrap_or(443))?;
    Ok(())
}

fn allowed_hub_host(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    host == "huggingface.co"
        || host.ends_with(".huggingface.co")
        || host.ends_with(".hf.co")
        || host.ends_with(".xethub.hf.co")
}

fn reject_private_resolution(host: &str, port: u16) -> Result<()> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        if blocked_ip(ip) {
            bail!("Hub URL resolves directly to blocked address {ip}");
        }
        return Ok(());
    }
    let addresses: Vec<_> = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("unable to resolve Hub host '{host}'"))?
        .collect();
    if addresses.is_empty() {
        bail!("Hub host '{host}' resolved to no addresses");
    }
    if addresses.iter().any(|address| blocked_ip(address.ip())) {
        bail!("Hub host '{host}' resolved to a private/loopback/link-local address");
    }
    Ok(())
}

fn blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_broadcast()
                || v.is_documentation()
                || v.is_unspecified()
                || v.octets()[0] == 0
                || v.octets()[0] >= 224
                || v.octets() == [169, 254, 169, 254]
        }
        IpAddr::V6(v) => {
            v.is_loopback()
                || v.is_unspecified()
                || v.is_unique_local()
                || v.is_unicast_link_local()
        }
    }
}
fn validate_repo_id(repo: &str) -> Result<()> {
    let mut parts = repo.split('/');
    let owner = parts.next().unwrap_or("");
    let name = parts.next().unwrap_or("");
    if owner.is_empty()
        || name.is_empty()
        || parts.next().is_some()
        || ![owner, name].into_iter().all(valid_slug)
    {
        bail!("Hub model id must be OWNER/NAME using safe repository characters");
    }
    Ok(())
}
fn valid_slug(value: &str) -> bool {
    value.len() <= 256
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && !value.starts_with('.')
        && !value.ends_with('.')
}
fn validate_revision(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 512
        || value.contains("..")
        || value.contains('\\')
        || value.chars().any(char::is_control)
    {
        bail!("unsafe Hub revision");
    }
    Ok(())
}
fn validate_commit_sha(value: &str) -> Result<()> {
    if value.len() < 40 || value.len() > 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("Hub revision is not an immutable hexadecimal commit SHA");
    }
    Ok(())
}
fn validate_member_path(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 16 * 1024 || value.contains("://") {
        bail!("unsafe Hub repository member path");
    }
    // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
    let path = Path::new(value);
    if path.is_absolute()
        || path
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        bail!("unsafe Hub repository member path '{value}'");
    }
    Ok(())
}
fn safe_destination(root: &Path, relative: &str) -> Result<PathBuf> {
    validate_member_path(relative)?;
    let root_meta = std::fs::symlink_metadata(root)
        .with_context(|| format!("unable to inspect staging root '{}'", root.display()))?;
    if root_meta.file_type().is_symlink() || !root_meta.is_dir() {
        bail!("staging root must be a real directory, not a symlink");
    }
    let canonical_root = std::fs::canonicalize(root)?;
    // `relative` passed validate_member_path and canonical_root is the real staging root.
    // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
    Ok(canonical_root.join(relative))
}
fn ensure_safe_staging_parent(root: &Path, relative: &str) -> Result<()> {
    validate_member_path(relative)?;
    let canonical_root = std::fs::canonicalize(root)?;
    let mut current = canonical_root.clone();
    // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
    let mut components = Path::new(relative).components().peekable();
    while let Some(component) = components.next() {
        if components.peek().is_none() {
            break;
        }
        let Component::Normal(name) = component else {
            bail!("unsafe Hub repository member path");
        };
        // `name` comes from a validated relative member path.
        // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
        current.push(name);
        match std::fs::symlink_metadata(&current) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.is_dir() {
                    bail!(
                        "staging path component '{}' is not a real directory",
                        current.display()
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                crate::paths::ensure_private_dir(&current)?;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("unable to inspect staging path '{}'", current.display())
                })
            }
        }
        let canonical = std::fs::canonicalize(&current)?;
        if !canonical.starts_with(&canonical_root) {
            bail!("staging destination escapes root");
        }
    }
    Ok(())
}
fn parse_next_link(header: Option<&str>) -> Option<String> {
    let header = header?;
    for part in header.split(',') {
        let mut pieces = part.split(';');
        let url = pieces
            .next()?
            .trim()
            .trim_start_matches('<')
            .trim_end_matches('>');
        let rel = pieces.any(|p| {
            p.trim().eq_ignore_ascii_case("rel=\"next\"")
                || p.trim().eq_ignore_ascii_case("rel=next")
        });
        if rel {
            return Some(url.to_owned());
        }
    }
    None
}
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn blocks_private_ips() {
        assert!(blocked_ip("127.0.0.1".parse().unwrap()));
        assert!(blocked_ip("169.254.169.254".parse().unwrap()));
        assert!(!blocked_ip("8.8.8.8".parse().unwrap()));
    }
    #[test]
    fn validates_repo() {
        assert!(validate_repo_id("org/model-name").is_ok());
        assert!(validate_repo_id("../../etc/passwd").is_err());
    }
    #[test]
    fn secret_compare() {
        assert!(verify_webhook_secret(Some("abc"), "abc"));
        assert!(!verify_webhook_secret(Some("abd"), "abc"));
    }
    #[test]
    fn security_member_selector_includes_loader_and_serialization_risk() {
        for path in [
            "pytorch_model.bin",
            "weights/model.pkl",
            "model.safetensors",
            "loader.py",
            "native/extension.so",
            "config.json",
            "chat_template.jinja",
            "requirements.txt",
        ] {
            assert!(
                is_security_relevant_member(path),
                "expected security member: {path}"
            );
        }
        assert!(!is_security_relevant_member("README.md"));
        assert!(!is_security_relevant_member("assets/logo.png"));
    }

    #[test]
    fn lfs_expectation_valid_sha256() {
        let file = HubFile {
            path: "model.safetensors".to_owned(),
            size: Some(1024),
            blob_id: None,
            lfs: Some(serde_json::json!({
                "oid": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "size": 1024,
                "pointerSize": 128
            })),
        };
        let exp = file.expectation().unwrap();
        assert_eq!(
            exp.sha256,
            Some(
                "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    .to_owned()
            )
        );
        assert_eq!(exp.size, Some(1024));
        assert_eq!(exp.source, IntegrityExpectationSource::GitLfs);
    }

    #[test]
    fn lfs_expectation_normalizes_uppercase_hex() {
        let file = HubFile {
            path: "model.safetensors".to_owned(),
            size: Some(1024),
            blob_id: None,
            lfs: Some(serde_json::json!({
                "oid": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
                "size": 1024
            })),
        };
        let exp = file.expectation().unwrap();
        assert_eq!(
            exp.sha256,
            Some(
                "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    .to_owned()
            )
        );
    }

    #[test]
    fn lfs_expectation_malformed_oid() {
        let file = HubFile {
            path: "model.safetensors".to_owned(),
            size: Some(1024),
            blob_id: None,
            lfs: Some(serde_json::json!({
                "oid": "sha256:invalid_hex_string",
                "size": 1024
            })),
        };
        assert!(file.expectation().is_err());
    }

    #[test]
    fn lfs_expectation_unsupported_algorithm() {
        let file = HubFile {
            path: "model.safetensors".to_owned(),
            size: Some(1024),
            blob_id: None,
            lfs: Some(serde_json::json!({
                "oid": "sha512:abcdef123456",
                "size": 1024
            })),
        };
        let exp = file.expectation().unwrap();
        assert_eq!(exp.sha256, None);
        assert_eq!(exp.source, IntegrityExpectationSource::UnsupportedAlgorithm);
    }

    #[test]
    fn lfs_expectation_size_conflict() {
        let file = HubFile {
            path: "model.safetensors".to_owned(),
            size: Some(2048),
            blob_id: None,
            lfs: Some(serde_json::json!({
                "oid": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "size": 1024
            })),
        };
        assert!(file.expectation().is_err());
    }

    #[test]
    fn lfs_expectation_missing_lfs() {
        let file = HubFile {
            path: "model.safetensors".to_owned(),
            size: Some(1024),
            blob_id: None,
            lfs: None,
        };
        let exp = file.expectation().unwrap();
        assert_eq!(exp.sha256, None);
        assert_eq!(exp.size, Some(1024));
        assert_eq!(exp.source, IntegrityExpectationSource::None);
    }
}
