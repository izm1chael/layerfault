//! Hugging Face download and tokenizer helpers for desktop apps.

use crate::CandelabraError;
use futures::StreamExt;
use hf_hub::{
    api::sync::{ApiBuilder, ApiRepo},
    Cache, Repo,
};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;
use tokenizers::Tokenizer;
use tokio::sync::mpsc::Sender;

const DEFAULT_REVISION: &str = "main";
const TOKENIZER_FILENAME: &str = "tokenizer.json";

/// Progress information emitted during model downloads.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DownloadProgress {
    /// Number of bytes downloaded so far.
    pub downloaded_bytes: u64,
    /// Total bytes to download (0 if unknown).
    pub total_bytes: u64,
    /// Download percentage (0.0-100.0).
    pub percentage: f32,
    /// Current download speed in bytes per second.
    pub speed_bytes_per_sec: f64,
    /// Name of the file being downloaded.
    pub filename: String,
}

struct RemoteMetadata {
    commit_hash: String,
    total_bytes: u64,
}

/// Checks if a model file is already present in the local Hugging Face cache.
pub fn check_model_cached(repo_id: &str, filename: &str) -> bool {
    cached_model_path(&Cache::default(), repo_id, filename).is_some()
}

/// Downloads a model file via `hf-hub` and returns the local cached path.
pub fn download_model(repo_id: &str, filename: &str) -> Result<PathBuf, CandelabraError> {
    let api = build_hf_api()?;
    api.model(repo_id.to_string())
        .get(filename)
        .map_err(|e| CandelabraError::Download(format!("Failed to download model file: {}", e)))
}

/// Downloads a tokenizer file via `hf-hub` and returns the local cached path.
pub fn download_tokenizer(repo_id: &str) -> Result<PathBuf, CandelabraError> {
    download_model(repo_id, TOKENIZER_FILENAME)
}

/// Loads a tokenizer from disk.
pub fn load_tokenizer<P: AsRef<Path>>(path: P) -> Result<Tokenizer, CandelabraError> {
    Tokenizer::from_file(path.as_ref())
        .map_err(|e| CandelabraError::Tokenizer(format!("Failed to load tokenizer: {}", e)))
}

/// Downloads and loads a tokenizer from the Hugging Face cache.
pub fn load_tokenizer_from_repo(repo_id: &str) -> Result<Tokenizer, CandelabraError> {
    let tokenizer_path = download_tokenizer(repo_id)?;
    load_tokenizer(tokenizer_path)
}

/// Downloads a model file with progress reporting via callback.
pub async fn download_model_with_progress<F>(
    repo_id: &str,
    filename: &str,
    mut on_progress: F,
) -> Result<PathBuf, CandelabraError>
where
    F: FnMut(DownloadProgress) + Send,
{
    if let Some(cached_path) = Cache::default().model(repo_id.to_string()).get(filename) {
        emit_cached_progress(filename, &cached_path, &mut on_progress)?;
        return Ok(cached_path);
    }

    let api = build_hf_api()?;
    let repo = api.model(repo_id.to_string());
    let metadata = fetch_remote_metadata(&repo, filename).await?;
    let file_path = get_snapshot_file_path(repo_id, &metadata.commit_hash, filename);

    if let Some(parent) = file_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let temp_path = temp_download_path(&file_path);
    if temp_path.exists() {
        let _ = std::fs::remove_file(&temp_path);
    }

    let client = build_http_client()?;
    let url = repo.url(filename);
    let mut request = client.get(&url);
    if let Some(token) = Cache::default().token() {
        request = request.bearer_auth(token);
    }

    let response = request
        .send()
        .await
        .map_err(|e| CandelabraError::Download(format!("Failed to start download: {}", e)))?;

    if !response.status().is_success() {
        return Err(CandelabraError::Download(format!(
            "Download failed with status: {}",
            response.status()
        )));
    }

    let total_bytes = response.content_length().unwrap_or(metadata.total_bytes);
    let mut file = std::fs::File::create(&temp_path)?;
    let mut downloaded = 0_u64;
    let mut stream = response.bytes_stream();
    let mut speed_samples: VecDeque<(Instant, u64)> = VecDeque::new();

    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result
            .map_err(|e| CandelabraError::Download(format!("Download stream error: {}", e)))?;

        file.write_all(&chunk)?;
        downloaded += chunk.len() as u64;

        let now = Instant::now();
        speed_samples.push_back((now, downloaded));
        while let Some((time, _)) = speed_samples.front() {
            if now.duration_since(*time).as_secs_f64() > 1.0 {
                speed_samples.pop_front();
            } else {
                break;
            }
        }

        on_progress(DownloadProgress {
            downloaded_bytes: downloaded,
            total_bytes,
            percentage: percentage(downloaded, total_bytes),
            speed_bytes_per_sec: rolling_speed(&speed_samples, downloaded, now),
            filename: filename.to_string(),
        });
    }

    file.flush()?;
    drop(file);

    std::fs::rename(&temp_path, &file_path)?;
    create_cache_ref(repo_id, &metadata.commit_hash)?;

    Ok(file_path)
}

/// Downloads a model file with progress reporting via Tokio channel.
pub async fn download_model_with_channel(
    repo_id: &str,
    filename: &str,
    progress_tx: Sender<DownloadProgress>,
) -> Result<PathBuf, CandelabraError> {
    download_model_with_progress(repo_id, filename, move |progress| {
        let _ = progress_tx.blocking_send(progress);
    })
    .await
}

/// Downloads a tokenizer file with progress reporting via callback.
pub async fn download_tokenizer_with_progress<F>(
    repo_id: &str,
    on_progress: F,
) -> Result<PathBuf, CandelabraError>
where
    F: FnMut(DownloadProgress) + Send,
{
    download_model_with_progress(repo_id, TOKENIZER_FILENAME, on_progress).await
}

/// Downloads a tokenizer file with progress reporting via Tokio channel.
pub async fn download_tokenizer_with_channel(
    repo_id: &str,
    progress_tx: Sender<DownloadProgress>,
) -> Result<PathBuf, CandelabraError> {
    download_model_with_channel(repo_id, TOKENIZER_FILENAME, progress_tx).await
}

fn build_hf_api() -> Result<hf_hub::api::sync::Api, CandelabraError> {
    ApiBuilder::new()
        .with_progress(false)
        .build()
        .map_err(|e| CandelabraError::Download(format!("Failed to create HF API: {}", e)))
}

fn build_http_client() -> Result<reqwest::Client, CandelabraError> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()
        .map_err(|e| CandelabraError::Download(format!("Failed to create HTTP client: {}", e)))
}

async fn fetch_remote_metadata(
    repo: &ApiRepo,
    filename: &str,
) -> Result<RemoteMetadata, CandelabraError> {
    let client = build_http_client()?;
    let mut request = client.head(repo.url(filename));
    if let Some(token) = Cache::default().token() {
        request = request.bearer_auth(token);
    }

    let head_response = request.send().await.ok();
    let total_bytes = head_response
        .as_ref()
        .and_then(reqwest::Response::content_length)
        .unwrap_or(0);

    let commit_hash = head_response
        .as_ref()
        .and_then(|response| response.headers().get("x-repo-commit"))
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| {
            repo.info()
                .map(|info| info.sha)
                .unwrap_or_else(|_| DEFAULT_REVISION.to_string())
        });

    Ok(RemoteMetadata {
        commit_hash,
        total_bytes,
    })
}

fn emit_cached_progress<F>(
    filename: &str,
    path: &Path,
    on_progress: &mut F,
) -> Result<(), CandelabraError>
where
    F: FnMut(DownloadProgress),
{
    let total_bytes = std::fs::metadata(path)?.len();
    on_progress(DownloadProgress {
        downloaded_bytes: total_bytes,
        total_bytes,
        percentage: 100.0,
        speed_bytes_per_sec: 0.0,
        filename: filename.to_string(),
    });
    Ok(())
}

fn cached_model_path(cache: &Cache, repo_id: &str, filename: &str) -> Option<PathBuf> {
    cache.model(repo_id.to_string()).get(filename)
}

fn get_snapshot_file_path(repo_id: &str, commit_hash: &str, filename: &str) -> PathBuf {
    let cache_root = Cache::default().path().clone();
    let repo = Repo::model(repo_id.to_string());
    cache_root
        .join(repo.folder_name())
        .join("snapshots")
        .join(commit_hash)
        .join(filename)
}

fn create_cache_ref(repo_id: &str, commit_hash: &str) -> Result<(), CandelabraError> {
    Cache::default()
        .model(repo_id.to_string())
        .create_ref(commit_hash)
        .map_err(|e| CandelabraError::Download(format!("Failed to update cache ref: {}", e)))
}

fn temp_download_path(file_path: &Path) -> PathBuf {
    let extension = file_path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| format!("{value}.tmp"))
        .unwrap_or_else(|| "tmp".to_string());
    file_path.with_extension(extension)
}

fn percentage(downloaded: u64, total_bytes: u64) -> f32 {
    if total_bytes == 0 {
        return 0.0;
    }
    (downloaded as f32 / total_bytes as f32) * 100.0
}

fn rolling_speed(samples: &VecDeque<(Instant, u64)>, downloaded: u64, now: Instant) -> f64 {
    if samples.len() < 2 {
        return 0.0;
    }

    let Some((oldest_time, oldest_bytes)) = samples.front() else {
        return 0.0;
    };
    let elapsed = now.duration_since(*oldest_time).as_secs_f64();
    if elapsed <= 0.0 {
        return 0.0;
    }

    (downloaded - *oldest_bytes) as f64 / elapsed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new() -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time before unix epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!("candelabra-test-{unique}"));
            fs::create_dir_all(&path).expect("failed to create temp dir");
            Self { path }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn check_model_cached_uses_hf_layout() {
        let temp_dir = TempDir::new();
        let cache_root = temp_dir.path.join("hub");
        fs::create_dir_all(&cache_root).expect("failed to create cache root");
        let cache = Cache::new(cache_root);

        let repo_id = "org/model";
        let filename = "weights.gguf";
        let commit_hash = "abc123";
        let snapshot_file = cache
            .path()
            .join(Repo::model(repo_id.to_string()).folder_name())
            .join("snapshots")
            .join(commit_hash)
            .join(filename);

        fs::create_dir_all(snapshot_file.parent().expect("snapshot parent"))
            .expect("failed to create snapshot dir");
        fs::write(&snapshot_file, b"model").expect("failed to write snapshot file");
        cache
            .model(repo_id.to_string())
            .create_ref(commit_hash)
            .expect("failed to create cache ref");

        assert!(cached_model_path(&cache, repo_id, filename).is_some());
    }

    #[test]
    fn rolling_speed_is_zero_without_enough_samples() {
        let samples = VecDeque::from([(Instant::now(), 128)]);
        assert_eq!(rolling_speed(&samples, 128, Instant::now()), 0.0);
    }

    #[test]
    fn percentage_handles_unknown_sizes() {
        assert_eq!(percentage(1024, 0), 0.0);
    }
}
