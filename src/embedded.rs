//! Embedded, Rust-native inference backend for admitted quantized GGUF models.
//!
//! This backend deliberately does not download models or tokenizers. The caller
//! supplies local paths that have already passed Layerfault admission.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Instant;

const MAX_PROMPT_BYTES: usize = 512 * 1024;
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_TOKENS: usize = 4096;
const MAX_DURATION_SECONDS: u64 = 600;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedIdentity {
    pub backend: String,
    pub version: String,
    pub architecture: String,
    pub model_sha256: String,
    pub tokenizer_sha256: String,
    pub deterministic_requested: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedResult {
    pub identity: EmbeddedIdentity,
    pub output: String,
    pub output_sha256: String,
    pub duration_ms: u64,
    pub max_tokens: usize,
    pub temperature: f64,
    pub stopped_for_output_cap: bool,
}

pub fn run(
    model_path: &Path,
    tokenizer_path: &Path,
    prompt: &str,
    max_tokens: usize,
    timeout_seconds: u64,
) -> Result<EmbeddedResult> {
    if prompt.len() > MAX_PROMPT_BYTES {
        bail!("embedded prompt exceeds {MAX_PROMPT_BYTES} byte safety cap");
    }
    let max_tokens = max_tokens.clamp(1, MAX_TOKENS);
    let timeout_seconds = timeout_seconds.clamp(1, MAX_DURATION_SECONDS);
    static_admit(model_path)?;
    require_regular_file(tokenizer_path, "tokenizer")?;

    let model_sha256 = hash_path(model_path)?;
    let tokenizer_sha256 = hash_path(tokenizer_path)?;
    let tokenizer = candelabra::load_tokenizer(tokenizer_path)
        .with_context(|| format!("unable to load tokenizer '{}'", tokenizer_path.display()))?;
    let mut model = candelabra::Model::load(model_path).with_context(|| {
        format!(
            "unable to load admitted GGUF '{}' into embedded backend",
            model_path.display()
        )
    })?;
    let architecture = model.architecture().to_owned();

    let config = candelabra::InferenceConfig {
        prompt: prompt.to_owned(),
        max_tokens,
        temperature: 0.0,
        max_duration_secs: Some(timeout_seconds),
        model_id: "local-admitted-model".to_owned(),
        filename: model_path
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("model.gguf")
            .to_owned(),
        ..Default::default()
    };

    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_for_callback = Arc::clone(&cancel);
    let mut output = String::new();
    let mut capped = false;
    let started = Instant::now();
    let _inference = candelabra::run_inference(&mut model, &tokenizer, &config, cancel, |token| {
        if output.len().saturating_add(token.len()) > MAX_OUTPUT_BYTES {
            capped = true;
            cancel_for_callback.store(true, Ordering::SeqCst);
            return Ok(());
        }
        output.push_str(&token);
        Ok(())
    })
    .map_err(|error| anyhow!("embedded inference failed: {error}"))?;

    Ok(EmbeddedResult {
        identity: EmbeddedIdentity {
            backend: "candelabra-candle".to_owned(),
            version: "0.2.0".to_owned(),
            architecture,
            model_sha256: format!("sha256:{model_sha256}"),
            tokenizer_sha256: format!("sha256:{tokenizer_sha256}"),
            deterministic_requested: true,
        },
        output_sha256: format!("sha256:{}", hex::encode(Sha256::digest(output.as_bytes()))),
        output,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        max_tokens,
        temperature: 0.0,
        stopped_for_output_cap: capped,
    })
}

fn static_admit(path: &Path) -> Result<()> {
    let report =
        crate::formats::artifact::inspect(path, crate::formats::artifact::ArtifactScanMode::Full)?;
    if report.blocking() {
        bail!(
            "static admission blocked artifact '{}'; embedded inference was not run",
            path.display()
        );
    }
    if report.format != crate::formats::ArtifactFormat::Gguf {
        bail!(
            "embedded candelabra backend currently requires GGUF; detected {}",
            report.format.as_str()
        );
    }
    Ok(())
}

fn require_regular_file(path: &Path, label: &str) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("unable to inspect {label} '{}'", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("{label} must be a regular non-symlink file");
    }
    Ok(())
}

fn hash_path(path: &Path) -> Result<String> {
    use std::io::Read;
    let mut file = crate::safeio::open_readonly_nofollow(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn hard_caps_are_bounded() {
        const _: () = assert!(super::MAX_TOKENS <= 4096);
        const _: () = assert!(super::MAX_OUTPUT_BYTES <= 1024 * 1024);
    }
}
