//! Candelabra - a desktop-friendly wrapper around Candle for
//! quantized GGUF models (LLaMA, Qwen, Phi, Gemma).
//!
//! This crate provides:
//! - Async model downloads with progress reporting
//! - Optional Metal/CUDA device selection with CPU fallback
//! - Reusable model/tokenizer state for repeated inference runs
//! - A small, GUI-friendly API for token streaming and cancellation
//!
//! # Scope
//!
//! `candelabra` supports multi-architecture inference for quantized GGUFs
//! dynamically extracting the architecture string (llama, phi3, qwen2, etc)
//! to invoke the proper `candle-transformers` backend.
//!
//! # Example
//!
//! ```no_run
//! use candelabra::{download_model, load_tokenizer_from_repo, Model, InferenceConfig, run_inference};
//! use std::sync::{Arc, atomic::AtomicBool};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let model_path = download_model(
//!         "bartowski/SmolLM2-360M-Instruct-GGUF",
//!         "SmolLM2-360M-Instruct-Q4_K_M.gguf",
//!     )?;
//!     let tokenizer = load_tokenizer_from_repo("HuggingFaceTB/SmolLM2-360M-Instruct")?;
//!     let mut model = Model::load(&model_path)?;
//!     let cancel_token = Arc::new(AtomicBool::new(false));
//!     let config = InferenceConfig::default();
//!
//!     let _result = run_inference(
//!         &mut model,
//!         &tokenizer,
//!         &config,
//!         cancel_token,
//!         |_| Ok(()),
//!     )?;
//!
//!     Ok(())
//! }
//! ```

mod config;
mod device;
mod download;
mod inference;
mod model;

pub use config::{
    InferenceConfig, InferenceResult, InferenceTelemetry, ProfiledInferenceResult, StopReason,
};
pub use device::{get_best_device, get_device, DeviceType};
pub use download::{
    check_model_cached, download_model, download_model_with_channel, download_model_with_progress,
    download_tokenizer, download_tokenizer_with_channel, download_tokenizer_with_progress,
    load_tokenizer, load_tokenizer_from_repo, DownloadProgress,
};
pub use inference::{run_inference, run_inference_profiled, run_inference_with_channel};
pub use model::Model;

/// Error type for all candelabra operations.
#[derive(Debug, thiserror::Error)]
pub enum CandelabraError {
    /// Download failed
    #[error("Download error: {0}")]
    Download(String),

    /// Model loading failed
    #[error("Model error: {0}")]
    Model(String),

    /// Inference failed
    #[error("Inference error: {0}")]
    Inference(String),

    /// Tokenizer error
    #[error("Tokenizer error: {0}")]
    Tokenizer(String),

    /// Operation was cancelled
    #[error("Operation cancelled")]
    Cancelled,

    /// I/O error
    #[error("I/O error: {0}")]
    Io(String),

    /// Device error
    #[error("Device error: {0}")]
    Device(String),
}

impl From<std::io::Error> for CandelabraError {
    fn from(e: std::io::Error) -> Self {
        CandelabraError::Io(e.to_string())
    }
}

impl From<tokenizers::Error> for CandelabraError {
    fn from(e: tokenizers::Error) -> Self {
        CandelabraError::Tokenizer(e.to_string())
    }
}

impl From<candle_core::Error> for CandelabraError {
    fn from(e: candle_core::Error) -> Self {
        CandelabraError::Inference(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, CandelabraError>;
