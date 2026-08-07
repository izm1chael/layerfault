//! Configuration and result types for inference.

use serde::{Deserialize, Serialize};

/// Configuration for inference runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceConfig {
    /// HuggingFace repo ID (e.g. "bartowski/SmolLM2-360M-Instruct-GGUF")
    pub model_id: String,
    /// GGUF filename within the repo
    pub filename: String,
    /// Prompt fed to the model for token generation
    pub prompt: String,
    /// Maximum number of tokens to generate
    pub max_tokens: usize,
    /// Sampling temperature (0.0 = deterministic, higher = more random)
    pub temperature: f64,
    /// Optional wall-clock time limit in seconds (stops generation early if hit)
    pub max_duration_secs: Option<u64>,
    /// Whether generation should stop when an end-of-sequence token is sampled.
    #[serde(default = "default_stop_on_eos")]
    pub stop_on_eos: bool,
}

fn default_stop_on_eos() -> bool {
    true
}

impl Default for InferenceConfig {
    /// Returns a lightweight default config using a small quantized model
    /// suitable for quick benchmarking without requiring large downloads.
    fn default() -> Self {
        Self {
            model_id: "bartowski/SmolLM2-360M-Instruct-GGUF".to_string(),
            filename: "SmolLM2-360M-Instruct-Q4_K_M.gguf".to_string(),
            prompt: "Tell me a story about a helpful robot.".to_string(),
            max_tokens: 100,
            temperature: 0.7,
            max_duration_secs: Some(10),
            stop_on_eos: true,
        }
    }
}

/// Result produced by a completed inference run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceResult {
    /// Tokens generated per second (excludes prompt pre-fill)
    pub tokens_per_second: f64,
    /// Total number of tokens generated
    pub total_tokens: usize,
    /// Wall-clock duration of the generation loop in milliseconds
    pub duration_ms: u64,
    /// The text that was generated
    pub generated_text: String,
    /// The compute device used for inference (e.g. "Metal GPU", "CUDA GPU", "CPU")
    pub device_used: String,
}

/// Reason an inference run stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// The configured token limit was reached.
    MaxTokens,
    /// An end-of-sequence token was generated.
    EosToken,
    /// The configured duration limit was reached.
    TimeLimit,
    /// The caller requested zero generated tokens.
    NoTokensRequested,
}

/// Fine-grained timing and throughput telemetry for an inference run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceTelemetry {
    /// Tokens in the encoded prompt.
    pub prompt_tokens: usize,
    /// Tokens emitted by the decoder.
    pub generated_tokens: usize,
    /// Prompt tokenization duration in milliseconds.
    pub tokenization_ms: f64,
    /// Prompt tensor creation duration in milliseconds.
    pub prompt_tensor_ms: f64,
    /// Prompt forward-pass duration in milliseconds.
    pub prefill_ms: f64,
    /// Prompt tokens processed per second.
    pub prefill_tokens_per_second: f64,
    /// Time from decode start until the first token callback completes.
    pub time_to_first_token_ms: f64,
    /// Decode-loop duration in milliseconds.
    pub decode_ms: f64,
    /// Generated tokens per second.
    pub decode_tokens_per_second: f64,
    /// Average completed-token interval in milliseconds.
    pub avg_inter_token_ms: f64,
    /// Median completed-token interval in milliseconds.
    pub p50_inter_token_ms: f64,
    /// 95th percentile completed-token interval in milliseconds.
    pub p95_inter_token_ms: f64,
    /// Aggregate sampling duration in milliseconds.
    pub sampling_ms: f64,
    /// Aggregate generated-token detokenization duration in milliseconds.
    pub detokenize_ms: f64,
    /// Aggregate token callback duration in milliseconds.
    pub callback_ms: f64,
    /// Why generation stopped.
    pub stop_reason: StopReason,
    /// The compute device used for inference.
    pub device_used: String,
    /// The selected device family.
    pub device_type: String,
    /// GGUF architecture reported by model metadata.
    pub architecture: String,
}

/// Result produced by a profiled inference run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfiledInferenceResult {
    /// Legacy inference result for existing consumers.
    pub result: InferenceResult,
    /// Fine-grained benchmark telemetry.
    pub telemetry: InferenceTelemetry,
}
