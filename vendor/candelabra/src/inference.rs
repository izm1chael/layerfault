//! Token streaming inference with cancellation support.

use crate::{
    CandelabraError, InferenceConfig, InferenceResult, InferenceTelemetry, Model,
    ProfiledInferenceResult, StopReason,
};
use candle_core::Tensor;
use candle_transformers::generation::LogitsProcessor;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokenizers::Tokenizer;
use tokio::sync::mpsc::Sender;

const EOS_TOKEN_CANDIDATES: &[&str] = &["<|endoftext|>", "</s>", "<|eot_id|>", "<|end|>"];

/// Runs inference using reusable model and tokenizer state.
pub fn run_inference<F>(
    model: &mut Model,
    tokenizer: &Tokenizer,
    config: &InferenceConfig,
    cancel_token: Arc<AtomicBool>,
    on_token: F,
) -> Result<InferenceResult, CandelabraError>
where
    F: FnMut(String) -> Result<(), CandelabraError>,
{
    run_inference_profiled(model, tokenizer, config, cancel_token, on_token)
        .map(|profiled| profiled.result)
}

/// Runs inference using reusable model and tokenizer state, returning detailed telemetry.
pub fn run_inference_profiled<F>(
    model: &mut Model,
    tokenizer: &Tokenizer,
    config: &InferenceConfig,
    cancel_token: Arc<AtomicBool>,
    mut on_token: F,
) -> Result<ProfiledInferenceResult, CandelabraError>
where
    F: FnMut(String) -> Result<(), CandelabraError>,
{
    if cancel_token.load(Ordering::Relaxed) {
        return Err(CandelabraError::Cancelled);
    }

    let tokenization_start = Instant::now();
    let tokens = tokenizer
        .encode(config.prompt.clone(), true)
        .map_err(|e| CandelabraError::Tokenizer(format!("Encoding error: {}", e)))?;
    let tokenization_duration = tokenization_start.elapsed();
    let prompt_tokens = tokens.get_ids().len();

    if config.max_tokens == 0 {
        return Ok(zero_profiled_result(
            model,
            prompt_tokens,
            tokenization_duration,
            StopReason::NoTokensRequested,
        ));
    }

    let mut all_tokens = tokens.get_ids().to_vec();
    let mut generated_text = String::new();
    let mut logits_processor = LogitsProcessor::new(1337, Some(config.temperature), None);
    let eos_tokens = resolve_eos_token_ids(tokenizer);

    let prompt_tensor_start = Instant::now();
    let input = Tensor::new(&all_tokens[..], &model.device)
        .map_err(|e| CandelabraError::Inference(format!("Prompt tensor creation error: {}", e)))?
        .unsqueeze(0)
        .map_err(|e| CandelabraError::Inference(format!("Prompt tensor unsqueeze error: {}", e)))?;
    let prompt_tensor_duration = prompt_tensor_start.elapsed();

    let prefill_start = Instant::now();
    let prompt_logits = model
        .weights
        .forward(&input, 0)
        .map_err(|e| CandelabraError::Inference(format!("Prompt forward pass error: {}", e)))?;
    let prefill_duration = prefill_start.elapsed();
    let mut current_logits = prepare_logits(prompt_logits)?;

    // Measure generated-token throughput after prompt pre-fill.
    let start = Instant::now();
    let mut tokens_count = 0_usize;
    let mut sampling_duration = Duration::ZERO;
    let mut detokenize_duration = Duration::ZERO;
    let mut callback_duration = Duration::ZERO;
    let mut token_intervals = Vec::with_capacity(config.max_tokens);
    let mut last_token_at = start;
    let mut stop_reason = StopReason::MaxTokens;

    for _ in 0..config.max_tokens {
        if cancel_token.load(Ordering::Relaxed) {
            return Err(CandelabraError::Cancelled);
        }
        if hit_time_limit(start, config.max_duration_secs) {
            stop_reason = StopReason::TimeLimit;
            break;
        }

        let sample_start = Instant::now();
        let next_token = logits_processor
            .sample(&current_logits)
            .map_err(|e| CandelabraError::Inference(format!("Sampling error: {}", e)))?;
        sampling_duration += sample_start.elapsed();

        all_tokens.push(next_token);
        tokens_count += 1;

        let detokenize_start = Instant::now();
        let token_text = tokenizer
            .decode(&[next_token], true)
            .map_err(|e| CandelabraError::Tokenizer(format!("Decoding error: {}", e)))?;
        detokenize_duration += detokenize_start.elapsed();

        generated_text.push_str(&token_text);
        let callback_start = Instant::now();
        on_token(token_text)?;
        callback_duration += callback_start.elapsed();

        let token_done_at = Instant::now();
        token_intervals.push(token_done_at.duration_since(last_token_at));
        last_token_at = token_done_at;

        if config.stop_on_eos && eos_tokens.contains(&next_token) {
            stop_reason = StopReason::EosToken;
            break;
        }

        let input = Tensor::new(&[next_token], &model.device)
            .map_err(|e| CandelabraError::Inference(format!("Token tensor creation error: {}", e)))?
            .unsqueeze(0)
            .map_err(|e| {
                CandelabraError::Inference(format!("Token tensor unsqueeze error: {}", e))
            })?;

        let generation_logits = model
            .weights
            .forward(&input, all_tokens.len() - 1)
            .map_err(|e| {
                CandelabraError::Inference(format!("Generation forward pass error: {}", e))
            })?;
        current_logits = prepare_logits(generation_logits)?;
    }

    let duration = start.elapsed();
    let device_used = model.device_name();
    let result = InferenceResult {
        tokens_per_second: calculate_tokens_per_second(tokens_count, duration),
        total_tokens: tokens_count,
        duration_ms: duration.as_millis() as u64,
        generated_text,
        device_used: device_used.clone(),
    };
    let telemetry = InferenceTelemetry {
        prompt_tokens,
        generated_tokens: tokens_count,
        tokenization_ms: duration_ms_f64(tokenization_duration),
        prompt_tensor_ms: duration_ms_f64(prompt_tensor_duration),
        prefill_ms: duration_ms_f64(prefill_duration),
        prefill_tokens_per_second: calculate_tokens_per_second(prompt_tokens, prefill_duration),
        time_to_first_token_ms: token_intervals
            .first()
            .map(|duration| duration_ms_f64(*duration))
            .unwrap_or(0.0),
        decode_ms: duration_ms_f64(duration),
        decode_tokens_per_second: calculate_tokens_per_second(tokens_count, duration),
        avg_inter_token_ms: average_duration_ms(&token_intervals),
        p50_inter_token_ms: percentile_duration_ms(&token_intervals, 0.50),
        p95_inter_token_ms: percentile_duration_ms(&token_intervals, 0.95),
        sampling_ms: duration_ms_f64(sampling_duration),
        detokenize_ms: duration_ms_f64(detokenize_duration),
        callback_ms: duration_ms_f64(callback_duration),
        stop_reason,
        device_used,
        device_type: model.device_type().to_string(),
        architecture: model.architecture().to_string(),
    };

    Ok(ProfiledInferenceResult { result, telemetry })
}

/// Runs inference and streams tokens over a Tokio channel.
pub fn run_inference_with_channel(
    model: &mut Model,
    tokenizer: &Tokenizer,
    config: &InferenceConfig,
    cancel_token: Arc<AtomicBool>,
    token_tx: Sender<String>,
) -> Result<InferenceResult, CandelabraError> {
    run_inference(model, tokenizer, config, cancel_token, move |token| {
        token_tx
            .blocking_send(token)
            .map_err(|_| CandelabraError::Cancelled)
    })
}

fn prepare_logits(logits: Tensor) -> Result<Tensor, CandelabraError> {
    let mut logits = logits
        .squeeze(0)
        .map_err(|e| CandelabraError::Inference(format!("Logits squeeze error: {}", e)))?;

    if logits.dims().len() > 1 {
        logits = logits
            .get(logits.dim(0)? - 1)
            .map_err(|e| CandelabraError::Inference(format!("Logits get error: {}", e)))?;
    }

    logits
        .clamp(-100.0, 100.0)
        .map_err(|e| CandelabraError::Inference(format!("Logits clamp error: {}", e)))
}

fn resolve_eos_token_ids(tokenizer: &Tokenizer) -> Vec<u32> {
    let mut eos_tokens = Vec::new();
    for candidate in EOS_TOKEN_CANDIDATES {
        if let Some(token_id) = tokenizer.token_to_id(candidate) {
            if !eos_tokens.contains(&token_id) {
                eos_tokens.push(token_id);
            }
        }
    }
    eos_tokens
}

fn hit_time_limit(start: Instant, max_duration_secs: Option<u64>) -> bool {
    match max_duration_secs {
        Some(limit) => start.elapsed().as_secs() >= limit,
        None => false,
    }
}

fn calculate_tokens_per_second(tokens_count: usize, duration: Duration) -> f64 {
    let elapsed = duration.as_secs_f64();
    if tokens_count == 0 || elapsed <= 0.0 {
        0.0
    } else {
        tokens_count as f64 / elapsed
    }
}

fn duration_ms_f64(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

fn average_duration_ms(durations: &[Duration]) -> f64 {
    if durations.is_empty() {
        return 0.0;
    }

    durations
        .iter()
        .map(|duration| duration.as_secs_f64())
        .sum::<f64>()
        * 1000.0
        / durations.len() as f64
}

fn percentile_duration_ms(durations: &[Duration], percentile: f64) -> f64 {
    if durations.is_empty() {
        return 0.0;
    }

    let mut sorted = durations.to_vec();
    sorted.sort_unstable();
    let rank = ((sorted.len() - 1) as f64 * percentile.clamp(0.0, 1.0)).round() as usize;
    duration_ms_f64(sorted[rank])
}

fn zero_result(device_used: String) -> InferenceResult {
    InferenceResult {
        tokens_per_second: 0.0,
        total_tokens: 0,
        duration_ms: 0,
        generated_text: String::new(),
        device_used,
    }
}

fn zero_profiled_result(
    model: &Model,
    prompt_tokens: usize,
    tokenization_duration: Duration,
    stop_reason: StopReason,
) -> ProfiledInferenceResult {
    let device_used = model.device_name();
    let result = zero_result(device_used.clone());
    let telemetry = InferenceTelemetry {
        prompt_tokens,
        generated_tokens: 0,
        tokenization_ms: duration_ms_f64(tokenization_duration),
        prompt_tensor_ms: 0.0,
        prefill_ms: 0.0,
        prefill_tokens_per_second: 0.0,
        time_to_first_token_ms: 0.0,
        decode_ms: 0.0,
        decode_tokens_per_second: 0.0,
        avg_inter_token_ms: 0.0,
        p50_inter_token_ms: 0.0,
        p95_inter_token_ms: 0.0,
        sampling_ms: 0.0,
        detokenize_ms: 0.0,
        callback_ms: 0.0,
        stop_reason,
        device_used,
        device_type: model.device_type().to_string(),
        architecture: model.architecture().to_string(),
    };

    ProfiledInferenceResult { result, telemetry }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tokenizers::models::wordlevel::WordLevel;

    fn build_test_tokenizer() -> Tokenizer {
        let vocab = HashMap::from([
            ("[UNK]".to_string(), 0),
            ("hello".to_string(), 1),
            ("</s>".to_string(), 2),
            ("<|endoftext|>".to_string(), 3),
        ]);
        let model = WordLevel::builder()
            .vocab(vocab)
            .unk_token("[UNK]".to_string())
            .build()
            .expect("failed to build wordlevel tokenizer");
        Tokenizer::new(model)
    }

    #[test]
    fn zero_result_has_empty_metrics() {
        let result = zero_result("CPU".to_string());
        assert_eq!(result.total_tokens, 0);
        assert_eq!(result.duration_ms, 0);
        assert_eq!(result.tokens_per_second, 0.0);
        assert!(result.generated_text.is_empty());
    }

    #[test]
    fn calculate_tokens_per_second_handles_zero_duration() {
        assert_eq!(calculate_tokens_per_second(10, Duration::ZERO), 0.0);
        assert_eq!(calculate_tokens_per_second(0, Duration::from_secs(1)), 0.0);
    }

    #[test]
    fn resolves_common_eos_token_ids() {
        let tokenizer = build_test_tokenizer();
        let eos_tokens = resolve_eos_token_ids(&tokenizer);
        assert_eq!(eos_tokens, vec![3, 2]);
    }

    #[test]
    fn time_limit_zero_stops_immediately() {
        assert!(hit_time_limit(Instant::now(), Some(0)));
    }
}
