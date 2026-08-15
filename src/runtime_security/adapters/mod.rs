use super::{RuntimeAdapter, RuntimeKind};
use regex::Regex;

mod generic;
mod gpt4all;
mod jan;
mod koboldcpp;
mod llama_cpp;
mod lmstudio;
mod localai;
mod mlx;
mod ollama;
mod textgen_webui;
mod tgi;
mod transformers;
mod vllm;

pub use gpt4all::GPT4ALL;
pub use jan::JAN;
pub use koboldcpp::KOBOLD_CPP;
pub use llama_cpp::LLAMA_CPP;
pub use lmstudio::LM_STUDIO;
pub use localai::LOCAL_AI;
pub use mlx::MLX;
pub use ollama::OLLAMA;
pub use textgen_webui::TEXTGEN_WEBUI;
pub use tgi::TGI;
pub use transformers::TRANSFORMERS;
pub use vllm::VLLM;

pub(crate) fn extract_semver(raw: &str) -> Option<String> {
    let re = Regex::new(r"(?i)(?:v|version\s*)?(\d+)\.(\d+)\.(\d+)(?:[-+][0-9A-Za-z.-]+)?").ok()?;
    let captures = re.captures(raw)?;
    Some(format!(
        "{}.{}.{}",
        &captures[1], &captures[2], &captures[3]
    ))
}

pub(crate) fn extract_build(raw: &str) -> Option<String> {
    let re = Regex::new(r"(?i)(?:build|b)\s*([0-9]{2,})").ok()?;
    let captures = re.captures(raw)?;
    Some(format!("b{}", &captures[1]))
}

pub fn all_adapters() -> [&'static dyn RuntimeAdapter; 12] {
    [
        &OLLAMA,
        &LM_STUDIO,
        &LLAMA_CPP,
        &VLLM,
        &TRANSFORMERS,
        &TGI,
        &LOCAL_AI,
        &MLX,
        &GPT4ALL,
        &JAN,
        &KOBOLD_CPP,
        &TEXTGEN_WEBUI,
    ]
}

pub fn adapter_for(kind: RuntimeKind) -> &'static dyn RuntimeAdapter {
    all_adapters()
        .into_iter()
        .find(|adapter| adapter.kind() == kind)
        .expect("every RuntimeKind has a compiled adapter")
}
