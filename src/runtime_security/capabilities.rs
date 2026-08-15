use super::RuntimeKind;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeCapabilities {
    pub runtime: RuntimeKind,
    #[serde(default)]
    pub formats: Vec<String>,
    #[serde(default)]
    pub architectures: Vec<String>,
    pub supports_custom_code: SupportState,
    pub supports_auto_map: SupportState,
    pub supports_remote_models: SupportState,
    pub supports_tokenizer_templates: SupportState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportState {
    Supported,
    Unsupported,
    Conditional,
    Unknown,
}

impl RuntimeCapabilities {
    /// Conservative compiled capability facts. Unknown is preferred over an
    /// unmaintained compatibility claim.
    pub fn for_runtime(runtime: RuntimeKind) -> Self {
        use RuntimeKind::*;
        use SupportState::*;
        let mut result = Self {
            runtime,
            formats: Vec::new(),
            architectures: Vec::new(),
            supports_custom_code: Unknown,
            supports_auto_map: Unknown,
            supports_remote_models: Unknown,
            supports_tokenizer_templates: Unknown,
        };
        match runtime {
            LlamaCpp => {
                result.formats = vec!["gguf".into()];
                result.supports_custom_code = Unsupported;
                result.supports_auto_map = Unsupported;
                result.supports_remote_models = Conditional;
                result.supports_tokenizer_templates = Conditional;
            }
            Ollama => {
                result.formats = vec!["gguf".into(), "ollama".into(), "package".into()];
                result.supports_custom_code = Unsupported;
                result.supports_auto_map = Unsupported;
                result.supports_remote_models = Supported;
                result.supports_tokenizer_templates = Conditional;
            }
            Transformers => {
                result.formats = vec![
                    "safetensors".into(),
                    "pytorch".into(),
                    "pickle".into(),
                    "package".into(),
                ];
                result.supports_custom_code = Conditional;
                result.supports_auto_map = Conditional;
                result.supports_remote_models = Supported;
                result.supports_tokenizer_templates = Supported;
            }
            Vllm => {
                result.formats = vec!["safetensors".into(), "pytorch".into(), "package".into()];
                result.supports_custom_code = Conditional;
                result.supports_auto_map = Conditional;
                result.supports_remote_models = Supported;
                result.supports_tokenizer_templates = Supported;
            }
            LmStudio => {
                result.formats = vec!["gguf".into()];
                result.supports_custom_code = Unsupported;
                result.supports_auto_map = Unsupported;
                result.supports_remote_models = Conditional;
                result.supports_tokenizer_templates = Conditional;
            }
            TextGenerationInference => {
                result.formats = vec!["safetensors".into(), "pytorch".into(), "package".into()];
                result.supports_custom_code = Conditional;
                result.supports_auto_map = Conditional;
                result.supports_remote_models = Supported;
                result.supports_tokenizer_templates = Supported;
            }
            LocalAi | Mlx | Gpt4All | Jan | KoboldCpp | TextGenerationWebUi => {}
        }
        result
    }
}
