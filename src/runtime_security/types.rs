use crate::advisory::RuntimeInfo;
use crate::coverage::Coverage;
use crate::scanner::LayerScanResult;
use anyhow::{anyhow, Result};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeKind {
    Ollama,
    LmStudio,
    LlamaCpp,
    Vllm,
    Transformers,
    TextGenerationInference,
    LocalAi,
    Mlx,
    Gpt4All,
    Jan,
    KoboldCpp,
    TextGenerationWebUi,
}

impl RuntimeKind {
    pub const ALL: [Self; 12] = [
        Self::Ollama,
        Self::LmStudio,
        Self::LlamaCpp,
        Self::Vllm,
        Self::Transformers,
        Self::TextGenerationInference,
        Self::LocalAi,
        Self::Mlx,
        Self::Gpt4All,
        Self::Jan,
        Self::KoboldCpp,
        Self::TextGenerationWebUi,
    ];

    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "ollama" => Ok(Self::Ollama),
            "lmstudio" | "lm-studio" | "lms" => Ok(Self::LmStudio),
            "llama-cpp" | "llamacpp" | "llama" => Ok(Self::LlamaCpp),
            "vllm" => Ok(Self::Vllm),
            "transformers" | "hf-transformers" => Ok(Self::Transformers),
            "tgi" | "text-generation-inference" => Ok(Self::TextGenerationInference),
            "localai" | "local-ai" => Ok(Self::LocalAi),
            "mlx" | "mlx-lm" => Ok(Self::Mlx),
            "gpt4all" => Ok(Self::Gpt4All),
            "jan" => Ok(Self::Jan),
            "koboldcpp" | "kobold-cpp" => Ok(Self::KoboldCpp),
            "text-generation-webui" | "textgen-webui" | "oobabooga" => {
                Ok(Self::TextGenerationWebUi)
            }
            other => Err(anyhow!("Unknown runtime '{other}'")),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ollama => "ollama",
            Self::LmStudio => "lmstudio",
            Self::LlamaCpp => "llama-cpp",
            Self::Vllm => "vllm",
            Self::Transformers => "transformers",
            Self::TextGenerationInference => "text-generation-inference",
            Self::LocalAi => "localai",
            Self::Mlx => "mlx",
            Self::Gpt4All => "gpt4all",
            Self::Jan => "jan",
            Self::KoboldCpp => "koboldcpp",
            Self::TextGenerationWebUi => "text-generation-webui",
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RuntimeInstallation {
    pub runtime: RuntimeKind,
    pub executable: Option<String>,
    pub executable_sha256: Option<String>,
    pub raw_version: Option<String>,
    pub parsed_version: Option<String>,
    pub discovery: RuntimeDiscoveryMethod,
    #[serde(default)]
    pub package_root: Option<String>,
    #[serde(default)]
    pub process_ids: Vec<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeDiscoveryMethod {
    PathExecutable,
    RunningProcess,
    PythonDistribution,
    ApplicationBundle,
    ExplicitPath,
}

impl From<RuntimeInfo> for RuntimeInstallation {
    fn from(value: RuntimeInfo) -> Self {
        Self {
            runtime: value.runtime,
            executable: Some(value.executable),
            executable_sha256: Some(value.executable_sha256),
            raw_version: Some(value.raw_version),
            parsed_version: value.parsed_version,
            discovery: RuntimeDiscoveryMethod::ExplicitPath,
            package_root: None,
            process_ids: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RuntimeConfiguration {
    #[serde(default)]
    pub listen_addresses: Vec<String>,
    #[serde(default)]
    pub listen_ports: Vec<u16>,
    #[serde(default)]
    pub command_args: Vec<String>,
    #[serde(default)]
    pub environment_facts: Vec<RuntimeEnvironmentFact>,
    #[serde(default)]
    pub config_files: Vec<String>,
    pub python_optimized: Option<bool>,
    pub trust_remote_code: Option<bool>,
    pub authentication: PostureState,
    pub tls: PostureState,
    pub network_exposure: PostureState,
    /// A middleware/plugin was configured that loads additional code at
    /// startup (e.g. vLLM's `--middleware`/`--tool-parser-plugin`). Distinct
    /// from `trust_remote_code`: this is code the *operator's own launch
    /// command* points at, not code bundled with a downloaded model.
    #[serde(default)]
    pub custom_code_extension: Option<bool>,
    /// The runtime is configured to deserialize model weights via a
    /// pickle-based load path (e.g. vLLM's `--load-format pt`) rather than a
    /// safe tensor format.
    #[serde(default)]
    pub pickle_weight_loading: Option<bool>,
    /// CORS is configured to allow any origin (a wildcard, or the
    /// runtime's unconfigured default when that default is a wildcard).
    #[serde(default)]
    pub cors_wildcard_origin: Option<bool>,
    /// A chat template was overridden from the runtime's launch
    /// configuration rather than the one bundled with the model.
    #[serde(default)]
    pub custom_chat_template: Option<bool>,
    /// The model is loaded from a pinned, immutable revision rather than a
    /// floating reference (e.g. a branch name or no revision at all).
    #[serde(default)]
    pub revision_pinned: Option<bool>,
    /// The runtime is configured to read media (images/audio) from local
    /// filesystem paths supplied in requests.
    #[serde(default)]
    pub local_media_access: Option<bool>,
    /// An endpoint or mode is enabled that exposes per-request/per-slot
    /// internal state (e.g. another client's in-flight prompt) across
    /// clients sharing the same server instance.
    #[serde(default)]
    pub cross_tenant_state_exposure: Option<bool>,
}

impl Default for RuntimeConfiguration {
    fn default() -> Self {
        Self {
            listen_addresses: Vec::new(),
            listen_ports: Vec::new(),
            command_args: Vec::new(),
            environment_facts: Vec::new(),
            config_files: Vec::new(),
            python_optimized: None,
            trust_remote_code: None,
            authentication: PostureState::Unknown,
            tls: PostureState::Unknown,
            network_exposure: PostureState::Unknown,
            custom_code_extension: None,
            pickle_weight_loading: None,
            cors_wildcard_origin: None,
            custom_chat_template: None,
            revision_pinned: None,
            local_media_access: None,
            cross_tenant_state_exposure: None,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RuntimeEnvironmentFact {
    pub name: String,
    pub value_class: EnvironmentValueClass,
    pub present: bool,
    #[serde(default)]
    pub normalized_value: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentValueClass {
    Boolean,
    Address,
    Port,
    SecurityMode,
    Opaque,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostureState {
    Enabled,
    Disabled,
    Unknown,
    NotApplicable,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RuntimePosture {
    pub installation: RuntimeInstallation,
    pub configuration: RuntimeConfiguration,
    pub coverage: Coverage,
    pub findings: Vec<LayerScanResult>,
}
