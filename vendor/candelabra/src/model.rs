//! Model loading wrapper for GGUF format models.

use crate::device::{device_name, get_best_device, panic_payload_message};
use crate::{CandelabraError, DeviceType};
use candle_core::Tensor;
use candle_core::{quantized::gguf_file, DType, Device};
use candle_transformers::models::quantized_gemma3::ModelWeights as Gemma3Weights;
use candle_transformers::models::quantized_glm4::ModelWeights as Glm4Weights;
use candle_transformers::models::quantized_lfm2::ModelWeights as Lfm2Weights;
use candle_transformers::models::quantized_llama::ModelWeights as LlamaWeights;
use candle_transformers::models::quantized_phi::ModelWeights as PhiWeights;
use candle_transformers::models::quantized_phi3::ModelWeights as Phi3Weights;
use candle_transformers::models::quantized_qwen2::ModelWeights as Qwen2Weights;
use candle_transformers::models::quantized_qwen3::ModelWeights as Qwen3Weights;
#[cfg(feature = "qwen3-moe")]
use candle_transformers::models::quantized_qwen3_moe::GGUFQWenMoE as Qwen3MoeWeights;
use candle_transformers::models::smol::quantized_smollm3::QuantizedModelForCausalLM as SmolLm3Weights;
use std::io::{Read, Seek};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};

const SUPPORTED_ARCHITECTURES: &str = "llama, mistral, gemma, gemma2, mixtral, phi2, phi3, qwen2, qwen3, gemma3, glm4, lfm2/LFM2.5, smollm3";
const QWEN35_UNSUPPORTED_REASON: &str = "Qwen3.5 GGUFs use a newer hybrid Gated DeltaNet + attention architecture. candle-transformers 0.9.2 does not expose a quantized Qwen3.5 backend yet, so candelabra cannot safely run these weights until Candle adds that model implementation.";
#[cfg(not(feature = "qwen3-moe"))]
const QWEN3_MOE_UNAVAILABLE_REASON: &str = "Qwen3 MoE GGUF support requires candelabra's `qwen3-moe` feature and a candle-transformers build that exposes `models::quantized_qwen3_moe`. The currently selected Candle source does not provide that backend by default.";

/// Different quantized model architectures supported by candelabra
pub enum QuantizedWeights {
    Llama(LlamaWeights),
    Phi(PhiWeights),
    Phi3(Phi3Weights),
    Qwen2(Qwen2Weights),
    Qwen3(Qwen3Weights),
    #[cfg(feature = "qwen3-moe")]
    Qwen3Moe(Qwen3MoeWeights),
    Gemma3(Gemma3Weights),
    Glm4(Glm4Weights),
    Lfm2(Lfm2Weights),
    SmolLm3(SmolLm3Weights),
}

impl QuantizedWeights {
    pub fn forward(
        &mut self,
        x: &Tensor,
        seqlen_offset: usize,
    ) -> Result<Tensor, candle_core::Error> {
        match self {
            Self::Llama(w) => w.forward(x, seqlen_offset),
            Self::Phi(w) => w.forward(x, seqlen_offset),
            Self::Phi3(w) => w.forward(x, seqlen_offset),
            Self::Qwen2(w) => w.forward(x, seqlen_offset),
            Self::Qwen3(w) => w.forward(x, seqlen_offset),
            #[cfg(feature = "qwen3-moe")]
            Self::Qwen3Moe(w) => w.forward(x, seqlen_offset),
            Self::Gemma3(w) => w.forward(x, seqlen_offset),
            Self::Glm4(w) => w.forward(x, seqlen_offset),
            Self::Lfm2(w) => w.forward(x, seqlen_offset),
            Self::SmolLm3(w) => w.forward(x, seqlen_offset),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuantizedArchitecture {
    Llama,
    Phi,
    Phi3,
    Qwen2,
    Qwen3,
    Qwen3Moe,
    Gemma3,
    Glm4,
    Lfm2,
    SmolLm3,
}

impl QuantizedArchitecture {
    fn from_gguf_value(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            // These architectures share Candle's quantized LLaMA loader.
            "llama" | "mistral" | "gemma" | "gemma2" | "mixtral" => Some(Self::Llama),
            "phi2" | "phi" => Some(Self::Phi),
            "phi3" => Some(Self::Phi3),
            "qwen2" => Some(Self::Qwen2),
            "qwen3" => Some(Self::Qwen3),
            "qwen3moe" | "qwen3_moe" | "qwen3-moe" => Some(Self::Qwen3Moe),
            "gemma3" => Some(Self::Gemma3),
            "glm4" => Some(Self::Glm4),
            "lfm2" | "lfm2.5" | "lfm25" | "lfm2_5" | "lfm2-5" => Some(Self::Lfm2),
            "smollm3" | "smol-lm3" | "smol_lm3" => Some(Self::SmolLm3),
            _ => None,
        }
    }
}

fn metadata_string(content: &gguf_file::Content, key: &str) -> Option<String> {
    content
        .metadata
        .get(key)
        .and_then(|value| value.to_string().ok())
        .map(ToOwned::to_owned)
}

fn is_qwen35_name(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    normalized.contains("qwen3.5")
        || normalized.contains("qwen3_5")
        || normalized.contains("qwen3-5")
        || normalized.contains("qwen35")
}

fn known_unsupported_architecture_reason(
    architecture: &str,
    content: &gguf_file::Content,
) -> Option<&'static str> {
    if is_qwen35_name(architecture)
        || metadata_string(content, "general.name")
            .as_deref()
            .is_some_and(is_qwen35_name)
    {
        return Some(QWEN35_UNSUPPORTED_REASON);
    }

    None
}

#[cfg(feature = "qwen3-moe")]
fn load_qwen3_moe_weights<R: Read + Seek>(
    content: gguf_file::Content,
    file: &mut R,
    device: &Device,
) -> Result<QuantizedWeights, CandelabraError> {
    Qwen3MoeWeights::from_gguf(content, file, device, DType::F32)
        .map(QuantizedWeights::Qwen3Moe)
        .map_err(|e| CandelabraError::Model(format!("Failed to load Qwen3 MoE weights: {}", e)))
}

#[cfg(not(feature = "qwen3-moe"))]
fn load_qwen3_moe_weights<R: Read + Seek>(
    _content: gguf_file::Content,
    _file: &mut R,
    _device: &Device,
) -> Result<QuantizedWeights, CandelabraError> {
    Err(CandelabraError::Model(
        QWEN3_MOE_UNAVAILABLE_REASON.to_string(),
    ))
}

/// A loaded model ready for inference.
pub struct Model {
    /// The quantized model weights
    pub(crate) weights: QuantizedWeights,
    /// The compute device (Metal, CUDA, or CPU)
    pub(crate) device: Device,
    /// The type of device being used
    device_type: DeviceType,
    /// GGUF architecture name as reported by model metadata.
    architecture: String,
    /// Original GGUF path, used to rebuild mutable model state between isolated runs.
    model_path: PathBuf,
}

impl Model {
    /// Load a GGUF model from the given path.
    ///
    /// This method automatically selects the best available device
    /// (Metal > CUDA > CPU) and loads the model weights.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the GGUF model file
    ///
    /// # Returns
    ///
    /// A loaded `Model` ready for inference.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, CandelabraError> {
        let path = path.as_ref();
        let (device, device_type) = get_best_device();
        match catch_unwind(AssertUnwindSafe(|| {
            Self::load_with_device(path, device, device_type)
        })) {
            Ok(result) => result,
            Err(panic) if device_type != DeviceType::Cpu => {
                let message = panic_payload_message(panic.as_ref());
                eprintln!(
                    "{} model load panicked, falling back to CPU: {}",
                    device_type, message
                );
                Self::load_cpu_after_accelerator_panic(path, device_type, &message)
            }
            Err(panic) => Err(CandelabraError::Model(format!(
                "CPU model load panicked: {}",
                panic_payload_message(panic.as_ref())
            ))),
        }
    }

    fn load_cpu_after_accelerator_panic(
        path: &Path,
        device_type: DeviceType,
        accelerator_panic: &str,
    ) -> Result<Self, CandelabraError> {
        match catch_unwind(AssertUnwindSafe(|| {
            Self::load_with_device(path, Device::Cpu, DeviceType::Cpu)
        })) {
            Ok(Ok(model)) => Ok(model),
            Ok(Err(cpu_error)) => Err(CandelabraError::Model(format!(
                "{} model load panicked ({}); CPU fallback failed: {}",
                device_type, accelerator_panic, cpu_error
            ))),
            Err(cpu_panic) => Err(CandelabraError::Model(format!(
                "{} model load panicked ({}); CPU fallback also panicked: {}",
                device_type,
                accelerator_panic,
                panic_payload_message(cpu_panic.as_ref())
            ))),
        }
    }

    /// Load a GGUF model with a specific device.
    ///
    /// Use this when you want to control which device is used,
    /// such as for testing or when the user has selected a specific device.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the GGUF model file
    /// * `device` - The compute device to use
    /// * `device_type` - The type of device (for reporting purposes)
    ///
    /// # Returns
    ///
    /// A loaded `Model` ready for inference.
    pub fn load_with_device<P: AsRef<Path>>(
        path: P,
        device: Device,
        device_type: DeviceType,
    ) -> Result<Self, CandelabraError> {
        let path = path.as_ref();

        let mut file = std::fs::File::open(path)
            .map_err(|e| CandelabraError::Model(format!("Failed to open model file: {}", e)))?;

        let content = gguf_file::Content::read(&mut file)
            .map_err(|e| CandelabraError::Model(format!("Failed to read GGUF content: {}", e)))?;

        let architecture = metadata_string(&content, "general.architecture").ok_or_else(|| {
            CandelabraError::Model(
                "Failed to find general.architecture in GGUF metadata".to_string(),
            )
        })?;

        if let Some(reason) = known_unsupported_architecture_reason(&architecture, &content) {
            return Err(CandelabraError::Model(reason.to_string()));
        }

        let Some(architecture_kind) = QuantizedArchitecture::from_gguf_value(&architecture) else {
            return Err(CandelabraError::Model(format!(
                "Unsupported architecture: {}. Supported natively: {}.",
                architecture, SUPPORTED_ARCHITECTURES
            )));
        };

        let weights = match architecture_kind {
            QuantizedArchitecture::Llama => QuantizedWeights::Llama(
                LlamaWeights::from_gguf(content, &mut file, &device).map_err(|e| {
                    CandelabraError::Model(format!(
                        "Failed to load LLaMA/Mistral/Gemma weights: {}",
                        e
                    ))
                })?,
            ),
            QuantizedArchitecture::Phi => {
                QuantizedWeights::Phi(PhiWeights::from_gguf(content, &mut file, &device).map_err(
                    |e| CandelabraError::Model(format!("Failed to load Phi weights: {}", e)),
                )?)
            }
            QuantizedArchitecture::Phi3 => QuantizedWeights::Phi3(
                Phi3Weights::from_gguf(false, content, &mut file, &device).map_err(|e| {
                    CandelabraError::Model(format!("Failed to load Phi3 weights: {}", e))
                })?,
            ),
            QuantizedArchitecture::Qwen2 => QuantizedWeights::Qwen2(
                Qwen2Weights::from_gguf(content, &mut file, &device).map_err(|e| {
                    CandelabraError::Model(format!("Failed to load Qwen2 weights: {}", e))
                })?,
            ),
            QuantizedArchitecture::Qwen3 => QuantizedWeights::Qwen3(
                Qwen3Weights::from_gguf(content, &mut file, &device).map_err(|e| {
                    CandelabraError::Model(format!("Failed to load Qwen3 weights: {}", e))
                })?,
            ),
            QuantizedArchitecture::Qwen3Moe => load_qwen3_moe_weights(content, &mut file, &device)?,
            QuantizedArchitecture::Gemma3 => QuantizedWeights::Gemma3(
                Gemma3Weights::from_gguf(content, &mut file, &device).map_err(|e| {
                    CandelabraError::Model(format!("Failed to load Gemma3 weights: {}", e))
                })?,
            ),
            QuantizedArchitecture::Glm4 => QuantizedWeights::Glm4(
                Glm4Weights::from_gguf(content, &mut file, &device, DType::F32).map_err(|e| {
                    CandelabraError::Model(format!("Failed to load GLM4 weights: {}", e))
                })?,
            ),
            QuantizedArchitecture::Lfm2 => QuantizedWeights::Lfm2(
                Lfm2Weights::from_gguf(content, &mut file, &device).map_err(|e| {
                    CandelabraError::Model(format!("Failed to load LFM2 weights: {}", e))
                })?,
            ),
            QuantizedArchitecture::SmolLm3 => {
                QuantizedWeights::SmolLm3(SmolLm3Weights::from_gguf(path, &device).map_err(
                    |e| CandelabraError::Model(format!("Failed to load SmolLM3 weights: {}", e)),
                )?)
            }
        };

        Ok(Self {
            weights,
            device,
            device_type,
            architecture,
            model_path: path.to_path_buf(),
        })
    }

    /// Returns a human-readable name for the compute device in use.
    pub fn device_name(&self) -> String {
        device_name(&self.device)
    }

    /// Returns the device type selected for this model.
    pub fn device_type(&self) -> DeviceType {
        self.device_type
    }

    /// Returns the GGUF architecture name reported by model metadata.
    pub fn architecture(&self) -> &str {
        &self.architecture
    }

    /// Reset any internal state (KV cache, etc.).
    pub fn reset(&mut self) {
        if let Err(error) = self.reset_state() {
            eprintln!("Failed to reset model state: {error}");
        }
    }

    /// Rebuilds the model weights to clear backend-owned KV cache.
    ///
    /// Some quantized Candle backends keep cache inside private weight fields
    /// without exposing a clear method. Reloading preserves the selected device
    /// while guaranteeing the next inference starts from an empty sequence state.
    pub fn reset_state(&mut self) -> Result<(), CandelabraError> {
        let reloaded =
            Self::load_with_device(&self.model_path, self.device.clone(), self.device_type)?;
        self.weights = reloaded.weights;
        self.architecture = reloaded.architecture;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        gguf_file, known_unsupported_architecture_reason, metadata_string, QuantizedArchitecture,
    };
    use candle_core::quantized::gguf_file::Value;
    use std::collections::HashMap;

    fn content_with_metadata(metadata: HashMap<String, Value>) -> gguf_file::Content {
        gguf_file::Content {
            magic: gguf_file::VersionedMagic::GgufV3,
            metadata,
            tensor_infos: HashMap::new(),
            tensor_data_offset: 0,
        }
    }

    #[test]
    fn maps_llama_family_architectures_to_llama_loader() {
        for arch in ["llama", "mistral", "gemma", "gemma2", "mixtral"] {
            assert_eq!(
                QuantizedArchitecture::from_gguf_value(arch),
                Some(QuantizedArchitecture::Llama)
            );
        }
    }

    #[test]
    fn maps_additional_supported_architectures() {
        let cases = [
            ("phi2", QuantizedArchitecture::Phi),
            ("phi", QuantizedArchitecture::Phi),
            ("phi3", QuantizedArchitecture::Phi3),
            ("qwen2", QuantizedArchitecture::Qwen2),
            ("qwen3", QuantizedArchitecture::Qwen3),
            ("qwen3moe", QuantizedArchitecture::Qwen3Moe),
            ("qwen3_moe", QuantizedArchitecture::Qwen3Moe),
            ("gemma3", QuantizedArchitecture::Gemma3),
            ("glm4", QuantizedArchitecture::Glm4),
            ("lfm2", QuantizedArchitecture::Lfm2),
            ("lfm2.5", QuantizedArchitecture::Lfm2),
            ("lfm2_5", QuantizedArchitecture::Lfm2),
            ("smollm3", QuantizedArchitecture::SmolLm3),
        ];

        for (arch, expected) in cases {
            assert_eq!(QuantizedArchitecture::from_gguf_value(arch), Some(expected));
        }
    }

    #[test]
    fn architecture_mapping_is_case_and_whitespace_tolerant() {
        assert_eq!(
            QuantizedArchitecture::from_gguf_value(" Qwen3-MoE "),
            Some(QuantizedArchitecture::Qwen3Moe)
        );
    }

    #[test]
    fn detects_qwen35_as_known_unsupported_architecture() {
        let content = content_with_metadata(HashMap::new());
        assert!(known_unsupported_architecture_reason("qwen3.5", &content).is_some());
        assert!(known_unsupported_architecture_reason("qwen35_moe", &content).is_some());
    }

    #[test]
    fn detects_qwen35_from_model_name_even_when_architecture_is_generic() {
        let content = content_with_metadata(HashMap::from([(
            "general.name".to_string(),
            Value::String("Qwen3.5-27B".to_string()),
        )]));

        assert!(known_unsupported_architecture_reason("qwen3", &content).is_some());
    }

    #[test]
    fn metadata_string_reads_string_values_only() {
        let content = content_with_metadata(HashMap::from([
            (
                "general.architecture".to_string(),
                Value::String("lfm2".to_string()),
            ),
            ("general.file_type".to_string(), Value::U32(15)),
        ]));

        assert_eq!(
            metadata_string(&content, "general.architecture").as_deref(),
            Some("lfm2")
        );
        assert_eq!(metadata_string(&content, "general.file_type"), None);
    }
}
