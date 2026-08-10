pub mod artifact;
pub mod extent;
pub mod gguf;
pub mod identification;
pub mod keras;
pub mod onnx;
pub mod pickle;
pub mod safetensors;
pub mod tensorflow;
pub mod tflite;

pub use extent::ParsedExtent;
pub use identification::{ArtifactIdentification, ContradictionKind, FormatContradiction};

use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactFormat {
    Gguf,
    Safetensors,
    SafetensorsIndex,
    Onnx,
    Pickle,
    TensorFlowSavedModel,
    TensorFlowCheckpoint,
    TensorFlowLite,
    KerasArchive,
    KerasHdf5,
    Unknown,
}

impl ArtifactFormat {
    pub fn detect(path: &Path, prefix: &[u8]) -> Self {
        ArtifactIdentification::identify(path, prefix).selected
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gguf => "gguf",
            Self::Safetensors => "safetensors",
            Self::SafetensorsIndex => "safetensors-index",
            Self::Onnx => "onnx",
            Self::Pickle => "pickle",
            Self::TensorFlowSavedModel => "tensorflow-savedmodel",
            Self::TensorFlowCheckpoint => "tensorflow-checkpoint",
            Self::TensorFlowLite => "tflite",
            Self::KerasArchive => "keras",
            Self::KerasHdf5 => "keras-hdf5",
            Self::Unknown => "unknown",
        }
    }
}
