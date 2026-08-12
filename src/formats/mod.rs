pub mod artifact;
pub mod coreml;
pub mod differential;
pub mod executorch;
pub mod extent;
pub mod gguf;
pub mod identification;
pub mod keras;
pub mod mlx;
pub mod npy;
pub mod onnx;
pub mod openvino;
pub mod pickle;
pub mod pytorch;
pub mod safetensors;
pub mod tensorflow;
pub mod tensorrt;
pub mod tflite;

pub use differential::{
    extract_normalized, extract_normalized_opened, NormalizedMetadataEntry, NormalizedModel,
    NormalizedTensor,
};
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
    PyTorchZip,
    TorchScript,
    TorchPackage,
    ExecuTorch,
    OpenVinoIr,
    TensorRtEngine,
    CoreMlModel,
    CoreMlPackage,
    MlxPackage,
    TensorFlowSavedModel,
    TensorFlowCheckpoint,
    TensorFlowLite,
    KerasArchive,
    KerasHdf5,
    Npy,
    Npz,
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
            Self::PyTorchZip => "pytorch-zip",
            Self::TorchScript => "torchscript",
            Self::TorchPackage => "torch-package",
            Self::ExecuTorch => "executorch",
            Self::OpenVinoIr => "openvino-ir",
            Self::TensorRtEngine => "tensorrt-engine",
            Self::CoreMlModel => "coreml-model",
            Self::CoreMlPackage => "coreml-package",
            Self::MlxPackage => "mlx-package",
            Self::TensorFlowSavedModel => "tensorflow-savedmodel",
            Self::TensorFlowCheckpoint => "tensorflow-checkpoint",
            Self::TensorFlowLite => "tflite",
            Self::KerasArchive => "keras",
            Self::KerasHdf5 => "keras-hdf5",
            Self::Npy => "npy",
            Self::Npz => "npz",
            Self::Unknown => "unknown",
        }
    }
}
