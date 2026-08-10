pub mod artifact;
pub mod gguf;
pub mod keras;
pub mod onnx;
pub mod pickle;
pub mod safetensors;
pub mod tensorflow;
pub mod tflite;

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
        let name = path
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let ext = path
            .extension()
            .and_then(|v| v.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if prefix.starts_with(b"GGUF") || ext == "gguf" {
            Self::Gguf
        } else if name.ends_with(".safetensors.index.json") {
            Self::SafetensorsIndex
        } else if ext == "safetensors" {
            Self::Safetensors
        } else if matches!(
            ext.as_str(),
            "pkl" | "pickle" | "joblib" | "pt" | "pth" | "ckpt"
        ) || (prefix.len() >= 2 && prefix[0] == 0x80 && (2..=5).contains(&prefix[1]))
        {
            Self::Pickle
        } else if ext == "onnx" {
            Self::Onnx
        } else if name == "saved_model.pb" {
            Self::TensorFlowSavedModel
        } else if ext == "index" && !name.ends_with(".safetensors.index.json") {
            Self::TensorFlowCheckpoint
        } else if prefix.len() >= 8 && &prefix[4..8] == b"TFL3" || ext == "tflite" {
            Self::TensorFlowLite
        } else if ext == "keras" {
            Self::KerasArchive
        } else if matches!(ext.as_str(), "h5" | "hdf5") {
            Self::KerasHdf5
        } else {
            Self::Unknown
        }
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
