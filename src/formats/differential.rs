//! Cross-format normalized structural model representation for differential validation.
//!
//! Provides canonicalized structural facts (tensors, metadata, shape, offsets,
//! endianness, version, inputs/outputs, global refs) extracted by Layerfault's
//! independent pure-Rust parsers. Used by differential testing tools to compare
//! Layerfault against authoritative reference implementations without false diffs.

use super::{
    gguf, keras, onnx, pickle, safetensors, tensorflow, tflite, ArtifactFormat,
    ArtifactIdentification,
};
use crate::safeio::open_readonly_nofollow;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Normalized tensor description across serialization formats.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct NormalizedTensor {
    pub name: String,
    pub dtype: String,
    pub shape: Vec<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_len: Option<u64>,
}

/// Normalized metadata entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct NormalizedMetadataEntry {
    pub key: String,
    pub value_type: String,
    pub value: String,
}

/// Normalized structural facts extracted from a model artifact.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalizedModel {
    pub format: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endian: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alignment: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_bytes: Option<u64>,
    pub metadata: Vec<NormalizedMetadataEntry>,
    pub tensors: Vec<NormalizedTensor>,
    pub inputs: Vec<String>,
    pub outputs: Vec<String>,
    pub external_data: Vec<String>,
    pub global_refs: Vec<String>,
}

impl NormalizedModel {
    /// Sort inner collections deterministically.
    pub fn canonicalize(&mut self) {
        self.metadata.sort();
        self.tensors.sort();
        self.inputs.sort();
        self.outputs.sort();
        self.external_data.sort();
        self.global_refs.sort();
    }
}

/// Extract normalized structural facts from a file path.
pub fn extract_normalized(path: &Path) -> Result<NormalizedModel> {
    let file = open_readonly_nofollow(path)?;
    let mut prefix = [0u8; 8192];
    let mut cloned = file.try_clone()?;
    let read_len = cloned.read(&mut prefix).unwrap_or(0);
    let id = ArtifactIdentification::identify(path, &prefix[..read_len]);
    extract_normalized_opened(path, &file, id.selected)
}

/// Extract normalized structural facts from an opened file with known format.
pub fn extract_normalized_opened(
    _path: &Path,
    file: &File,
    format: ArtifactFormat,
) -> Result<NormalizedModel> {
    let mut cloned = file.try_clone()?;
    let file_len = cloned.seek(SeekFrom::End(0))?;
    cloned.seek(SeekFrom::Start(0))?;

    let mut norm = match format {
        ArtifactFormat::Gguf => {
            let inv = gguf::parse_file(file, file_len).context("failed to parse GGUF")?;
            let mut norm = NormalizedModel {
                format: "gguf".to_string(),
                version: Some(u64::from(inv.version)),
                endian: Some(match inv.endian {
                    gguf::Endian::Little => "little".to_string(),
                    gguf::Endian::Big => "big".to_string(),
                }),
                alignment: Some(inv.alignment),
                header_bytes: None,
                metadata: Vec::new(),
                tensors: Vec::new(),
                inputs: Vec::new(),
                outputs: Vec::new(),
                external_data: Vec::new(),
                global_refs: Vec::new(),
            };
            for (key, entry) in inv.metadata {
                let v = entry
                    .string_value
                    .clone()
                    .or_else(|| entry.unsigned_value.map(|u| u.to_string()))
                    .or_else(|| entry.signed_value.map(|s| s.to_string()))
                    .or_else(|| entry.float_value.map(|f| f.to_string()))
                    .or_else(|| entry.bool_value.map(|b| b.to_string()))
                    .unwrap_or_else(|| entry.digest.clone());
                norm.metadata.push(NormalizedMetadataEntry {
                    key,
                    value_type: format!("{}", entry.value_type),
                    value: v,
                });
            }
            for tensor in inv.tensors {
                norm.tensors.push(NormalizedTensor {
                    name: tensor.name,
                    dtype: format!("{}", tensor.tensor_type),
                    shape: tensor.dimensions,
                    offset: Some(tensor.offset),
                    byte_len: tensor.byte_len,
                });
            }
            norm
        }

        ArtifactFormat::Safetensors => {
            let inv = safetensors::inventory_file(file, file_len)
                .context("failed to parse Safetensors")?;
            let mut norm = NormalizedModel {
                format: "safetensors".to_string(),
                version: None,
                endian: None,
                alignment: None,
                header_bytes: Some(inv.summary.header_bytes),
                metadata: Vec::new(),
                tensors: Vec::new(),
                inputs: Vec::new(),
                outputs: Vec::new(),
                external_data: Vec::new(),
                global_refs: Vec::new(),
            };
            for (key, val) in inv.metadata {
                norm.metadata.push(NormalizedMetadataEntry {
                    key,
                    value_type: "string".to_string(),
                    value: val,
                });
            }
            for tensor in inv.tensors {
                norm.tensors.push(NormalizedTensor {
                    name: tensor.name,
                    dtype: tensor.dtype,
                    shape: tensor.shape,
                    offset: Some(tensor.start),
                    byte_len: Some(tensor.end.saturating_sub(tensor.start)),
                });
            }
            norm
        }

        ArtifactFormat::Onnx => {
            let summary = onnx::inspect(file, file_len).context("failed to parse ONNX")?;
            let mut norm = NormalizedModel {
                format: "onnx".to_string(),
                version: summary.ir_version,
                endian: None,
                alignment: None,
                header_bytes: None,
                metadata: Vec::new(),
                tensors: Vec::new(),
                inputs: Vec::new(),
                outputs: Vec::new(),
                external_data: Vec::new(),
                global_refs: Vec::new(),
            };
            if let Some(p) = summary.producer_name {
                norm.metadata.push(NormalizedMetadataEntry {
                    key: "producer_name".to_string(),
                    value_type: "string".to_string(),
                    value: p,
                });
            }
            if let Some(d) = summary.domain {
                norm.metadata.push(NormalizedMetadataEntry {
                    key: "domain".to_string(),
                    value_type: "string".to_string(),
                    value: d,
                });
            }
            norm.metadata.push(NormalizedMetadataEntry {
                key: "node_count".to_string(),
                value_type: "u64".to_string(),
                value: summary.node_count.to_string(),
            });
            for ext in summary.external_data {
                norm.external_data.push(ext.location);
            }
            norm
        }

        ArtifactFormat::Pickle => {
            let analysis =
                pickle::analyze_bytes(&read_all_bounded(file, file_len, 64 * 1024 * 1024)?)
                    .context("failed to analyze Pickle opcodes")?;
            let mut norm = NormalizedModel {
                format: "pickle".to_string(),
                version: None,
                endian: None,
                alignment: None,
                header_bytes: None,
                metadata: Vec::new(),
                tensors: Vec::new(),
                inputs: Vec::new(),
                outputs: Vec::new(),
                external_data: Vec::new(),
                global_refs: analysis.globals.into_iter().collect(),
            };
            norm.metadata.push(NormalizedMetadataEntry {
                key: "opcode_count".to_string(),
                value_type: "usize".to_string(),
                value: analysis.opcode_count.to_string(),
            });
            norm
        }

        ArtifactFormat::TensorFlowSavedModel | ArtifactFormat::TensorFlowCheckpoint => {
            let summary = tensorflow::inspect_saved_model(file, file_len)
                .context("failed to inspect TensorFlow model")?;
            let mut norm = NormalizedModel {
                format: "tensorflow".to_string(),
                version: None,
                endian: None,
                alignment: None,
                header_bytes: None,
                metadata: Vec::new(),
                tensors: Vec::new(),
                inputs: Vec::new(),
                outputs: Vec::new(),
                external_data: Vec::new(),
                global_refs: Vec::new(),
            };
            norm.metadata.push(NormalizedMetadataEntry {
                key: "kind".to_string(),
                value_type: "string".to_string(),
                value: summary.kind,
            });
            norm
        }

        ArtifactFormat::TensorFlowLite => {
            let summary = tflite::inspect(file, file_len).context("failed to inspect TFLite")?;
            let mut norm = NormalizedModel {
                format: "tflite".to_string(),
                version: Some(u64::from(summary.schema_version)),
                endian: Some("little".to_string()),
                alignment: None,
                header_bytes: None,
                metadata: Vec::new(),
                tensors: Vec::new(),
                inputs: Vec::new(),
                outputs: Vec::new(),
                external_data: summary.associated_files,
                global_refs: Vec::new(),
            };
            if let Some(op) = summary.operator_code_count {
                norm.metadata.push(NormalizedMetadataEntry {
                    key: "operator_code_count".to_string(),
                    value_type: "u32".to_string(),
                    value: op.to_string(),
                });
            }
            if let Some(sub) = summary.subgraph_count {
                norm.metadata.push(NormalizedMetadataEntry {
                    key: "subgraph_count".to_string(),
                    value_type: "u32".to_string(),
                    value: sub.to_string(),
                });
            }
            norm
        }

        ArtifactFormat::KerasArchive | ArtifactFormat::KerasHdf5 => {
            let summary = keras::inspect(file).context("failed to inspect Keras model")?;
            let mut norm = NormalizedModel {
                format: "keras".to_string(),
                version: None,
                endian: None,
                alignment: None,
                header_bytes: None,
                metadata: Vec::new(),
                tensors: Vec::new(),
                inputs: Vec::new(),
                outputs: Vec::new(),
                external_data: Vec::new(),
                global_refs: Vec::new(),
            };
            norm.metadata.push(NormalizedMetadataEntry {
                key: "entries".to_string(),
                value_type: "usize".to_string(),
                value: summary.entries.to_string(),
            });
            norm.metadata.push(NormalizedMetadataEntry {
                key: "has_config".to_string(),
                value_type: "bool".to_string(),
                value: summary.has_config.to_string(),
            });
            norm.metadata.push(NormalizedMetadataEntry {
                key: "has_weights".to_string(),
                value_type: "bool".to_string(),
                value: summary.has_weights.to_string(),
            });
            norm
        }

        other => {
            let mut norm = NormalizedModel {
                format: other.as_str().to_string(),
                version: None,
                endian: None,
                alignment: None,
                header_bytes: None,
                metadata: Vec::new(),
                tensors: Vec::new(),
                inputs: Vec::new(),
                outputs: Vec::new(),
                external_data: Vec::new(),
                global_refs: Vec::new(),
            };
            norm.metadata.push(NormalizedMetadataEntry {
                key: "file_size".to_string(),
                value_type: "u64".to_string(),
                value: file_len.to_string(),
            });
            norm
        }
    };

    norm.canonicalize();
    Ok(norm)
}

fn read_all_bounded(file: &File, len: u64, max_cap: u64) -> Result<Vec<u8>> {
    let read_len = len.min(max_cap);
    let mut cloned = file.try_clone()?;
    cloned.seek(SeekFrom::Start(0))?;
    let mut buf = vec![0u8; usize::try_from(read_len).unwrap_or(0)];
    cloned.read_exact(&mut buf)?;
    Ok(buf)
}
