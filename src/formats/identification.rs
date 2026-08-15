//! Independent format claim, magic/container probing, and contradiction detection.

use super::ArtifactFormat;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ArtifactIdentification {
    pub extension_claim: Option<ArtifactFormat>,
    pub magic_candidates: Vec<ArtifactFormat>,
    pub container_candidates: Vec<ArtifactFormat>,
    pub selected: ArtifactFormat,
    pub contradictions: Vec<FormatContradiction>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FormatContradiction {
    pub kind: ContradictionKind,
    pub claim: Option<ArtifactFormat>,
    pub content: ArtifactFormat,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContradictionKind {
    ExtensionMismatch,
    ContainerSmuggling,
    SerializationSmuggling,
    PolyglotOverlapping,
}

impl ArtifactIdentification {
    pub fn identify(path: &Path, prefix: &[u8]) -> Self {
        Self::identify_name(&path.to_string_lossy(), prefix)
    }

    /// Identify content using a logical package or archive member name. This
    /// avoids treating untrusted metadata as an operating-system path.
    pub fn identify_name(name: &str, prefix: &[u8]) -> Self {
        let extension_claim = map_extension_claim_name(name);
        let magic_candidates = probe_magic(prefix);
        let container_candidates = probe_container(prefix);

        let mut contradictions = Vec::new();
        let selected = resolve_selected(
            extension_claim,
            &magic_candidates,
            &container_candidates,
            &mut contradictions,
        );

        Self {
            extension_claim,
            magic_candidates,
            container_candidates,
            selected,
            contradictions,
        }
    }
}

/// Map extension/filename role independently without reading file content.
pub fn map_extension_claim(path: &Path) -> Option<ArtifactFormat> {
    map_extension_claim_name(&path.to_string_lossy())
}

pub fn map_extension_claim_name(value: &str) -> Option<ArtifactFormat> {
    let name = crate::safeio::portable_file_name(value).to_ascii_lowercase();
    let ext = crate::safeio::portable_extension(value).to_ascii_lowercase();

    if name.ends_with(".safetensors.index.json") {
        Some(ArtifactFormat::SafetensorsIndex)
    } else if ext == "safetensors" {
        Some(ArtifactFormat::Safetensors)
    } else if ext == "gguf" {
        Some(ArtifactFormat::Gguf)
    } else if matches!(
        ext.as_str(),
        "pkl" | "pickle" | "joblib" | "pt" | "pth" | "ckpt"
    ) {
        Some(ArtifactFormat::Pickle)
    } else if ext == "pkg" {
        Some(ArtifactFormat::TorchPackage)
    } else if ext == "pte" {
        Some(ArtifactFormat::ExecuTorch)
    } else if ext == "onnx" {
        Some(ArtifactFormat::Onnx)
    } else if ext == "xml" {
        Some(ArtifactFormat::OpenVinoIr)
    } else if matches!(ext.as_str(), "engine" | "plan" | "trt") {
        Some(ArtifactFormat::TensorRtEngine)
    } else if ext == "mlmodel" {
        Some(ArtifactFormat::CoreMlModel)
    } else if ext == "mlpackage" {
        Some(ArtifactFormat::CoreMlPackage)
    } else if name == "saved_model.pb" {
        Some(ArtifactFormat::TensorFlowSavedModel)
    } else if ext == "index" && !name.ends_with(".safetensors.index.json") {
        Some(ArtifactFormat::TensorFlowCheckpoint)
    } else if ext == "tflite" {
        Some(ArtifactFormat::TensorFlowLite)
    } else if ext == "keras" {
        Some(ArtifactFormat::KerasArchive)
    } else if matches!(ext.as_str(), "h5" | "hdf5") {
        Some(ArtifactFormat::KerasHdf5)
    } else if ext == "npy" {
        Some(ArtifactFormat::Npy)
    } else if ext == "npz" {
        Some(ArtifactFormat::Npz)
    } else {
        None
    }
}

/// Probe magic signatures independently of filename.
pub fn probe_magic(prefix: &[u8]) -> Vec<ArtifactFormat> {
    let mut candidates = Vec::new();

    if prefix.starts_with(b"GGUF") {
        candidates.push(ArtifactFormat::Gguf);
    }
    if prefix.starts_with(b"\x93NUMPY") {
        candidates.push(ArtifactFormat::Npy);
    }
    if prefix.len() >= 9 {
        let header_len = u64::from_le_bytes(prefix[..8].try_into().expect("8 bytes"));
        if header_len > 0 && header_len <= 32 * 1024 * 1024 && prefix[8] == b'{' {
            candidates.push(ArtifactFormat::Safetensors);
        }
    }
    if is_pickle_prefix(prefix) {
        candidates.push(ArtifactFormat::Pickle);
    }
    if prefix.len() >= 8
        && (&prefix[4..6] == b"ET" || prefix.starts_with(b"ET12") || prefix.starts_with(b"ET11"))
    {
        candidates.push(ArtifactFormat::ExecuTorch);
    }
    if prefix.starts_with(b"TRT") || prefix.starts_with(b"ptrt") {
        candidates.push(ArtifactFormat::TensorRtEngine);
    }
    if prefix.starts_with(b"<?xml") || prefix.starts_with(b"<net") {
        candidates.push(ArtifactFormat::OpenVinoIr);
    }
    if prefix.len() >= 8 && &prefix[4..8] == b"TFL3" {
        candidates.push(ArtifactFormat::TensorFlowLite);
    }
    if prefix.starts_with(b"\x89HDF\r\n\x1a\n") {
        candidates.push(ArtifactFormat::KerasHdf5);
    }

    candidates
}

/// Probe generic container signatures (e.g. ZIP).
pub fn probe_container(prefix: &[u8]) -> Vec<ArtifactFormat> {
    let mut candidates = Vec::new();
    if prefix.starts_with(b"PK\x03\x04")
        || prefix.starts_with(b"PK\x05\x06")
        || prefix.starts_with(b"PK\x07\x08")
    {
        candidates.push(ArtifactFormat::PyTorchZip);
        candidates.push(ArtifactFormat::KerasArchive);
        candidates.push(ArtifactFormat::Npz);
    }
    candidates
}

fn is_pickle_prefix(prefix: &[u8]) -> bool {
    if prefix.len() >= 2 && prefix[0] == 0x80 && (2..=5).contains(&prefix[1]) {
        return true;
    }
    // Protocol 0/1 text pickles or common opcode sequences
    if prefix.starts_with(b"ccopy_reg\n")
        || prefix.starts_with(b"cos\n")
        || prefix.starts_with(b"(dp")
        || prefix.starts_with(b"(i")
        || prefix.starts_with(b"(S'")
    {
        return true;
    }
    false
}

fn resolve_selected(
    extension_claim: Option<ArtifactFormat>,
    magic_candidates: &[ArtifactFormat],
    container_candidates: &[ArtifactFormat],
    contradictions: &mut Vec<FormatContradiction>,
) -> ArtifactFormat {
    if let Some(&magic) = magic_candidates.first() {
        if let Some(claimed) = extension_claim {
            if claimed != magic
                && !(claimed == ArtifactFormat::Pickle && magic == ArtifactFormat::Pickle)
            {
                let kind = if magic == ArtifactFormat::Pickle {
                    ContradictionKind::SerializationSmuggling
                } else {
                    ContradictionKind::ExtensionMismatch
                };
                contradictions.push(FormatContradiction {
                    kind,
                    claim: Some(claimed),
                    content: magic,
                    detail: format!(
                        "Extension claims {} but content magic identifies {}",
                        claimed.as_str(),
                        magic.as_str()
                    ),
                });
            }
        }
        return magic;
    }

    if !container_candidates.is_empty() {
        if let Some(claimed) = extension_claim {
            if matches!(
                claimed,
                ArtifactFormat::Safetensors
                    | ArtifactFormat::Gguf
                    | ArtifactFormat::Onnx
                    | ArtifactFormat::Npy
            ) {
                contradictions.push(FormatContradiction {
                    kind: ContradictionKind::ContainerSmuggling,
                    claim: Some(claimed),
                    content: ArtifactFormat::Unknown,
                    detail: format!(
                        "Extension claims {} but content is a generic container (ZIP)",
                        claimed.as_str()
                    ),
                });
                return ArtifactFormat::Unknown;
            } else if matches!(
                claimed,
                ArtifactFormat::KerasArchive
                    | ArtifactFormat::PyTorchZip
                    | ArtifactFormat::TorchScript
                    | ArtifactFormat::TorchPackage
                    | ArtifactFormat::Npz
            ) {
                return claimed;
            } else if claimed == ArtifactFormat::Pickle {
                return ArtifactFormat::PyTorchZip;
            }
        }
        return ArtifactFormat::PyTorchZip;
    }

    extension_claim.unwrap_or(ArtifactFormat::Unknown)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_claim_mapped_independently() {
        assert_eq!(
            map_extension_claim(Path::new("model.safetensors")),
            Some(ArtifactFormat::Safetensors)
        );
        assert_eq!(
            map_extension_claim(Path::new("model.gguf")),
            Some(ArtifactFormat::Gguf)
        );
        assert_eq!(map_extension_claim(Path::new("weights.bin")), None);
    }

    #[test]
    fn safetensors_containing_pickle_triggers_contradiction() {
        let ident =
            ArtifactIdentification::identify(Path::new("model.safetensors"), &[0x80, 0x02, b'c']);
        assert_eq!(ident.extension_claim, Some(ArtifactFormat::Safetensors));
        assert_eq!(ident.selected, ArtifactFormat::Pickle);
        assert_eq!(ident.contradictions.len(), 1);
        assert_eq!(
            ident.contradictions[0].kind,
            ContradictionKind::SerializationSmuggling
        );
    }

    #[test]
    fn gguf_containing_zip_triggers_container_smuggling() {
        let ident =
            ArtifactIdentification::identify(Path::new("weights.gguf"), b"PK\x03\x04\x14\x00");
        assert_eq!(ident.extension_claim, Some(ArtifactFormat::Gguf));
        assert_eq!(ident.selected, ArtifactFormat::Unknown);
        assert_eq!(ident.contradictions.len(), 1);
        assert_eq!(
            ident.contradictions[0].kind,
            ContradictionKind::ContainerSmuggling
        );
    }

    #[test]
    fn bin_extension_with_pickle_has_no_mismatch() {
        let ident = ArtifactIdentification::identify(Path::new("weights.bin"), &[0x80, 0x04, 0x95]);
        assert_eq!(ident.extension_claim, None);
        assert_eq!(ident.selected, ArtifactFormat::Pickle);
        assert!(ident.contradictions.is_empty());
    }
}
