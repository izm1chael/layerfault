use super::{keras, onnx, safetensors, tensorflow, tflite, ArtifactFormat};
use crate::safeio::open_readonly_nofollow;
use crate::scanner::{
    BinaryScanner, Confidence, FindingClass, LayerScanResult, MetadataScanner, ScanStatus,
};
use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactScanMode {
    Full,
    StructureOnly,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ArtifactReport {
    pub path: String,
    pub name: String,
    pub format: ArtifactFormat,
    pub size: u64,
    pub sha256: Option<String>,
    pub results: Vec<LayerScanResult>,
}

impl ArtifactReport {
    pub fn blocking(&self) -> bool {
        self.results
            .iter()
            .any(|finding| finding.status == ScanStatus::Fail)
    }
}

pub fn inspect(path: &Path, mode: ArtifactScanMode) -> Result<ArtifactReport> {
    let file = open_readonly_nofollow(path)?;
    let mut prefix = [0_u8; 8];
    let mut cloned = file.try_clone()?;
    cloned.seek(SeekFrom::Start(0))?;
    let count = cloned.read(&mut prefix)?;
    let format = ArtifactFormat::detect(path, &prefix[..count]);
    inspect_opened(path, file, format, mode)
}

pub fn inspect_with_format(
    path: &Path,
    format: ArtifactFormat,
    mode: ArtifactScanMode,
) -> Result<ArtifactReport> {
    let file = open_readonly_nofollow(path)?;
    inspect_opened(path, file, format, mode)
}

pub fn inspect_opened_file(
    path: &Path,
    file: &File,
    format: ArtifactFormat,
    mode: ArtifactScanMode,
) -> Result<ArtifactReport> {
    inspect_opened(path, file.try_clone()?, format, mode)
}

fn inspect_opened(
    path: &Path,
    file: File,
    format: ArtifactFormat,
    mode: ArtifactScanMode,
) -> Result<ArtifactReport> {
    let size = file.metadata()?.len();
    let sha256 = if mode == ArtifactScanMode::Full {
        Some(hash_sha256(&file)?)
    } else {
        None
    };
    let identity = sha256
        .clone()
        .unwrap_or_else(|| format!("file:{}", path.display()));
    let media = match format {
        ArtifactFormat::Gguf => "application/x-gguf",
        ArtifactFormat::Safetensors => "application/x-safetensors",
        ArtifactFormat::SafetensorsIndex => "application/x-safetensors-index+json",
        ArtifactFormat::Onnx => "application/x-onnx",
        ArtifactFormat::TensorFlowSavedModel => "application/x-tensorflow-savedmodel",
        ArtifactFormat::TensorFlowCheckpoint => "application/x-tensorflow-checkpoint",
        ArtifactFormat::TensorFlowLite => "application/x-tflite",
        ArtifactFormat::KerasArchive => "application/x-keras",
        ArtifactFormat::KerasHdf5 => "application/x-hdf5",
        ArtifactFormat::Unknown => "application/octet-stream",
    };
    let mut results = Vec::new();
    match format {
        ArtifactFormat::Gguf => {
            results.extend(MetadataScanner::scan_file_results(
                &file, size, &identity, media,
            )?);
            if mode == ArtifactScanMode::Full {
                results.push(BinaryScanner::scan_file(&file, size, &identity, media)?);
            }
        }
        ArtifactFormat::Safetensors => {
            results.push(safetensors::scan_file(&file, size, &identity, media)?);
            if mode == ArtifactScanMode::Full {
                results.push(BinaryScanner::scan_file(&file, size, &identity, media)?);
            }
        }
        ArtifactFormat::SafetensorsIndex => {
            results.push(safetensors::scan_index(path, &file, size, &identity, media)?);
        }
        ArtifactFormat::Onnx => results.push(onnx::scan(&file, size, &identity, media)?),
        ArtifactFormat::TensorFlowSavedModel => results.push(tensorflow::scan_saved_model(&file, size, &identity, media)?),
        ArtifactFormat::TensorFlowCheckpoint => results.push(tensorflow::scan_checkpoint(path, &file, size, &identity, media)?),
        ArtifactFormat::TensorFlowLite => results.push(tflite::scan(&file, size, &identity, media)?),
        ArtifactFormat::KerasArchive => results.push(keras::scan(&file, size, &identity, media)?),
        ArtifactFormat::KerasHdf5 => results.push(LayerScanResult {
            layer_digest: identity.clone(), media_type: media.to_owned(), check_type: crate::scanner::CheckType::KerasStructure,
            status: ScanStatus::Warn, finding_class: FindingClass::Compatibility, confidence: Confidence::High,
            detail: Some("Keras/TensorFlow HDF5 container recognized. This build hashes and package-scans the file but does not execute or fully decode arbitrary HDF5 object graphs.".to_owned()),
            matches: vec!["[LF-KERAS-HDF5-LIMIT] HDF5 model recognized with explicit bounded capability limit".to_owned()], duration_ms: 0,
        }),
        ArtifactFormat::Unknown => {
            results.push(LayerScanResult {
                layer_digest: identity.clone(),
                media_type: media.to_owned(),
                check_type: crate::scanner::CheckType::LayerPolicy,
                status: ScanStatus::Warn,
                finding_class: FindingClass::Compatibility,
                confidence: Confidence::High,
                detail: Some("Unknown artifact format: integrity can be hashed but no structural parser is available".to_owned()),
                matches: vec!["[LF-FORMAT-UNKNOWN] unknown artifact format".to_owned()],
                duration_ms: 0,
            });
        }
    }
    Ok(ArtifactReport {
        path: path.display().to_string(),
        name: path
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("artifact")
            .to_owned(),
        format,
        size,
        sha256,
        results,
    })
}

pub fn inspect_dir(
    root: &Path,
    recursive: bool,
    mode: ArtifactScanMode,
) -> Result<Vec<ArtifactReport>> {
    if !root.is_dir() {
        return Err(anyhow!("'{}' is not a directory", root.display()));
    }
    let mut paths = Vec::<PathBuf>::new();
    if recursive {
        for entry in walkdir::WalkDir::new(root).follow_links(false) {
            let entry = entry?;
            if entry.file_type().is_file() && known_extension(entry.path()) {
                paths.push(entry.into_path());
            }
        }
    } else {
        for entry in std::fs::read_dir(root) // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path -- caller explicitly selected this local scan root; entries are read-only and symlinks are not followed
            .with_context(|| format!("Unable to read '{}'", root.display()))?
        {
            let entry = entry?;
            if entry.file_type()?.is_file() && known_extension(&entry.path()) {
                paths.push(entry.path());
            }
        }
    }
    paths.sort();
    paths.into_iter().map(|path| inspect(&path, mode)).collect()
}

fn known_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|ext| {
            matches!(ext.to_ascii_lowercase().as_str(), "gguf" | "safetensors" | "onnx" | "tflite" | "keras" | "h5" | "hdf5" | "index" | "pb")
        })
        || path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                name.to_ascii_lowercase()
                    .ends_with(".safetensors.index.json")
            })
}

fn hash_sha256(file: &File) -> Result<String> {
    let started = Instant::now();
    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0_u8; 1024 * 1024];
    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    let _ = started;
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}
