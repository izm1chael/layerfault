use super::{keras, onnx, safetensors, tensorflow, tflite, ArtifactFormat};
use crate::safeio::open_readonly_nofollow;
use crate::scanner::{
    BinaryScanner, Confidence, FindingClass, LayerScanResult, MetadataScanner, ScanStatus,
};
use anyhow::{anyhow, Context, Result};
use rayon::prelude::*;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactScanMode {
    Full,
    StructureOnly,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ArtifactCacheInfo {
    pub digest: String,
    pub evidence: String,
    pub digest_min_bytes: u64,
    pub evidence_min_bytes: u64,
    pub evidence_revision: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ArtifactReport {
    pub path: String,
    pub name: String,
    pub format: ArtifactFormat,
    pub size: u64,
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compound_identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache: Option<ArtifactCacheInfo>,
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
    inspect_opened(path, file, format, mode, None)
}

pub fn inspect_with_format(
    path: &Path,
    format: ArtifactFormat,
    mode: ArtifactScanMode,
) -> Result<ArtifactReport> {
    let file = open_readonly_nofollow(path)?;
    inspect_opened(path, file, format, mode, None)
}

pub fn inspect_opened_file(
    path: &Path,
    file: &File,
    format: ArtifactFormat,
    mode: ArtifactScanMode,
) -> Result<ArtifactReport> {
    inspect_opened(path, file.try_clone()?, format, mode, None)
}

pub fn inspect_opened_file_with_sha256(
    path: &Path,
    file: &File,
    format: ArtifactFormat,
    mode: ArtifactScanMode,
    sha256: &str,
) -> Result<ArtifactReport> {
    inspect_opened(
        path,
        file.try_clone()?,
        format,
        mode,
        Some(sha256.to_owned()),
    )
}

fn inspect_opened(
    path: &Path,
    file: File,
    format: ArtifactFormat,
    mode: ArtifactScanMode,
    precomputed_sha256: Option<String>,
) -> Result<ArtifactReport> {
    let size = file.metadata()?.len();
    let before = crate::hashcache::capture_identity(path, &file)?;
    let discriminator = format!(
        "artifact:{}:{}",
        format.as_str(),
        match mode {
            ArtifactScanMode::Full => "full",
            ArtifactScanMode::StructureOnly => "structure",
        }
    );
    // ONNX reports may bind external tensor sidecars. A cache record keyed only
    // by the main protobuf file cannot prove those sidecars are still unchanged,
    // so compound ONNX admission deliberately revalidates them on every scan.
    let evidence_cache_safe = format != ArtifactFormat::Onnx;
    if evidence_cache_safe {
        if let Some(mut report) = crate::hashcache::load_evidence::<ArtifactReport>(
            "artifact-reports",
            path,
            &file,
            &discriminator,
        )? {
            if precomputed_sha256
                .as_deref()
                .is_none_or(|expected| report.sha256.as_deref() == Some(expected))
            {
                let policy = crate::hashcache::cache_policy();
                report.cache = Some(ArtifactCacheInfo {
                    digest: "REUSED_BY_EVIDENCE".to_owned(),
                    evidence: "HIT".to_owned(),
                    digest_min_bytes: policy.digest_min_bytes,
                    evidence_min_bytes: policy.evidence_min_bytes,
                    evidence_revision: policy.evidence_revision.to_owned(),
                });
                return Ok(report);
            }
        }
    }
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
    let fuse_binary = mode == ArtifactScanMode::Full
        && matches!(format, ArtifactFormat::Gguf | ArtifactFormat::Safetensors)
        && precomputed_sha256.is_none();
    let mut fused_binary = None;
    let mut digest_cache_state = "NOT_USED".to_owned();
    let sha256 = if mode == ArtifactScanMode::Full {
        match precomputed_sha256 {
            Some(value) => {
                digest_cache_state = "PRECOMPUTED".to_owned();
                Some(value)
            }
            None if fuse_binary => {
                let mut stream = crate::scanner::binary::BinaryStreamScanner::new();
                let (outcome, streamed) =
                    crate::hashcache::sha256_prefixed_with_observer(path, &file, |bytes| {
                        stream.observe(&file, size, bytes)
                    })?;
                digest_cache_state = if outcome.cache_hit { "HIT" } else { "MISS" }.to_owned();
                let identity = outcome.sha256.clone();
                fused_binary = Some(if streamed {
                    stream.finish(&identity, media)
                } else {
                    BinaryScanner::scan_file(&file, size, &identity, media)?
                });
                Some(identity)
            }
            None => {
                let outcome = crate::hashcache::sha256_prefixed(path, &file)?;
                digest_cache_state = if outcome.cache_hit { "HIT" } else { "MISS" }.to_owned();
                Some(outcome.sha256)
            }
        }
    } else {
        None
    };
    let identity = sha256
        .clone()
        .unwrap_or_else(|| format!("file:{}", path.display()));
    let mut results = Vec::new();
    let mut compound_identity = None;
    match format {
        ArtifactFormat::Gguf => {
            results.extend(MetadataScanner::scan_file_results(
                &file, size, &identity, media,
            )?);
            if mode == ArtifactScanMode::Full {
                results.push(match fused_binary.take() {
                    Some(result) => result,
                    None => BinaryScanner::scan_file(&file, size, &identity, media)?,
                });
            }
        }
        ArtifactFormat::Safetensors => {
            results.push(safetensors::scan_file(&file, size, &identity, media)?);
            if mode == ArtifactScanMode::Full {
                results.push(match fused_binary.take() {
                    Some(result) => result,
                    None => BinaryScanner::scan_file(&file, size, &identity, media)?,
                });
            }
        }
        ArtifactFormat::SafetensorsIndex => {
            results.push(safetensors::scan_index(path, &file, size, &identity, media)?);
        }
        ArtifactFormat::Onnx => {
            let (finding, compound) = onnx::scan(path, &file, size, &identity, media)?;
            compound_identity = compound;
            results.push(finding);
        }
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
    let report = ArtifactReport {
        path: path.display().to_string(),
        name: path
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("artifact")
            .to_owned(),
        format,
        size,
        sha256,
        compound_identity,
        cache: {
            let policy = crate::hashcache::cache_policy();
            Some(ArtifactCacheInfo {
                digest: digest_cache_state,
                evidence: if !evidence_cache_safe {
                    "BYPASS_COMPOUND".to_owned()
                } else if crate::hashcache::evidence_eligible(size) {
                    "MISS".to_owned()
                } else {
                    "BYPASS_SMALL".to_owned()
                },
                digest_min_bytes: policy.digest_min_bytes,
                evidence_min_bytes: policy.evidence_min_bytes,
                evidence_revision: policy.evidence_revision.to_owned(),
            })
        },
        results,
    };
    if !crate::hashcache::identity_unchanged(path, &file, &before)? {
        return Err(anyhow!(
            "Artifact '{}' changed while it was being scanned",
            path.display()
        ));
    }
    if evidence_cache_safe {
        crate::hashcache::store_evidence(
            "artifact-reports",
            path,
            &file,
            &before,
            &discriminator,
            &report,
        )?;
    }
    Ok(report)
}

pub fn inspect_dir(
    root: &Path,
    recursive: bool,
    mode: ArtifactScanMode,
    jobs: usize,
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
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(jobs.clamp(1, 64))
        .build()?;
    pool.install(|| {
        paths
            .into_par_iter()
            .map(|path| inspect(&path, mode))
            .collect()
    })
}

fn known_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|ext| {
            matches!(
                ext.to_ascii_lowercase().as_str(),
                "gguf"
                    | "safetensors"
                    | "onnx"
                    | "tflite"
                    | "keras"
                    | "h5"
                    | "hdf5"
                    | "index"
                    | "pb"
            )
        })
        || path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                name.to_ascii_lowercase()
                    .ends_with(".safetensors.index.json")
            })
}
