use super::{
    coreml, executorch, gguf, keras, mlx, onnx, openvino, pickle, pytorch, safetensors, tensorflow,
    tensorrt, tflite, ArtifactFormat, ArtifactIdentification,
};
use crate::finding_evidence::{structural_invariant, EvidenceSubject, FindingBuilder};
use crate::safeio::open_readonly_nofollow;
use crate::scanner::{
    BinaryScanner, CheckType, Confidence, FindingClass, LayerScanResult, MetadataScanner,
    ScanStatus,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics: Option<crate::scanner::ScanMetrics>,
    pub results: Vec<LayerScanResult>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub budget: Vec<crate::budget::BudgetUsage>,
}

impl ArtifactReport {
    pub fn blocking(&self) -> bool {
        self.results
            .iter()
            .any(|finding| finding.status == ScanStatus::Fail)
    }
}

pub fn inspect(path: &Path, mode: ArtifactScanMode) -> Result<ArtifactReport> {
    let budget =
        crate::budget::ScanBudget::new(crate::budget::ScanBudgetProfile::Default.limits())?;
    inspect_with_budget(path, mode, &budget)
}

pub fn inspect_with_budget(
    path: &Path,
    mode: ArtifactScanMode,
    budget: &crate::budget::ScanBudget,
) -> Result<ArtifactReport> {
    let file = open_readonly_nofollow(path)?;
    inspect_opened(path, file, None, mode, None, budget)
}

pub fn inspect_with_format(
    path: &Path,
    format: ArtifactFormat,
    mode: ArtifactScanMode,
) -> Result<ArtifactReport> {
    let budget =
        crate::budget::ScanBudget::new(crate::budget::ScanBudgetProfile::Default.limits())?;
    inspect_with_format_budget(path, format, mode, &budget)
}

pub fn inspect_with_format_budget(
    path: &Path,
    format: ArtifactFormat,
    mode: ArtifactScanMode,
    budget: &crate::budget::ScanBudget,
) -> Result<ArtifactReport> {
    let file = open_readonly_nofollow(path)?;
    inspect_opened(path, file, Some(format), mode, None, budget)
}

pub fn inspect_opened_file(
    path: &Path,
    file: &File,
    format: ArtifactFormat,
    mode: ArtifactScanMode,
) -> Result<ArtifactReport> {
    let budget =
        crate::budget::ScanBudget::new(crate::budget::ScanBudgetProfile::Default.limits())?;
    inspect_opened(path, file.try_clone()?, Some(format), mode, None, &budget)
}

pub fn inspect_opened_file_with_sha256(
    path: &Path,
    file: &File,
    format: ArtifactFormat,
    mode: ArtifactScanMode,
    sha256: &str,
) -> Result<ArtifactReport> {
    let budget =
        crate::budget::ScanBudget::new(crate::budget::ScanBudgetProfile::Default.limits())?;
    inspect_opened(
        path,
        file.try_clone()?,
        Some(format),
        mode,
        Some(sha256.to_owned()),
        &budget,
    )
}

pub fn inspect_opened_file_with_sha256_budget(
    path: &Path,
    file: &File,
    format: ArtifactFormat,
    mode: ArtifactScanMode,
    sha256: &str,
    budget: &crate::budget::ScanBudget,
) -> Result<ArtifactReport> {
    inspect_opened(
        path,
        file.try_clone()?,
        Some(format),
        mode,
        Some(sha256.to_owned()),
        budget,
    )
}

fn inspect_opened(
    path: &Path,
    file: File,
    supplied_format: Option<ArtifactFormat>,
    mode: ArtifactScanMode,
    precomputed_sha256: Option<String>,
    budget: &crate::budget::ScanBudget,
) -> Result<ArtifactReport> {
    let size = file.metadata()?.len();
    budget
        .consume(crate::budget::BudgetDimension::Objects, 1, "artifact")
        .map_err(|error| anyhow!("global scan budget exhausted: {error}"))?;
    budget
        .consume(
            crate::budget::BudgetDimension::SourceBytes,
            size,
            "artifact source",
        )
        .map_err(|error| anyhow!("global scan budget exhausted: {error}"))?;
    let mut prefix_buf = [0_u8; 512];
    let mut cloned = file.try_clone()?;
    cloned.seek(SeekFrom::Start(0))?;
    let n = cloned.read(&mut prefix_buf).unwrap_or(0);

    let identification = match supplied_format {
        Some(fmt) => {
            let mut id = ArtifactIdentification::identify(path, &prefix_buf[..n]);
            id.selected = fmt;
            id
        }
        None => ArtifactIdentification::identify(path, &prefix_buf[..n]),
    };
    let format = identification.selected;
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
        ArtifactFormat::Pickle => "application/x-python-pickle",
        ArtifactFormat::PyTorchZip | ArtifactFormat::TorchScript | ArtifactFormat::TorchPackage => {
            "application/x-pytorch-zip"
        }
        ArtifactFormat::ExecuTorch => "application/x-executorch",
        ArtifactFormat::OpenVinoIr => "application/x-openvino-ir",
        ArtifactFormat::TensorRtEngine => "application/x-tensorrt-engine",
        ArtifactFormat::CoreMlModel => "application/x-coreml-model",
        ArtifactFormat::CoreMlPackage => "application/x-coreml-package",
        ArtifactFormat::MlxPackage => "application/x-mlx-package",
        ArtifactFormat::TensorFlowSavedModel => "application/x-tensorflow-savedmodel",
        ArtifactFormat::TensorFlowCheckpoint => "application/x-tensorflow-checkpoint",
        ArtifactFormat::TensorFlowLite => "application/x-tflite",
        ArtifactFormat::KerasArchive => "application/x-keras",
        ArtifactFormat::KerasHdf5 => "application/x-hdf5",
        ArtifactFormat::Unknown => "application/octet-stream",
    };
    let session = crate::scanner::ScanSession::new(path, &file)?;
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
            None => {
                let mut observers: Vec<Box<dyn crate::scanner::StreamObserver>> = Vec::new();
                if fuse_binary {
                    observers.push(Box::new(crate::scanner::BinaryStreamObserver::new()));
                }
                let (digest_val, obs_results) = session.run(media, observers)?;
                digest_cache_state = if session.metrics.borrow().cache_hits > 0 {
                    "HIT".to_owned()
                } else {
                    "MISS".to_owned()
                };
                if fuse_binary {
                    fused_binary = obs_results.into_iter().next();
                }
                Some(digest_val)
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

    for contradiction in &identification.contradictions {
        let rule_id = match contradiction.kind {
            crate::formats::ContradictionKind::SerializationSmuggling
            | crate::formats::ContradictionKind::ContainerSmuggling => {
                "LF-FORMAT-CONTENT-SMUGGLING"
            }
            crate::formats::ContradictionKind::ExtensionMismatch => "LF-FORMAT-CLAIM-MISMATCH",
            crate::formats::ContradictionKind::PolyglotOverlapping => "LF-FORMAT-POLYGLOT",
        };
        let subject = EvidenceSubject::member(&path.display().to_string())
            .with_sha256(sha256.clone())
            .with_media_type(media);
        results.push(
            FindingBuilder::new(rule_id, CheckType::LayerPolicy, ScanStatus::Fail)
                .class(FindingClass::Structural)
                .confidence(Confidence::High)
                .digest(&identity)
                .media_type(media)
                .subject(subject.clone())
                .detail(&contradiction.detail)
                .evidence(structural_invariant(
                    subject,
                    "format extension claim contradicts observed content magic",
                    serde_json::json!({
                        "filename": path.file_name().and_then(|v| v.to_str()).unwrap_or(""),
                        "extension_claim": contradiction.claim.map(|c| c.as_str()),
                        "content_candidate": contradiction.content.as_str(),
                        "detail": contradiction.detail,
                    }),
                ))
                .finish(),
        );
    }

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
            results.push(safetensors::scan_file(&file, size, &identity, media, budget)?);
            if mode == ArtifactScanMode::Full {
                results.push(match fused_binary.take() {
                    Some(result) => result,
                    None => BinaryScanner::scan_file(&file, size, &identity, media)?,
                });
            }
        }
        ArtifactFormat::SafetensorsIndex => {
            results.push(safetensors::scan_index(path, &file, size, &identity, media, budget)?);
        }
        ArtifactFormat::Onnx => {
            let (finding, compound) = onnx::scan(path, &file, size, &identity, media)?;
            compound_identity = compound;
            results.push(finding);
        }
        ArtifactFormat::Pickle => {
            results.extend(pickle::scan(path, &file, size, &identity, media, budget)?);
        }
        ArtifactFormat::PyTorchZip
        | ArtifactFormat::TorchScript
        | ArtifactFormat::TorchPackage => {
            results.extend(pytorch::scan(path, &file, size, &identity, media)?);
        }
        ArtifactFormat::ExecuTorch => {
            results.extend(executorch::scan(path, &file, size, &identity, media)?);
        }
        ArtifactFormat::OpenVinoIr => {
            results.extend(openvino::scan(path, &file, size, &identity, media)?);
        }
        ArtifactFormat::TensorRtEngine => {
            results.extend(tensorrt::scan(path, &file, size, &identity, media)?);
        }
        ArtifactFormat::CoreMlModel => {
            results.extend(coreml::scan_model(path, &file, size, &identity, media)?);
        }
        ArtifactFormat::CoreMlPackage => {
            results.extend(coreml::scan_package(path, &identity, media)?);
        }
        ArtifactFormat::MlxPackage => {
            results.extend(mlx::scan_package(path, &identity, media)?);
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
            ..Default::default()
        }),
        ArtifactFormat::Unknown => {
            let mut prefix_buf = [0_u8; 512];
            let mut cloned = file.try_clone()?;
            cloned.seek(SeekFrom::Start(0))?;
            let n = cloned.read(&mut prefix_buf).unwrap_or(0);
            let detection = crate::archive::detect_archive_format(path, &prefix_buf[..n]);
            if detection.format != crate::archive::ArchiveFormat::Unknown {
                match crate::archive::inspect_opened(
                    path,
                    &file,
                    &identity,
                    &crate::archive::ArchiveLimits::default(),
                    0,
                    budget,
                ) {
                    Ok(arch_report) => results.extend(arch_report.findings),
                    Err(error) => results.push(LayerScanResult {
                        layer_digest: identity.clone(),
                        media_type: media.to_owned(),
                        check_type: crate::scanner::CheckType::LayerPolicy,
                        status: ScanStatus::Fail,
                        finding_class: FindingClass::Structural,
                        confidence: Confidence::High,
                        detail: Some(format!(
                            "Archive container '{}' failed inspection safely: {error}",
                            path.display()
                        )),
                        matches: vec![
                            "[LF-ARCHIVE-MALFORMED] archive inspection failed".to_owned(),
                        ],
                        duration_ms: 0,
                        ..Default::default()
                    }),
                }
            } else {
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
                    ..Default::default()
                });
            }
        }
    }

    let trailing_subject = EvidenceSubject::member(&path.display().to_string())
        .with_sha256(sha256.clone())
        .with_media_type(media);
    match format {
        ArtifactFormat::Gguf => {
            if let Ok(inv) = gguf::parse_file(&file, size) {
                let extent = inv.logical_extent(size);
                if let Ok(Some(finding)) = crate::formats::extent::inspect_trailing_data(
                    &file,
                    extent,
                    &trailing_subject,
                    &identity,
                    media,
                ) {
                    results.push(finding);
                }
            }
        }
        ArtifactFormat::Safetensors => {
            if let Ok(inv) = safetensors::inventory_file(&file, size) {
                let extent = inv.logical_extent(size);
                if let Ok(Some(finding)) = crate::formats::extent::inspect_trailing_data(
                    &file,
                    extent,
                    &trailing_subject,
                    &identity,
                    media,
                ) {
                    results.push(finding);
                }
            }
        }
        _ => {}
    }
    // Every branch above tags `matches[0]` with a `[RULE-ID]` prefix already;
    // backfill the structured identity fields for any finding still built as
    // a plain struct literal so evidence attribution stays consistent
    // regardless of construction style.
    for result in &mut results {
        if result.rule_id.is_none() {
            let rule = crate::policy::rule_id(result);
            crate::finding_evidence::ensure_finding_identity(result, &rule);
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
        metrics: Some(session.metrics.into_inner()),
        budget: budget.snapshot(None),
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
    let budget =
        crate::budget::ScanBudget::new(crate::budget::ScanBudgetProfile::Default.limits())?;
    inspect_dir_with_budget(root, recursive, mode, jobs, &budget)
}

pub fn inspect_dir_with_budget(
    root: &Path,
    recursive: bool,
    mode: ArtifactScanMode,
    jobs: usize,
    budget: &crate::budget::ScanBudget,
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
            .filter_map(|path| {
                // Cooperative cancellation: don't start scanning a queued
                // path once the deadline/cancellation has already tripped,
                // and don't let a deadline hit mid-file discard every other
                // file's already-completed report — only a genuine (non
                // control) error still aborts the whole directory scan.
                if budget.check().is_err() {
                    return None;
                }
                match inspect_with_budget(&path, mode, budget) {
                    Ok(report) => Some(Ok(report)),
                    Err(error) => {
                        if budget.check().is_err() {
                            None
                        } else {
                            Some(Err(error))
                        }
                    }
                }
            })
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
                    | "zip"
                    | "whl"
                    | "tar"
                    | "tgz"
            )
        })
        || path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                let lower = name.to_ascii_lowercase();
                lower.ends_with(".safetensors.index.json") || lower.ends_with(".tar.gz")
            })
}
