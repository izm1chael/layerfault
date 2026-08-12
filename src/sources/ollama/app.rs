use super::manifest::{Layer, ModelRef, ResolvedModel};
use crate::policy::{EffectivePolicy, PolicyAction, PolicyDecision};
use crate::provenance::{self, TrustState};
use crate::report::ModelReport;
use crate::scanner::{
    CheckType, Confidence, ConfigScanner, FindingClass, HeuristicsScanner, IntegrityScanner,
    LayerScanResult, MetadataScanner, ScanStatus,
};
use crate::{discovery, manifest, scanner, ThresholdConfig};
use anyhow::Result;
use ed25519_dalek::VerifyingKey;
use indicatif::{MultiProgress, ProgressDrawTarget};
use rayon::prelude::*;
use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

type LayerScanCell = Arc<OnceLock<Vec<LayerScanResult>>>;
type LayerScanCache = Arc<Mutex<BTreeMap<String, LayerScanCell>>>;

#[derive(Debug, Clone, serde::Serialize)]
pub struct EvaluatedReport {
    #[serde(flatten)]
    pub report: ModelReport,
    pub trust_state: TrustState,
    pub trusted_signatures: usize,
    pub signer_fingerprints: Vec<String>,
    pub policy: PolicyDecision,
}

pub struct ScanOptions<'a> {
    pub thresholds: &'a ThresholdConfig,
    pub verifying_key: Option<&'a VerifyingKey>,
    pub trust_store: &'a crate::trust::TrustStore,
    pub policy: &'a EffectivePolicy,
    pub jobs: usize,
    pub quiet: bool,
    pub budget: crate::budget::ScanBudget,
    pub scheduler: crate::scheduler::AdaptiveScheduler,
}

pub fn resolve_base_dir(override_dir: Option<&Path>) -> Result<PathBuf> {
    match override_dir {
        Some(path) => {
            discovery::validate_models_dir(path)?;
            Ok(path.to_path_buf())
        }
        None => discovery::resolve_models_dir(),
    }
}

pub fn select_models(base_dir: &Path, selector: Option<&str>) -> Result<Vec<ModelRef>> {
    match selector {
        Some(selector) => Ok(vec![manifest::find_model(base_dir, selector)?]),
        None => {
            let models = manifest::discover_all_models(base_dir)?;
            if models.is_empty() {
                anyhow::bail!("No local Ollama model manifests were found");
            }
            Ok(models)
        }
    }
}

pub fn scan_selected(
    base_dir: &Path,
    selector: Option<&str>,
    options: &ScanOptions<'_>,
) -> Result<Vec<EvaluatedReport>> {
    let models = select_models(base_dir, selector)?;
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(options.jobs)
        .build()?;
    let progress = if options.quiet {
        MultiProgress::with_draw_target(ProgressDrawTarget::hidden())
    } else {
        MultiProgress::new()
    };
    let cache: LayerScanCache = Arc::new(Mutex::new(BTreeMap::new()));
    Ok(pool.install(|| {
        models
            .into_par_iter()
            .map(|model| scan_model_safe(base_dir, model, options, &progress, &cache))
            .collect()
    }))
}

fn scan_model_safe(
    base_dir: &Path,
    model_ref: ModelRef,
    options: &ScanOptions<'_>,
    progress: &MultiProgress,
    cache: &LayerScanCache,
) -> EvaluatedReport {
    let model_name = model_ref.name.clone();
    match scan_model(base_dir, model_ref, options, progress, cache) {
        Ok(value) => value,
        Err(error) => {
            let report = ModelReport {
                model_name: model_name.clone(),
                results: vec![scan_error(
                    "manifest",
                    "application/vnd.ollama.image.manifest",
                    format!("Model scan failed safely: {error}"),
                )],
            };
            let policy = options
                .policy
                .evaluate(&model_name, &report.results, TrustState::Invalid);
            EvaluatedReport {
                report,
                trust_state: TrustState::Invalid,
                trusted_signatures: 0,
                signer_fingerprints: Vec::new(),
                policy,
            }
        }
    }
}

fn scan_model(
    base_dir: &Path,
    model_ref: ModelRef,
    options: &ScanOptions<'_>,
    progress: &MultiProgress,
    cache: &LayerScanCache,
) -> Result<EvaluatedReport> {
    let model = manifest::load_model(&model_ref)?;
    let mut results = manifest_compatibility_results(&model);

    for layer in model.descriptors() {
        results.extend(scan_layer_cached(
            base_dir,
            layer,
            options.thresholds,
            progress,
            cache,
            &options.budget,
        ));
    }

    let provenance =
        provenance::verify_model(base_dir, &model, options.trust_store, options.verifying_key)?;
    results.push(provenance.finding);

    let report = ModelReport {
        model_name: model.name.clone(),
        results,
    };
    let model_size = model
        .descriptors()
        .fold(0_u64, |acc, layer| acc.saturating_add(layer.size));
    let context = crate::policy::PolicyContext {
        source: Some("ollama".to_owned()),
        format: Some("ollama-manifest".to_owned()),
        model_size: Some(model_size),
        trusted_signatures: provenance.trusted_signatures,
        signer_fingerprints: provenance.signer_fingerprints.clone(),
        now_unix: crate::paths::now_unix(),
        ..crate::policy::PolicyContext::default()
    };
    let policy = options.policy.evaluate_with_context(
        &model.name,
        &report.results,
        provenance.state,
        &context,
    );
    Ok(EvaluatedReport {
        report,
        trust_state: provenance.state,
        trusted_signatures: provenance.trusted_signatures,
        signer_fingerprints: provenance.signer_fingerprints,
        policy,
    })
}

fn manifest_compatibility_results(model: &ResolvedModel) -> Vec<LayerScanResult> {
    let mut results = Vec::new();
    if let Some(schema) = model.manifest.schema_version {
        if schema != 2 {
            results.push(policy_result(
                &model.digest,
                "application/vnd.ollama.image.manifest",
                ScanStatus::Warn,
                format!("Unrecognized OCI schemaVersion {schema}; descriptors will still be integrity checked"),
            ));
        }
    }
    if let Some(media_type) = &model.manifest.media_type {
        if !media_type.contains("manifest") {
            results.push(policy_result(
                &model.digest,
                media_type,
                ScanStatus::Warn,
                format!("Unusual manifest mediaType '{media_type}'"),
            ));
        }
    }
    results
}

fn scan_layer_cached(
    base_dir: &Path,
    layer: &Layer,
    thresholds: &ThresholdConfig,
    progress: &MultiProgress,
    cache: &LayerScanCache,
    budget: &crate::budget::ScanBudget,
) -> Vec<LayerScanResult> {
    // One OnceLock per descriptor key coalesces concurrent misses. Shared base
    // layers referenced by many models are therefore hashed/scanned once, not
    // once per racing model worker. Failed scans are removed after all current
    // waiters receive the same safe result so a later encounter may retry.
    let key = format!(
        "{}|{}|{}|{}|{}",
        layer.digest,
        layer.media_type,
        thresholds.max_temperature.to_bits(),
        thresholds.max_ctx,
        thresholds.max_predict
    );
    let cell = match cache.lock() {
        Ok(mut guard) => Arc::clone(
            guard
                .entry(key.clone())
                .or_insert_with(|| Arc::new(OnceLock::new())),
        ),
        Err(_) => return scan_layer_safe(base_dir, layer, thresholds, progress, budget),
    };
    let results = cell
        .get_or_init(|| scan_layer_safe(base_dir, layer, thresholds, progress, budget))
        .clone();

    let verified = results.iter().any(|result| {
        result.check_type == CheckType::IntegrityHash && result.status == ScanStatus::Pass
    }) && !results
        .iter()
        .any(|result| result.check_type == CheckType::ScanError);
    if !verified {
        if let Ok(mut guard) = cache.lock() {
            if guard
                .get(&key)
                .is_some_and(|current| Arc::ptr_eq(current, &cell))
            {
                guard.remove(&key);
            }
        }
    }
    results
}

fn scan_layer_safe(
    base_dir: &Path,
    layer: &Layer,
    thresholds: &ThresholdConfig,
    progress: &MultiProgress,
    budget: &crate::budget::ScanBudget,
) -> Vec<LayerScanResult> {
    match scan_layer(base_dir, layer, thresholds, progress, budget) {
        Ok(results) => results,
        Err(error) => vec![scan_error(
            &layer.digest,
            &layer.media_type,
            format!("Descriptor scan failed safely: {error}"),
        )],
    }
}

fn scan_layer(
    base_dir: &Path,
    layer: &Layer,
    thresholds: &ThresholdConfig,
    progress: &MultiProgress,
    budget: &crate::budget::ScanBudget,
) -> Result<Vec<LayerScanResult>> {
    budget
        .consume(crate::budget::BudgetDimension::Objects, 1, "ollama layer")
        .map_err(|error| anyhow::anyhow!("global scan budget exhausted: {error}"))?;
    budget
        .consume(
            crate::budget::BudgetDimension::SourceBytes,
            layer.size,
            "ollama layer source",
        )
        .map_err(|error| anyhow::anyhow!("global scan budget exhausted: {error}"))?;
    let media_type = layer.base_media_type();
    let full_media = layer.media_type.as_str();
    let binary_media = matches!(
        media_type,
        "application/vnd.ollama.image.model"
            | "application/vnd.ollama.image.projector"
            | "application/vnd.ollama.image.adapter"
            | "application/vnd.ollama.image.draft"
            | "application/vnd.ollama.image.tensor"
    );
    let (integrity, verified) = if binary_media {
        IntegrityScanner::open_and_verify_with_binary(base_dir, layer, progress, full_media)?
    } else {
        IntegrityScanner::open_and_verify(base_dir, layer, progress)?
    };
    let mut results = vec![integrity];
    let Some(verified) = verified else {
        return Ok(results);
    };
    let is_gguf = file_starts_with_gguf(&verified.file)?;

    match media_type {
        "application/vnd.ollama.image.model"
        | "application/vnd.ollama.image.projector"
        | "application/vnd.ollama.image.adapter"
        | "application/vnd.ollama.image.draft" => {
            results.push(match verified.binary_scan.clone() {
                Some(result) => result,
                None => scanner::BinaryScanner::scan_file(
                    &verified.file,
                    verified.len,
                    &layer.digest,
                    full_media,
                )?,
            });
            if is_gguf {
                results.extend(MetadataScanner::scan_file_results(
                    &verified.file,
                    verified.len,
                    &layer.digest,
                    full_media,
                )?);
            } else if media_type == "application/vnd.ollama.image.model" {
                results.push(policy_result(
                    &layer.digest,
                    full_media,
                    ScanStatus::Warn,
                    "Legacy model layer is not GGUF; binary integrity was verified but GGUF structural checks are not applicable".to_owned(),
                ));
            }
        }
        "application/vnd.ollama.image.tensor" => {
            results.push(match verified.binary_scan.clone() {
                Some(result) => result,
                None => scanner::BinaryScanner::scan_file(
                    &verified.file,
                    verified.len,
                    &layer.digest,
                    full_media,
                )?,
            });
        }
        "application/vnd.ollama.image.template"
        | "application/vnd.ollama.image.system"
        | "application/vnd.ollama.image.tokenizer.config"
        | "application/vnd.ollama.image.json"
        | "application/vnd.docker.container.image.v1+json" => {
            results.push(HeuristicsScanner::scan_file(
                &verified.file,
                &layer.digest,
                full_media,
            )?);
        }
        "application/vnd.ollama.image.params" => {
            results.push(ConfigScanner::scan_file(
                &verified.file,
                &layer.digest,
                full_media,
                thresholds,
            )?);
        }
        "application/vnd.ollama.image.config" => {
            if full_media.to_ascii_lowercase().contains("type=gguf") || is_gguf {
                results.extend(MetadataScanner::scan_file_results(
                    &verified.file,
                    verified.len,
                    &layer.digest,
                    full_media,
                )?);
            } else {
                results.push(HeuristicsScanner::scan_file(
                    &verified.file,
                    &layer.digest,
                    full_media,
                )?);
            }
        }
        "application/vnd.ollama.image.tokenizer" | "application/vnd.ollama.image.license" => {
            results.push(policy_result(
                &layer.digest,
                full_media,
                ScanStatus::Pass,
                "Descriptor integrity verified; no high-confidence deep scanner is applied to this layer type".to_owned(),
            ));
        }
        _ => {
            results.push(policy_result(
                &layer.digest,
                full_media,
                ScanStatus::Warn,
                format!(
                    "Unknown layer media type '{full_media}': digest/size verified, deep content inspection skipped"
                ),
            ));
        }
    }
    Ok(results)
}

fn file_starts_with_gguf(file: &std::fs::File) -> Result<bool> {
    let mut cloned = file.try_clone()?;
    cloned.seek(SeekFrom::Start(0))?;
    let mut magic = [0_u8; 4];
    match cloned.read_exact(&mut magic) {
        Ok(()) => Ok(&magic == b"GGUF"),
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn policy_result(
    digest: &str,
    media_type: &str,
    status: ScanStatus,
    detail: String,
) -> LayerScanResult {
    let mut result = LayerScanResult {
        layer_digest: digest.to_owned(),
        media_type: media_type.to_owned(),
        check_type: CheckType::LayerPolicy,
        status,
        finding_class: FindingClass::Compatibility,
        confidence: Confidence::High,
        detail: Some(detail),
        matches: Vec::new(),
        duration_ms: 0,
        ..Default::default()
    };
    crate::finding_evidence::ensure_finding_identity(&mut result, "LF-LAYERPOLICY");
    result
}

fn scan_error(digest: &str, media_type: &str, detail: String) -> LayerScanResult {
    let mut result = LayerScanResult {
        layer_digest: digest.to_owned(),
        media_type: media_type.to_owned(),
        check_type: CheckType::ScanError,
        status: ScanStatus::Fail,
        finding_class: FindingClass::Operational,
        confidence: Confidence::High,
        detail: Some(detail),
        matches: vec!["[LF-SCAN-ERROR] scan error".to_owned()],
        duration_ms: 0,
        ..Default::default()
    };
    crate::finding_evidence::ensure_finding_identity(&mut result, "LF-SCAN-ERROR");
    result
}

pub fn scanner_exit_code(reports: &[EvaluatedReport]) -> i32 {
    crate::decision::SecurityDecision::scanner_finding_exit_code(
        reports
            .iter()
            .flat_map(|report| report.report.results.iter()),
    )
}

pub fn policy_exit_code(reports: &[EvaluatedReport]) -> i32 {
    let scanner = scanner_exit_code(reports);
    let policy_block = reports
        .iter()
        .any(|report| report.policy.action == PolicyAction::Block);
    let policy_warn = reports
        .iter()
        .any(|report| report.policy.action == PolicyAction::Warn);
    crate::decision::SecurityDecision::combine_scanner_and_policy_exit_code(
        scanner,
        policy_block,
        policy_warn,
    )
}

pub fn default_jobs() -> usize {
    std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(1)
}
