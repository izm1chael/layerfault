//! Bounded local dataset fingerprinting and poisoning-evidence analysis.
//! Dataset indicators are evidence only; they cannot prove malicious poisoning.

use anyhow::{anyhow, bail, Context, Result};
use rayon::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

const MAX_FILES: usize = 100_000;
/// Monolithic JSON needs an in-memory DOM in this build. Line-oriented formats
/// are streamed and are deliberately not subject to this byte limit.
const MAX_JSON_BYTES_FOR_RECORD_PARSE: u64 = 256 * 1024 * 1024;
const MAX_RECORDS: usize = 250_000;
const MAX_RECORD_BYTES: usize = 1024 * 1024;
const MAX_TOKEN_KEYS: usize = 200_000;
const MAX_DUPLICATE_EXAMPLES: usize = 100;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DatasetFormat {
    Json,
    Jsonl,
    Csv,
    Tsv,
    Text,
    ParquetOpaque,
    Directory,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetFile {
    pub path: String,
    pub format: DatasetFormat,
    pub bytes: u64,
    pub sha256: String,
    /// Exact number of syntactically parsed records when record parsing is
    /// available for this format, otherwise zero with `parse_warning` set.
    pub parsed_records: usize,
    /// Number of records selected for poisoning analysis in this invocation.
    /// Fingerprint-only calls report zero because they do not run content
    /// poisoning analysis.
    pub records_analyzed: usize,
    pub parse_warning: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetCoverage {
    pub records_available: usize,
    pub records_analyzed: usize,
    pub record_limit: usize,
    pub record_limit_reached: bool,
    pub token_key_limit: usize,
    pub token_key_limit_reached: bool,
    pub opaque_or_unparsed_files: usize,
    pub sampling_strategy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetFingerprint {
    pub version: u32,
    pub identity: String,
    pub root: String,
    pub total_bytes: u64,
    pub files: Vec<DatasetFile>,
    /// Retained for compatibility. This is the number of records that a
    /// bounded poisoning pass would be permitted to analyze.
    pub records_sampled: usize,
    pub coverage: DatasetCoverage,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoisonIndicator {
    pub rule_id: String,
    pub confidence: String,
    pub count: u64,
    pub detail: String,
    pub examples: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoisoningReview {
    pub version: u32,
    pub dataset: DatasetFingerprint,
    pub state: String,
    pub indicators: Vec<PoisonIndicator>,
    pub records_analyzed: usize,
    pub coverage: DatasetCoverage,
    pub boundary: String,
}

#[derive(Debug, Clone)]
struct Record {
    text: String,
    label: Option<String>,
}

#[derive(Debug, Clone)]
struct DatasetPlan {
    path: PathBuf,
    relative: String,
    format: DatasetFormat,
    bytes: u64,
}

#[derive(Debug, Clone)]
struct CountedFile {
    plan: DatasetPlan,
    sha256: String,
    records_available: usize,
    parse_warning: Option<String>,
}

#[derive(Debug, Default)]
struct LocalAnalysis {
    duplicate_counts: HashMap<String, (u64, String)>,
    token_counts: HashMap<String, u64>,
    label_token_counts: HashMap<(String, String), u64>,
    label_counts: HashMap<String, u64>,
    indicators: BTreeMap<String, (u64, Vec<String>)>,
    records_analyzed: usize,
    token_key_limit_reached: bool,
}

#[derive(Debug)]
struct DatasetInventory {
    fingerprint: DatasetFingerprint,
    counted: Vec<CountedFile>,
}

pub fn fingerprint(path: &Path) -> Result<DatasetFingerprint> {
    fingerprint_with_jobs(path, crate::app::default_jobs())
}

pub fn fingerprint_with_jobs(path: &Path, jobs: usize) -> Result<DatasetFingerprint> {
    Ok(build_inventory(path, jobs)?.fingerprint)
}

pub fn compare(left: &Path, right: &Path) -> Result<serde_json::Value> {
    compare_with_jobs(left, right, crate::app::default_jobs())
}

pub fn compare_with_jobs(left: &Path, right: &Path, jobs: usize) -> Result<serde_json::Value> {
    let left_fp = fingerprint_with_jobs(left, jobs)?;
    let right_fp = fingerprint_with_jobs(right, jobs)?;
    let left_map: BTreeMap<_, _> = left_fp.files.iter().map(|f| (&f.path, &f.sha256)).collect();
    let right_map: BTreeMap<_, _> = right_fp
        .files
        .iter()
        .map(|f| (&f.path, &f.sha256))
        .collect();
    let mut names: BTreeSet<&String> = left_map.keys().copied().collect();
    names.extend(right_map.keys().copied());
    let mut changes = Vec::new();
    for name in names {
        let before = left_map.get(name).copied();
        let after = right_map.get(name).copied();
        if before != after {
            changes.push(serde_json::json!({
                "path": name,
                "state": match (before, after) {(None,Some(_))=>"ADDED",(Some(_),None)=>"REMOVED",_=>"CHANGED"},
                "before": before,
                "after": after
            }));
        }
    }
    Ok(serde_json::json!({"left":left_fp,"right":right_fp,"changes":changes}))
}

pub fn poisoning_review(path: &Path) -> Result<PoisoningReview> {
    poisoning_review_with_jobs(path, crate::app::default_jobs())
}

pub fn poisoning_review_with_jobs(path: &Path, jobs: usize) -> Result<PoisoningReview> {
    let mut inventory = build_inventory(path, jobs)?;
    let quotas = analysis_quotas(&inventory.counted);
    let token_key_quotas = token_key_quotas(&quotas);

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(jobs.max(1))
        .thread_name(|index| format!("layerfault-dataset-{index}"))
        .build()
        .context("unable to create bounded dataset analysis pool")?;
    let local_results: Vec<Result<LocalAnalysis>> = pool.install(|| {
        inventory
            .counted
            .par_iter()
            .zip(quotas.par_iter().zip(token_key_quotas.par_iter()))
            .map(|(file, (quota, token_key_quota))| analyze_file(file, *quota, *token_key_quota))
            .collect()
    });

    let mut aggregate = LocalAnalysis::default();
    for (index, result) in local_results.into_iter().enumerate() {
        let local = result.with_context(|| {
            format!(
                "unable to analyze dataset member '{}'",
                inventory.counted[index].plan.path.display()
            )
        })?;
        let analyzed = local.records_analyzed;
        merge_analysis(&mut aggregate, local);
        if let Some(file) = inventory.fingerprint.files.get_mut(index) {
            file.records_analyzed = analyzed;
        }
    }

    add_duplicate_indicator(&mut aggregate);
    add_rare_trigger_indicator(&mut aggregate);

    let opaque_count = inventory
        .fingerprint
        .files
        .iter()
        .filter(|file| file.parse_warning.is_some())
        .count();
    let opaque: Vec<String> = inventory
        .fingerprint
        .files
        .iter()
        .filter(|file| file.parse_warning.is_some())
        .map(|file| file.path.clone())
        .take(MAX_DUPLICATE_EXAMPLES)
        .collect();
    if opaque_count > 0 {
        aggregate.indicators.insert(
            "LF-DATASET-COVERAGE-LIMIT".to_owned(),
            (opaque_count as u64, opaque),
        );
    }

    let records_available = inventory
        .counted
        .iter()
        .map(|file| file.records_available)
        .fold(0_usize, |acc, value| acc.saturating_add(value));
    let records_analyzed = aggregate.records_analyzed;
    let coverage = DatasetCoverage {
        records_available,
        records_analyzed,
        record_limit: MAX_RECORDS,
        record_limit_reached: records_available > records_analyzed,
        token_key_limit: MAX_TOKEN_KEYS,
        token_key_limit_reached: aggregate.token_key_limit_reached,
        opaque_or_unparsed_files: inventory
            .counted
            .iter()
            .filter(|file| file.parse_warning.is_some())
            .count(),
        sampling_strategy: if records_available > records_analyzed {
            "DETERMINISTIC_STRATIFIED_FULL_RANGE".to_owned()
        } else {
            "FULL_RECORD_COVERAGE".to_owned()
        },
    };
    inventory.fingerprint.records_sampled = records_analyzed;
    inventory.fingerprint.coverage = coverage.clone();

    let indicators: Vec<PoisonIndicator> = aggregate
        .indicators
        .into_iter()
        .map(|(rule_id, (count, examples))| PoisonIndicator {
            confidence: confidence(&rule_id).to_owned(),
            detail: detail(&rule_id).to_owned(),
            rule_id,
            count,
            examples,
        })
        .collect();
    let state = if indicators
        .iter()
        .any(|value| value.rule_id == "LF-DATASET-RARE-TRIGGER-CORRELATION")
    {
        "ANOMALOUS"
    } else if indicators.is_empty() {
        "NO_SUSPICIOUS_INDICATORS_OBSERVED"
    } else {
        "REVIEW"
    };

    Ok(PoisoningReview {
        version: 2,
        dataset: inventory.fingerprint,
        state: state.to_owned(),
        indicators,
        records_analyzed,
        coverage,
        boundary: "Dataset indicators are bounded statistical/content evidence. They do not establish that training data was maliciously poisoned or that all poisoning is absent. When the record limit is reached, Layerfault deterministically samples across the complete record range instead of inspecting only the head of the dataset.".to_owned(),
    })
}

fn build_inventory(path: &Path, jobs: usize) -> Result<DatasetInventory> {
    let plans = enumerate(path)?;
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(jobs.max(1))
        .thread_name(|index| format!("layerfault-dataset-inventory-{index}"))
        .build()
        .context("unable to create bounded dataset inventory pool")?;
    let results: Vec<Result<CountedFile>> =
        pool.install(|| plans.par_iter().map(count_and_hash).collect());
    let mut counted = Vec::with_capacity(results.len());
    for result in results {
        counted.push(result?);
    }

    let mut total_bytes = 0_u64;
    let mut records_available = 0_usize;
    let mut identity_hasher = Sha256::new();
    identity_hasher.update(b"layerfault-dataset-v1\0");
    let mut files = Vec::with_capacity(counted.len());
    for file in &counted {
        total_bytes = total_bytes
            .checked_add(file.plan.bytes)
            .ok_or_else(|| anyhow!("dataset byte count overflow"))?;
        records_available = records_available.saturating_add(file.records_available);
        identity_hasher.update((file.plan.relative.len() as u64).to_le_bytes());
        identity_hasher.update(file.plan.relative.as_bytes());
        identity_hasher.update(file.plan.bytes.to_le_bytes());
        identity_hasher.update(file.sha256.as_bytes());
        files.push(DatasetFile {
            path: file.plan.relative.clone(),
            format: file.plan.format,
            bytes: file.plan.bytes,
            sha256: format!("sha256:{}", file.sha256),
            parsed_records: file.records_available,
            records_analyzed: 0,
            parse_warning: file.parse_warning.clone(),
        });
    }
    let opaque_or_unparsed_files = counted
        .iter()
        .filter(|file| file.parse_warning.is_some())
        .count();
    let records_sampled = records_available.min(MAX_RECORDS);
    let fingerprint = DatasetFingerprint {
        version: 2,
        identity: format!(
            "lfdataset:sha256:{}",
            hex::encode(identity_hasher.finalize())
        ),
        root: path.display().to_string(),
        total_bytes,
        files,
        records_sampled,
        coverage: DatasetCoverage {
            records_available,
            records_analyzed: 0,
            record_limit: MAX_RECORDS,
            record_limit_reached: records_available > MAX_RECORDS,
            token_key_limit: MAX_TOKEN_KEYS,
            token_key_limit_reached: false,
            opaque_or_unparsed_files,
            sampling_strategy: "NOT_RUN_FINGERPRINT_ONLY".to_owned(),
        },
    };
    Ok(DatasetInventory {
        fingerprint,
        counted,
    })
}

fn enumerate(path: &Path) -> Result<Vec<DatasetPlan>> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("unable to inspect dataset '{}'", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("dataset root may not be a symlink");
    }
    if metadata.is_file() {
        let root = std::fs::canonicalize(path.parent().unwrap_or_else(|| Path::new(".")))?;
        let canonical = std::fs::canonicalize(path)?;
        return Ok(vec![plan_for(root, canonical)?]);
    }
    if !metadata.is_dir() {
        bail!("dataset target must be a regular file or directory");
    }
    let canonical_root = std::fs::canonicalize(path)?;
    let mut out = Vec::new();
    for entry in walkdir::WalkDir::new(path).follow_links(false) {
        let entry = entry?;
        if entry.path() == path || entry.file_type().is_dir() {
            continue;
        }
        if out.len() >= MAX_FILES {
            bail!("dataset contains more than {MAX_FILES} files");
        }
        if entry.file_type().is_symlink() || !entry.file_type().is_file() {
            bail!(
                "dataset contains a non-regular member '{}'",
                entry.path().display()
            );
        }
        let canonical = std::fs::canonicalize(entry.path())?;
        if !canonical.starts_with(&canonical_root) {
            bail!("dataset member escapes the dataset root");
        }
        out.push(plan_for(canonical_root.clone(), canonical)?);
    }
    out.sort_by(|a, b| a.relative.cmp(&b.relative));
    Ok(out)
}

fn plan_for(root: PathBuf, path: PathBuf) -> Result<DatasetPlan> {
    let metadata = std::fs::symlink_metadata(&path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("dataset member '{}' is not a regular file", path.display());
    }
    let relative = path
        .strip_prefix(&root)
        .unwrap_or(&path)
        .to_string_lossy()
        .replace('\\', "/");
    Ok(DatasetPlan {
        format: detect_format(&path),
        bytes: metadata.len(),
        path,
        relative,
    })
}

fn count_and_hash(plan: &DatasetPlan) -> Result<CountedFile> {
    // Open/hash through safeio/hashcache first; count_records independently opens
    // with no-follow semantics. The inventory reuses both results for all later
    // poisoning work in this command rather than fingerprinting a second time.
    let sha256 = hash_file(&plan.path)?;
    let (records_available, parse_warning) = match count_records(&plan.path, plan.format) {
        Ok(count) => (count, None),
        Err(error) => (0, Some(error.to_string())),
    };
    Ok(CountedFile {
        plan: plan.clone(),
        sha256,
        records_available,
        parse_warning,
    })
}

fn detect_format(path: &Path) -> DatasetFormat {
    let name = path
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if name.ends_with(".jsonl") || name.ends_with(".ndjson") {
        DatasetFormat::Jsonl
    } else if name.ends_with(".json") {
        DatasetFormat::Json
    } else if name.ends_with(".csv") {
        DatasetFormat::Csv
    } else if name.ends_with(".tsv") {
        DatasetFormat::Tsv
    } else if name.ends_with(".txt") || name.ends_with(".text") || name.ends_with(".md") {
        DatasetFormat::Text
    } else if name.ends_with(".parquet") {
        DatasetFormat::ParquetOpaque
    } else {
        DatasetFormat::Unknown
    }
}

fn parseable(format: DatasetFormat) -> bool {
    matches!(
        format,
        DatasetFormat::Json
            | DatasetFormat::Jsonl
            | DatasetFormat::Csv
            | DatasetFormat::Tsv
            | DatasetFormat::Text
    )
}

fn count_records(path: &Path, format: DatasetFormat) -> Result<usize> {
    if !parseable(format) {
        bail!(
            "record parsing is unavailable for {:?} dataset members",
            format
        );
    }
    if format == DatasetFormat::Json && path.metadata()?.len() > MAX_JSON_BYTES_FOR_RECORD_PARSE {
        bail!(
            "monolithic JSON exceeds {} byte record parsing cap; file is still fully fingerprinted",
            MAX_JSON_BYTES_FOR_RECORD_PARSE
        );
    }
    let mut count = 0_usize;
    visit_records(path, format, None, |_, _| {
        count = count.saturating_add(1);
        Ok(())
    })?;
    Ok(count)
}

/// Deterministically allocate the global record budget across every parseable
/// member. Every non-empty member receives at least one record when the budget
/// permits (MAX_FILES < MAX_RECORDS), then the remaining budget is distributed
/// proportionally by record population.
fn analysis_quotas(files: &[CountedFile]) -> Vec<usize> {
    let total: usize = files
        .iter()
        .map(|file| file.records_available)
        .fold(0_usize, |acc, value| acc.saturating_add(value));
    if total <= MAX_RECORDS {
        return files.iter().map(|file| file.records_available).collect();
    }

    let mut quotas = vec![0_usize; files.len()];
    let active: Vec<usize> = files
        .iter()
        .enumerate()
        .filter_map(|(index, file)| (file.records_available > 0).then_some(index))
        .collect();
    let mut remaining = MAX_RECORDS;
    for &index in &active {
        if remaining == 0 {
            break;
        }
        quotas[index] = 1;
        remaining -= 1;
    }
    if remaining == 0 {
        return quotas;
    }

    let extra_total: usize = active
        .iter()
        .map(|&index| files[index].records_available.saturating_sub(1))
        .sum();
    if extra_total == 0 {
        return quotas;
    }
    let mut remainders = Vec::with_capacity(active.len());
    let mut allocated = 0_usize;
    for &index in &active {
        let capacity = files[index].records_available.saturating_sub(1);
        let numerator = (remaining as u128).saturating_mul(capacity as u128);
        let share = (numerator / extra_total as u128) as usize;
        let share = share.min(capacity);
        quotas[index] = quotas[index].saturating_add(share);
        allocated = allocated.saturating_add(share);
        remainders.push((numerator % extra_total as u128, index));
    }
    let mut leftover = remaining.saturating_sub(allocated);
    remainders.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    for (_, index) in remainders {
        if leftover == 0 {
            break;
        }
        if quotas[index] < files[index].records_available {
            quotas[index] += 1;
            leftover -= 1;
        }
    }
    quotas
}

fn selected_indices(total: usize, quota: usize) -> Vec<usize> {
    if quota == 0 || total == 0 {
        return Vec::new();
    }
    if quota >= total {
        return (0..total).collect();
    }
    if quota == 1 {
        return vec![total / 2];
    }
    let last = total - 1;
    (0..quota)
        .map(|position| position.saturating_mul(last) / (quota - 1))
        .collect()
}

fn token_key_quotas(record_quotas: &[usize]) -> Vec<usize> {
    let active: Vec<usize> = record_quotas
        .iter()
        .enumerate()
        .filter_map(|(index, quota)| (*quota > 0).then_some(index))
        .collect();
    let mut out = vec![0_usize; record_quotas.len()];
    if active.is_empty() {
        return out;
    }
    let mut remaining = MAX_TOKEN_KEYS;
    for &index in &active {
        if remaining == 0 {
            break;
        }
        out[index] = 1;
        remaining -= 1;
    }
    if remaining == 0 {
        return out;
    }
    let total_records: usize = active
        .iter()
        .map(|&index| record_quotas[index])
        .fold(0_usize, |acc, value| acc.saturating_add(value));
    if total_records == 0 {
        return out;
    }
    let mut allocated = 0_usize;
    let mut remainders = Vec::with_capacity(active.len());
    for &index in &active {
        let numerator = (remaining as u128).saturating_mul(record_quotas[index] as u128);
        let share = usize::try_from(numerator / total_records as u128).unwrap_or(usize::MAX);
        out[index] = out[index].saturating_add(share);
        allocated = allocated.saturating_add(share);
        remainders.push((numerator % total_records as u128, index));
    }
    let mut leftover = remaining.saturating_sub(allocated);
    remainders.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    for (_, index) in remainders {
        if leftover == 0 {
            break;
        }
        out[index] = out[index].saturating_add(1);
        leftover -= 1;
    }
    out
}

fn analyze_file(file: &CountedFile, quota: usize, token_key_quota: usize) -> Result<LocalAnalysis> {
    let mut out = LocalAnalysis::default();
    if quota == 0 || file.parse_warning.is_some() || !parseable(file.plan.format) {
        return Ok(out);
    }
    let selected = selected_indices(file.records_available, quota);
    visit_records(
        &file.plan.path,
        file.plan.format,
        Some(&selected),
        |_, record| {
            observe_record(&mut out, record, token_key_quota);
            Ok(())
        },
    )?;
    Ok(out)
}

fn observe_record(out: &mut LocalAnalysis, record: Record, token_key_quota: usize) {
    out.records_analyzed = out.records_analyzed.saturating_add(1);
    let normalized = normalize(&record.text);
    if normalized.is_empty() {
        return;
    }
    let digest = hex::encode(Sha256::digest(normalized.as_bytes()));
    let entry = out
        .duplicate_counts
        .entry(digest)
        .or_insert((0, bounded(&record.text, 240)));
    entry.0 = entry.0.saturating_add(1);

    if contains_zero_width(&record.text) {
        add(&mut out.indicators, "LF-DATASET-ZERO-WIDTH", &record.text);
    }
    if has_url(&record.text) {
        add(
            &mut out.indicators,
            "LF-DATASET-URL-CONCENTRATION",
            &record.text,
        );
    }
    if credential_like(&record.text) {
        add(
            &mut out.indicators,
            "LF-DATASET-CREDENTIAL-LIKE",
            &record.text,
        );
    }
    if unsafe_code_like(&record.text) {
        add(
            &mut out.indicators,
            "LF-DATASET-UNSAFE-CODE-PATTERN",
            &record.text,
        );
    }

    let record_tokens = tokens(&normalized);
    for token in record_tokens.iter().take(512) {
        bounded_increment(
            &mut out.token_counts,
            token.clone(),
            token_key_quota,
            &mut out.token_key_limit_reached,
        );
        if let Some(label) = record.label.as_ref() {
            bounded_increment(
                &mut out.label_token_counts,
                (token.clone(), label.clone()),
                token_key_quota,
                &mut out.token_key_limit_reached,
            );
        }
    }
    if let Some(label) = record.label {
        *out.label_counts.entry(label).or_default() += 1;
    }
}

fn bounded_increment<K>(map: &mut HashMap<K, u64>, key: K, max_keys: usize, limited: &mut bool)
where
    K: std::hash::Hash + Eq,
{
    if let Some(value) = map.get_mut(&key) {
        *value = value.saturating_add(1);
    } else if map.len() < max_keys {
        map.insert(key, 1);
    } else {
        *limited = true;
    }
}

fn merge_analysis(target: &mut LocalAnalysis, source: LocalAnalysis) {
    target.records_analyzed = target
        .records_analyzed
        .saturating_add(source.records_analyzed);
    target.token_key_limit_reached |= source.token_key_limit_reached;

    let mut duplicates: Vec<_> = source.duplicate_counts.into_iter().collect();
    duplicates.sort_by(|a, b| a.0.cmp(&b.0));
    for (digest, (count, example)) in duplicates {
        let entry = target
            .duplicate_counts
            .entry(digest)
            .or_insert((0, example));
        entry.0 = entry.0.saturating_add(count);
    }
    merge_count_map(
        &mut target.token_counts,
        source.token_counts,
        &mut target.token_key_limit_reached,
    );
    merge_count_map(
        &mut target.label_token_counts,
        source.label_token_counts,
        &mut target.token_key_limit_reached,
    );
    for (label, count) in source.label_counts {
        let entry = target.label_counts.entry(label).or_default();
        *entry = entry.saturating_add(count);
    }
    for (rule, (count, examples)) in source.indicators {
        let entry = target.indicators.entry(rule).or_insert((0, Vec::new()));
        entry.0 = entry.0.saturating_add(count);
        for example in examples {
            if entry.1.len() >= MAX_DUPLICATE_EXAMPLES {
                break;
            }
            entry.1.push(example);
        }
    }
}

fn merge_count_map<K>(target: &mut HashMap<K, u64>, source: HashMap<K, u64>, limited: &mut bool)
where
    K: std::hash::Hash + Eq + Ord,
{
    let mut entries: Vec<_> = source.into_iter().collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    for (key, count) in entries {
        if let Some(value) = target.get_mut(&key) {
            *value = value.saturating_add(count);
        } else if target.len() < MAX_TOKEN_KEYS {
            target.insert(key, count);
        } else {
            *limited = true;
        }
    }
}

fn add_duplicate_indicator(analysis: &mut LocalAnalysis) {
    let mut entries: Vec<_> = analysis.duplicate_counts.values().collect();
    entries.sort_by(|a, b| a.1.cmp(&b.1));
    let mut examples = Vec::new();
    let mut extra = 0_u64;
    for (count, example) in entries {
        if *count > 1 {
            extra = extra.saturating_add(count.saturating_sub(1));
            if examples.len() < MAX_DUPLICATE_EXAMPLES {
                examples.push(example.clone());
            }
        }
    }
    if extra > 0 {
        analysis.indicators.insert(
            "LF-DATASET-DUPLICATE-CONCENTRATION".to_owned(),
            (extra, examples),
        );
    }
}

fn add_rare_trigger_indicator(analysis: &mut LocalAnalysis) {
    if analysis.label_counts.len() <= 1 {
        return;
    }
    // Build the best label association once. The previous implementation
    // rescanned every label/token pair for every rare token.
    let mut best: HashMap<String, (String, u64)> = HashMap::new();
    for ((token, label), count) in &analysis.label_token_counts {
        let entry = best.entry(token.clone()).or_insert((label.clone(), 0));
        if *count > entry.1 || (*count == entry.1 && label < &entry.0) {
            *entry = (label.clone(), *count);
        }
    }
    let mut tokens: Vec<_> = analysis.token_counts.iter().collect();
    tokens.sort_by(|a, b| a.0.cmp(b.0));
    for (token, total) in tokens {
        if *total < 3 || *total > 100 {
            continue;
        }
        let Some((label, count_for_label)) = best.get(token) else {
            continue;
        };
        if count_for_label.saturating_mul(100) >= total.saturating_mul(90) {
            let (count, examples) = analysis
                .indicators
                .entry("LF-DATASET-RARE-TRIGGER-CORRELATION".to_owned())
                .or_insert((0, Vec::new()));
            *count = count.saturating_add(1);
            if examples.len() < MAX_DUPLICATE_EXAMPLES {
                examples.push(format!(
                    "token='{token}' label='{label}' occurrences={count_for_label}/{total}"
                ));
            }
        }
    }
}

/// Stream records and invoke `visitor` in source order. `selected` is an
/// optional sorted list of record indexes. Parsers still validate every record
/// so malformed content cannot be hidden in an unselected region, but only
/// selected records are materialized into security-analysis text.
fn visit_records<F>(
    path: &Path,
    format: DatasetFormat,
    selected: Option<&[usize]>,
    mut visitor: F,
) -> Result<()>
where
    F: FnMut(usize, Record) -> Result<()>,
{
    match format {
        DatasetFormat::Text => visit_text(path, selected, &mut visitor),
        DatasetFormat::Jsonl => visit_jsonl(path, selected, &mut visitor),
        DatasetFormat::Json => visit_json(path, selected, &mut visitor),
        DatasetFormat::Csv => visit_delimited(path, b',', selected, &mut visitor),
        DatasetFormat::Tsv => visit_delimited(path, b'\t', selected, &mut visitor),
        _ => Ok(()),
    }
}

fn wants(selected: Option<&[usize]>, position: &mut usize, index: usize) -> bool {
    let Some(selected) = selected else {
        return true;
    };
    while *position < selected.len() && selected[*position] < index {
        *position += 1;
    }
    *position < selected.len() && selected[*position] == index
}

fn visit_text<F>(path: &Path, selected: Option<&[usize]>, visitor: &mut F) -> Result<()>
where
    F: FnMut(usize, Record) -> Result<()>,
{
    let file = crate::safeio::open_readonly_nofollow(path)?;
    let mut reader = BufReader::new(file);
    let mut bytes = Vec::new();
    let mut index = 0_usize;
    let mut selected_position = 0_usize;
    loop {
        bytes.clear();
        let read = reader.read_until(b'\n', &mut bytes)?;
        if read == 0 {
            break;
        }
        trim_line_ending(&mut bytes);
        if bytes.is_empty() {
            continue;
        }
        if bytes.len() > MAX_RECORD_BYTES {
            bail!("text dataset record exceeds byte cap");
        }
        if wants(selected, &mut selected_position, index) {
            let text = String::from_utf8_lossy(&bytes).into_owned();
            visitor(index, Record { text, label: None })?;
        }
        index = index.saturating_add(1);
    }
    Ok(())
}

fn visit_jsonl<F>(path: &Path, selected: Option<&[usize]>, visitor: &mut F) -> Result<()>
where
    F: FnMut(usize, Record) -> Result<()>,
{
    let file = crate::safeio::open_readonly_nofollow(path)?;
    let mut reader = BufReader::new(file);
    let mut bytes = Vec::new();
    let mut index = 0_usize;
    let mut selected_position = 0_usize;
    loop {
        bytes.clear();
        let read = reader.read_until(b'\n', &mut bytes)?;
        if read == 0 {
            break;
        }
        trim_line_ending(&mut bytes);
        if bytes.iter().all(|byte| byte.is_ascii_whitespace()) {
            continue;
        }
        if bytes.len() > MAX_RECORD_BYTES {
            bail!("JSONL dataset record exceeds byte cap");
        }
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).context("invalid JSONL record")?;
        if wants(selected, &mut selected_position, index) {
            visitor(index, record_from_json(&value))?;
        }
        index = index.saturating_add(1);
    }
    Ok(())
}

fn visit_json<F>(path: &Path, selected: Option<&[usize]>, visitor: &mut F) -> Result<()>
where
    F: FnMut(usize, Record) -> Result<()>,
{
    let file = crate::safeio::open_readonly_nofollow(path)?;
    let bytes = crate::safeio::read_all_from_file(&file, MAX_JSON_BYTES_FOR_RECORD_PARSE)?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).context("invalid JSON dataset")?;
    let mut selected_position = 0_usize;
    match value {
        serde_json::Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                if wants(selected, &mut selected_position, index) {
                    visitor(index, record_from_json(value))?;
                }
            }
        }
        other => {
            if wants(selected, &mut selected_position, 0) {
                visitor(0, record_from_json(&other))?;
            }
        }
    }
    Ok(())
}

fn visit_delimited<F>(
    path: &Path,
    delimiter: u8,
    selected: Option<&[usize]>,
    visitor: &mut F,
) -> Result<()>
where
    F: FnMut(usize, Record) -> Result<()>,
{
    let file = crate::safeio::open_readonly_nofollow(path)?;
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(delimiter)
        .flexible(true)
        .from_reader(file);
    let headers = reader.headers()?.clone();
    let text_columns: Vec<usize> = headers
        .iter()
        .enumerate()
        .filter_map(|(i, h)| {
            let h = h.to_ascii_lowercase();
            matches!(
                h.as_str(),
                "text"
                    | "prompt"
                    | "input"
                    | "instruction"
                    | "question"
                    | "response"
                    | "output"
                    | "completion"
                    | "content"
            )
            .then_some(i)
        })
        .collect();
    let label_column = headers.iter().position(|h| {
        matches!(
            h.to_ascii_lowercase().as_str(),
            "label" | "target" | "class" | "category"
        )
    });
    let mut selected_position = 0_usize;
    for (index, row) in reader.records().enumerate() {
        let row = row?;
        if !wants(selected, &mut selected_position, index) {
            continue;
        }
        let text = if text_columns.is_empty() {
            row.iter().take(64).collect::<Vec<_>>().join(" ")
        } else {
            text_columns
                .iter()
                .filter_map(|i| row.get(*i))
                .collect::<Vec<_>>()
                .join(" ")
        };
        if text.len() > MAX_RECORD_BYTES {
            bail!("delimited dataset record exceeds byte cap");
        }
        visitor(
            index,
            Record {
                text,
                label: label_column.and_then(|i| row.get(i)).map(str::to_owned),
            },
        )?;
    }
    Ok(())
}

fn trim_line_ending(bytes: &mut Vec<u8>) {
    while bytes
        .last()
        .is_some_and(|byte| matches!(*byte, b'\n' | b'\r'))
    {
        bytes.pop();
    }
}

fn record_from_json(value: &serde_json::Value) -> Record {
    let label = value.as_object().and_then(|object| {
        ["label", "target", "class", "category"]
            .iter()
            .find_map(|key| object.get(*key))
            .and_then(scalar_string)
    });
    let mut parts = Vec::new();
    collect_text(value, &mut parts, 0);
    let mut text = parts.join(" ");
    if text.len() > MAX_RECORD_BYTES {
        text.truncate(nearest_boundary(&text, MAX_RECORD_BYTES));
    }
    Record { text, label }
}

fn collect_text(value: &serde_json::Value, out: &mut Vec<String>, depth: usize) {
    if depth > 8 || out.len() > 128 {
        return;
    }
    match value {
        serde_json::Value::String(value) => out.push(value.clone()),
        serde_json::Value::Array(values) => {
            for value in values.iter().take(128) {
                collect_text(value, out, depth + 1);
            }
        }
        serde_json::Value::Object(object) => {
            for (key, value) in object.iter().take(128) {
                if !matches!(key.as_str(), "label" | "target" | "class" | "category") {
                    collect_text(value, out, depth + 1);
                }
            }
        }
        _ => {}
    }
}

fn scalar_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        serde_json::Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn normalize(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

fn tokens(value: &str) -> Vec<String> {
    value
        .split(|c: char| !c.is_alphanumeric() && c != '_' && c != '-')
        .filter(|v| v.len() >= 3 && v.len() <= 128)
        .take(4096)
        .map(str::to_owned)
        .collect()
}

fn contains_zero_width(value: &str) -> bool {
    value.chars().any(|c| {
        matches!(
            c,
            '\u{200b}' | '\u{200c}' | '\u{200d}' | '\u{2060}' | '\u{feff}'
        )
    })
}

fn has_url(value: &str) -> bool {
    lazy_static::lazy_static! {static ref URL:Regex=Regex::new(r"(?i)https?://[a-z0-9._~%/-]+").expect("static URL regex");}
    URL.is_match(value)
}

fn credential_like(value: &str) -> bool {
    lazy_static::lazy_static! {static ref SECRET:Regex=Regex::new(r#"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-/+=]{12,}"#).expect("static secret regex");}
    SECRET.is_match(value)
}

fn unsafe_code_like(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        "shell=true",
        "shell = true",
        "verify=false",
        "verify = false",
        "pickle.loads(",
        "yaml.load(",
        "os.system(",
        "subprocess.popen(",
        "md5(",
        "sha1(",
    ]
    .iter()
    .any(|p| lower.contains(p))
}

fn add(map: &mut BTreeMap<String, (u64, Vec<String>)>, rule: &str, text: &str) {
    let entry = map.entry(rule.to_owned()).or_insert((0, Vec::new()));
    entry.0 = entry.0.saturating_add(1);
    if entry.1.len() < MAX_DUPLICATE_EXAMPLES {
        entry.1.push(bounded(text, 240));
    }
}

fn bounded(value: &str, cap: usize) -> String {
    if value.len() <= cap {
        return value.to_owned();
    }
    let end = nearest_boundary(value, cap);
    format!("{}…", &value[..end])
}

fn nearest_boundary(value: &str, mut end: usize) -> usize {
    end = end.min(value.len());
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    end
}

fn confidence(rule: &str) -> &'static str {
    match rule {
        "LF-DATASET-RARE-TRIGGER-CORRELATION" => "MEDIUM",
        "LF-DATASET-CREDENTIAL-LIKE" => "MEDIUM",
        "LF-DATASET-COVERAGE-LIMIT" => "HIGH",
        _ => "LOW",
    }
}

fn detail(rule: &str) -> &'static str {
    match rule {
        "LF-DATASET-DUPLICATE-CONCENTRATION" => "Repeated records may reflect contamination, oversampling or deliberate trigger amplification; investigate in context.",
        "LF-DATASET-RARE-TRIGGER-CORRELATION" => "A relatively rare token is strongly concentrated in one observed label/target in the bounded sample.",
        "LF-DATASET-ZERO-WIDTH" => "Zero-width Unicode was present in dataset content and can hide trigger text or formatting.",
        "LF-DATASET-URL-CONCENTRATION" => "URL-bearing content was observed; high/repeated concentration can be relevant to targeted-content poisoning.",
        "LF-DATASET-CREDENTIAL-LIKE" => "Credential-like material was observed and may indicate accidental secret contamination.",
        "LF-DATASET-UNSAFE-CODE-PATTERN" => "Security-sensitive insecure-code patterns were observed in training text.",
        "LF-DATASET-COVERAGE-LIMIT" => "One or more dataset members could be fingerprinted but not record-parsed by this build. Layerfault will not report a clean poisoning review when material dataset content was opaque or unavailable to record parsing.",
        _ => "Dataset anomaly requires investigation.",
    }
}

fn hash_file(path: &Path) -> Result<String> {
    let file = crate::safeio::open_readonly_nofollow(path)?;
    Ok(crate::hashcache::sha256_hex(path, &file)?.sha256)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let thread_name: String = std::thread::current()
            .name()
            .unwrap_or("test")
            .chars()
            .map(|value| {
                if value.is_ascii_alphanumeric() || matches!(value, '-' | '_') {
                    value
                } else {
                    '_'
                }
            })
            .collect();
        std::env::temp_dir().join(format!(
            "layerfault-dataset-{name}-{}-{}",
            std::process::id(),
            thread_name
        ))
    }

    #[test]
    fn test_fixture_paths_are_windows_safe() {
        let path = temp("portable");
        let name = path.file_name().and_then(|value| value.to_str()).unwrap();
        assert!(!name.contains([':', '<', '>', '"', '/', '\\', '|', '?', '*']));
    }

    #[test]
    fn detects_zero_width() {
        assert!(contains_zero_width("hello\u{200b}world"));
    }

    #[test]
    fn normalizes_whitespace() {
        assert_eq!(normalize(" A  B\nC "), "a b c");
    }

    #[test]
    fn quotas_are_bounded_and_cover_every_nonempty_file() {
        let root = PathBuf::from("/tmp");
        let files: Vec<_> = [400_000_usize, 200_000, 10]
            .into_iter()
            .enumerate()
            .map(|(index, count)| CountedFile {
                plan: DatasetPlan {
                    path: root.join(format!("{index}.jsonl")),
                    relative: format!("{index}.jsonl"),
                    format: DatasetFormat::Jsonl,
                    bytes: 1,
                },
                sha256: "00".repeat(32),
                records_available: count,
                parse_warning: None,
            })
            .collect();
        let quotas = analysis_quotas(&files);
        assert_eq!(quotas.iter().sum::<usize>(), MAX_RECORDS);
        assert!(quotas.iter().all(|quota| *quota > 0));
        assert!(quotas[0] > quotas[1]);
    }

    #[test]
    fn parallel_token_key_budgets_remain_globally_bounded() {
        let record_quotas = vec![100_000, 75_000, 50_000, 25_000];
        let quotas = token_key_quotas(&record_quotas);
        assert_eq!(quotas.len(), record_quotas.len());
        assert_eq!(quotas.iter().sum::<usize>(), MAX_TOKEN_KEYS);
        assert!(quotas.iter().all(|quota| *quota > 0));
    }

    #[test]
    fn stratified_selection_includes_head_middle_and_tail() {
        let selected = selected_indices(1_000_000, 5);
        assert_eq!(selected.first().copied(), Some(0));
        assert_eq!(selected.last().copied(), Some(999_999));
        assert!(selected
            .iter()
            .any(|index| *index > 400_000 && *index < 600_000));
    }

    #[test]
    fn opaque_parquet_does_not_report_clean_poisoning_review() {
        let root = temp("parquet-limit");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create dataset fixture");
        std::fs::write(root.join("train.parquet"), b"PAR1bounded-fixturePAR1")
            .expect("write parquet fixture");
        let report = poisoning_review_with_jobs(&root, 1).expect("poisoning review");
        assert_eq!(report.state, "REVIEW");
        assert!(report
            .indicators
            .iter()
            .any(|indicator| indicator.rule_id == "LF-DATASET-COVERAGE-LIMIT"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn jobs_do_not_change_dataset_security_result() {
        let root = temp("determinism");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create dataset fixture");
        for file in 0..4 {
            let mut body = String::new();
            for index in 0..500 {
                let label = if index % 2 == 0 { "safe" } else { "other" };
                body.push_str(&format!(
                    "{{\"text\":\"sample {file} {index}\",\"label\":\"{label}\"}}\n"
                ));
            }
            std::fs::write(root.join(format!("part-{file}.jsonl")), body).expect("write fixture");
        }
        let one = poisoning_review_with_jobs(&root, 1).expect("jobs=1");
        let four = poisoning_review_with_jobs(&root, 4).expect("jobs=4");
        assert_eq!(one.dataset.identity, four.dataset.identity);
        assert_eq!(one.state, four.state);
        assert_eq!(
            serde_json::to_value(&one.indicators).expect("serialize indicators"),
            serde_json::to_value(&four.indicators).expect("serialize indicators")
        );
        assert_eq!(
            one.coverage.records_analyzed,
            four.coverage.records_analyzed
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn tail_records_are_selected_when_budget_is_bounded() {
        let selected = selected_indices(MAX_RECORDS + 50_000, MAX_RECORDS);
        assert_eq!(selected[0], 0);
        assert_eq!(*selected.last().expect("tail index"), MAX_RECORDS + 49_999);
    }
}
