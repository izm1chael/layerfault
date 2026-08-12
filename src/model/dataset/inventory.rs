use super::readers::{parseable, visit_records, MAX_JSON_BYTES_FOR_RECORD_PARSE};
use super::types::{
    CountedFile, DatasetCoverage, DatasetFile, DatasetFingerprint, DatasetInventory, DatasetPlan,
};
use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const MAX_FILES: usize = 100_000;
const MAX_RECORDS: usize = super::sampling::MAX_RECORDS;
const MAX_TOKEN_KEYS: usize = super::sampling::MAX_TOKEN_KEYS;

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
    let mut names: std::collections::BTreeSet<&String> = left_map.keys().copied().collect();
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

pub(super) fn build_inventory(path: &Path, jobs: usize) -> Result<DatasetInventory> {
    let plans = enumerate(path)?;
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(jobs.max(1))
        .thread_name(|index| format!("layerfault-dataset-inventory-{index}"))
        .build()
        .context("unable to create bounded dataset inventory pool")?;
    let results: Vec<Result<CountedFile>> = pool.install(|| {
        use rayon::prelude::*;
        plans.par_iter().map(count_and_hash).collect()
    });
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
        // `Path::parent()` returns `Some("")` for a bare relative filename
        // like "train.jsonl" (not `None`), so the empty-parent case must be
        // folded into "." explicitly or canonicalization fails outright.
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let root = std::fs::canonicalize(parent)?;
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

fn detect_format(path: &Path) -> super::types::DatasetFormat {
    use super::types::DatasetFormat;
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

pub(super) fn count_records(path: &Path, format: super::types::DatasetFormat) -> Result<usize> {
    if !parseable(format) {
        bail!(
            "record parsing is unavailable for {:?} dataset members",
            format
        );
    }
    if format == super::types::DatasetFormat::Json
        && path.metadata()?.len() > MAX_JSON_BYTES_FOR_RECORD_PARSE
    {
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

fn hash_file(path: &Path) -> Result<String> {
    let file = crate::safeio::open_readonly_nofollow(path)?;
    Ok(crate::hashcache::sha256_hex(path, &file)?.sha256)
}
