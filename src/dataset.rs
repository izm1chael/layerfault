//! Bounded local dataset fingerprinting and poisoning-evidence analysis.
//! Dataset indicators are evidence only; they cannot prove malicious poisoning.

use anyhow::{anyhow, bail, Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

const MAX_FILES: usize = 100_000;
const MAX_FILE_BYTES_FOR_RECORD_PARSE: u64 = 256 * 1024 * 1024;
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
    pub parsed_records: usize,
    pub parse_warning: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatasetFingerprint {
    pub version: u32,
    pub identity: String,
    pub root: String,
    pub total_bytes: u64,
    pub files: Vec<DatasetFile>,
    pub records_sampled: usize,
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
    pub boundary: String,
}

#[derive(Debug, Clone)]
struct Record {
    text: String,
    label: Option<String>,
}

pub fn fingerprint(path: &Path) -> Result<DatasetFingerprint> {
    let targets = enumerate(path)?;
    let mut files = Vec::with_capacity(targets.len());
    let mut total_bytes = 0_u64;
    let mut records_sampled = 0_usize;
    let mut identity_hasher = Sha256::new();
    identity_hasher.update(b"layerfault-dataset-v1\0");

    for (root, file_path) in targets {
        let relative = file_path
            .strip_prefix(&root)
            .unwrap_or(&file_path)
            .to_string_lossy()
            .replace('\\', "/");
        let metadata = std::fs::symlink_metadata(&file_path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!(
                "dataset member '{}' is not a regular file",
                file_path.display()
            );
        }
        let bytes = metadata.len();
        total_bytes = total_bytes
            .checked_add(bytes)
            .ok_or_else(|| anyhow!("dataset byte count overflow"))?;
        let sha256 = hash_file(&file_path)?;
        let format = detect_format(&file_path);
        let parsed = count_records(&file_path, format)
            .unwrap_or((0, Some("record parsing unavailable".to_owned())));
        records_sampled = records_sampled.saturating_add(parsed.0).min(MAX_RECORDS);
        identity_hasher.update((relative.len() as u64).to_le_bytes());
        identity_hasher.update(relative.as_bytes());
        identity_hasher.update(bytes.to_le_bytes());
        identity_hasher.update(sha256.as_bytes());
        files.push(DatasetFile {
            path: relative,
            format,
            bytes,
            sha256: format!("sha256:{sha256}"),
            parsed_records: parsed.0,
            parse_warning: parsed.1,
        });
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(DatasetFingerprint {
        version: 1,
        identity: format!(
            "lfdataset:sha256:{}",
            hex::encode(identity_hasher.finalize())
        ),
        root: path.display().to_string(),
        total_bytes,
        files,
        records_sampled,
    })
}

pub fn compare(left: &Path, right: &Path) -> Result<serde_json::Value> {
    let left_fp = fingerprint(left)?;
    let right_fp = fingerprint(right)?;
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
    let dataset = fingerprint(path)?;
    let targets = enumerate(path)?;
    let mut duplicate_counts: HashMap<String, (u64, String)> = HashMap::new();
    let mut token_counts: HashMap<String, u64> = HashMap::new();
    let mut label_token_counts: HashMap<(String, String), u64> = HashMap::new();
    let mut label_counts: HashMap<String, u64> = HashMap::new();
    let mut indicators: BTreeMap<String, (u64, Vec<String>)> = BTreeMap::new();
    let mut records_analyzed = 0_usize;

    for (_, file_path) in targets {
        let format = detect_format(&file_path);
        if !matches!(
            format,
            DatasetFormat::Json
                | DatasetFormat::Jsonl
                | DatasetFormat::Csv
                | DatasetFormat::Tsv
                | DatasetFormat::Text
        ) {
            continue;
        }
        for record in records(&file_path, format)? {
            if records_analyzed >= MAX_RECORDS {
                break;
            }
            records_analyzed += 1;
            let normalized = normalize(&record.text);
            if normalized.is_empty() {
                continue;
            }
            let digest = hex::encode(Sha256::digest(normalized.as_bytes()));
            let entry = duplicate_counts
                .entry(digest)
                .or_insert((0, bounded(&record.text, 240)));
            entry.0 = entry.0.saturating_add(1);

            if contains_zero_width(&record.text) {
                add(&mut indicators, "LF-DATASET-ZERO-WIDTH", &record.text);
            }
            if has_url(&record.text) {
                add(
                    &mut indicators,
                    "LF-DATASET-URL-CONCENTRATION",
                    &record.text,
                );
            }
            if credential_like(&record.text) {
                add(&mut indicators, "LF-DATASET-CREDENTIAL-LIKE", &record.text);
            }
            if unsafe_code_like(&record.text) {
                add(
                    &mut indicators,
                    "LF-DATASET-UNSAFE-CODE-PATTERN",
                    &record.text,
                );
            }

            let tokens = tokens(&normalized);
            for token in tokens.iter().take(512) {
                if token_counts.len() < MAX_TOKEN_KEYS || token_counts.contains_key(token) {
                    *token_counts.entry(token.clone()).or_default() += 1;
                }
                if let Some(label) = record.label.as_ref() {
                    if label_token_counts.len() < MAX_TOKEN_KEYS
                        || label_token_counts.contains_key(&(token.clone(), label.clone()))
                    {
                        *label_token_counts
                            .entry((token.clone(), label.clone()))
                            .or_default() += 1;
                    }
                }
            }
            if let Some(label) = record.label {
                *label_counts.entry(label).or_default() += 1;
            }
        }
    }

    let mut duplicate_examples = Vec::new();
    let mut duplicate_extra = 0_u64;
    for (count, example) in duplicate_counts.values() {
        if *count > 1 {
            duplicate_extra = duplicate_extra.saturating_add(count.saturating_sub(1));
            if duplicate_examples.len() < MAX_DUPLICATE_EXAMPLES {
                duplicate_examples.push(example.clone());
            }
        }
    }
    if duplicate_extra > 0 {
        indicators.insert(
            "LF-DATASET-DUPLICATE-CONCENTRATION".to_owned(),
            (duplicate_extra, duplicate_examples),
        );
    }

    // Flag rare tokens that are disproportionately associated with one label.
    if label_counts.len() > 1 {
        for (token, total) in token_counts
            .iter()
            .filter(|(_, total)| **total >= 3 && **total <= 100)
        {
            let mut best_label = None;
            let mut best = 0_u64;
            for ((candidate, label), count) in &label_token_counts {
                if candidate == token && *count > best {
                    best = *count;
                    best_label = Some(label);
                }
            }
            if let Some(label) = best_label {
                if best.saturating_mul(100) >= total.saturating_mul(90) {
                    let (count, examples) = indicators
                        .entry("LF-DATASET-RARE-TRIGGER-CORRELATION".to_owned())
                        .or_insert((0, Vec::new()));
                    *count += 1;
                    if examples.len() < MAX_DUPLICATE_EXAMPLES {
                        examples.push(format!(
                            "token='{token}' label='{label}' occurrences={best}/{total}"
                        ));
                    }
                }
            }
        }
    }

    let coverage_limited: Vec<String> = dataset
        .files
        .iter()
        .filter(|file| {
            file.format == DatasetFormat::ParquetOpaque
                || (file.parsed_records == 0 && file.parse_warning.is_some())
        })
        .map(|file| file.path.clone())
        .take(MAX_DUPLICATE_EXAMPLES)
        .collect();
    if !coverage_limited.is_empty() {
        indicators.insert(
            "LF-DATASET-COVERAGE-LIMIT".to_owned(),
            (coverage_limited.len() as u64, coverage_limited),
        );
    }

    let indicators: Vec<PoisonIndicator> = indicators
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
        version: 1,
        dataset,
        state: state.to_owned(),
        indicators,
        records_analyzed,
        boundary: "Dataset indicators are bounded statistical/content evidence. They do not establish that training data was maliciously poisoned or that all poisoning is absent.".to_owned(),
    })
}

fn enumerate(path: &Path) -> Result<Vec<(PathBuf, PathBuf)>> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("unable to inspect dataset '{}'", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("dataset root may not be a symlink");
    }
    if metadata.is_file() {
        let root = path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        return Ok(vec![(root, path.to_path_buf())]);
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
        out.push((canonical_root.clone(), canonical));
    }
    out.sort_by(|a, b| a.1.cmp(&b.1));
    Ok(out)
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

fn count_records(path: &Path, format: DatasetFormat) -> Result<(usize, Option<String>)> {
    if path.metadata()?.len() > MAX_FILE_BYTES_FOR_RECORD_PARSE {
        return Ok((
            0,
            Some("file exceeds per-file record parsing cap; fingerprinted only".to_owned()),
        ));
    }
    match records(path, format) {
        Ok(records) => Ok((records.len(), None)),
        Err(error) => Ok((0, Some(error.to_string()))),
    }
}

fn records(path: &Path, format: DatasetFormat) -> Result<Vec<Record>> {
    if path.metadata()?.len() > MAX_FILE_BYTES_FOR_RECORD_PARSE {
        bail!("file exceeds per-file record parsing cap");
    }
    match format {
        DatasetFormat::Text => text_records(path),
        DatasetFormat::Jsonl => jsonl_records(path),
        DatasetFormat::Json => json_records(path),
        DatasetFormat::Csv => delimited_records(path, b','),
        DatasetFormat::Tsv => delimited_records(path, b'\t'),
        _ => Ok(Vec::new()),
    }
}

fn text_records(path: &Path) -> Result<Vec<Record>> {
    let file = crate::safeio::open_readonly_nofollow(path)?;
    let mut out = Vec::new();
    for line in BufReader::new(file).lines().take(MAX_RECORDS) {
        let line = line?;
        if line.len() > MAX_RECORD_BYTES {
            bail!("text dataset record exceeds byte cap");
        }
        if !line.trim().is_empty() {
            out.push(Record {
                text: line,
                label: None,
            });
        }
    }
    Ok(out)
}

fn jsonl_records(path: &Path) -> Result<Vec<Record>> {
    let file = crate::safeio::open_readonly_nofollow(path)?;
    let mut out = Vec::new();
    for line in BufReader::new(file).lines().take(MAX_RECORDS) {
        let line = line?;
        if line.len() > MAX_RECORD_BYTES {
            bail!("JSONL dataset record exceeds byte cap");
        }
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value =
            serde_json::from_str(&line).context("invalid JSONL record")?;
        out.push(record_from_json(&value));
    }
    Ok(out)
}

fn json_records(path: &Path) -> Result<Vec<Record>> {
    let file = crate::safeio::open_readonly_nofollow(path)?;
    let bytes = crate::safeio::read_all_from_file(&file, MAX_FILE_BYTES_FOR_RECORD_PARSE)?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).context("invalid JSON dataset")?;
    match value {
        serde_json::Value::Array(values) => Ok(values
            .iter()
            .take(MAX_RECORDS)
            .map(record_from_json)
            .collect()),
        other => Ok(vec![record_from_json(&other)]),
    }
}

fn delimited_records(path: &Path, delimiter: u8) -> Result<Vec<Record>> {
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
    let mut out = Vec::new();
    for row in reader.records().take(MAX_RECORDS) {
        let row = row?;
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
        out.push(Record {
            text,
            label: label_column.and_then(|i| row.get(i)).map(str::to_owned),
        });
    }
    Ok(out)
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
    lazy_static::lazy_static! {static ref SECRET:Regex=Regex::new(r#"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['"]?[A-Za-z0-9_\-/+=]{12,}"#).expect("static secret regex");}
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
    match rule{"LF-DATASET-DUPLICATE-CONCENTRATION"=>"Repeated records may reflect contamination, oversampling or deliberate trigger amplification; investigate in context.","LF-DATASET-RARE-TRIGGER-CORRELATION"=>"A relatively rare token is strongly concentrated in one observed label/target in the bounded sample.","LF-DATASET-ZERO-WIDTH"=>"Zero-width Unicode was present in dataset content and can hide trigger text or formatting.","LF-DATASET-URL-CONCENTRATION"=>"URL-bearing content was observed; high/repeated concentration can be relevant to targeted-content poisoning.","LF-DATASET-CREDENTIAL-LIKE"=>"Credential-like material was observed and may indicate accidental secret contamination.","LF-DATASET-UNSAFE-CODE-PATTERN"=>"Security-sensitive insecure-code patterns were observed in training text.","LF-DATASET-COVERAGE-LIMIT"=>"One or more dataset members could be fingerprinted but not record-parsed by this build. Layerfault will not report a clean poisoning review when material dataset content was opaque or beyond the parsing cap.",_=>"Dataset anomaly requires investigation."}
}

fn hash_file(path: &Path) -> Result<String> {
    let file = crate::safeio::open_readonly_nofollow(path)?;
    Ok(crate::hashcache::sha256_hex(path, &file)?.sha256)
}

#[cfg(test)]
mod tests {
    #[test]
    fn detects_zero_width() {
        assert!(super::contains_zero_width("hello\u{200b}world"));
    }

    #[test]
    fn normalizes_whitespace() {
        assert_eq!(super::normalize(" A  B\nC "), "a b c");
    }

    #[test]
    fn opaque_parquet_does_not_report_clean_poisoning_review() {
        let root = std::env::temp_dir().join(format!(
            "layerfault-dataset-parquet-limit-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create dataset fixture");
        std::fs::write(root.join("train.parquet"), b"PAR1bounded-fixturePAR1")
            .expect("write parquet fixture");
        let report = super::poisoning_review(&root).expect("poisoning review");
        assert_eq!(report.state, "REVIEW");
        assert!(report
            .indicators
            .iter()
            .any(|indicator| indicator.rule_id == "LF-DATASET-COVERAGE-LIMIT"));
        let _ = std::fs::remove_dir_all(root);
    }
}
