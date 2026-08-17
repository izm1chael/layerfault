use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

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
pub(super) struct Record {
    pub(super) text: String,
    pub(super) label: Option<String>,
}

#[derive(Debug, Clone)]
pub(super) struct DatasetPlan {
    pub(super) path: PathBuf,
    pub(super) relative: String,
    pub(super) format: DatasetFormat,
    pub(super) bytes: u64,
}

#[derive(Debug, Clone)]
pub(super) struct CountedFile {
    pub(super) plan: DatasetPlan,
    pub(super) sha256: String,
    pub(super) records_available: usize,
    pub(super) parse_warning: Option<String>,
}

#[derive(Debug, Default)]
pub(super) struct LocalAnalysis {
    /// Keyed by exact-content SHA-256 digest: (occurrence count, a bounded
    /// display example, a SimHash fingerprint of the full normalized text
    /// used for near-duplicate clustering). One entry per distinct exact
    /// digest, so near-duplicate comparison never re-flags exact duplicates
    /// against themselves.
    pub(super) duplicate_counts: HashMap<String, (u64, String, u64)>,
    pub(super) token_counts: HashMap<String, u64>,
    pub(super) label_token_counts: HashMap<(String, String), u64>,
    pub(super) label_counts: HashMap<String, u64>,
    pub(super) indicators: BTreeMap<String, (u64, Vec<String>)>,
    pub(super) records_analyzed: usize,
    pub(super) token_key_limit_reached: bool,
}

#[derive(Debug)]
pub(super) struct DatasetInventory {
    pub(super) fingerprint: DatasetFingerprint,
    pub(super) counted: Vec<CountedFile>,
}

pub(super) fn nearest_boundary(value: &str, mut end: usize) -> usize {
    end = end.min(value.len());
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    end
}
