use crate::coverage::Coverage;
use crate::scanner::{Confidence, LayerScanResult};
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRegion {
    pub offset: u64,
    pub length: u64,
    pub kind: RegionKind,
    #[serde(default)]
    pub owner: Option<String>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionKind {
    Header,
    Metadata,
    TensorData,
    Alignment,
    Gap,
    Trailing,
    Unknown,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarvedObject {
    pub object_type: String,
    pub offset: u64,
    pub observed_length: u64,
    pub region_kind: RegionKind,
    #[serde(default)]
    pub owner: Option<String>,
    pub sha256_prefix_window: String,
    pub confidence: Confidence,
    pub evidence_only: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForensicsProfile {
    Standard,
    Research,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TensorForensicsReport {
    pub artifact_sha256: String,
    pub regions: Vec<FileRegion>,
    pub carved: Vec<CarvedObject>,
    pub findings: Vec<LayerScanResult>,
    pub coverage: Coverage,
}
