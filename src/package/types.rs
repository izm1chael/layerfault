use super::*;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct PackageMerkleLeaf {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub leaf_hash: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PackageEntry {
    pub relative_path: String,
    pub kind: String,
    pub size: u64,
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest_cache: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PackageReport {
    pub root: String,
    pub fingerprint: String,
    pub merkle_identity: String,
    pub files: Vec<PackageEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub merkle_manifest: Vec<PackageMerkleLeaf>,
    pub total_bytes: u64,
    pub findings: Vec<LayerScanResult>,
    /// Structural relationships between findings, such as a configuration
    /// reference resolving to a module that carries a code-execution primitive.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub correlations: Vec<crate::finding_evidence::FindingCorrelation>,
    /// What the scan actually examined.
    pub coverage: crate::coverage::Coverage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics: Option<crate::scanner::ScanMetrics>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incremental_diagnostics: Option<crate::incremental::IncrementalDiagnostics>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PackageFingerprintReport {
    pub root: String,
    pub fingerprint: String,
    pub merkle_identity: String,
    pub files: Vec<PackageEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub merkle_manifest: Vec<PackageMerkleLeaf>,
    pub total_bytes: u64,
}

/// Maximum `auto_map` entries retained as evidence from one configuration.
impl PackageReport {
    pub fn blocking(&self) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.status == ScanStatus::Fail)
    }
}
