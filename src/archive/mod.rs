pub mod detect;
pub mod limits;
pub mod member;
pub mod tar;
pub mod zip;

pub use detect::{
    detect_archive_format, detect_archive_format_confirmed, detect_archive_format_name,
    ArchiveFormat,
};
pub use limits::{ArchiveBudgetTracker, ArchiveLimits};
pub use member::{normalize_member_path, NormalizedMemberPath};

use crate::safeio::open_readonly_nofollow;
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use anyhow::{anyhow, Context, Result};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageState {
    Complete,
    Incomplete,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ArchiveCoverage {
    pub state: CoverageState,
    pub inspected_members: usize,
    pub skipped_members: usize,
    pub total_uncompressed_bytes: u64,
    pub details: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ArchiveMemberReport {
    pub virtual_path: String,
    pub raw_name: String,
    pub size_compressed: u64,
    pub size_uncompressed: u64,
    pub sha256: Option<String>,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub is_hardlink: bool,
    pub link_target: Option<String>,
    pub is_encrypted: bool,
    pub format_smuggling: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ArchiveReport {
    pub format: ArchiveFormat,
    pub members: Vec<ArchiveMemberReport>,
    pub findings: Vec<LayerScanResult>,
    pub coverage: ArchiveCoverage,
}

pub fn inspect(path: &Path, limits: &ArchiveLimits) -> Result<ArchiveReport> {
    let budget =
        crate::budget::ScanBudget::new(crate::budget::ScanBudgetProfile::Default.limits())?;
    inspect_with_budget(path, limits, &budget)
}

pub fn inspect_with_budget(
    path: &Path,
    limits: &ArchiveLimits,
    budget: &crate::budget::ScanBudget,
) -> Result<ArchiveReport> {
    let file = open_readonly_nofollow(path)?;
    let identity = format!("file:{}", path.display());
    inspect_opened(path, &file, &identity, limits, 0, budget)
}

pub fn inspect_opened(
    display_path: &Path,
    file: &File,
    identity: &str,
    limits: &ArchiveLimits,
    depth: usize,
    budget: &crate::budget::ScanBudget,
) -> Result<ArchiveReport> {
    budget
        .consume(
            crate::budget::BudgetDimension::ArchiveMembers,
            1,
            "archive container",
        )
        .map_err(|error| anyhow!("global scan budget exhausted: {error}"))?;
    let mut cloned = file.try_clone().with_context(|| {
        format!(
            "Unable to clone file handle for '{}'",
            display_path.display()
        )
    })?;
    cloned.seek(SeekFrom::Start(0))?;
    let mut prefix_buf = [0_u8; 512];
    let n = cloned.read(&mut prefix_buf)?;
    let prefix = &prefix_buf[..n];

    let detection = detect_archive_format_confirmed(display_path, prefix, file);
    let mut findings = Vec::new();

    if detection.mismatch {
        findings.push(LayerScanResult {
            layer_digest: identity.to_owned(),
            media_type: "application/vnd.layerfault.archive".to_owned(),
            check_type: CheckType::PackageSecurity,
            status: ScanStatus::Fail,
            finding_class: FindingClass::Integrity,
            confidence: Confidence::High,
            detail: Some(format!(
                "Archive format smuggling detected: file extension suggests '{}' but container magic header matches '{}'",
                detection.claimed_format.as_str(),
                detection.format.as_str()
            )),
            matches: vec!["[LF-ARCHIVE-FORMAT-MISMATCH] container extension and magic signature contradict".to_owned()],
            duration_ms: 0,
            ..Default::default()
        });
        crate::finding_evidence::ensure_finding_identity(
            findings.last_mut().expect("just pushed"),
            "LF-ARCHIVE-FORMAT-MISMATCH",
        );
    }

    let mut archive_budget = ArchiveBudgetTracker::new(limits.clone(), depth);

    let is_wheel = detection.format == ArchiveFormat::Wheel;
    let mut report = match detection.format {
        ArchiveFormat::Zip | ArchiveFormat::Wheel => zip::inspect_zip(
            display_path,
            file,
            identity,
            &mut archive_budget,
            is_wheel,
            detection.format,
            budget,
        )?,
        ArchiveFormat::Tar | ArchiveFormat::TarGz => {
            let is_gz = detection.format == ArchiveFormat::TarGz;
            tar::inspect_tar(
                display_path,
                file,
                identity,
                &mut archive_budget,
                is_gz,
                detection.format,
                budget,
            )?
        }
        ArchiveFormat::Unknown => {
            return Err(anyhow!(
                "Unsupported archive container format for '{}'",
                display_path.display()
            ));
        }
    };

    report.findings.extend(findings);
    Ok(report)
}
