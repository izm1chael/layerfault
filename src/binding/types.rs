use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StagingMechanism {
    Reflink,
    StreamCopy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BindingKind {
    #[serde(alias = "none", alias = "best-effort", alias = "best_effort")]
    None,
    #[serde(alias = "path-revalidated", alias = "path_revalidated")]
    PathRevalidated,
    #[serde(
        alias = "file-staged-rehashed",
        alias = "staged-copy",
        alias = "staged_copy"
    )]
    FileStagedRehashed,
    #[serde(alias = "package-staged-rehashed", alias = "package_staged_rehashed")]
    PackageStagedRehashed,
    #[serde(
        alias = "runtime-store-revalidated",
        alias = "revalidated-before-launch",
        alias = "revalidated_before_launch"
    )]
    RuntimeStoreRevalidated,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ComponentBinding {
    pub role: String,
    pub original_path: String,
    pub fingerprint: String,
    pub staged_root_identity: String,
    pub member_count: usize,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExecutionManifest {
    pub version: u32,
    pub components: Vec<ComponentBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_sha256: Option<String>,
    pub binding: BindingKind,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BoundMember {
    pub relative_path: String,
    pub expected_sha256: String,
    pub staged_sha256: String,
    pub bytes: u64,
    pub mechanism: StagingMechanism,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BindingRecord {
    pub kind: BindingKind,
    pub original: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<ExecutionManifest>,
}

pub struct StagedArtifact {
    pub(crate) root: PathBuf,
    pub(crate) path: PathBuf,
    pub record: BindingRecord,
}

impl StagedArtifact {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn cleanup(mut self) -> Result<()> {
        let root = std::mem::take(&mut self.root);
        if root.as_os_str().is_empty() {
            return Ok(());
        }
        fs::remove_dir_all(&root).with_context(|| {
            format!(
                "Unable to remove admission staging directory '{}'",
                root.display()
            )
        })
    }
}

impl Drop for StagedArtifact {
    fn drop(&mut self) {
        if !self.root.as_os_str().is_empty() {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

pub struct StagedPackage {
    pub(crate) root: PathBuf,
    pub(crate) path: PathBuf,
    pub source_fingerprint: String,
    pub staged_fingerprint: String,
    pub members: Vec<BoundMember>,
    pub record: BindingRecord,
    pub reflinked_members: usize,
    pub copied_members: usize,
}

impl StagedPackage {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn cleanup(mut self) -> Result<()> {
        let root = std::mem::take(&mut self.root);
        if root.as_os_str().is_empty() {
            return Ok(());
        }
        fs::remove_dir_all(&root).with_context(|| {
            format!(
                "Unable to remove admission package staging directory '{}'",
                root.display()
            )
        })
    }
}

impl Drop for StagedPackage {
    fn drop(&mut self) {
        if !self.root.as_os_str().is_empty() {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
