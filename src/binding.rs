use crate::safeio::open_readonly_nofollow;
use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

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
    root: PathBuf,
    path: PathBuf,
    pub record: BindingRecord,
}

impl StagedArtifact {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn revalidate(&self) -> Result<()> {
        let expected =
            self.record.sha256.as_deref().ok_or_else(|| {
                anyhow!("Staged artifact has no recorded digest for revalidation")
            })?;
        let mut file = open_readonly_nofollow(&self.path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 1024 * 1024];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        let observed = format!("sha256:{}", hex::encode(hasher.finalize()));
        if !observed.eq_ignore_ascii_case(expected) {
            bail!(
                "Staged artifact digest changed before launch: expected {}, observed {}",
                expected,
                observed
            );
        }
        Ok(())
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
    root: PathBuf,
    path: PathBuf,
    pub source_fingerprint: String,
    pub staged_fingerprint: String,
    pub members: Vec<BoundMember>,
    pub record: BindingRecord,
}

impl StagedPackage {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn revalidate(&self) -> Result<()> {
        let current = crate::package::fingerprint(&self.path)?;
        if current != self.staged_fingerprint {
            bail!(
                "Staged package fingerprint changed before launch: expected {}, observed {}",
                self.staged_fingerprint,
                current
            );
        }
        Ok(())
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

pub fn stage_verified(path: &Path, expected_sha256: &str) -> Result<StagedArtifact> {
    let parent = crate::paths::config_dir()?.join("admission-staging");
    stage_verified_under(path, expected_sha256, &parent, false)
}

pub fn stage_verified_executable(path: &Path, expected_sha256: &str) -> Result<StagedArtifact> {
    let parent = crate::paths::config_dir()?.join("runtime-staging");
    stage_verified_under(path, expected_sha256, &parent, true)
}

pub fn stage_verified_under(
    path: &Path,
    expected_sha256: &str,
    parent: &Path,
    executable: bool,
) -> Result<StagedArtifact> {
    if !expected_sha256.starts_with("sha256:") {
        return Err(anyhow!(
            "Execution binding requires a canonical sha256 artifact digest"
        ));
    }
    let source = open_readonly_nofollow(path)?;
    crate::paths::ensure_private_dir(parent)?;
    let short = expected_sha256
        .trim_start_matches("sha256:")
        .chars()
        .take(16)
        .collect::<String>();
    let root = create_unique_dir(parent, &short)?;
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("Artifact path '{}' has no file name", path.display()))?;
    let target = root.join(file_name);

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut destination = options
        .open(&target)
        .with_context(|| format!("Unable to create staged artifact '{}'", target.display()))?;
    let mut reader = source.try_clone()?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        destination.write_all(&buffer[..n])?;
        hasher.update(&buffer[..n]);
    }
    destination.sync_all()?;
    let observed = format!("sha256:{}", hex::encode(hasher.finalize()));
    if !observed.eq_ignore_ascii_case(expected_sha256) {
        let _ = fs::remove_dir_all(&root);
        return Err(anyhow!("Artifact changed between admission and execution binding: expected {expected_sha256}, observed {observed}"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if executable { 0o500 } else { 0o400 };
        fs::set_permissions(&target, fs::Permissions::from_mode(mode))?;
    }
    Ok(StagedArtifact {
        root: root.clone(),
        path: target.clone(),
        record: BindingRecord {
            kind: BindingKind::FileStagedRehashed,
            original: path.display().to_string(),
            runtime_path: Some(target.display().to_string()),
            sha256: Some(observed),
            detail: "Runtime receives a private copy created from a no-follow file descriptor after admission; the copy digest is rechecked before launch".to_owned(),
            manifest: None,
        },
    })
}

pub fn stage_verified_package(
    root: &Path,
    expected_report: &crate::package::PackageReport,
) -> Result<StagedPackage> {
    let parent = crate::paths::config_dir()?.join("package-staging");
    stage_verified_package_under(root, expected_report, &parent)
}

pub fn stage_verified_package_under(
    root: &Path,
    expected_report: &crate::package::PackageReport,
    parent: &Path,
) -> Result<StagedPackage> {
    let root_meta = fs::symlink_metadata(root)
        .with_context(|| format!("Unable to inspect package root '{}'", root.display()))?;
    if root_meta.file_type().is_symlink() {
        bail!(
            "Package root '{}' is a symlink; refusal required for execution binding",
            root.display()
        );
    }
    if !root_meta.is_dir() {
        bail!(
            "Package root '{}' must resolve to a directory",
            root.display()
        );
    }

    crate::paths::ensure_private_dir(parent)?;
    let short_fp = expected_report
        .fingerprint
        .trim_start_matches("lfpkg:sha256:")
        .trim_start_matches("sha256:")
        .chars()
        .take(16)
        .collect::<String>();
    let staging_root = create_unique_dir(parent, &short_fp)?;
    let staged_pkg_dir = staging_root.join("package");
    fs::create_dir_all(&staged_pkg_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&staged_pkg_dir, fs::Permissions::from_mode(0o700))?;
    }

    let mut members = Vec::new();
    for entry in &expected_report.files {
        if entry.kind == "symlink" {
            let _ = fs::remove_dir_all(&staging_root);
            bail!(
                "Package member '{}' is a symlink; execution binding refuses symlink package members",
                entry.relative_path
            );
        }
        let expected_sha256 = entry.sha256.as_deref().ok_or_else(|| {
            anyhow!(
                "Package member '{}' has missing sha256 digest in admission report",
                entry.relative_path
            )
        })?;

        let rel_path = Path::new(&entry.relative_path);
        if rel_path.is_absolute()
            || rel_path.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir | std::path::Component::Prefix(_)
                )
            })
        {
            let _ = fs::remove_dir_all(&staging_root);
            bail!(
                "Package member relative path '{}' contains invalid traversal or absolute prefix",
                entry.relative_path
            );
        }

        let source_path = root.join(rel_path);
        let pre_meta = fs::symlink_metadata(&source_path).with_context(|| {
            format!(
                "Unable to inspect package member '{}'",
                source_path.display()
            )
        })?;
        if pre_meta.file_type().is_symlink() {
            let _ = fs::remove_dir_all(&staging_root);
            bail!(
                "Package member '{}' resolved to a symlink",
                source_path.display()
            );
        }

        let source_file = open_readonly_nofollow(&source_path)?;
        let staged_target_path = staged_pkg_dir.join(rel_path);
        if let Some(target_parent) = staged_target_path.parent() {
            fs::create_dir_all(target_parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(target_parent, fs::Permissions::from_mode(0o700))?;
            }
        }

        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut dest_file = options.open(&staged_target_path).with_context(|| {
            format!(
                "Unable to create staged package member '{}'",
                staged_target_path.display()
            )
        })?;

        let mut reader = source_file.try_clone()?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0_u8; 1024 * 1024];
        let mut copied_bytes = 0_u64;
        loop {
            let n = reader.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            dest_file.write_all(&buffer[..n])?;
            hasher.update(&buffer[..n]);
            copied_bytes = copied_bytes.saturating_add(n as u64);
        }
        dest_file.sync_all()?;

        let post_meta = fs::symlink_metadata(&source_path)?;
        if pre_meta.len() != post_meta.len() {
            let _ = fs::remove_dir_all(&staging_root);
            bail!(
                "Package member '{}' changed size during staging copy (TOCTOU violation)",
                source_path.display()
            );
        }

        let observed_sha256 = format!("sha256:{}", hex::encode(hasher.finalize()));
        if !observed_sha256.eq_ignore_ascii_case(expected_sha256) {
            let _ = fs::remove_dir_all(&staging_root);
            bail!(
                "Package member '{}' hash changed during staging copy: expected {}, observed {}",
                entry.relative_path,
                expected_sha256,
                observed_sha256
            );
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&staged_target_path, fs::Permissions::from_mode(0o400))?;
        }

        members.push(BoundMember {
            relative_path: entry.relative_path.clone(),
            expected_sha256: expected_sha256.to_owned(),
            staged_sha256: observed_sha256,
            bytes: copied_bytes,
        });
    }

    let staged_fingerprint = crate::package::fingerprint(&staged_pkg_dir)?;
    if staged_fingerprint != expected_report.fingerprint {
        let _ = fs::remove_dir_all(&staging_root);
        bail!(
            "Staged package fingerprint mismatch: admission reported {}, staged observed {}",
            expected_report.fingerprint,
            staged_fingerprint
        );
    }

    let total_bytes: u64 = members.iter().map(|m| m.bytes).sum();
    let component = ComponentBinding {
        role: "model".to_owned(),
        original_path: root.display().to_string(),
        fingerprint: expected_report.fingerprint.clone(),
        staged_root_identity: staged_fingerprint.clone(),
        member_count: members.len(),
        total_bytes,
    };
    let manifest = ExecutionManifest {
        version: 1,
        components: vec![component],
        runtime_sha256: None,
        binding: BindingKind::PackageStagedRehashed,
    };

    let record = BindingRecord {
        kind: BindingKind::PackageStagedRehashed,
        original: root.display().to_string(),
        runtime_path: Some(staged_pkg_dir.display().to_string()),
        sha256: Some(staged_fingerprint.clone()),
        detail: format!(
            "Private read-only package staged from no-follow descriptors; verified {} members ({total_bytes} bytes); staged fingerprint equals admitted fingerprint {}",
            members.len(),
            expected_report.fingerprint
        ),
        manifest: Some(manifest),
    };

    Ok(StagedPackage {
        root: staging_root,
        path: staged_pkg_dir,
        source_fingerprint: expected_report.fingerprint.clone(),
        staged_fingerprint,
        members,
        record,
    })
}

pub fn build_compound_manifest(
    components: Vec<ComponentBinding>,
    runtime_sha256: Option<String>,
) -> ExecutionManifest {
    ExecutionManifest {
        version: 1,
        components,
        runtime_sha256,
        binding: BindingKind::PackageStagedRehashed,
    }
}

pub fn revalidated(
    original: impl Into<String>,
    sha256: Option<String>,
    detail: impl Into<String>,
) -> BindingRecord {
    BindingRecord {
        kind: BindingKind::RuntimeStoreRevalidated,
        original: original.into(),
        runtime_path: None,
        sha256,
        detail: detail.into(),
        manifest: None,
    }
}

pub fn path_revalidated(
    original: impl Into<String>,
    sha256: Option<String>,
    detail: impl Into<String>,
) -> BindingRecord {
    BindingRecord {
        kind: BindingKind::PathRevalidated,
        original: original.into(),
        runtime_path: None,
        sha256,
        detail: detail.into(),
        manifest: None,
    }
}

pub fn best_effort(original: impl Into<String>, detail: impl Into<String>) -> BindingRecord {
    BindingRecord {
        kind: BindingKind::None,
        original: original.into(),
        runtime_path: None,
        sha256: None,
        detail: detail.into(),
        manifest: None,
    }
}

fn create_unique_dir(parent: &Path, short: &str) -> Result<PathBuf> {
    for counter in 0_u32..32 {
        let candidate = parent.join(format!(
            "{}-{}-{}-{counter}",
            crate::paths::now_unix(),
            std::process::id(),
            short
        ));
        match fs::create_dir(&candidate) {
            Ok(()) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700))?;
                }
                return Ok(candidate);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(anyhow!(
        "Unable to allocate a unique admission staging directory"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    #[test]
    fn staged_copy_matches_expected_digest() -> Result<()> {
        let base = std::env::temp_dir().join(format!(
            "layerfault-binding-test-{}-{}",
            std::process::id(),
            crate::paths::now_unix()
        ));
        let parent = base.join("staging");
        fs::create_dir_all(&base)?;
        let source = base.join("source.gguf");
        fs::write(&source, b"verified artifact")?;
        let digest = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(b"verified artifact"))
        );
        let staged = stage_verified_under(&source, &digest, &parent, false)?;
        assert_eq!(fs::read(staged.path())?, b"verified artifact");
        staged.cleanup()?;
        let _ = fs::remove_dir_all(base);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn staged_executable_is_private_and_executable() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!(
            "layerfault-binding-executable-{}-{}",
            std::process::id(),
            crate::paths::now_unix()
        ));
        let parent = base.join("staging");
        fs::create_dir_all(&base)?;
        let source = base.join("runtime");
        fs::write(&source, b"verified executable")?;
        let digest = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(b"verified executable"))
        );
        let staged = stage_verified_under(&source, &digest, &parent, true)?;
        assert_eq!(
            fs::metadata(staged.path())?.permissions().mode() & 0o777,
            0o500
        );
        staged.cleanup()?;
        let _ = fs::remove_dir_all(base);
        Ok(())
    }

    #[test]
    fn staged_package_verifies_members_and_fingerprint() -> Result<()> {
        let base = std::env::temp_dir().join(format!(
            "layerfault-pkg-binding-test-{}-{}",
            std::process::id(),
            crate::paths::now_unix()
        ));
        let pkg_dir = base.join("model_package");
        fs::create_dir_all(&pkg_dir)?;
        fs::write(pkg_dir.join("config.json"), b"{\"model_type\": \"test\"}")?;
        fs::write(pkg_dir.join("model.safetensors"), b"fake weight bytes")?;

        let report = crate::package::inspect(&pkg_dir)?;
        let parent = base.join("staging_parent");
        let staged_pkg = stage_verified_package_under(&pkg_dir, &report, &parent)?;

        assert_eq!(staged_pkg.source_fingerprint, report.fingerprint);
        assert_eq!(staged_pkg.staged_fingerprint, report.fingerprint);
        assert_eq!(staged_pkg.members.len(), 2);
        assert!(staged_pkg.path().join("config.json").is_file());
        assert!(staged_pkg.path().join("model.safetensors").is_file());
        assert_eq!(
            fs::read(staged_pkg.path().join("config.json"))?,
            b"{\"model_type\": \"test\"}"
        );

        staged_pkg.revalidate()?;
        staged_pkg.cleanup()?;
        let _ = fs::remove_dir_all(base);
        Ok(())
    }

    #[test]
    fn staged_package_refuses_symlink_members() -> Result<()> {
        let base = std::env::temp_dir().join(format!(
            "layerfault-pkg-symlink-test-{}-{}",
            std::process::id(),
            crate::paths::now_unix()
        ));
        let pkg_dir = base.join("symlink_package");
        fs::create_dir_all(&pkg_dir)?;
        fs::write(pkg_dir.join("config.json"), b"{}")?;
        #[cfg(unix)]
        std::os::unix::fs::symlink(pkg_dir.join("config.json"), pkg_dir.join("link.json"))?;

        let mut report = crate::package::inspect(&pkg_dir)?;

        let parent = base.join("staging_parent");
        // Ensure that if a symlink exists, staging fails cleanly
        report.files.push(crate::package::PackageEntry {
            relative_path: "link.json".to_owned(),
            kind: "symlink".to_owned(),
            size: 0,
            sha256: Some("sha256:1234".to_owned()),
            digest_cache: None,
        });

        let result = stage_verified_package_under(&pkg_dir, &report, &parent);
        assert!(result.is_err());
        let _ = fs::remove_dir_all(base);
        Ok(())
    }
}
