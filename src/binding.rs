use crate::safeio::open_readonly_nofollow;
use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BindingKind {
    StagedCopy,
    RevalidatedBeforeLaunch,
    BestEffort,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct BindingRecord {
    pub kind: BindingKind,
    pub original: String,
    pub runtime_path: Option<String>,
    pub sha256: Option<String>,
    pub detail: String,
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

pub fn stage_verified(path: &Path, expected_sha256: &str) -> Result<StagedArtifact> {
    let parent = crate::paths::config_dir()?.join("admission-staging");
    stage_verified_under(path, expected_sha256, &parent, false)
}

pub fn stage_verified_executable(path: &Path, expected_sha256: &str) -> Result<StagedArtifact> {
    let parent = crate::paths::config_dir()?.join("runtime-staging");
    stage_verified_under(path, expected_sha256, &parent, true)
}

fn stage_verified_under(
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
            kind: BindingKind::StagedCopy,
            original: path.display().to_string(),
            runtime_path: Some(target.display().to_string()),
            sha256: Some(observed),
            detail: "Runtime receives a private copy created from a no-follow file descriptor after admission; the copy digest is rechecked before launch".to_owned(),
        },
    })
}

pub fn revalidated(
    original: impl Into<String>,
    sha256: Option<String>,
    detail: impl Into<String>,
) -> BindingRecord {
    BindingRecord {
        kind: BindingKind::RevalidatedBeforeLaunch,
        original: original.into(),
        runtime_path: None,
        sha256,
        detail: detail.into(),
    }
}

pub fn best_effort(original: impl Into<String>, detail: impl Into<String>) -> BindingRecord {
    BindingRecord {
        kind: BindingKind::BestEffort,
        original: original.into(),
        runtime_path: None,
        sha256: None,
        detail: detail.into(),
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
}
