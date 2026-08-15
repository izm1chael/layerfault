use super::PolicyProfile;
use anyhow::{anyhow, bail, Context, Result};
use std::path::Path;

#[derive(Debug, Clone, serde::Serialize)]
pub struct OverrideRecord {
    pub version: u32,
    pub created_unix: u64,
    pub model: String,
    pub reason: String,
    pub profile: PolicyProfile,
    pub trust_state: crate::provenance::TrustState,
    pub scanner_exit_code: i32,
}

pub fn record_policy_override(
    record: &OverrideRecord,
    path: Option<&Path>,
) -> Result<std::path::PathBuf> {
    use std::fs::OpenOptions;
    use std::io::Write;
    if record.reason.trim().len() < 8 {
        return Err(anyhow!(
            "Policy override reason must be at least 8 characters"
        ));
    }
    let path = match path {
        Some(path) => path.to_path_buf(),
        None => crate::paths::config_dir()?.join("override-audit.jsonl"),
    };
    // `Path::parent()` returns `Some("")` for a bare relative filename (not
    // `None`), so the empty-parent case must be folded into "." explicitly.
    let parent = match path.parent() {
        None => bail!("Override log path has no parent"),
        Some(parent) if parent.as_os_str().is_empty() => Path::new("."),
        Some(parent) => parent,
    };
    crate::paths::ensure_private_dir(parent)?;
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(anyhow!(
                "Refusing to append to symlinked override log '{}'",
                path.display()
            ))
        }
        Ok(metadata) if !metadata.is_file() => {
            return Err(anyhow!(
                "Override log '{}' is not a regular file",
                path.display()
            ))
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options
        .open(&path)
        .with_context(|| format!("Unable to open override audit log '{}'", path.display()))?;
    let mut line = serde_json::to_vec(record)?;
    line.push(b'\n');
    file.write_all(&line)?;
    file.sync_data()?;
    Ok(path)
}
