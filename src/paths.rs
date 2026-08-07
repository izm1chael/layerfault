use anyhow::{anyhow, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

pub fn config_dir() -> Result<PathBuf> {
    if let Ok(value) = std::env::var("LAYERFAULT_CONFIG_DIR") {
        if !value.trim().is_empty() {
            return Ok(PathBuf::from(value));
        }
    }

    #[cfg(windows)]
    {
        let base = std::env::var("APPDATA")
            .map(PathBuf::from)
            .map_err(|_| anyhow!("Cannot determine APPDATA; set LAYERFAULT_CONFIG_DIR"))?;
        return Ok(base.join("layerfault"));
    }

    #[cfg(not(windows))]
    {
        if let Ok(value) = std::env::var("XDG_CONFIG_HOME") {
            if !value.trim().is_empty() {
                return Ok(PathBuf::from(value).join("layerfault"));
            }
        }
        let home = std::env::var("HOME")
            .map(PathBuf::from)
            .map_err(|_| anyhow!("Cannot determine HOME; set LAYERFAULT_CONFIG_DIR"))?;
        Ok(home.join(".config").join("layerfault"))
    }
}

pub fn ensure_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("Unable to create '{}'", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("Unable to secure '{}'", path.display()))?;
    }
    Ok(())
}

pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("Path '{}' has no parent", path.display()))?;
    ensure_private_dir(parent)?;

    let tmp = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("layerfault"),
        std::process::id()
    ));
    fs::write(&tmp, bytes)
        .with_context(|| format!("Unable to write temporary file '{}'", tmp.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("Unable to secure '{}'", tmp.display()))?;
    }

    if path.exists() {
        fs::remove_file(path).with_context(|| format!("Unable to replace '{}'", path.display()))?;
    }
    fs::rename(&tmp, path).with_context(|| format!("Unable to install '{}'", path.display()))?;
    Ok(())
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0)
}
