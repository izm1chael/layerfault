use anyhow::{anyhow, bail, Context, Result};
use std::fs;
use std::io::Write;
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

pub fn cache_dir() -> Result<PathBuf> {
    if let Ok(value) = std::env::var("LAYERFAULT_CACHE_DIR") {
        if !value.trim().is_empty() {
            return Ok(PathBuf::from(value));
        }
    }

    #[cfg(windows)]
    {
        let base = std::env::var("LOCALAPPDATA")
            .or_else(|_| std::env::var("APPDATA"))
            .map(PathBuf::from)
            .map_err(|_| anyhow!("Cannot determine LOCALAPPDATA; set LAYERFAULT_CACHE_DIR"))?;
        return Ok(base.join("layerfault").join("cache"));
    }

    #[cfg(not(windows))]
    {
        if let Ok(value) = std::env::var("XDG_CACHE_HOME") {
            if !value.trim().is_empty() {
                return Ok(PathBuf::from(value).join("layerfault"));
            }
        }
        let home = std::env::var("HOME")
            .map(PathBuf::from)
            .map_err(|_| anyhow!("Cannot determine HOME; set LAYERFAULT_CACHE_DIR"))?;
        Ok(home.join(".cache").join("layerfault"))
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
    // `Path::parent()` returns `Some("")` for a bare relative filename like
    // "out.json" (not `None`), so the empty-parent case must be folded into
    // "." explicitly or downstream directory/permission operations fail on
    // the empty path with an opaque error that never names the real target.
    let parent = match path.parent() {
        None => bail!("Path '{}' has no parent", path.display()),
        Some(parent) if parent.as_os_str().is_empty() => Path::new("."),
        Some(parent) => parent,
    };
    ensure_private_dir(parent)?;

    // NamedTempFile reserves a fresh inode with exclusive creation. Its persist
    // operation uses the platform's atomic replacement primitive, including
    // MoveFileExW with REPLACE_EXISTING on Windows.
    let prefix = format!(
        ".{}.tmp-",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("layerfault")
    );
    let mut tmp = tempfile::Builder::new()
        .prefix(&prefix)
        .tempfile_in(parent)
        .with_context(|| {
            format!(
                "Unable to reserve private temporary file for '{}'",
                path.display()
            )
        })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    tmp.as_file_mut()
        .write_all(bytes)
        .with_context(|| format!("Unable to write temporary file for '{}'", path.display()))?;
    tmp.as_file()
        .sync_all()
        .with_context(|| format!("Unable to sync temporary file for '{}'", path.display()))?;
    tmp.persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("Unable to atomically install '{}'", path.display()))?;
    Ok(())
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0)
}

/// Read a secret from `NAME` or, preferably for container deployments,
/// `NAME_FILE`. Secret files are opened without following symlinks and are
/// capped to avoid accidentally reading arbitrary large host files.
pub fn secret_from_env(name: &str) -> Result<Option<String>> {
    let file_name = format!("{name}_FILE");
    if let Ok(path) = std::env::var(&file_name) {
        if !path.trim().is_empty() {
            let file = crate::safeio::open_readonly_nofollow(Path::new(path.trim()))
                .with_context(|| format!("Unable to open secret file from {file_name}"))?;
            let bytes = crate::safeio::read_all_from_file(&file, 1024 * 1024)?;
            let value = String::from_utf8(bytes).context("secret file is not valid UTF-8")?;
            let value = value.trim_end_matches(['\r', '\n']).to_owned();
            if value.is_empty() {
                return Ok(None);
            }
            return Ok(Some(value));
        }
    }
    Ok(std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_write_replaces_existing_file() -> Result<()> {
        let root =
            std::env::temp_dir().join(format!("layerfault-write-replace-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        let output = root.join("report.json");
        write_private(&output, b"first")?;
        write_private(&output, b"second")?;
        assert_eq!(fs::read(&output)?, b"second");
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn private_write_replaces_symlink_without_following_it() -> Result<()> {
        use std::os::unix::fs::symlink;
        let root =
            std::env::temp_dir().join(format!("layerfault-write-private-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        let victim = root.join("victim");
        let output = root.join("report.json");
        fs::write(&victim, b"do-not-touch")?;
        symlink(&victim, &output)?;
        write_private(&output, b"new-evidence")?;
        assert_eq!(fs::read(&victim)?, b"do-not-touch");
        assert_eq!(fs::read(&output)?, b"new-evidence");
        assert!(!fs::symlink_metadata(&output)?.file_type().is_symlink());
        let _ = fs::remove_dir_all(root);
        Ok(())
    }
}
