use anyhow::{anyhow, Context, Result};
use std::fs::{File, OpenOptions, ReadDir};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Open a file for read-only scanning while refusing a final-component symlink on Unix.
///
/// Keeping the returned descriptor open across integrity verification and deep scanning
/// prevents a path replacement from swapping in different bytes between those phases.
pub fn open_readonly_nofollow(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }

    let file = options
        .open(path)
        .with_context(|| format!("Unable to safely open '{}'", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("Unable to stat '{}'", path.display()))?;

    if !metadata.is_file() {
        return Err(anyhow!("'{}' is not a regular file", path.display()));
    }

    Ok(file)
}

pub fn validated_relative_path(value: &str, allow_curdir: bool) -> Result<PathBuf> {
    if value.is_empty()
        || value.len() > 16 * 1024
        || value.contains("//")
        || value.contains('\\')
        || value.contains("://")
        || value.chars().any(char::is_control)
        || value.starts_with('/')
        || value.starts_with('\\')
    {
        return Err(anyhow!("unsafe relative member path"));
    }
    let mut output = PathBuf::new();
    let mut normal = 0usize;
    for segment in value.split('/') {
        if segment.is_empty() || segment == ".." || segment.contains(':') {
            return Err(anyhow!("unsafe relative member path component"));
        }
        if segment == "." {
            if allow_curdir {
                continue;
            }
            return Err(anyhow!("current-directory components are not allowed"));
        }
        output.push(segment);
        normal += 1;
    }
    if normal == 0 {
        return Err(anyhow!(
            "relative member path contains no normal components"
        ));
    }
    Ok(output)
}

pub fn canonical_regular_file_within(
    root: &Path,
    relative: &str,
    allow_curdir: bool,
) -> Result<PathBuf> {
    let relative = validated_relative_path(relative, allow_curdir)?;
    let root_meta = std::fs::symlink_metadata(root)?;
    if root_meta.file_type().is_symlink() || !root_meta.is_dir() {
        return Err(anyhow!("containment root must be a real directory"));
    }
    let canonical_root = std::fs::canonicalize(root)?;
    let candidate = canonical_root.join(relative);
    let metadata = std::fs::symlink_metadata(&candidate)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(anyhow!("contained path must be a regular non-symlink file"));
    }
    let canonical = std::fs::canonicalize(&candidate)?;
    if !canonical.starts_with(&canonical_root) {
        return Err(anyhow!("contained path escapes root"));
    }
    let _ = open_readonly_nofollow(&canonical)?;
    Ok(canonical)
}

pub fn optional_regular_file_within(
    root: &Path,
    relative: &str,
    allow_curdir: bool,
) -> Result<Option<PathBuf>> {
    let relative = validated_relative_path(relative, allow_curdir)?;
    let root_meta = std::fs::symlink_metadata(root)?;
    if root_meta.file_type().is_symlink() || !root_meta.is_dir() {
        return Err(anyhow!("containment root must be a real directory"));
    }
    let canonical_root = std::fs::canonicalize(root)?;
    // The relative path has already been validated; canonicalize only existing files.
    let candidate = canonical_root.join(relative);
    match std::fs::symlink_metadata(&candidate) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(anyhow!("contained path must be a regular non-symlink file"));
            }
            let canonical = std::fs::canonicalize(&candidate)?;
            if !canonical.starts_with(&canonical_root) {
                return Err(anyhow!("contained path escapes root"));
            }
            let _ = open_readonly_nofollow(&canonical)?;
            Ok(Some(canonical))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

pub fn read_dir_nofollow(path: &Path) -> Result<ReadDir> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(anyhow!("directory must be a real directory"));
    }
    // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
    Ok(std::fs::read_dir(std::fs::canonicalize(path)?)?)
}

pub fn canonical_executable(path: &Path) -> Result<PathBuf> {
    let canonical = std::fs::canonicalize(path)?;
    let _ = open_readonly_nofollow(&canonical)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if std::fs::metadata(&canonical)?.permissions().mode() & 0o111 == 0 {
            return Err(anyhow!("executable has no execute permission bits"));
        }
    }
    Ok(canonical)
}

pub fn canonical_executable_nosymlink(path: &Path) -> Result<PathBuf> {
    if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(anyhow!("executable may not be a symlink"));
    }
    canonical_executable(path)
}

pub fn command_for_executable(path: &Path) -> Result<Command> {
    // The executable path is canonicalized and checked immediately above.
    // nosemgrep: rust.actix.command-injection.rust-actix-command-injection
    // nosemgrep: rust.actix.command-injection.rust-actix-command-injection
    Ok(Command::new(canonical_executable(path)?)) // nosemgrep: rust.actix.command-injection.rust-actix-command-injection.rust-actix-command-injection
}

pub fn rewind(file: &mut File) -> Result<()> {
    file.seek(SeekFrom::Start(0))?;
    Ok(())
}

pub fn read_all_from_file(file: &File, max_bytes: u64) -> Result<Vec<u8>> {
    let len = file.metadata()?.len();
    if len > max_bytes {
        return Err(anyhow!(
            "File is {len} bytes, exceeding the {max_bytes}-byte safety limit"
        ));
    }

    let mut cloned = file.try_clone()?;
    rewind(&mut cloned)?;
    let mut bytes = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
    cloned
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(anyhow!("File exceeded the configured read safety limit"));
    }
    Ok(bytes)
}

pub fn sha256_path(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut file = open_readonly_nofollow(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn opens_regular_file() -> Result<()> {
        let path = std::env::temp_dir().join("layerfault_safeio_regular");
        fs::write(&path, b"ok")?;
        let file = open_readonly_nofollow(&path)?;
        assert_eq!(file.metadata()?.len(), 2);
        let _ = fs::remove_file(path);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlink() -> Result<()> {
        use std::os::unix::fs::symlink;
        let root = std::env::temp_dir().join("layerfault_safeio_symlink");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        fs::write(root.join("target"), b"ok")?;
        symlink(root.join("target"), root.join("link"))?;
        assert!(open_readonly_nofollow(&root.join("link")).is_err());
        let _ = fs::remove_dir_all(root);
        Ok(())
    }
}
