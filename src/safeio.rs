use anyhow::{anyhow, Context, Result};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

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
