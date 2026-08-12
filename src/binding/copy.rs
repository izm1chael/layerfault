use super::types::StagingMechanism;
use crate::safeio::open_readonly_nofollow;
use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub fn probe_reflink_support() -> bool {
    #[cfg(target_os = "linux")]
    {
        let parent = match crate::paths::config_dir() {
            Ok(p) => p.join("reflink-probe"),
            Err(_) => std::env::temp_dir().join("layerfault-reflink-probe"),
        };
        if fs::create_dir_all(&parent).is_err() {
            return false;
        }
        let pid = std::process::id();
        let src_path = parent.join(format!(".probe_src_{pid}"));
        let dst_path = parent.join(format!(".probe_dst_{pid}"));

        let result = (|| -> Result<bool> {
            fs::write(&src_path, b"reflink_probe_bytes")?;
            let source_file = open_readonly_nofollow(&src_path)?;
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let dest_file = options.open(&dst_path)?;
            let success = rustix::fs::ioctl_ficlone(&dest_file, &source_file).is_ok();
            Ok(success)
        })()
        .unwrap_or(false);

        let _ = fs::remove_file(&src_path);
        let _ = fs::remove_file(&dst_path);
        let _ = fs::remove_dir(&parent);

        result
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

pub fn copy_or_reflink_member(
    source_path: &Path,
    staged_target_path: &Path,
    expected_sha256: &str,
    executable: bool,
) -> Result<(StagingMechanism, u64, String)> {
    copy_or_reflink_member_impl(
        source_path,
        staged_target_path,
        expected_sha256,
        executable,
        false,
    )
}

pub fn copy_or_reflink_member_force_fallback(
    source_path: &Path,
    staged_target_path: &Path,
    expected_sha256: &str,
    executable: bool,
) -> Result<(StagingMechanism, u64, String)> {
    copy_or_reflink_member_impl(
        source_path,
        staged_target_path,
        expected_sha256,
        executable,
        true,
    )
}

fn copy_or_reflink_member_impl(
    source_path: &Path,
    staged_target_path: &Path,
    expected_sha256: &str,
    executable: bool,
    force_fallback: bool,
) -> Result<(StagingMechanism, u64, String)> {
    let source_file = open_readonly_nofollow(source_path)?;
    let pre_meta = fs::symlink_metadata(source_path)
        .with_context(|| format!("Unable to inspect source file '{}'", source_path.display()))?;
    if pre_meta.file_type().is_symlink() {
        bail!("Source file '{}' is a symlink", source_path.display());
    }
    if !pre_meta.is_file() {
        bail!(
            "Source file '{}' is not a regular file",
            source_path.display()
        );
    }

    if let Some(target_parent) = staged_target_path.parent() {
        fs::create_dir_all(target_parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(target_parent, fs::Permissions::from_mode(0o700))?;
        }
    }

    if let Ok(target_meta) = fs::symlink_metadata(staged_target_path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if pre_meta.dev() == target_meta.dev() && pre_meta.ino() == target_meta.ino() {
                bail!(
                    "Hardlink detected between source '{}' and destination '{}'; hardlinks break isolation and are strictly prohibited for secure staging",
                    source_path.display(),
                    staged_target_path.display()
                );
            }
        }
    }

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let dest_file = options.open(staged_target_path).with_context(|| {
        format!(
            "Unable to create staged file '{}'",
            staged_target_path.display()
        )
    })?;

    let mut mechanism = StagingMechanism::StreamCopy;
    let mut reflink_ok = false;

    if !force_fallback {
        #[cfg(target_os = "linux")]
        {
            if rustix::fs::ioctl_ficlone(&dest_file, &source_file).is_ok() {
                reflink_ok = true;
                mechanism = StagingMechanism::Reflink;
            }
        }
    }

    let (observed_sha256, copied_bytes) = if reflink_ok {
        drop(dest_file);
        let mut dest_read = open_readonly_nofollow(staged_target_path)?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0_u8; 1024 * 1024];
        let mut bytes = 0_u64;
        loop {
            let n = dest_read.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
            bytes = bytes.saturating_add(n as u64);
        }
        let obs = format!("sha256:{}", hex::encode(hasher.finalize()));
        crate::perf_metrics::record_logical_staged_bytes(bytes);
        crate::perf_metrics::record_reflinked_member();
        (obs, bytes)
    } else {
        let mut dest_write = dest_file;
        let mut reader = source_file.try_clone()?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0_u8; 1024 * 1024];
        let mut bytes = 0_u64;
        loop {
            let n = reader.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            dest_write.write_all(&buffer[..n])?;
            hasher.update(&buffer[..n]);
            bytes = bytes.saturating_add(n as u64);
        }
        dest_write.sync_all()?;
        let obs = format!("sha256:{}", hex::encode(hasher.finalize()));
        crate::perf_metrics::record_logical_staged_bytes(bytes);
        crate::perf_metrics::record_stream_copied_bytes(bytes);
        crate::perf_metrics::record_copied_member();
        (obs, bytes)
    };

    let post_source_meta = fs::symlink_metadata(source_path)?;
    if pre_meta.len() != post_source_meta.len() {
        bail!(
            "Source file '{}' changed size during staging (TOCTOU violation)",
            source_path.display()
        );
    }

    let post_dest_meta = fs::symlink_metadata(staged_target_path)?;
    if !post_dest_meta.is_file() {
        bail!(
            "Staged destination file '{}' is not a regular file",
            staged_target_path.display()
        );
    }

    if post_dest_meta.len() != pre_meta.len() {
        bail!(
            "Staged destination file '{}' size mismatch: source {}, destination {}",
            staged_target_path.display(),
            pre_meta.len(),
            post_dest_meta.len()
        );
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if post_source_meta.dev() == post_dest_meta.dev()
            && post_source_meta.ino() == post_dest_meta.ino()
        {
            bail!(
                "Hardlink detected between source '{}' and destination '{}'; hardlinks break isolation and are strictly prohibited for secure staging",
                source_path.display(),
                staged_target_path.display()
            );
        }
    }

    if !observed_sha256.eq_ignore_ascii_case(expected_sha256) {
        bail!(
            "Staged file '{}' hash changed during staging: expected {}, observed {}",
            staged_target_path.display(),
            expected_sha256,
            observed_sha256
        );
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if executable { 0o500 } else { 0o400 };
        fs::set_permissions(staged_target_path, fs::Permissions::from_mode(mode))?;
    }

    Ok((mechanism, copied_bytes, observed_sha256))
}

pub(crate) fn create_unique_dir(parent: &Path, short: &str) -> Result<PathBuf> {
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
    fn test_reflink_unsupported_fallback() -> Result<()> {
        let base = std::env::temp_dir().join(format!(
            "layerfault-reflink-fallback-{}-{}",
            std::process::id(),
            crate::paths::now_unix()
        ));
        fs::create_dir_all(&base)?;
        let source = base.join("source.dat");
        let dest = base.join("dest.dat");
        fs::write(&source, b"test reflink fallback content")?;
        let digest = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(b"test reflink fallback content"))
        );

        let (mechanism, bytes, sha) =
            copy_or_reflink_member_force_fallback(&source, &dest, &digest, false)?;
        assert_eq!(mechanism, StagingMechanism::StreamCopy);
        assert_eq!(bytes, b"test reflink fallback content".len() as u64);
        assert_eq!(sha, digest);
        assert_eq!(fs::read(&dest)?, b"test reflink fallback content");

        let _ = fs::remove_dir_all(base);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn test_hardlink_detection_refusal() -> Result<()> {
        let base = std::env::temp_dir().join(format!(
            "layerfault-hardlink-test-{}-{}",
            std::process::id(),
            crate::paths::now_unix()
        ));
        fs::create_dir_all(&base)?;
        let source = base.join("source.dat");
        let dest = base.join("hardlink_dest.dat");
        fs::write(&source, b"hardlink test data")?;

        // Manually create a hardlink destination
        fs::hard_link(&source, &dest)?;

        let digest = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(b"hardlink test data"))
        );

        // Copying/staging should refuse hardlinks because source and dest share inode
        let result = copy_or_reflink_member(&source, &dest, &digest, false);
        assert!(result.is_err());
        let err_msg = format!("{:#}", result.unwrap_err());
        assert!(err_msg.contains("Hardlink detected") || err_msg.contains("exists"));

        let _ = fs::remove_dir_all(base);
        Ok(())
    }
}
