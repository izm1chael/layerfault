use super::copy::{copy_or_reflink_member, create_unique_dir};
use super::types::{
    BindingKind, BindingRecord, BoundMember, ComponentBinding, ExecutionManifest, StagedArtifact,
    StagedPackage, StagingMechanism,
};
use crate::error::{ErrorKind, LayerfaultError, Severity};
use anyhow::{anyhow, bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Directory names under the config dir that hold private short-lived
/// staged copies created during execution binding (see `create_unique_dir`,
/// which embeds the creating process's pid in each entry's name).
const STAGING_ROOT_NAMES: [&str; 3] = ["admission-staging", "runtime-staging", "package-staging"];

/// Minimum age before an orphaned staging directory is eligible for
/// removal. `Drop` never runs on SIGKILL, so a killed process's staging
/// directory is a permanent leak unless something else reclaims it; this
/// margin just avoids racing a directory that's still mid-creation by a
/// process whose pid we failed to parse.
const STALE_STAGING_MIN_AGE_SECS: u64 = 300;

/// All staging roots that may accumulate orphaned copies if a `layerfault`
/// process staging into them is killed before it can clean up after itself.
pub fn staging_roots() -> Result<Vec<PathBuf>> {
    let base = crate::paths::config_dir()?;
    Ok(STAGING_ROOT_NAMES
        .iter()
        .map(|name| base.join(name))
        .collect())
}

fn is_pid_alive(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        Path::new(&format!("/proc/{pid}")).exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        // No portable, safe (non-`unsafe`) liveness check without `/proc`;
        // assume alive so staleness falls back to the age check alone
        // rather than risking removal of a directory still in active use.
        let _ = pid;
        true
    }
}

/// `create_unique_dir` names entries `{unix_timestamp}-{pid}-{short}-{counter}`;
/// pull the creation time and owning pid back out of that name.
fn parse_staging_dir_name(name: &str) -> (Option<u64>, Option<u32>) {
    let mut fields = name.splitn(4, '-');
    let created_at = fields.next().and_then(|value| value.parse::<u64>().ok());
    let owner_pid = fields.next().and_then(|value| value.parse::<u32>().ok());
    (created_at, owner_pid)
}

/// Staging directories under `parent` whose owning process is confirmed
/// dead (or whose name couldn't be attributed to a pid at all) and which
/// have sat for at least `STALE_STAGING_MIN_AGE_SECS`. Read-only: callers
/// decide whether to actually remove what's returned.
pub fn stale_staging_dirs(parent: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(parent) else {
        return Vec::new();
    };
    let now = crate::paths::now_unix();
    let mut stale = Vec::new();
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        let (created_at, owner_pid) = parse_staging_dir_name(name);
        let age_secs = created_at.map(|created| now.saturating_sub(created));
        if age_secs.is_none_or(|age| age < STALE_STAGING_MIN_AGE_SECS) {
            continue;
        }
        let orphaned = match owner_pid {
            Some(pid) => !is_pid_alive(pid),
            None => true,
        };
        if orphaned {
            stale.push(path);
        }
    }
    stale
}

/// Best-effort pre-flight reclaim of `parent`'s stale staging directories,
/// run before staging a new copy into it. Individual removal failures are
/// ignored: this is opportunistic cleanup, not a precondition for the
/// current operation, and must never block or fail staging.
fn sweep_stale_staging(parent: &Path) {
    let stale = stale_staging_dirs(parent);
    if !stale.is_empty() {
        let mut removed = 0usize;
        for path in &stale {
            if fs::remove_dir_all(path).is_ok() {
                removed = removed.saturating_add(1);
            }
        }
        if removed == 0 {
            return;
        }
        crate::diagnostics::emit_full(
            crate::diagnostics::Level::Info,
            "staging_sweep",
            &format!("cleaned up {removed} orphaned staging directories"),
            parent.to_str(),
            None,
        );
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
        return Err(LayerfaultError::new(
            ErrorKind::ExecutionBinding,
            Severity::Error,
            "Execution binding requires a canonical sha256 artifact digest",
        )
        .with_code("LF-ERR-BINDING-DIGEST-SCHEME")
        .with_subject(format!("expected={expected_sha256}"))
        .with_hint("format digest as 'sha256:<hex>'")
        .into());
    }
    crate::paths::ensure_private_dir(parent)?;
    sweep_stale_staging(parent);
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

    let (mechanism, _bytes, observed) =
        match copy_or_reflink_member(path, &target, expected_sha256, executable) {
            Ok(res) => res,
            Err(err) => {
                let _ = fs::remove_dir_all(&root);
                return Err(err);
            }
        };

    let mechanism_str = match mechanism {
        StagingMechanism::Reflink => "reflink",
        StagingMechanism::StreamCopy => "stream-copy",
    };

    Ok(StagedArtifact {
        root: root.clone(),
        path: target.clone(),
        record: BindingRecord {
            kind: BindingKind::FileStagedRehashed,
            original: path.display().to_string(),
            runtime_path: Some(target.display().to_string()),
            sha256: Some(observed),
            detail: format!(
                "Runtime receives a private {mechanism_str} copy created from a no-follow file descriptor after admission; the copy digest is rechecked before launch"
            ),
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
    sweep_stale_staging(parent);
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
    let mut reflinked_members = 0usize;
    let mut copied_members = 0usize;

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

        let rel_path = match crate::safeio::validated_relative_path(&entry.relative_path, true) {
            Ok(path) => path,
            Err(error) => {
                let _ = fs::remove_dir_all(&staging_root);
                return Err(anyhow!(
                    "Package member relative path '{}' is unsafe: {error}",
                    entry.relative_path
                ));
            }
        };

        let source_path = root.join(&rel_path);
        let staged_target_path = staged_pkg_dir.join(&rel_path);

        let (mechanism, bytes, observed_sha256) =
            match copy_or_reflink_member(&source_path, &staged_target_path, expected_sha256, false)
            {
                Ok(res) => res,
                Err(err) => {
                    let _ = fs::remove_dir_all(&staging_root);
                    return Err(err);
                }
            };

        match mechanism {
            StagingMechanism::Reflink => reflinked_members += 1,
            StagingMechanism::StreamCopy => copied_members += 1,
        }

        members.push(BoundMember {
            relative_path: entry.relative_path.clone(),
            expected_sha256: expected_sha256.to_owned(),
            staged_sha256: observed_sha256,
            bytes,
            mechanism,
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
            "Private read-only package staged from no-follow descriptors; verified {} members ({total_bytes} bytes, {reflinked_members} reflinked, {copied_members} copied); staged fingerprint equals admitted fingerprint {}",
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
        reflinked_members,
        copied_members,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::fs::OpenOptions;

    #[test]
    fn test_destination_hash_matches() -> Result<()> {
        let base = std::env::temp_dir().join(format!(
            "layerfault-dest-hash-{}-{}",
            std::process::id(),
            crate::paths::now_unix()
        ));
        let parent = base.join("staging");
        fs::create_dir_all(&base)?;
        let source = base.join("source.gguf");
        fs::write(&source, b"verified artifact content")?;
        let digest = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(b"verified artifact content"))
        );

        let staged = stage_verified_under(&source, &digest, &parent, false)?;
        assert_eq!(fs::read(staged.path())?, b"verified artifact content");
        assert_eq!(staged.record.sha256.as_deref(), Some(digest.as_str()));

        staged.cleanup()?;
        let _ = fs::remove_dir_all(base);
        Ok(())
    }

    #[test]
    fn test_source_mutation_after_clone_does_not_alter_staged_bytes() -> Result<()> {
        let base = std::env::temp_dir().join(format!(
            "layerfault-source-mutation-{}-{}",
            std::process::id(),
            crate::paths::now_unix()
        ));
        let parent = base.join("staging");
        fs::create_dir_all(&base)?;
        let source = base.join("model.safetensors");
        fs::write(&source, b"original uncorrupted model weights")?;
        let digest = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(b"original uncorrupted model weights"))
        );

        let staged = stage_verified_under(&source, &digest, &parent, false)?;
        assert_eq!(
            fs::read(staged.path())?,
            b"original uncorrupted model weights"
        );

        // Mutate source file after staging
        fs::write(&source, b"CORRUPTED PAYLOAD BY ATTACKER")?;

        // Staged copy must remain untampered
        assert_eq!(
            fs::read(staged.path())?,
            b"original uncorrupted model weights"
        );
        staged.revalidate()?;

        staged.cleanup()?;
        let _ = fs::remove_dir_all(base);
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn test_staged_mutation_does_not_alter_source() -> Result<()> {
        let base = std::env::temp_dir().join(format!(
            "layerfault-staged-mutation-{}-{}",
            std::process::id(),
            crate::paths::now_unix()
        ));
        let parent = base.join("staging");
        fs::create_dir_all(&base)?;
        let source = base.join("model.bin");
        fs::write(&source, b"source model data")?;
        let digest = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(b"source model data"))
        );

        let staged = stage_verified_under(&source, &digest, &parent, false)?;

        // Verify staged file is read-only (0o400)
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(staged.path())?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o400);

        // Attempt writing to staged file should fail because it's read-only
        let write_res = OpenOptions::new().write(true).open(staged.path());
        assert!(write_res.is_err());

        // Source file remains untouched
        assert_eq!(fs::read(&source)?, b"source model data");

        staged.cleanup()?;
        let _ = fs::remove_dir_all(base);
        Ok(())
    }

    #[test]
    fn test_partial_failure_cleans_destination() -> Result<()> {
        let base = std::env::temp_dir().join(format!(
            "layerfault-partial-fail-{}-{}",
            std::process::id(),
            crate::paths::now_unix()
        ));
        let pkg_dir = base.join("bad_package");
        fs::create_dir_all(&pkg_dir)?;
        fs::write(pkg_dir.join("file1.json"), b"valid file 1")?;
        fs::write(pkg_dir.join("file2.json"), b"file 2 content")?;

        let mut report = crate::package::inspect(&pkg_dir)?;
        // Tamper with expected hash of file2 in admission report
        for entry in &mut report.files {
            if entry.relative_path == "file2.json" {
                entry.sha256 = Some(
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                        .to_owned(),
                );
            }
        }

        let parent = base.join("staging_parent");
        let result = stage_verified_package_under(&pkg_dir, &report, &parent);
        assert!(result.is_err());

        // Verify that parent staging directory was cleaned up and contains no leaked artifacts
        if parent.exists() {
            let entries = fs::read_dir(&parent)?.count();
            assert_eq!(
                entries, 0,
                "Partial failure leaked staging files in parent directory"
            );
        }

        let _ = fs::remove_dir_all(base);
        Ok(())
    }

    #[test]
    fn test_mixed_reflink_copy_package() -> Result<()> {
        let base = std::env::temp_dir().join(format!(
            "layerfault-mixed-pkg-{}-{}",
            std::process::id(),
            crate::paths::now_unix()
        ));
        let pkg_dir = base.join("mixed_package");
        fs::create_dir_all(&pkg_dir)?;
        fs::write(pkg_dir.join("config.json"), b"{\"model_type\": \"mixed\"}")?;
        fs::write(pkg_dir.join("weights.safetensors"), b"safetensors weights")?;

        let report = crate::package::inspect(&pkg_dir)?;
        let parent = base.join("staging_parent");
        let staged_pkg = stage_verified_package_under(&pkg_dir, &report, &parent)?;

        assert_eq!(staged_pkg.members.len(), 2);
        assert_eq!(staged_pkg.reflinked_members + staged_pkg.copied_members, 2);
        assert_eq!(staged_pkg.source_fingerprint, report.fingerprint);
        assert_eq!(staged_pkg.staged_fingerprint, report.fingerprint);

        staged_pkg.revalidate()?;
        staged_pkg.cleanup()?;
        let _ = fs::remove_dir_all(base);
        Ok(())
    }

    #[test]
    fn test_read_only_execution_mount_preserved() -> Result<()> {
        let base = std::env::temp_dir().join(format!(
            "layerfault-readonly-mount-{}-{}",
            std::process::id(),
            crate::paths::now_unix()
        ));
        let pkg_dir = base.join("ro_package");
        fs::create_dir_all(&pkg_dir)?;
        fs::write(pkg_dir.join("config.json"), b"{}")?;

        let report = crate::package::inspect(&pkg_dir)?;
        let parent = base.join("staging_parent");
        let staged_pkg = stage_verified_package_under(&pkg_dir, &report, &parent)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir_mode = fs::metadata(staged_pkg.path())?.permissions().mode() & 0o777;
            assert_eq!(dir_mode, 0o700);

            let file_mode = fs::metadata(staged_pkg.path().join("config.json"))?
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(file_mode, 0o400);
        }

        staged_pkg.cleanup()?;
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

    #[test]
    #[cfg(target_os = "linux")]
    fn stale_staging_dirs_reclaims_only_aged_orphans_with_a_dead_owner() -> Result<()> {
        let base = std::env::temp_dir().join(format!(
            "layerfault-stale-staging-{}-{}",
            std::process::id(),
            crate::paths::now_unix()
        ));
        fs::create_dir_all(&base)?;
        let now = crate::paths::now_unix();

        let mut child = std::process::Command::new("true").spawn()?;
        let dead_pid = child.id();
        child.wait()?;

        // Orphaned: past the grace period, owning process is confirmed dead.
        let dead_owner = base.join(format!("{}-{dead_pid}-deadbeef-0", now - 3600));
        fs::create_dir_all(&dead_owner)?;

        // Still in use: past the grace period, but owned by this live test process.
        let live_owner = base.join(format!("{}-{}-deadbeef-0", now - 3600, std::process::id()));
        fs::create_dir_all(&live_owner)?;

        // Not yet eligible: owner is dead, but the directory is still within
        // the grace period (could be a live process whose pid we mis-parsed).
        let fresh_dead_owner = base.join(format!("{now}-{dead_pid}-deadbeef-0"));
        fs::create_dir_all(&fresh_dead_owner)?;

        let stale = stale_staging_dirs(&base);
        assert!(stale.contains(&dead_owner));
        assert!(!stale.contains(&live_owner));
        assert!(!stale.contains(&fresh_dead_owner));

        fs::remove_dir_all(&base)?;
        Ok(())
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn staging_orphaned_by_a_killed_process_is_reclaimed_by_the_next_stage_call() -> Result<()> {
        let base = std::env::temp_dir().join(format!(
            "layerfault-staging-sweep-{}-{}",
            std::process::id(),
            crate::paths::now_unix()
        ));
        let parent = base.join("staging");
        fs::create_dir_all(&parent)?;

        let mut child = std::process::Command::new("true").spawn()?;
        let dead_pid = child.id();
        child.wait()?;

        // Simulate what a killed prior invocation leaves behind: a fully
        // formed staging entry whose owning process no longer exists, old
        // enough to clear the grace period.
        let orphan = parent.join(format!(
            "{}-{dead_pid}-deadbeef-0",
            crate::paths::now_unix() - 3600
        ));
        fs::create_dir_all(&orphan)?;
        fs::write(orphan.join("leaked.bin"), b"orphaned staged copy")?;

        let source = base.join("source.gguf");
        fs::write(&source, b"verified artifact content")?;
        let digest = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(b"verified artifact content"))
        );
        let staged = stage_verified_under(&source, &digest, &parent, false)?;

        assert!(
            !orphan.exists(),
            "staging into the same parent must reclaim the dead process's orphaned copy"
        );

        staged.cleanup()?;
        let _ = fs::remove_dir_all(base);
        Ok(())
    }
}
