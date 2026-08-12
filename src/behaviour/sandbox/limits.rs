use anyhow::{bail, Context, Result};
use std::fs::File;
use std::path::{Path, PathBuf};

const MIN_ADDRESS_SPACE_LIMIT_MB: u64 = 512;
const MAX_ADDRESS_SPACE_LIMIT_MB: u64 = 256 * 1024;
const ACTIVE_MODEL_ENTRY_LIMIT: usize = 100_000;

pub(crate) fn configured_memory_budget_bytes() -> u64 {
    crate::doctor::recommended_active_memory_budget_bytes()
        .unwrap_or(4 * 1024 * 1024 * 1024)
        .clamp(
            MIN_ADDRESS_SPACE_LIMIT_MB * 1024 * 1024,
            MAX_ADDRESS_SPACE_LIMIT_MB * 1024 * 1024,
        )
}

pub(super) fn configured_address_space_limit_bytes() -> u64 {
    address_space_limit_bytes(
        configured_memory_budget_bytes(),
        std::env::var("LAYERFAULT_BEHAVIOUR_ADDRESS_SPACE_MB")
            .ok()
            .as_deref(),
    )
}

fn address_space_limit_bytes(memory_budget: u64, hard_override_mb: Option<&str>) -> u64 {
    if let Some(mb) = hard_override_mb.and_then(|value| value.parse::<u64>().ok()) {
        return mb
            .clamp(MIN_ADDRESS_SPACE_LIMIT_MB, MAX_ADDRESS_SPACE_LIMIT_MB)
            .saturating_mul(1024 * 1024);
    }
    // RLIMIT_AS constrains virtual address space, not resident memory. Keep it
    // above the conservative physical-memory admission budget so runtimes such
    // as PyTorch can map shared libraries/arenas without being rejected purely
    // because of virtual mappings, while still bounding runaway allocation.
    let expanded = (memory_budget.saturating_mul(3) / 2).saturating_add(512 * 1024 * 1024);
    expanded.clamp(
        MIN_ADDRESS_SPACE_LIMIT_MB * 1024 * 1024,
        MAX_ADDRESS_SPACE_LIMIT_MB * 1024 * 1024,
    )
}

pub(super) fn active_target_bytes(path: &Path) -> Result<u64> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("unable to inspect active target '{}'", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("active target may not be a symlink");
    }
    if metadata.is_file() {
        return Ok(metadata.len());
    }
    if !metadata.is_dir() {
        bail!("active target must be a regular file or directory");
    }
    let mut total = 0_u64;
    let mut entries = 0_usize;
    for entry in walkdir::WalkDir::new(path).follow_links(false) {
        let entry = entry.with_context(|| format!("unable to enumerate '{}'", path.display()))?;
        entries = entries.saturating_add(1);
        if entries > ACTIVE_MODEL_ENTRY_LIMIT {
            bail!(
                "active target contains too many filesystem entries for bounded memory preflight"
            );
        }
        if entry.file_type().is_symlink() {
            bail!(
                "active target contains symlink '{}', which is not allowed",
                entry.path().display()
            );
        }
        let metadata = entry.metadata()?;
        if metadata.is_file() {
            total = total.saturating_add(metadata.len());
        }
    }
    Ok(total)
}

#[cfg(unix)]
pub(super) fn pinned_active_target_bytes(file: &File, display_path: &Path) -> Result<u64> {
    use std::os::fd::AsRawFd;

    let metadata = file.metadata().with_context(|| {
        format!(
            "unable to inspect active target '{}'",
            display_path.display()
        )
    })?;
    if metadata.is_file() {
        return Ok(metadata.len());
    }
    if !metadata.is_dir() {
        bail!("active target must be a regular file or directory");
    }
    let descriptor_path = PathBuf::from(format!("/proc/self/fd/{}/.", file.as_raw_fd()));
    active_target_bytes(&descriptor_path)
}

#[cfg(not(unix))]
pub(super) fn pinned_active_target_bytes(_file: &File, _display_path: &Path) -> Result<u64> {
    bail!("descriptor-pinned behavioural sandbox inputs require Unix")
}

fn estimated_runtime_memory_bytes(
    runtime: &Path,
    model: &File,
    model_path: &Path,
    base: Option<(&File, &Path)>,
) -> Result<u64> {
    let model_bytes = pinned_active_target_bytes(model, model_path)?;
    let base_bytes = base
        .map(|(file, path)| pinned_active_target_bytes(file, path))
        .transpose()?
        .unwrap_or(0);
    let weights = model_bytes.saturating_add(base_bytes);
    let runtime_name = runtime
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let (numerator, denominator, overhead) = if runtime_name.contains("python") {
        // Transformers frequently materializes weights plus allocator/runtime
        // state beyond the serialized file size. Stay conservative on small
        // CPU-only hosts: a skipped active run is safer than host OOM.
        (2_u64, 1_u64, 1024_u64 * 1024 * 1024)
    } else {
        (5_u64, 4_u64, 768_u64 * 1024 * 1024)
    };
    Ok((weights.saturating_mul(numerator) / denominator).saturating_add(overhead))
}

pub(super) fn ensure_active_target_fits(
    runtime: &Path,
    model: &File,
    model_path: &Path,
    base: Option<(&File, &Path)>,
) -> Result<()> {
    let budget = configured_memory_budget_bytes();
    let estimate = estimated_runtime_memory_bytes(runtime, model, model_path, base)?;
    if estimate > budget {
        bail!(
            "active analysis skipped: estimated runtime memory {:.1} GiB exceeds safe host budget {:.1} GiB; static analysis remains available (override with LAYERFAULT_BEHAVIOUR_MEMORY_MB only when the host can safely support it)",
            estimate as f64 / 1073741824.0,
            budget as f64 / 1073741824.0
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_space_limit_uses_admission_budget_unless_hard_overridden() {
        let gib = 1024_u64 * 1024 * 1024;
        assert_eq!(address_space_limit_bytes(4 * gib, None), 6 * gib + gib / 2);
        assert_eq!(address_space_limit_bytes(4 * gib, Some("2048")), 2 * gib);
        assert_eq!(
            address_space_limit_bytes(4 * gib, Some("not-a-number")),
            6 * gib + gib / 2
        );
    }

    #[cfg(unix)]
    #[test]
    fn active_target_preflight_rejects_nested_symlinks() -> Result<()> {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir()?;
        let outside = tempfile::NamedTempFile::new()?;
        symlink(outside.path(), root.path().join("weights.bin"))?;
        let error = active_target_bytes(root.path()).unwrap_err();
        assert!(error.to_string().contains("contains symlink"));
        let pinned = super::super::command::pin_active_path(root.path())?;
        let error = pinned_active_target_bytes(&pinned, root.path()).unwrap_err();
        assert!(error.to_string().contains("contains symlink"));
        Ok(())
    }
}
