use super::*;

pub(super) struct PackageDiscovery {
    pub(super) paths: Vec<PathBuf>,
    pub(super) symlinks: Vec<(String, Option<PathBuf>)>,
}
pub(super) fn discover_package(root: &Path) -> Result<PackageDiscovery> {
    let mut paths = Vec::new();
    let mut symlinks = Vec::new();
    let mut entries = 0usize;
    let mut declared_bytes = 0u64;
    let mut walker = WalkDir::new(root).follow_links(false).into_iter();
    while let Some(entry) = walker.next() {
        let entry = entry?;
        if entry.depth() == 0 {
            continue;
        }
        if entry.depth() > MAX_PACKAGE_DEPTH {
            bail!(
                "Package entry '{}' exceeds maximum traversal depth {MAX_PACKAGE_DEPTH}",
                entry.path().display()
            );
        }
        let rel = safe_relative(root, entry.path())?;
        if ignored_path(&rel) {
            if entry.file_type().is_dir() {
                walker.skip_current_dir();
            }
            continue;
        }
        entries = entries.saturating_add(1);
        enforce_package_discovery_limits(entries, entry.depth(), rel.len(), declared_bytes)?;
        if entry.file_type().is_symlink() {
            symlinks.push((rel, std::fs::read_link(entry.path()).ok()));
            continue;
        }
        if entry.file_type().is_file() {
            declared_bytes = checked_package_total(declared_bytes, entry.metadata()?.len())?;
            paths.push(entry.into_path());
        }
    }
    Ok(PackageDiscovery { paths, symlinks })
}

pub(super) fn enforce_package_discovery_limits(
    entries: usize,
    depth: usize,
    path_bytes: usize,
    total_bytes: u64,
) -> Result<()> {
    if entries > MAX_PACKAGE_ENTRIES {
        bail!("Package exceeds maximum entry count {MAX_PACKAGE_ENTRIES}");
    }
    if depth > MAX_PACKAGE_DEPTH {
        bail!("Package exceeds maximum traversal depth {MAX_PACKAGE_DEPTH}");
    }
    if path_bytes > MAX_PACKAGE_PATH_BYTES {
        bail!("Package member path exceeds {MAX_PACKAGE_PATH_BYTES} bytes");
    }
    if total_bytes > MAX_PACKAGE_TOTAL_BYTES {
        bail!("Package exceeds maximum aggregate size {MAX_PACKAGE_TOTAL_BYTES} bytes");
    }
    Ok(())
}

pub(super) fn checked_package_total(current: u64, next: u64) -> Result<u64> {
    let total = current
        .checked_add(next)
        .ok_or_else(|| anyhow!("Package aggregate size overflow"))?;
    enforce_package_discovery_limits(0, 0, 0, total)?;
    Ok(total)
}

pub(super) fn ignored_path(rel: &str) -> bool {
    rel.split('/').any(|part| {
        matches!(
            part,
            ".git" | "target" | "__pycache__" | ".cache" | ".venv" | "venv"
        ) || part.starts_with(".layerfault")
            || part.starts_with(".tmp-")
            || part.contains(".tmp-")
    })
}

pub(super) fn safe_relative(root: &Path, path: &Path) -> Result<String> {
    let rel = path
        .strip_prefix(root)
        .with_context(|| format!("'{}' escaped package root", path.display()))?;
    let mut out = Vec::new();
    for component in rel.components() {
        match component {
            Component::Normal(value) => {
                let value = value.to_str().ok_or_else(|| anyhow!("Package-relative path contains non-UTF-8 component; canonical package identities require portable UTF-8 member names"))?;
                out.push(value.to_owned());
            }
            _ => return Err(anyhow!("Unsafe package-relative path '{}'", rel.display())),
        }
    }
    Ok(out.join("/"))
}
