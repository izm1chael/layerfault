use super::executable::infer_quantization;
use super::*;
pub fn hf_cache_root(override_path: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = override_path {
        return Ok(path.to_path_buf());
    }
    if let Ok(value) = std::env::var("HF_HUB_CACHE") {
        if !value.trim().is_empty() {
            return Ok(PathBuf::from(value));
        }
    }
    if let Ok(value) = std::env::var("HF_HOME") {
        if !value.trim().is_empty() {
            return Ok(PathBuf::from(value).join("hub"));
        }
    }
    let home = std::env::var("HOME")
        .map_err(|_| anyhow!("Cannot determine Hugging Face cache root; set HF_HUB_CACHE"))?;
    Ok(PathBuf::from(home).join(".cache/huggingface/hub"))
}

pub fn audit_hf_cache(override_path: Option<&Path>) -> Result<Vec<HfRepoAudit>> {
    let root = hf_cache_root(override_path)?;
    if !root.is_dir() {
        return Err(anyhow!(
            "Hugging Face cache '{}' does not exist",
            root.display()
        ));
    }
    let mut reports = Vec::new();
    let entries =
        fs::read_dir(&root).with_context(|| format!("Unable to read '{}'", root.display()))?; // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with("models--") {
            continue;
        }
        reports.push(audit_hf_repo(&entry.path(), &name)?);
    }
    reports.sort_by(|a, b| a.repository.cmp(&b.repository));
    Ok(reports)
}

fn audit_hf_repo(root: &Path, folder_name: &str) -> Result<HfRepoAudit> {
    let repository = folder_name
        .strip_prefix("models--")
        .unwrap_or(folder_name)
        .replace("--", "/");
    let refs_root = root.join("refs");
    let snapshots_root = root.join("snapshots");
    let blobs_root = root.join("blobs");
    let mut refs = BTreeMap::new();
    if refs_root.is_dir() {
        for entry in WalkDir::new(&refs_root).follow_links(false) {
            let entry = entry?;
            if entry.file_type().is_file() {
                let value = fs::read_to_string(entry.path())
                    .unwrap_or_default()
                    .trim()
                    .to_owned();
                let rel = entry
                    .path()
                    .strip_prefix(&refs_root)
                    .unwrap_or(entry.path())
                    .display()
                    .to_string();
                refs.insert(rel, value);
            }
        }
    }
    let referenced_snapshots = refs.values().cloned().collect::<BTreeSet<_>>();
    let mut snapshots = Vec::new();
    let mut invalid_links = Vec::new();
    let mut artifacts = Vec::new();
    let mut package_findings = Vec::new();
    let mut package_cache =
        BTreeMap::<(PathBuf, String), Vec<crate::scanner::LayerScanResult>>::new();
    let mut referenced_blobs = BTreeSet::<PathBuf>::new();
    if snapshots_root.is_dir() {
        let revisions = fs::read_dir(&snapshots_root)?; // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
        for revision in revisions {
            let revision = revision?;
            if !revision.file_type()?.is_dir() {
                continue;
            }
            let revision_name = revision.file_name().to_string_lossy().into_owned();
            snapshots.push(revision_name.clone());
            for entry in WalkDir::new(revision.path()).follow_links(false) {
                let entry = entry?;
                if !entry.file_type().is_symlink() {
                    continue;
                }
                let link_path = entry.path();
                let target = match fs::read_link(link_path) {
                    Ok(target) => target,
                    Err(error) => {
                        invalid_links.push(format!("{}: {error}", link_path.display()));
                        continue;
                    }
                };
                let resolved = if target.is_absolute() {
                    target
                } else {
                    link_path.parent().unwrap_or(root).join(target)
                };
                let canonical = match fs::canonicalize(&resolved) {
                    Ok(value) => value,
                    Err(error) => {
                        invalid_links.push(format!(
                            "{} -> {}: {error}",
                            link_path.display(),
                            resolved.display()
                        ));
                        continue;
                    }
                };
                let canonical_blobs =
                    fs::canonicalize(&blobs_root).unwrap_or_else(|_| blobs_root.clone());
                if !canonical.starts_with(&canonical_blobs) || !canonical.is_file() {
                    invalid_links.push(format!(
                        "{} -> {} escapes repository blobs",
                        link_path.display(),
                        canonical.display()
                    ));
                    continue;
                }
                referenced_blobs.insert(canonical.clone());
                let format = format_from_path(link_path);
                if format == ArtifactFormat::Unknown {
                    // Package scanning is path-role sensitive: the same content-addressed blob can be
                    // linked under different filenames/extensions inside snapshots. Cache only when
                    // both the blob and its presented role match.
                    let role = link_path
                        .file_name()
                        .and_then(|v| v.to_str())
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    let cache_key = (canonical.clone(), role);
                    if let Some(cached) = package_cache.get(&cache_key) {
                        package_findings.extend(cached.clone());
                    } else {
                        match crate::package::inspect_member(link_path, &canonical) {
                            Ok(findings) => {
                                package_cache.insert(cache_key, findings.clone());
                                package_findings.extend(findings);
                            }
                            Err(error) => invalid_links.push(format!(
                                "{} package scan failed safely: {error}",
                                link_path.display()
                            )),
                        }
                    }
                }
                if format == ArtifactFormat::SafetensorsIndex {
                    if let Err(error) = validate_hf_safetensors_index(
                        link_path,
                        &canonical,
                        &revision.path(),
                        &canonical_blobs,
                    ) {
                        invalid_links.push(format!("{}: {error}", link_path.display()));
                    }
                    continue;
                }
                if format != ArtifactFormat::Unknown {
                    let rel = link_path
                        .strip_prefix(revision.path())
                        .unwrap_or(link_path)
                        .display()
                        .to_string();
                    let identity = format!("hf://{repository}@{revision_name}/{rel}");
                    let size = fs::metadata(&canonical).map(|m| m.len()).unwrap_or(0);
                    artifacts.push(SourceArtifact {
                        source: SourceKind::HfCache,
                        identity,
                        path: canonical,
                        display_path: link_path.display().to_string(),
                        format,
                        size,
                        architecture: None,
                        quantization: infer_quantization(link_path),
                    });
                }
            }
        }
    }
    snapshots.sort();
    let snapshot_set = snapshots.iter().cloned().collect::<BTreeSet<_>>();
    let detached_snapshots = snapshot_set
        .difference(&referenced_snapshots)
        .cloned()
        .collect();
    let missing_ref_snapshots = referenced_snapshots
        .difference(&snapshot_set)
        .cloned()
        .collect();
    let mut orphaned_blobs = Vec::new();
    if blobs_root.is_dir() {
        let entries = fs::read_dir(&blobs_root)?; // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
        for entry in entries {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let canonical = fs::canonicalize(entry.path()).unwrap_or_else(|_| entry.path());
                if !referenced_blobs.contains(&canonical) {
                    orphaned_blobs.push(entry.file_name().to_string_lossy().into_owned());
                }
            }
        }
    }
    orphaned_blobs.sort();
    artifacts.sort_by(|a, b| a.identity.cmp(&b.identity));
    Ok(HfRepoAudit {
        repository,
        root: root.display().to_string(),
        refs,
        snapshots,
        detached_snapshots,
        missing_ref_snapshots,
        invalid_links,
        orphaned_blobs,
        artifacts,
        package_findings,
    })
}

fn validate_hf_safetensors_index(
    display_path: &Path,
    blob_path: &Path,
    snapshot_root: &Path,
    canonical_blobs: &Path,
) -> Result<()> {
    let file = crate::safeio::open_readonly_nofollow(blob_path)?;
    let bytes = crate::safeio::read_all_from_file(&file, 100 * 1024 * 1024)?;
    let map = crate::formats::safetensors::parse_index_weight_map(&bytes)?;
    if map.is_empty() || map.len() > 1_000_000 {
        return Err(anyhow!(
            "Safetensors weight_map is empty or exceeds the safety limit"
        ));
    }
    let mut shards = BTreeSet::new();
    for shard in map.values() {
        let relative = Path::new(shard); // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path -- constrained to relative Normal components before joining to the snapshot root
        if relative.is_absolute()
            || relative.as_os_str().is_empty()
            || relative
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return Err(anyhow!("unsafe Safetensors shard path '{shard}'"));
        }
        if !shard.to_ascii_lowercase().ends_with(".safetensors") {
            return Err(anyhow!(
                "Safetensors index references non-Safetensors shard '{shard}'"
            ));
        }
        shards.insert(shard.to_owned());
    }
    for shard in shards {
        let link = snapshot_root.join(&shard);
        let metadata = fs::symlink_metadata(&link).with_context(|| {
            format!(
                "index '{}' references missing shard '{shard}'",
                display_path.display()
            )
        })?;
        if !metadata.file_type().is_symlink() {
            return Err(anyhow!(
                "referenced shard '{shard}' is not a Hugging Face snapshot symlink"
            ));
        }
        let target = fs::read_link(&link)?; // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path -- link target is canonicalized and required to remain inside canonical_blobs before opening
        let resolved = if target.is_absolute() {
            target
        } else {
            link.parent().unwrap_or(snapshot_root).join(target)
        };
        let canonical = fs::canonicalize(&resolved)?;
        if !canonical.starts_with(canonical_blobs) || !canonical.is_file() {
            return Err(anyhow!(
                "referenced shard '{shard}' resolves outside repository blobs"
            ));
        }
        let shard_file = crate::safeio::open_readonly_nofollow(&canonical)?;
        crate::formats::safetensors::validate_file(&shard_file, shard_file.metadata()?.len())
            .with_context(|| format!("referenced shard '{shard}' is structurally invalid"))?;
    }
    Ok(())
}
