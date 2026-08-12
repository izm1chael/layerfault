use super::classify::classify;
use super::*;

pub fn fingerprint(root: &Path) -> Result<String> {
    Ok(fingerprint_report(root)?.fingerprint)
}

/// Compute package identity without running the deep security scanners. The
/// same no-follow hashing and race checks are retained, so callers that only
/// need a stable package identity no longer pay for duplicate content parsing.
pub fn fingerprint_report(root: &Path) -> Result<PackageFingerprintReport> {
    let metadata = std::fs::symlink_metadata(root)
        .with_context(|| format!("Unable to inspect package root '{}'", root.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(anyhow!("Package root '{}' is a symlink; supply the real package directory so identity boundaries are explicit", root.display()));
    }
    if !metadata.is_dir() {
        return Err(anyhow!("'{}' is not a directory", root.display()));
    }
    let root = root.canonicalize()?;
    let mut discovery = discover_package(&root)?;
    if let Some((rel, _)) = discovery.symlinks.first() {
        return Err(anyhow!(
            "Package contains symlink '{}'; fingerprint-only identity refuses ambiguous package members",
            rel
        ));
    }
    discovery
        .paths
        .sort_by_key(|path| safe_relative(&root, path).unwrap_or_default());
    let mut files = Vec::new();
    let mut total_bytes = 0_u64;
    for path in discovery.paths {
        let rel = safe_relative(&root, &path)?;
        let file = open_readonly_nofollow(&path)?;
        let size = file.metadata()?.len();
        let hash = crate::hashcache::sha256_prefixed(&path, &file)?;
        if !crate::hashcache::identity_unchanged(&path, &file, &hash.identity)? {
            return Err(anyhow!(
                "Package file '{}' changed while its fingerprint was being computed",
                rel
            ));
        }
        total_bytes = checked_package_total(total_bytes, size)?;
        files.push(PackageEntry {
            relative_path: rel,
            kind: classify(&path).to_owned(),
            size,
            sha256: Some(hash.sha256),
            digest_cache: Some(if hash.cache_hit {
                "HIT".to_owned()
            } else if crate::hashcache::digest_eligible(size) {
                "MISS".to_owned()
            } else {
                "BYPASS_SMALL".to_owned()
            }),
        });
    }
    let fingerprint = package_fingerprint(&files);
    let (merkle_identity, merkle_manifest) = compute_merkle_tree(&files, None);
    Ok(PackageFingerprintReport {
        root: root.display().to_string(),
        fingerprint,
        merkle_identity,
        files,
        merkle_manifest,
        total_bytes,
    })
}

pub(super) fn package_fingerprint(files: &[PackageEntry]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"layerfault-package-identity\0");
    for entry in files {
        hasher.update(entry.relative_path.as_bytes());
        hasher.update([0]);
        hasher.update(entry.kind.as_bytes());
        hasher.update([0]);
        hasher.update(entry.size.to_string().as_bytes());
        hasher.update([0]);
        hasher.update(entry.sha256.as_deref().unwrap_or("missing").as_bytes());
        hasher.update([0xff]);
    }
    format!("lfpkg:sha256:{}", hex::encode(hasher.finalize()))
}

pub fn compute_merkle_leaf(path: &str, sha256: &str, size: u64, kind: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"layerfault-merkle-leaf-v1\0");
    hasher.update(path.as_bytes());
    hasher.update([0]);
    hasher.update(sha256.as_bytes());
    hasher.update([0]);
    hasher.update(size.to_string().as_bytes());
    hasher.update([0]);
    hasher.update(kind.as_bytes());
    hasher.update([0]);
    hex::encode(hasher.finalize())
}

pub fn compute_merkle_tree(
    files: &[PackageEntry],
    previous_manifest: Option<&[PackageMerkleLeaf]>,
) -> (String, Vec<PackageMerkleLeaf>) {
    let mut leaves = Vec::with_capacity(files.len());

    let prev_map: std::collections::BTreeMap<&str, &PackageMerkleLeaf> = previous_manifest
        .map(|manifest| {
            manifest
                .iter()
                .map(|entry| (entry.path.as_str(), entry))
                .collect()
        })
        .unwrap_or_default();

    for entry in files {
        let sha256_str = entry.sha256.as_deref().unwrap_or("missing");
        let leaf_hash = if let Some(prev) = prev_map.get(entry.relative_path.as_str()) {
            if prev.sha256 == sha256_str && prev.size == entry.size {
                prev.leaf_hash.clone()
            } else {
                compute_merkle_leaf(&entry.relative_path, sha256_str, entry.size, &entry.kind)
            }
        } else {
            compute_merkle_leaf(&entry.relative_path, sha256_str, entry.size, &entry.kind)
        };

        leaves.push(PackageMerkleLeaf {
            path: entry.relative_path.clone(),
            sha256: sha256_str.to_owned(),
            size: entry.size,
            leaf_hash,
        });
    }

    leaves.sort_by(|a, b| a.path.cmp(&b.path));

    let mut dir_nodes: std::collections::BTreeMap<
        String,
        std::collections::BTreeMap<String, String>,
    > = std::collections::BTreeMap::new();
    dir_nodes.entry(String::new()).or_default();

    for leaf in &leaves {
        let (parent_str, file_name) = match leaf.path.rfind('/') {
            Some(idx) => (&leaf.path[..idx], &leaf.path[idx + 1..]),
            None => ("", leaf.path.as_str()),
        };

        dir_nodes
            .entry(parent_str.to_owned())
            .or_default()
            .insert(file_name.to_owned(), leaf.leaf_hash.clone());

        let mut curr = parent_str;
        while !curr.is_empty() {
            dir_nodes.entry(curr.to_owned()).or_default();
            curr = match curr.rfind('/') {
                Some(idx) => &curr[..idx],
                None => "",
            };
        }
    }

    let mut dir_paths: Vec<String> = dir_nodes.keys().cloned().collect();
    dir_paths.sort_by_key(|p| (std::cmp::Reverse(p.len()), p.clone()));

    let mut root_node_hash = String::new();

    for dir_path in dir_paths {
        let children = dir_nodes.remove(&dir_path).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(b"layerfault-merkle-node-v1\0");
        for (child_name, child_hash) in &children {
            hasher.update(child_name.as_bytes());
            hasher.update([0]);
            hasher.update(child_hash.as_bytes());
            hasher.update([0]);
        }
        let node_hash = hex::encode(hasher.finalize());

        if dir_path.is_empty() {
            root_node_hash = node_hash;
        } else {
            let (parent_dir, dir_name) = match dir_path.rfind('/') {
                Some(idx) => (&dir_path[..idx], &dir_path[idx + 1..]),
                None => ("", dir_path.as_str()),
            };
            dir_nodes
                .entry(parent_dir.to_owned())
                .or_default()
                .insert(dir_name.to_owned(), node_hash);
        }
    }

    let merkle_identity = format!("lfpkg:v2:sha256:{root_node_hash}");
    (merkle_identity, leaves)
}
