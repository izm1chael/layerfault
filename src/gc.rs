use crate::{audit, baseline::Baseline};
use anyhow::{anyhow, Context, Result};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, serde::Serialize)]
pub struct GcCandidate {
    pub digest: String,
    pub path: String,
    pub bytes: u64,
    pub protected_by_baseline: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct GcPlan {
    pub candidates: Vec<GcCandidate>,
    pub recoverable_bytes: u64,
    pub protected_orphans: Vec<String>,
}

pub fn plan(base_dir: &Path) -> Result<GcPlan> {
    let audit = audit::audit_store(base_dir)?;
    if audit.invalid_model_count > 0 {
        // A manifest that failed to parse could reference blobs we have no
        // way to see. Treating its descriptors as absent would make those
        // blobs look orphaned and eligible for deletion, so refuse to plan
        // at all rather than risk destroying data a broken-but-legitimate
        // manifest still points at.
        let broken = audit
            .models
            .iter()
            .filter(|model| !model.valid)
            .map(|model| model.model.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(anyhow!(
            "Refusing to plan garbage collection: {} manifest(s) could not be parsed ({broken}); \
             their referenced blobs cannot be confirmed and would be misidentified as orphaned",
            audit.invalid_model_count
        ));
    }
    let protected = baseline_descriptors()?;
    let mut candidates = Vec::new();
    let mut protected_orphans = Vec::new();
    for digest in audit.orphaned_blobs {
        if protected.contains(&digest) {
            protected_orphans.push(digest);
            continue;
        }
        let path = base_dir.join("blobs").join(digest.replace(':', "-"));
        let bytes = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        candidates.push(GcCandidate {
            digest,
            path: path.display().to_string(),
            bytes,
            protected_by_baseline: false,
        });
    }
    let recoverable_bytes = candidates.iter().map(|entry| entry.bytes).sum();
    Ok(GcPlan {
        candidates,
        recoverable_bytes,
        protected_orphans,
    })
}

pub fn execute(base_dir: &Path, expected: &GcPlan) -> Result<u64> {
    let current = plan(base_dir)?;
    let expected_set = expected
        .candidates
        .iter()
        .map(|entry| &entry.digest)
        .collect::<BTreeSet<_>>();
    let current_set = current
        .candidates
        .iter()
        .map(|entry| &entry.digest)
        .collect::<BTreeSet<_>>();
    if expected_set != current_set {
        return Err(anyhow!(
            "Model store changed after GC planning; rerun the dry-run before deleting anything"
        ));
    }
    let mut deleted = 0_u64;
    let blobs_root = base_dir.join("blobs");
    for entry in current.candidates {
        let path = crate::manifest::resolve_blob_path(base_dir, &entry.digest)?;
        if path.parent() != Some(blobs_root.as_path()) {
            return Err(anyhow!("Refusing unsafe GC path '{}'", path.display()));
        }
        fs::remove_file(&path).with_context(|| format!("Unable to delete '{}'", path.display()))?;
        deleted = deleted.saturating_add(entry.bytes);
    }
    Ok(deleted)
}

fn baseline_descriptors() -> Result<BTreeSet<String>> {
    let mut protected = BTreeSet::new();
    let dir = crate::paths::config_dir()?.join("baselines");
    if !dir.is_dir() {
        return Ok(protected);
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        if let Ok(baseline) = Baseline::load(&entry.path()) {
            for model in baseline.models.values() {
                protected.extend(model.descriptors.iter().cloned());
            }
        }
    }
    Ok(protected)
}
