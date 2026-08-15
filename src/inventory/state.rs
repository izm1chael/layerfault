use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const MAX_STATE: u64 = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 250_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventoryState {
    pub version: u32,
    pub created_unix: u64,
    pub updated_unix: u64,
    pub entries: Vec<InventoryStateEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventoryStateEntry {
    pub key: String,
    pub source: String,
    pub identity: String,
    pub path: String,
    pub byte_sha256: Option<String>,
    pub package_identity: Option<String>,
    pub structural_identity: Option<String>,
    pub tokenizer_identity: Option<String>,
    pub size: u64,
    pub last_seen_unix: u64,
    pub approval: ApprovalState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalState {
    Unknown,
    Approved {
        receipt_path: String,
        receipt_sha256: String,
    },
    Stale {
        reason: String,
    },
    Blocked {
        reason: String,
    },
}

#[derive(Debug, Clone, Default)]
pub struct InventoryOptions {
    pub lmstudio: bool,
    pub hf_cache: bool,
    pub directories: Vec<PathBuf>,
    pub hf_root: Option<PathBuf>,
    pub structure_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventoryDelta {
    pub previous_updated_unix: u64,
    pub current_updated_unix: u64,
    pub added: Vec<InventoryStateEntry>,
    pub removed: Vec<InventoryStateEntry>,
    pub modified: Vec<ModifiedInventoryEntry>,
    pub approval_changes: Vec<ApprovalChange>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rule_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModifiedInventoryEntry {
    pub before: InventoryStateEntry,
    pub after: InventoryStateEntry,
    pub changes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalChange {
    pub key: String,
    pub before: ApprovalState,
    pub after: ApprovalState,
}

pub fn default_state_path() -> Result<PathBuf> {
    Ok(crate::paths::config_dir()?
        .join("inventory")
        .join("state-v1.json"))
}

pub fn stable_key(
    source: &str,
    identity: &str,
    byte: Option<&str>,
    package: Option<&str>,
    path: &str,
) -> String {
    let value = byte.or(package).map(str::to_owned).unwrap_or_else(|| {
        if !identity.is_empty() {
            format!("{source}\0{identity}")
        } else {
            format!("path\0{path}")
        }
    });
    let mut h = Sha256::new();
    h.update(b"layerfault:inventory-key:v1\0");
    h.update(value.as_bytes());
    format!("lfinv:v1:{}", hex::encode(h.finalize()))
}

pub fn snapshot(options: &InventoryOptions) -> Result<InventoryState> {
    let now = crate::paths::now_unix();
    let discovered = super::discover_non_ollama(
        options.lmstudio,
        options.hf_cache,
        &options.directories,
        options.hf_root.as_deref(),
    );
    let scanned = super::scan_artifacts(&discovered, options.structure_only);
    let mut entries = scanned
        .into_iter()
        .map(|entry| {
            let source = entry.source.as_str().to_owned();
            let key = stable_key(
                &source,
                &entry.identity,
                entry.sha256.as_deref(),
                None,
                &entry.path,
            );
            InventoryStateEntry {
                key,
                source,
                identity: entry.identity,
                path: entry.path,
                byte_sha256: entry.sha256,
                package_identity: None,
                structural_identity: None,
                tokenizer_identity: None,
                size: entry.size,
                last_seen_unix: now,
                approval: if entry.blocking {
                    ApprovalState::Blocked {
                        reason: "current Layerfault inventory scan contains blocking findings"
                            .into(),
                    }
                } else {
                    ApprovalState::Unknown
                },
            }
        })
        .collect::<Vec<_>>();
    if entries.len() > MAX_ENTRIES {
        bail!("inventory contains more than {MAX_ENTRIES} entries");
    }
    entries.sort_by(|a, b| a.key.cmp(&b.key).then(a.path.cmp(&b.path)));
    Ok(InventoryState {
        version: 1,
        created_unix: now,
        updated_unix: now,
        entries,
    })
}

pub fn load_state(path: &Path) -> Result<InventoryState> {
    let file = crate::safeio::open_readonly_nofollow(path)?;
    let bytes = crate::safeio::read_all_from_file(&file, MAX_STATE)?;
    let state: InventoryState = serde_json::from_slice(&bytes)
        .with_context(|| format!("inventory state '{}' is invalid JSON", path.display()))?;
    if state.version != 1 {
        bail!("unsupported inventory state version {}", state.version);
    }
    if state.entries.len() > MAX_ENTRIES {
        bail!("inventory state exceeds entry cap");
    }
    Ok(state)
}

pub fn save_state(path: &Path, state: &InventoryState) -> Result<()> {
    if state.version != 1 || state.entries.len() > MAX_ENTRIES {
        bail!("invalid inventory state");
    }
    let bytes = serde_json::to_vec_pretty(state)?;
    if bytes.len() as u64 > MAX_STATE {
        bail!("inventory state exceeds 64 MiB cap");
    }
    crate::paths::write_private(path, &bytes)
}

fn compare_entries(
    before: &InventoryStateEntry,
    after: &InventoryStateEntry,
) -> (Vec<String>, Option<ApprovalChange>) {
    let mut changes = Vec::new();
    if before.path != after.path {
        changes.push("path".into());
    }
    if before.byte_sha256 != after.byte_sha256 {
        changes.push("byte_identity".into());
    }
    if before.package_identity != after.package_identity {
        changes.push("package_identity".into());
    }
    if before.structural_identity != after.structural_identity {
        changes.push("structural_identity".into());
    }
    if before.tokenizer_identity != after.tokenizer_identity {
        changes.push("tokenizer_identity".into());
    }
    if before.size != after.size {
        changes.push("size".into());
    }
    let approval = if before.approval != after.approval {
        changes.push("approval".into());
        Some(ApprovalChange {
            key: before.key.clone(),
            before: before.approval.clone(),
            after: after.approval.clone(),
        })
    } else {
        None
    };
    (changes, approval)
}

/// Diff state by immutable identity first, then reconcile unmatched entries by
/// source+path. The fallback is what turns a byte mutation at a known local
/// model path into `modified` rather than a misleading remove+add pair.
pub fn diff_states(previous: &InventoryState, current: &InventoryState) -> InventoryDelta {
    let prev_by_key = previous
        .entries
        .iter()
        .map(|e| (e.key.as_str(), e))
        .collect::<BTreeMap<_, _>>();
    let curr_by_key = current
        .entries
        .iter()
        .map(|e| (e.key.as_str(), e))
        .collect::<BTreeMap<_, _>>();
    let mut matched_prev = BTreeSet::new();
    let mut matched_curr = BTreeSet::new();
    let mut modified = Vec::new();
    let mut approval_changes = Vec::new();

    for (key, before) in &prev_by_key {
        if let Some(after) = curr_by_key.get(key) {
            matched_prev.insert((*key).to_owned());
            matched_curr.insert((*key).to_owned());
            let (changes, approval) = compare_entries(before, after);
            if let Some(change) = approval {
                approval_changes.push(change);
            }
            if !changes.is_empty() {
                modified.push(ModifiedInventoryEntry {
                    before: (*before).clone(),
                    after: (**after).clone(),
                    changes,
                });
            }
        }
    }

    let current_by_location = current
        .entries
        .iter()
        .filter(|e| !matched_curr.contains(&e.key))
        .map(|e| ((e.source.as_str(), e.path.as_str()), e))
        .collect::<BTreeMap<_, _>>();
    let unmatched_previous = previous
        .entries
        .iter()
        .filter(|e| !matched_prev.contains(&e.key))
        .collect::<Vec<_>>();
    for before in unmatched_previous {
        if let Some(after) =
            current_by_location.get(&(before.source.as_str(), before.path.as_str()))
        {
            matched_prev.insert(before.key.clone());
            matched_curr.insert(after.key.clone());
            let (mut changes, approval) = compare_entries(before, after);
            if !changes.iter().any(|c| c == "identity_key") {
                changes.push("identity_key".into());
            }
            if let Some(change) = approval {
                approval_changes.push(change);
            }
            modified.push(ModifiedInventoryEntry {
                before: before.clone(),
                after: (**after).clone(),
                changes,
            });
        }
    }

    let added = current
        .entries
        .iter()
        .filter(|e| !matched_curr.contains(&e.key))
        .cloned()
        .collect::<Vec<_>>();
    let removed = previous
        .entries
        .iter()
        .filter(|e| !matched_prev.contains(&e.key))
        .cloned()
        .collect::<Vec<_>>();
    let mut rule_ids = Vec::new();
    if !added.is_empty() {
        rule_ids.push("LF-INVENTORY-NEW-UNAPPROVED".into());
    }
    if !modified.is_empty() {
        rule_ids.push("LF-INVENTORY-MODIFIED".into());
    }
    if approval_changes
        .iter()
        .any(|c| matches!(c.after, ApprovalState::Stale { .. }))
    {
        rule_ids.push("LF-INVENTORY-APPROVAL-STALE".into());
    }
    if current
        .entries
        .iter()
        .any(|e| matches!(e.approval, ApprovalState::Blocked { .. }))
    {
        rule_ids.push("LF-INVENTORY-PREVIOUSLY-BLOCKED".into());
    }

    InventoryDelta {
        previous_updated_unix: previous.updated_unix,
        current_updated_unix: current.updated_unix,
        added,
        removed,
        modified,
        approval_changes,
        rule_ids,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn entry(hash: &str) -> InventoryStateEntry {
        InventoryStateEntry {
            key: stable_key("file", hash, Some(hash), None, "/models/a.gguf"),
            source: "file".into(),
            identity: hash.into(),
            path: "/models/a.gguf".into(),
            byte_sha256: Some(hash.into()),
            package_identity: None,
            structural_identity: None,
            tokenizer_identity: None,
            size: 10,
            last_seen_unix: 1,
            approval: ApprovalState::Unknown,
        }
    }
    #[test]
    fn byte_change_at_same_path_is_modified() {
        let before = InventoryState {
            version: 1,
            created_unix: 1,
            updated_unix: 1,
            entries: vec![entry("sha256:aaa")],
        };
        let after = InventoryState {
            version: 1,
            created_unix: 1,
            updated_unix: 2,
            entries: vec![entry("sha256:bbb")],
        };
        let delta = diff_states(&before, &after);
        assert_eq!(delta.modified.len(), 1);
        assert!(delta.added.is_empty() && delta.removed.is_empty());
        assert!(delta.rule_ids.iter().any(|r| r == "LF-INVENTORY-MODIFIED"));
    }
}
