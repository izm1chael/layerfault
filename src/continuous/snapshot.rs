use super::{EvidenceDomain, EvidenceRecord, ExecutionSnapshot, SecurityComponent, TrustState};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

const MAX_SNAPSHOT_BYTES: u64 = 64 * 1024 * 1024;

pub fn new(state: TrustState) -> ExecutionSnapshot {
    ExecutionSnapshot {
        version: 2,
        captured_unix: crate::paths::now_unix(),
        state,
        identities: BTreeMap::new(),
        evidence: BTreeMap::new(),
    }
}

pub fn set_identity(
    snapshot: &mut ExecutionSnapshot,
    component: SecurityComponent,
    identity: impl Into<String>,
) {
    snapshot.identities.insert(component, identity.into());
}

pub fn record_evidence(
    snapshot: &mut ExecutionSnapshot,
    domain: EvidenceDomain,
    identity: impl Into<String>,
    dependencies: Option<Vec<SecurityComponent>>,
) {
    snapshot.evidence.insert(
        domain,
        EvidenceRecord {
            identity: identity.into(),
            generated_unix: crate::paths::now_unix(),
            dependencies: dependencies
                .unwrap_or_else(|| super::default_dependencies(domain).to_vec()),
            stale: false,
            stale_reason: None,
        },
    );
}

pub fn canonical_bytes(snapshot: &ExecutionSnapshot) -> Result<Vec<u8>> {
    validate(snapshot)?;
    Ok(serde_json::to_vec(snapshot)?)
}

pub fn identity(snapshot: &ExecutionSnapshot) -> Result<String> {
    let mut clone = snapshot.clone();
    clone.captured_unix = 0;
    let mut hasher = Sha256::new();
    hasher.update(b"layerfault:execution-snapshot:v1\0");
    hasher.update(canonical_bytes(&clone)?);
    Ok(format!(
        "lfexecution:v1:sha256:{}",
        hex::encode(hasher.finalize())
    ))
}

pub fn load(path: &Path) -> Result<ExecutionSnapshot> {
    let file = crate::safeio::open_readonly_nofollow(path)?;
    let bytes = crate::safeio::read_all_from_file(&file, MAX_SNAPSHOT_BYTES)?;
    let snapshot: ExecutionSnapshot = serde_json::from_slice(&bytes)
        .with_context(|| format!("execution snapshot '{}' is invalid JSON", path.display()))?;
    validate(&snapshot)?;
    Ok(snapshot)
}

pub fn save(path: &Path, snapshot: &ExecutionSnapshot) -> Result<()> {
    validate(snapshot)?;
    let bytes = serde_json::to_vec_pretty(snapshot)?;
    if bytes.len() as u64 > MAX_SNAPSHOT_BYTES {
        bail!("execution snapshot exceeds the 64 MiB safety limit");
    }
    crate::paths::write_private(path, &bytes)
}

fn validate(snapshot: &ExecutionSnapshot) -> Result<()> {
    if !matches!(snapshot.version, 1 | 2) {
        bail!(
            "unsupported execution snapshot version {} (this build produces version 2 and reads versions 1-2)",
            snapshot.version
        );
    }
    if snapshot.identities.len() > 1024 || snapshot.evidence.len() > 128 {
        bail!("execution snapshot exceeds structural safety limits");
    }
    if snapshot
        .identities
        .values()
        .any(|value| value.is_empty() || value.len() > 64 * 1024)
    {
        bail!("execution snapshot contains an invalid identity value");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_one_snapshot_with_aggregate_environment_remains_loadable() {
        let snapshot: ExecutionSnapshot = serde_json::from_value(serde_json::json!({
            "version": 1,
            "captured_unix": 1,
            "state": "approved",
            "identities": {"behaviour_environment": "legacy-environment"},
            "evidence": {}
        }))
        .expect("version-1 snapshot must deserialize");

        validate(&snapshot).expect("version-1 snapshot must remain supported");
        assert_eq!(
            snapshot
                .identities
                .get(&SecurityComponent::BehaviourEnvironment)
                .map(String::as_str),
            Some("legacy-environment")
        );
    }
}
