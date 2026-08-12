use super::types::{BindingKind, BindingRecord, StagedArtifact, StagedPackage};
use crate::safeio::open_readonly_nofollow;
use anyhow::{anyhow, bail, Result};
use sha2::{Digest, Sha256};
use std::io::Read;

impl StagedArtifact {
    pub fn revalidate(&self) -> Result<()> {
        let expected =
            self.record.sha256.as_deref().ok_or_else(|| {
                anyhow!("Staged artifact has no recorded digest for revalidation")
            })?;
        let mut file = open_readonly_nofollow(&self.path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 1024 * 1024];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        let observed = format!("sha256:{}", hex::encode(hasher.finalize()));
        if !observed.eq_ignore_ascii_case(expected) {
            bail!(
                "Staged artifact digest changed before launch: expected {}, observed {}",
                expected,
                observed
            );
        }
        Ok(())
    }
}

impl StagedPackage {
    pub fn revalidate(&self) -> Result<()> {
        let current = crate::package::fingerprint(&self.path)?;
        if current != self.staged_fingerprint {
            bail!(
                "Staged package fingerprint changed before launch: expected {}, observed {}",
                self.staged_fingerprint,
                current
            );
        }
        Ok(())
    }
}

pub fn revalidated(
    original: impl Into<String>,
    sha256: Option<String>,
    detail: impl Into<String>,
) -> BindingRecord {
    BindingRecord {
        kind: BindingKind::RuntimeStoreRevalidated,
        original: original.into(),
        runtime_path: None,
        sha256,
        detail: detail.into(),
        manifest: None,
    }
}

pub fn path_revalidated(
    original: impl Into<String>,
    sha256: Option<String>,
    detail: impl Into<String>,
) -> BindingRecord {
    BindingRecord {
        kind: BindingKind::PathRevalidated,
        original: original.into(),
        runtime_path: None,
        sha256,
        detail: detail.into(),
        manifest: None,
    }
}

pub fn best_effort(original: impl Into<String>, detail: impl Into<String>) -> BindingRecord {
    BindingRecord {
        kind: BindingKind::None,
        original: original.into(),
        runtime_path: None,
        sha256: None,
        detail: detail.into(),
        manifest: None,
    }
}
