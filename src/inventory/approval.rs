use super::{ApprovalState, InventoryStateEntry};
use anyhow::{bail, Result};
use std::path::Path;
pub fn apply_receipt(
    entry: &mut InventoryStateEntry,
    receipt_path: &Path,
    trust_store: &crate::trust::TrustStore,
) -> Result<()> {
    let verification = crate::evidence::verify(receipt_path, Some(trust_store))?;
    if !verification.valid_signature
        || !verification.trusted
        || !verification.authorized_for_subject
    {
        bail!("receipt signature is not trusted/authorized for this inventory subject")
    }
    let envelope = crate::evidence::load(receipt_path)?;
    if envelope.payload.decision != "ALLOW" {
        bail!("receipt decision is not ALLOW")
    }
    let receipt = envelope
        .payload
        .admission_receipt
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("evidence has no admission receipt"))?;
    let expected = entry
        .byte_sha256
        .as_deref()
        .or(entry.package_identity.as_deref())
        .unwrap_or(&entry.identity);
    if normalize(&receipt.artifact_identity) != normalize(expected)
        && receipt.package_identity.as_deref().map(normalize) != Some(normalize(expected))
    {
        bail!("receipt artifact identity does not match inventory entry")
    };
    let digest = crate::safeio::sha256_path(receipt_path)?;
    entry.approval = ApprovalState::Approved {
        receipt_path: receipt_path.display().to_string(),
        receipt_sha256: digest,
    };
    Ok(())
}
pub fn refresh_staleness(entry: &mut InventoryStateEntry) -> Result<()> {
    let ApprovalState::Approved { receipt_path, .. } = entry.approval.clone() else {
        return Ok(());
    };
    let path = Path::new(&receipt_path);
    let envelope = match crate::evidence::load(path) {
        Ok(v) => v,
        Err(e) => {
            entry.approval = ApprovalState::Stale {
                reason: format!("receipt unavailable or invalid: {e}"),
            };
            return Ok(());
        }
    };
    let Some(receipt) = envelope.payload.admission_receipt else {
        entry.approval = ApprovalState::Stale {
            reason: "receipt context missing".into(),
        };
        return Ok(());
    };
    if receipt.ruleset_sha256 != crate::explain::ruleset_sha256() {
        entry.approval = ApprovalState::Stale {
            reason: "ruleset digest changed".into(),
        };
        return Ok(());
    }
    let expected = entry
        .byte_sha256
        .as_deref()
        .or(entry.package_identity.as_deref())
        .unwrap_or(&entry.identity);
    if normalize(&receipt.artifact_identity) != normalize(expected)
        && receipt.package_identity.as_deref().map(normalize) != Some(normalize(expected))
    {
        entry.approval = ApprovalState::Stale {
            reason: "artifact/package identity changed".into(),
        }
    }
    Ok(())
}
fn normalize(v: &str) -> String {
    let lower = v.trim().to_ascii_lowercase();
    lower.strip_prefix("sha256:").unwrap_or(&lower).to_owned()
}
