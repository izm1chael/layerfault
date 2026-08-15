use super::{IntelligenceFreshness, IntelligencePack, VerifiedIntelligencePack};
use crate::paths;
use crate::safeio::{open_readonly_nofollow, read_all_from_file};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

const MAX_STATE_BYTES: u64 = 64 * 1024;
const NINETY_DAYS: u64 = 90 * 24 * 60 * 60;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IntelligenceState {
    version: u32,
    highest_sequence: u64,
    pack_sha256: String,
    signer_sha256: String,
    accepted_unix: u64,
}

fn state_path() -> Result<PathBuf> {
    Ok(paths::cache_dir()?.join("intelligence").join("state.json"))
}

fn load_state() -> Result<Option<IntelligenceState>> {
    let path = state_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let file = open_readonly_nofollow(&path)?;
    let bytes = read_all_from_file(&file, MAX_STATE_BYTES)?;
    let state: IntelligenceState = serde_json::from_slice(&bytes)
        .with_context(|| format!("intelligence state '{}' is invalid", path.display()))?;
    if state.version != 1 {
        bail!("unsupported intelligence state version {}", state.version);
    }
    Ok(Some(state))
}

pub fn enforce_no_rollback(
    verified: &VerifiedIntelligencePack,
    allow_rollback: bool,
) -> Result<()> {
    let Some(state) = load_state()? else {
        return Ok(());
    };
    if !state
        .signer_sha256
        .eq_ignore_ascii_case(&verified.signer_sha256)
    {
        bail!(
            "intelligence signer changed from {} to {}; explicit signer migration is required",
            state.signer_sha256,
            verified.signer_sha256
        );
    }
    if verified.pack.sequence < state.highest_sequence && !allow_rollback {
        bail!(
            "intelligence sequence rollback rejected: {} < {}",
            verified.pack.sequence,
            state.highest_sequence
        );
    }
    if verified.pack.sequence == state.highest_sequence
        && !verified.sha256.eq_ignore_ascii_case(&state.pack_sha256)
    {
        bail!(
            "intelligence sequence {} was previously accepted with a different digest",
            verified.pack.sequence
        );
    }
    Ok(())
}

pub fn record_accepted(verified: &VerifiedIntelligencePack) -> Result<()> {
    if let Some(state) = load_state()? {
        if !state
            .signer_sha256
            .eq_ignore_ascii_case(&verified.signer_sha256)
        {
            bail!("refusing to replace intelligence rollback state with a different signer");
        }
    }
    let state = IntelligenceState {
        version: 1,
        highest_sequence: verified.pack.sequence,
        pack_sha256: verified.sha256.clone(),
        signer_sha256: verified.signer_sha256.clone(),
        accepted_unix: paths::now_unix(),
    };
    let bytes = serde_json::to_vec_pretty(&state)?;
    paths::write_private(&state_path()?, &bytes)
}

pub fn freshness(pack: &IntelligencePack, now_unix: u64) -> IntelligenceFreshness {
    if pack.expires_unix.is_some_and(|expires| expires < now_unix) {
        IntelligenceFreshness::Expired
    } else if pack.expires_unix.is_none()
        && now_unix.saturating_sub(pack.generated_unix) > NINETY_DAYS
    {
        IntelligenceFreshness::Stale
    } else {
        IntelligenceFreshness::Current
    }
}
