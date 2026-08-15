use super::{validate, IntelligencePack, MAX_PACK_BYTES};
use crate::safeio::{open_readonly_nofollow, read_all_from_file};
use anyhow::{Context, Result};
use std::path::Path;

const BUILTIN: &str = include_str!("../../intelligence/builtin-pack.json");

pub fn builtin_pack() -> Result<IntelligencePack> {
    parse_pack(BUILTIN.as_bytes())
}

pub fn load_pack(path: &Path) -> Result<(IntelligencePack, Vec<u8>)> {
    let file = open_readonly_nofollow(path)?;
    let bytes = read_all_from_file(&file, MAX_PACK_BYTES)?;
    let pack = parse_pack(&bytes)?;
    Ok((pack, bytes))
}

pub fn parse_pack(bytes: &[u8]) -> Result<IntelligencePack> {
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_PACK_BYTES {
        anyhow::bail!("intelligence pack exceeds {MAX_PACK_BYTES} bytes");
    }
    let pack: IntelligencePack =
        serde_json::from_slice(bytes).context("Layerfault intelligence pack is not valid JSON")?;
    validate(&pack)?;
    Ok(pack)
}

pub fn advisory_database(pack: &IntelligencePack) -> crate::advisory::AdvisoryDatabase {
    crate::advisory::AdvisoryDatabase {
        version: 1,
        generated_unix: pack.generated_unix,
        advisories: pack.runtime_advisories.clone(),
    }
}
