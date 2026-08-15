//! Signed, data-only security intelligence used by Layerfault admission.

mod bundle;
#[allow(dead_code)]
mod findings;
mod load;
mod mapping;
mod security;
mod signature;
mod state;
mod types;
mod validate;

pub use bundle::{export_bundle, import_bundle, verify_bundle, OfflineIntelligenceBundle};
pub use load::{advisory_database, builtin_pack, load_pack, parse_pack};
pub use mapping::mapping_for_rule;
pub use security::{assess_subjects, IntelligenceSubjects};
pub use signature::{load_verified, verify_detached, VerifiedIntelligencePack};
pub use state::{enforce_no_rollback, freshness, record_accepted};
pub use types::{
    AdapterIndicatorRecord, BuilderRecord, DeclarativeEdgeRecord, DeclarativeSinkKind,
    IntelligenceChannel, IntelligenceDisposition, IntelligenceFreshness, IntelligencePack,
    KnownIdentityRecord, PickleGadgetCapability, PickleGadgetRecord, RevocationRecord,
    RevocationTarget, ThreatMapping, ThreatMappingRecord,
};
pub use validate::{
    validate, MAX_MAPPINGS_PER_RECORD, MAX_PACK_BYTES, MAX_RECORDS_PER_SECTION, MAX_STRING_BYTES,
};

pub fn epoch(pack: &IntelligencePack) -> u64 {
    pack.epoch.unwrap_or(pack.sequence)
}

pub fn revocation_for<'a>(
    pack: &'a IntelligencePack,
    target: RevocationTarget,
    value: &str,
) -> Option<&'a RevocationRecord> {
    pack.revocations
        .iter()
        .find(|record| record.target == target && record.value.eq_ignore_ascii_case(value))
}

pub fn adapter_indicator<'a>(
    pack: &'a IntelligencePack,
    sha256: &str,
) -> Option<&'a AdapterIndicatorRecord> {
    let normalized = sha256.strip_prefix("sha256:").unwrap_or(sha256);
    pack.adapter_indicators.iter().find(|record| {
        record
            .sha256
            .strip_prefix("sha256:")
            .unwrap_or(record.sha256.as_str())
            .eq_ignore_ascii_case(normalized)
    })
}

pub fn pack_identity(pack: &IntelligencePack) -> anyhow::Result<String> {
    use sha2::{Digest, Sha256};
    validate(pack)?;
    let mut hasher = Sha256::new();
    hasher.update(b"layerfault:intelligence-pack:v1\0");
    hasher.update(serde_json::to_vec(pack)?);
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}
