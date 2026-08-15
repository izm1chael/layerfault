//! Signed, data-only security intelligence used by Layerfault admission.

#[allow(dead_code)]
mod findings;
mod load;
mod mapping;
mod signature;
mod state;
mod types;
mod validate;

pub use load::{advisory_database, builtin_pack, load_pack, parse_pack};
pub use mapping::mapping_for_rule;
pub use signature::{load_verified, verify_detached, VerifiedIntelligencePack};
pub use state::{enforce_no_rollback, freshness, record_accepted};
pub use types::{
    DeclarativeEdgeRecord, DeclarativeSinkKind, IntelligenceFreshness, IntelligencePack,
    KnownIdentityRecord, PickleGadgetCapability, PickleGadgetRecord, ThreatMapping,
    ThreatMappingRecord,
};
pub use validate::{
    validate, MAX_MAPPINGS_PER_RECORD, MAX_PACK_BYTES, MAX_RECORDS_PER_SECTION, MAX_STRING_BYTES,
};
