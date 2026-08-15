//! Exact identity and security assessment for executable model compositions.
//!
//! A composition binds the base model, ordered adapters, tokenizer/template
//! material and security-relevant merge/quantization configuration. Local path
//! metadata is deliberately excluded from the canonical identity.

mod adapter;
mod canonical;
mod findings;
mod manifest;
mod merge;
mod types;

pub use adapter::{inspect as inspect_adapter, AdapterAssessment, BaseRelation};
pub use canonical::{adapter_set_identity, canonical_bytes, identity, validate};
pub use findings::{adapter_analysis_incomplete, adapter_findings, assess};
pub use manifest::{
    load as load_manifest, resolve as resolve_manifest, write_example, ComponentReference,
    CompositionManifest,
};
pub use merge::verify_lora as verify_lora_merge;
pub use types::{
    ComponentIdentity, ComponentRole, CompositionAssessment, CompositionIdentity, MergeAssessment,
    MergeConfiguration, MergeVerificationState, ModelComposition, QuantizationConfiguration,
};
