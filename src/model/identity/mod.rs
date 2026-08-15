mod behavioural;
mod compare;
mod provenance;
mod structural;
mod tokenizer;
mod types;
mod weights;
use anyhow::Result;
pub use behavioural::BehaviourIdentityInput;
pub use compare::{compare, IdentityComparison, IdentityLayerComparison, IdentityRelationship};
pub use provenance::ProvenanceIdentityInput;
use std::path::Path;
pub use types::{
    IdentityBuildOptions, IdentityCoverage, IdentityStrength, IdentityValue, LayeredModelIdentity,
};
pub use weights::encode_f64;
pub fn build(
    target: &Path,
    package_report: Option<&crate::package::PackageReport>,
    snapshot: &crate::model::metadata::ModelSnapshot,
    tokenizer_report: Option<&crate::model::tokenizer::TokenizerSecurityReport>,
    provenance_input: Option<&ProvenanceIdentityInput>,
    behaviour_input: Option<&BehaviourIdentityInput>,
    options: &IdentityBuildOptions,
) -> Result<LayeredModelIdentity> {
    let byte = snapshot
        .identity
        .artifact_sha256
        .as_ref()
        .map(|v| IdentityValue {
            algorithm: "sha256".into(),
            value: if v.starts_with("sha256:") {
                v.clone()
            } else {
                format!("sha256:{v}")
            },
            strength: IdentityStrength::Exact,
            coverage: IdentityCoverage {
                complete: true,
                detail: "exact artifact bytes".into(),
            },
        });
    let package = package_report.map(|p| IdentityValue {
        algorithm: "lfpkg-v2-merkle-sha256".into(),
        value: p.merkle_identity.clone(),
        strength: IdentityStrength::Exact,
        coverage: IdentityCoverage {
            complete: p.coverage.complete,
            detail: "canonical package Merkle identity".into(),
        },
    });
    let structural = Some(structural::identity(snapshot)?);
    let tokenizer = tokenizer_report.map(tokenizer::identity).transpose()?;
    let weight_sample = if options.include_weight_sample {
        Some(weights::identity(snapshot)?)
    } else {
        None
    };
    let behavioural = if options.include_behavioural {
        behaviour_input.and_then(behavioural::identity)
    } else {
        None
    };
    let provenance = provenance_input.and_then(provenance::identity);
    let mut limitations = Vec::new();
    if tokenizer_report.is_none() {
        limitations.push("tokenizer security report unavailable".into())
    }
    if options.include_behavioural && behavioural.is_none() {
        limitations.push("deterministic behavioural identity unavailable".into())
    }
    let completeness = if limitations.is_empty() {
        crate::assurance::AnalysisCompleteness::Complete
    } else {
        crate::assurance::AnalysisCompleteness::Partial
    };
    Ok(LayeredModelIdentity {
        version: 1,
        subject: target
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("model")
            .into(),
        byte,
        package,
        structural,
        tokenizer,
        weight_sample,
        behavioural,
        provenance,
        completeness,
        limitations,
    })
}
