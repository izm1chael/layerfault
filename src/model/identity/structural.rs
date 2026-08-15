use super::{IdentityCoverage, IdentityStrength, IdentityValue};
use crate::model::metadata::ModelSnapshot;
use sha2::{Digest, Sha256};
#[derive(serde::Serialize)]
struct Doc<'a> {
    kind: &'a crate::model::metadata::ModelTargetKind,
    format: &'a str,
    architecture: &'a crate::model::metadata::ArchitectureSummary,
    tensors: Vec<(&'a str, &'a str, &'a Vec<u64>)>,
    members: Vec<(&'a str, &'a str)>,
}
pub fn identity(snapshot: &ModelSnapshot) -> anyhow::Result<IdentityValue> {
    let mut tensors = snapshot
        .tensors
        .iter()
        .map(|t| (t.name.as_str(), t.dtype.as_str(), &t.shape))
        .collect::<Vec<_>>();
    tensors.sort_by(|a, b| a.0.cmp(b.0));
    let mut members = snapshot
        .package_members
        .iter()
        .map(|m| (m.relative_path.as_str(), m.kind.as_str()))
        .collect::<Vec<_>>();
    members.sort();
    let bytes = serde_json::to_vec(&Doc {
        kind: &snapshot.kind,
        format: &snapshot.format,
        architecture: &snapshot.architecture,
        tensors,
        members,
    })?;
    let mut h = Sha256::new();
    h.update(b"layerfault:model-structural:v1\0");
    h.update(bytes);
    Ok(IdentityValue {
        algorithm: "layerfault-model-structural-v1-sha256".into(),
        value: format!("lfmodel:struct:v1:sha256:{}", hex::encode(h.finalize())),
        strength: IdentityStrength::Structural,
        coverage: IdentityCoverage {
            complete: true,
            detail: "stable architecture/tensor/package structural projection".into(),
        },
    })
}
