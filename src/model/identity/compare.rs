use super::LayeredModelIdentity;
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityComparison {
    pub left: String,
    pub right: String,
    pub layers: Vec<IdentityLayerComparison>,
    pub overall: IdentityRelationship,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityLayerComparison {
    pub layer: String,
    pub equal: Option<bool>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityRelationship {
    ExactSameArtifact,
    SamePackage,
    StructurallyConsistent,
    LikelyDerived,
    Divergent,
    Inconclusive,
}
pub fn compare(l: &LayeredModelIdentity, r: &LayeredModelIdentity) -> IdentityComparison {
    let pair = [
        ("byte", &l.byte, &r.byte),
        ("package", &l.package, &r.package),
        ("structural", &l.structural, &r.structural),
        ("tokenizer", &l.tokenizer, &r.tokenizer),
        ("weight_sample", &l.weight_sample, &r.weight_sample),
        ("behavioural", &l.behavioural, &r.behavioural),
        ("provenance", &l.provenance, &r.provenance),
    ];
    let layers = pair
        .iter()
        .map(|(n, a, b)| IdentityLayerComparison {
            layer: (*n).into(),
            equal: match (a, b) {
                (Some(a), Some(b)) => Some(a.algorithm == b.algorithm && a.value == b.value),
                _ => None,
            },
        })
        .collect::<Vec<_>>();
    let eq = |n: &str| layers.iter().find(|x| x.layer == n).and_then(|x| x.equal);
    let overall = if eq("byte") == Some(true) {
        IdentityRelationship::ExactSameArtifact
    } else if eq("package") == Some(true) {
        IdentityRelationship::SamePackage
    } else if eq("structural") == Some(false) {
        IdentityRelationship::Divergent
    } else if eq("structural") == Some(true) && eq("tokenizer") == Some(true) {
        IdentityRelationship::StructurallyConsistent
    } else if eq("structural") == Some(true) && eq("provenance") == Some(true) {
        IdentityRelationship::LikelyDerived
    } else {
        IdentityRelationship::Inconclusive
    };
    IdentityComparison {
        left: l.subject.clone(),
        right: r.subject.clone(),
        layers,
        overall,
    }
}
