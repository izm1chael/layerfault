use super::robust_stats::{robust_z, RobustZ};
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EmbeddingCandidate {
    pub token: String,
    pub token_id: u64,
    pub reason: String,
    pub l2_norm: f64,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EmbeddingAnomaly {
    pub token: String,
    pub token_id: u64,
    pub reason: String,
    pub norm: f64,
    pub robust_z_bucket: String,
}
pub fn analyze(candidates: &[EmbeddingCandidate], ordinary_norms: &[f64]) -> Vec<EmbeddingAnomaly> {
    candidates
        .iter()
        .filter_map(|c| {
            let z = robust_z(c.l2_norm, ordinary_norms);
            let suspicious = matches!(z, RobustZ::PositiveExtreme | RobustZ::NegativeExtreme)
                || matches!(z,RobustZ::Finite(v) if v.abs()>=8.0);
            suspicious.then(|| EmbeddingAnomaly {
                token: c.token.chars().take(256).collect(),
                token_id: c.token_id,
                reason: c.reason.clone(),
                norm: c.l2_norm,
                robust_z_bucket: match z {
                    RobustZ::Finite(v) => format!("{:.1}", v.clamp(-999.0, 999.0)),
                    RobustZ::PositiveExtreme => "positive_extreme".into(),
                    RobustZ::NegativeExtreme => "negative_extreme".into(),
                    RobustZ::Unavailable => "unavailable".into(),
                },
            })
        })
        .collect()
}
