use super::delta::{self, DeltaConcentration, TensorDeltaMass};
use super::embedding::{self, EmbeddingAnomaly, EmbeddingCandidate};
use crate::assurance::AnalysisCompleteness;
use crate::finding_evidence::{EvidenceKind, EvidenceSubject, FindingBuilder, FindingEvidence};
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackdoorProfile {
    Standard,
    Research,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TensorAnomaly {
    pub tensor: String,
    pub family: String,
    pub metric: String,
    pub detail: String,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NonFiniteObservation {
    pub tensor: String,
    pub candidate_count: u64,
    pub reference_count: Option<u64>,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BackdoorStaticInput {
    pub subject: String,
    pub reference: Option<String>,
    pub profile: BackdoorProfile,
    #[serde(default)]
    pub tensor_anomalies: Vec<TensorAnomaly>,
    #[serde(default)]
    pub embedding_candidates: Vec<EmbeddingCandidate>,
    #[serde(default)]
    pub ordinary_embedding_norms: Vec<f64>,
    #[serde(default)]
    pub delta_masses: Vec<TensorDeltaMass>,
    #[serde(default)]
    pub nonfinite: Vec<NonFiniteObservation>,
    #[serde(default)]
    pub dataset_findings: Vec<LayerScanResult>,
    #[serde(default)]
    pub adapter_findings: Vec<LayerScanResult>,
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BackdoorStaticReport {
    pub subject: String,
    pub reference: Option<String>,
    pub profile: BackdoorProfile,
    pub tensor_anomalies: Vec<TensorAnomaly>,
    pub embedding_anomalies: Vec<EmbeddingAnomaly>,
    pub delta_concentration: Option<DeltaConcentration>,
    pub nonfinite: Vec<NonFiniteObservation>,
    pub dataset_findings: Vec<LayerScanResult>,
    pub adapter_findings: Vec<LayerScanResult>,
    pub findings: Vec<LayerScanResult>,
    pub completeness: AnalysisCompleteness,
    pub limitations: Vec<String>,
}
fn finding(subject: &str, id: &str, detail: &str, evidence: serde_json::Value) -> LayerScanResult {
    finding_with_confidence(subject, id, detail, evidence, Confidence::High)
}
/// A weaker-signal counterpart to [`finding`]: same shape, lower confidence,
/// for indicators that are plausible but expected to also occur under
/// ordinary fine-tuning (see `LF-BACKDOOR-STATIC-DELTA-NOTABLE`).
fn notable_finding(
    subject: &str,
    id: &str,
    detail: &str,
    evidence: serde_json::Value,
) -> LayerScanResult {
    finding_with_confidence(subject, id, detail, evidence, Confidence::Medium)
}
fn finding_with_confidence(
    subject: &str,
    id: &str,
    detail: &str,
    evidence: serde_json::Value,
    confidence: Confidence,
) -> LayerScanResult {
    let sub = EvidenceSubject::identity(subject, "application/vnd.layerfault.model+json");
    FindingBuilder::new(id, CheckType::BackdoorForensics, ScanStatus::Warn)
        .class(FindingClass::ContentIndicator)
        .confidence(confidence)
        .subject(sub.clone())
        .detail(detail)
        .evidence(
            FindingEvidence::new(
                EvidenceKind::ForensicStatistic,
                sub,
                "probabilistic model-forensics indicator",
            )
            .structured(evidence),
        )
        .finish()
}
pub fn analyze_backdoor_static(i: BackdoorStaticInput) -> BackdoorStaticReport {
    let embedding_anomalies =
        embedding::analyze(&i.embedding_candidates, &i.ordinary_embedding_norms);
    let delta_concentration = delta::concentration(&i.delta_masses);
    let mut findings = Vec::new();
    let mut categories = 0;
    if let Some(d) = &delta_concentration {
        if delta::suspicious(d) {
            categories += 1;
            findings.push(finding(&i.subject,"LF-BACKDOOR-STATIC-DELTA-CONCENTRATION","sampled model deltas are highly localized; this is a research indicator, not proof of a backdoor",serde_json::json!(d)));
        } else if delta::notable(d) {
            categories += 1;
            findings.push(notable_finding(&i.subject,"LF-BACKDOOR-STATIC-DELTA-NOTABLE","the embedding table changed alongside a real cluster of other tensors; deltas are diffuse rather than concentrated, which is the shape a gradient fine-tuned backdoor typically takes",serde_json::json!(d)));
        }
    }
    if !embedding_anomalies.is_empty() {
        categories += 1;
        findings.push(finding(
            &i.subject,
            "LF-BACKDOOR-STATIC-EMBEDDING-OUTLIER",
            "security-relevant embedding candidates are robust statistical outliers",
            serde_json::json!(&embedding_anomalies),
        ));
    }
    if i.nonfinite
        .iter()
        .any(|n| n.candidate_count > n.reference_count.unwrap_or(0))
    {
        findings.push(finding(
            &i.subject,
            "LF-BACKDOOR-STATIC-NONFINITE",
            "candidate sampled tensors introduce non-finite values",
            serde_json::json!(&i.nonfinite),
        ));
    }
    if i.dataset_findings
        .iter()
        .any(|f| f.rule_id.as_deref().is_some_and(|x| x.contains("TRIGGER")))
    {
        categories += 1
    }
    if categories >= 2 {
        findings.push(finding(&i.subject,"LF-CORR-BACKDOOR-MULTI-SIGNAL","multiple independent backdoor-relevant indicators were observed; malicious intent is not established",serde_json::json!({"independent_categories":categories})));
    }
    let mut limitations = Vec::new();
    let completeness = if i.reference.is_none() {
        limitations.push("No parent/reference model was supplied; Layerfault cannot distinguish intended fine-tuning deltas from maliciously localized changes.".into());
        AnalysisCompleteness::Partial
    } else {
        AnalysisCompleteness::Complete
    };
    BackdoorStaticReport {
        subject: i.subject,
        reference: i.reference,
        profile: i.profile,
        tensor_anomalies: i.tensor_anomalies,
        embedding_anomalies,
        delta_concentration,
        nonfinite: i.nonfinite,
        dataset_findings: i.dataset_findings,
        adapter_findings: i.adapter_findings,
        findings,
        completeness,
        limitations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Same diffuse-fine-tune-with-embedding-delta shape as the real
    /// `pls-suffix`/`sent-sleeper` corpus fixtures: ~120 changed tensors,
    /// no small cluster dominating total delta mass.
    fn diffuse_finetune_delta_masses() -> Vec<TensorDeltaMass> {
        let mut masses = vec![TensorDeltaMass {
            tensor: "model.embed_tokens.weight".to_owned(),
            absolute_delta: 5.0,
        }];
        for i in 0..121 {
            masses.push(TensorDeltaMass {
                tensor: format!("model.layers.{i}.mlp.down_proj.weight"),
                absolute_delta: 1.0,
            });
        }
        masses
    }

    #[test]
    fn diffuse_finetuned_backdoor_shape_surfaces_a_notable_finding() {
        let report = analyze_backdoor_static(BackdoorStaticInput {
            subject: "test-subject".to_owned(),
            reference: Some("test-base".to_owned()),
            profile: BackdoorProfile::Research,
            tensor_anomalies: Vec::new(),
            embedding_candidates: Vec::new(),
            ordinary_embedding_norms: Vec::new(),
            delta_masses: diffuse_finetune_delta_masses(),
            nonfinite: Vec::new(),
            dataset_findings: Vec::new(),
            adapter_findings: Vec::new(),
        });
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("LF-BACKDOOR-STATIC-DELTA-NOTABLE")),
            "diffuse embedding-plus-cluster deltas that miss the strict concentration gate must still surface a finding: {:?}",
            report.findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("LF-BACKDOOR-STATIC-DELTA-CONCENTRATION")),
            "this shape must not also trip the strict concentration gate"
        );
    }
}
