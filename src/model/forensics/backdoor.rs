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
    let sub = EvidenceSubject::identity(subject, "application/vnd.layerfault.model+json");
    FindingBuilder::new(id, CheckType::BackdoorForensics, ScanStatus::Warn)
        .class(FindingClass::ContentIndicator)
        .confidence(Confidence::High)
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
