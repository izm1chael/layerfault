use super::{AdapterAssessment, BaseRelation, CompositionAssessment, ModelComposition};
use crate::finding_evidence::{structural_invariant, EvidenceSubject, FindingBuilder};
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};

pub fn assess(composition: ModelComposition) -> anyhow::Result<CompositionAssessment> {
    let identity = super::identity(&composition)?;
    let mut findings = Vec::new();
    let subject = EvidenceSubject::identity(
        &identity.value,
        "application/vnd.layerfault.model-composition+json",
    );
    if composition.completeness != crate::assurance::AnalysisCompleteness::Complete {
        findings.push(
            FindingBuilder::new("LF-COMPOSITION-INCOMPLETE", CheckType::ModelComposition, ScanStatus::Warn)
                .class(FindingClass::Structural)
                .confidence(Confidence::High)
                .subject(subject.clone())
                .detail("The executable model composition contains components whose identity is incomplete or unknown")
                .evidence(structural_invariant(subject.clone(), "composition completeness", serde_json::json!({
                    "completeness": composition.completeness,
                    "limitations": composition.limitations,
                })))
                .finish(),
        );
    }
    let mut seen = std::collections::BTreeSet::new();
    for (index, adapter) in composition.adapters.iter().enumerate() {
        if !seen.insert(adapter.identity.clone()) {
            findings.push(
                FindingBuilder::new(
                    "LF-COMPOSITION-DUPLICATE-ADAPTER",
                    CheckType::ModelComposition,
                    ScanStatus::Warn,
                )
                .class(FindingClass::Structural)
                .confidence(Confidence::High)
                .subject(subject.clone())
                .detail(
                    "The same adapter identity appears more than once in the ordered composition",
                )
                .evidence(structural_invariant(
                    subject.clone(),
                    "duplicate adapter identity",
                    serde_json::json!({
                        "index": index,
                        "adapter": adapter.name,
                        "identity": adapter.identity,
                    }),
                ))
                .finish(),
            );
        }
    }
    Ok(CompositionAssessment {
        composition,
        identity,
        findings,
    })
}

pub fn adapter_findings(
    assessment: &AdapterAssessment,
    composition_subject: &EvidenceSubject,
) -> Vec<LayerScanResult> {
    let mut out = Vec::new();
    match assessment.base_relation {
        BaseRelation::Mismatch => out.push(
            FindingBuilder::new(
                "LF-ADAPTER-BASE-MISMATCH",
                CheckType::ModelComposition,
                ScanStatus::Fail,
            )
            .class(FindingClass::Compatibility)
            .confidence(Confidence::High)
            .subject(composition_subject.clone())
            .detail(
                "The adapter declares a different base model from the expected composition base",
            )
            .evidence(structural_invariant(
                composition_subject.clone(),
                "adapter base mismatch",
                serde_json::json!({
                    "adapter": assessment.component.name,
                    "declared_base": assessment.declared_base,
                }),
            ))
            .finish(),
        ),
        BaseRelation::Unknown => out.push(
            FindingBuilder::new(
                "LF-ADAPTER-BASE-UNVERIFIED",
                CheckType::ModelComposition,
                ScanStatus::Warn,
            )
            .class(FindingClass::Compatibility)
            .confidence(Confidence::Medium)
            .subject(composition_subject.clone())
            .detail("The adapter base relationship could not be independently verified")
            .evidence(structural_invariant(
                composition_subject.clone(),
                "adapter base relationship",
                serde_json::json!({
                    "adapter": assessment.component.name,
                    "declared_base": assessment.declared_base,
                    "state": "unknown",
                }),
            ))
            .finish(),
        ),
        _ => {}
    }
    if !assessment.unexpected_modules.is_empty() {
        out.push(
            FindingBuilder::new(
                "LF-ADAPTER-UNEXPECTED-MODULE",
                CheckType::ModelComposition,
                ScanStatus::Warn,
            )
            .class(FindingClass::Structural)
            .confidence(Confidence::High)
            .subject(composition_subject.clone())
            .detail("Adapter tensors affect modules outside the declared target-module set")
            .evidence(structural_invariant(
                composition_subject.clone(),
                "declared and observed adapter modules",
                serde_json::json!({
                    "declared": assessment.target_modules,
                    "observed": assessment.observed_modules,
                    "unexpected": assessment.unexpected_modules,
                }),
            ))
            .finish(),
        );
    }
    out
}

pub fn adapter_analysis_incomplete(
    adapter: &str,
    detail: &str,
    composition_subject: &EvidenceSubject,
) -> LayerScanResult {
    FindingBuilder::new(
        "LF-ADAPTER-ANALYSIS-INCOMPLETE",
        CheckType::ModelComposition,
        ScanStatus::Warn,
    )
    .class(FindingClass::Structural)
    .confidence(Confidence::High)
    .subject(composition_subject.clone())
    .detail("Independent adapter security analysis could not be completed")
    .evidence(structural_invariant(
        composition_subject.clone(),
        "adapter analysis completeness",
        serde_json::json!({
            "adapter": adapter,
            "detail": detail,
            "state": "incomplete"
        }),
    ))
    .finish()
}
