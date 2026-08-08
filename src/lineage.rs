//! Claim-aware base/derived model comparison.

use crate::modelmeta::{ModelSnapshot, TensorSummary};
use crate::transformation::{
    DerivedIntegrityState, LineageState, TransformationManifest, TransformationType,
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonFinding {
    pub rule_id: String,
    pub domain: String,
    pub status: String,
    pub confidence: String,
    pub title: String,
    pub what_changed: String,
    pub why_security_relevant: String,
    pub evidence: Vec<String>,
    pub potential_impact: String,
    pub recommendation: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComparisonReport {
    pub schema_version: String,
    pub base: ModelSnapshot,
    pub derived: ModelSnapshot,
    pub claim: Option<TransformationType>,
    pub lineage: LineageState,
    pub derived_integrity: DerivedIntegrityState,
    pub findings: Vec<ComparisonFinding>,
    pub component_changes: BTreeMap<String, Value>,
    pub tensor_changes: TensorChangeSummary,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct TensorChangeSummary {
    pub base_count: usize,
    pub derived_count: usize,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub shape_changed: Vec<String>,
    pub dtype_changed: Vec<String>,
    pub schema_identical: bool,
}

pub fn compare_paths(
    base: &std::path::Path,
    derived: &std::path::Path,
    claim: Option<TransformationType>,
    manifest: Option<&TransformationManifest>,
) -> Result<ComparisonReport> {
    let base = crate::modelmeta::build_snapshot(base)?;
    let derived = crate::modelmeta::build_snapshot(derived)?;
    Ok(compare_snapshots(base, derived, claim, manifest))
}

pub fn compare_snapshots(
    base: ModelSnapshot,
    derived: ModelSnapshot,
    claim: Option<TransformationType>,
    manifest: Option<&TransformationManifest>,
) -> ComparisonReport {
    let mut findings = Vec::new();
    let mut components = BTreeMap::new();
    let tensors = compare_tensors(&base.tensors, &derived.tensors);

    component(
        &mut components,
        "architecture",
        &base.architecture.architecture,
        &derived.architecture.architecture,
    );
    component(
        &mut components,
        "layer_count",
        &base.architecture.layer_count,
        &derived.architecture.layer_count,
    );
    component(
        &mut components,
        "hidden_size",
        &base.architecture.hidden_size,
        &derived.architecture.hidden_size,
    );
    component(
        &mut components,
        "attention_heads",
        &base.architecture.attention_heads,
        &derived.architecture.attention_heads,
    );
    component(
        &mut components,
        "kv_heads",
        &base.architecture.kv_heads,
        &derived.architecture.kv_heads,
    );
    component(
        &mut components,
        "vocabulary_size",
        &base.architecture.vocabulary_size,
        &derived.architecture.vocabulary_size,
    );
    component(
        &mut components,
        "context_length",
        &base.architecture.context_length,
        &derived.architecture.context_length,
    );
    component(
        &mut components,
        "tokenizer",
        &base.tokenizer,
        &derived.tokenizer,
    );
    component(
        &mut components,
        "chat_template",
        &base.template,
        &derived.template,
    );
    component(
        &mut components,
        "generation_config",
        &base.generation,
        &derived.generation,
    );

    let arch_core_changed = base.architecture.architecture != derived.architecture.architecture
        || base.architecture.layer_count != derived.architecture.layer_count
        || base.architecture.hidden_size != derived.architecture.hidden_size
        || base.architecture.attention_heads != derived.architecture.attention_heads
        || base.architecture.kv_heads != derived.architecture.kv_heads;
    if arch_core_changed {
        findings.push(finding(
            "LF-LINEAGE-ARCH-MISMATCH",
            "lineage",
            "BLOCK",
            "HIGH",
            "Architecture differs from claimed base",
            "One or more core architecture fields changed between base and derived snapshots.",
            "Architecture mismatches can contradict claims that a model is a simple derivative of the supplied parent.",
            vec![format!("base={:?}", base.architecture), format!("derived={:?}", derived.architecture)],
            "The supplied base may be wrong, the derivative may have undergone an undeclared conversion, or the lineage claim may be false.",
            "Verify the exact base revision and transformation history before deployment.",
        ));
    }

    let tokenizer_changed = base.tokenizer != derived.tokenizer;
    let template_changed = base.template != derived.template;
    if tokenizer_changed {
        findings.push(finding(
            "LF-TOKENIZER-CHANGED", "tokenizer", "WARN", "HIGH",
            "Tokenizer differs from base", "Tokenizer fingerprints or special-token mappings changed.",
            "Tokenizer changes alter how apparent input maps to model tokens and can introduce trigger-relevant behavior.",
            vec![format!("base={:?}", base.tokenizer), format!("derived={:?}", derived.tokenizer)],
            "Inputs may be interpreted differently by the derived model.",
            "Review the tokenizer diff and confirm it was part of the intended transformation.",
        ));
    }
    if template_changed {
        findings.push(finding(
            "LF-TEMPLATE-CHANGED", "template", "WARN", "HIGH",
            "Chat template differs from base", "The exact chat-template fingerprint changed.",
            "Templates can alter role ordering, hidden instructions and tool framing without changing weights.",
            vec![format!("base={:?}", base.template), format!("derived={:?}", derived.template)],
            "Runtime behavior may differ even if model weights are otherwise consistent.",
            "Inspect the template content and verify the change is expected.",
        ));
    }
    if !tensors.added.is_empty() || !tensors.removed.is_empty() || !tensors.shape_changed.is_empty()
    {
        findings.push(finding(
            "LF-DERIVE-SCHEMA-MISMATCH", "derived_integrity", "WARN", "HIGH",
            "Tensor topology changed", "Tensor names or shapes differ between base and derived snapshots.",
            "Unexpected topology change can contradict quantization, LoRA-merge or simple conversion claims.",
            vec![format!("added={:?}", tensors.added), format!("removed={:?}", tensors.removed), format!("shape_changed={:?}", tensors.shape_changed)],
            "The derived artifact may contain undeclared architecture or parameter changes.",
            "Confirm the transformation type and compare against the publisher's reproducible build record.",
        ));
    }

    let mut contradicted = arch_core_changed;
    if let Some(claim) = claim {
        match claim {
            TransformationType::Quantization => {
                if tokenizer_changed {
                    contradicted = true;
                    findings.push(claim_contradiction(
                        "LF-LINEAGE-QUANTIZATION-TOKENIZER",
                        "Quantization-only claim changed the tokenizer",
                    ));
                }
                if template_changed {
                    contradicted = true;
                    findings.push(claim_contradiction(
                        "LF-LINEAGE-QUANTIZATION-TEMPLATE",
                        "Quantization-only claim changed the chat template",
                    ));
                }
                if !tensors.added.is_empty()
                    || !tensors.removed.is_empty()
                    || !tensors.shape_changed.is_empty()
                {
                    contradicted = true;
                }
            }
            TransformationType::LoraAdapter => {
                if !derived
                    .claims
                    .contains_key("adapter.base_model_name_or_path")
                {
                    findings.push(finding(
                        "LF-ADAPTER-BASE-UNVERIFIED", "adapter", "WARN", "MEDIUM",
                        "LoRA base claim is absent", "No adapter base_model_name_or_path claim was found.",
                        "An adapter should be bound to a compatible base to make its transformation context auditable.",
                        vec![], "The wrong base may be selected for loading or merge verification.",
                        "Supply the exact base and a signed transformation record.",
                    ));
                }
            }
            TransformationType::LoraMerge => {
                if !tensors.added.is_empty()
                    || !tensors.removed.is_empty()
                    || !tensors.shape_changed.is_empty()
                {
                    contradicted = true;
                }
            }
            TransformationType::Repackaging => {
                if base.tensor_schema_hash != derived.tensor_schema_hash
                    || tokenizer_changed
                    || template_changed
                {
                    contradicted = true;
                    findings.push(claim_contradiction(
                        "LF-LINEAGE-REPACKAGE-CONTENT",
                        "Repackaging claim changed model-semantic components",
                    ));
                }
            }
            TransformationType::TokenizerModification => {
                if !tokenizer_changed {
                    findings.push(finding(
                        "LF-LINEAGE-CLAIM-NO-EVIDENCE",
                        "lineage",
                        "WARN",
                        "MEDIUM",
                        "Claimed tokenizer modification was not observed",
                        "The normalized tokenizer summaries are identical.",
                        "A transformation claim without corresponding evidence cannot be verified.",
                        vec![],
                        "The manifest or supplied artifacts may not match.",
                        "Verify the exact child artifact and transformation record.",
                    ));
                }
            }
            TransformationType::TemplateModification => {
                if !template_changed {
                    findings.push(finding(
                        "LF-LINEAGE-CLAIM-NO-EVIDENCE",
                        "lineage",
                        "WARN",
                        "MEDIUM",
                        "Claimed template modification was not observed",
                        "The normalized chat-template summaries are identical.",
                        "A transformation claim without corresponding evidence cannot be verified.",
                        vec![],
                        "The manifest or supplied artifacts may not match.",
                        "Verify the exact child artifact and transformation record.",
                    ));
                }
            }
            TransformationType::FineTune
            | TransformationType::Conversion
            | TransformationType::Other => {}
        }
    }

    if let Some(manifest) = manifest {
        if manifest.parent.identity != base.identity.canonical
            || manifest.child.identity != derived.identity.canonical
        {
            contradicted = true;
            findings.push(claim_contradiction("LF-LINEAGE-MANIFEST-ENDPOINT", "Transformation manifest endpoints do not match the observed base/derived identities"));
        }
        if claim.is_some_and(|claim| claim != manifest.transformation.kind) {
            contradicted = true;
            findings.push(claim_contradiction(
                "LF-LINEAGE-MANIFEST-CLAIM",
                "CLI transformation claim conflicts with transformation manifest",
            ));
        }
    }

    let lineage = if contradicted {
        LineageState::Contradicted
    } else if base.identity.canonical == derived.identity.canonical {
        LineageState::Verified
    } else if arch_core_changed
        || base.architecture.architecture.is_none()
        || derived.architecture.architecture.is_none()
    {
        LineageState::Unverified
    } else {
        LineageState::Consistent
    };
    let derived_integrity = if contradicted {
        DerivedIntegrityState::Contradicted
    } else if findings.iter().any(|v| v.status == "WARN") {
        DerivedIntegrityState::Anomalous
    } else if tensors.schema_identical {
        DerivedIntegrityState::Consistent
    } else {
        DerivedIntegrityState::Unverified
    };
    findings.sort_by(|a, b| {
        a.rule_id
            .cmp(&b.rule_id)
            .then_with(|| a.title.cmp(&b.title))
    });
    ComparisonReport {
        schema_version: "1.0".to_owned(),
        base,
        derived,
        claim,
        lineage,
        derived_integrity,
        findings,
        component_changes: components,
        tensor_changes: tensors,
    }
}

fn compare_tensors(base: &[TensorSummary], derived: &[TensorSummary]) -> TensorChangeSummary {
    let left: BTreeMap<_, _> = base.iter().map(|v| (v.name.as_str(), v)).collect();
    let right: BTreeMap<_, _> = derived.iter().map(|v| (v.name.as_str(), v)).collect();
    let names: BTreeSet<_> = left.keys().chain(right.keys()).copied().collect();
    let mut out = TensorChangeSummary {
        base_count: base.len(),
        derived_count: derived.len(),
        ..Default::default()
    };
    for name in names {
        match (left.get(name), right.get(name)) {
            (None, Some(_)) => out.added.push(name.to_owned()),
            (Some(_), None) => out.removed.push(name.to_owned()),
            (Some(a), Some(b)) => {
                if a.shape != b.shape {
                    out.shape_changed.push(name.to_owned());
                }
                if a.dtype != b.dtype {
                    out.dtype_changed.push(name.to_owned());
                }
            }
            (None, None) => {}
        }
    }
    out.schema_identical =
        out.added.is_empty() && out.removed.is_empty() && out.shape_changed.is_empty();
    out
}

fn component<T: Serialize + PartialEq>(
    out: &mut BTreeMap<String, Value>,
    name: &str,
    base: &T,
    derived: &T,
) {
    out.insert(
        name.to_owned(),
        json!({"changed": base != derived, "base": base, "derived": derived}),
    );
}

fn claim_contradiction(rule: &str, title: &str) -> ComparisonFinding {
    finding(rule, "lineage", "BLOCK", "HIGH", title, title, "Observed components conflict with the declared transformation's expected invariants.", vec![], "The artifact should not be treated as the claimed derivative until the discrepancy is explained.", "Verify the exact parent, transformation parameters and publisher evidence.")
}

#[allow(clippy::too_many_arguments)]
fn finding(
    rule_id: &str,
    domain: &str,
    status: &str,
    confidence: &str,
    title: &str,
    what_changed: &str,
    why: &str,
    evidence: Vec<String>,
    impact: &str,
    recommendation: &str,
) -> ComparisonFinding {
    ComparisonFinding {
        rule_id: rule_id.to_owned(),
        domain: domain.to_owned(),
        status: status.to_owned(),
        confidence: confidence.to_owned(),
        title: title.to_owned(),
        what_changed: what_changed.to_owned(),
        why_security_relevant: why.to_owned(),
        evidence,
        potential_impact: impact.to_owned(),
        recommendation: recommendation.to_owned(),
    }
}
