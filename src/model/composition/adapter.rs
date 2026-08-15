use super::{ComponentIdentity, ComponentRole};
use crate::assurance::AnalysisCompleteness;
use anyhow::Result;
use std::path::Path;

#[derive(Debug, Clone, serde::Serialize)]
pub struct AdapterAssessment {
    pub component: ComponentIdentity,
    pub declared_base: Option<String>,
    pub base_relation: BaseRelation,
    pub target_modules: Vec<String>,
    pub observed_modules: Vec<String>,
    pub unexpected_modules: Vec<String>,
    pub report: crate::model::lora::LoraReport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaseRelation {
    Match,
    CompatibleNonIdentical,
    Mismatch,
    Unknown,
}

pub fn inspect(root: &Path, expected_base: Option<&str>) -> Result<AdapterAssessment> {
    let report = crate::model::lora::inspect_adapter(root, None)?;
    let digest = crate::safeio::sha256_path(&report.adapter_path)?;
    let mut observed_modules = report
        .tensors
        .iter()
        .filter_map(|tensor| module_name(&tensor.tensor))
        .collect::<Vec<_>>();
    observed_modules.sort();
    observed_modules.dedup();
    let mut target_modules = report.config.target_modules.clone();
    target_modules.sort();
    target_modules.dedup();
    let unexpected_modules = observed_modules
        .iter()
        .filter(|module| {
            !target_modules
                .iter()
                .any(|target| module_matches(module, target))
        })
        .cloned()
        .collect::<Vec<_>>();
    let declared_base = report.config.base_model_name_or_path.clone();
    let base_relation = match (expected_base, declared_base.as_deref()) {
        (Some(expected), Some(declared)) if expected == declared => BaseRelation::Match,
        (Some(expected), Some(declared))
            if normalized_tail(expected) == normalized_tail(declared) =>
        {
            BaseRelation::CompatibleNonIdentical
        }
        (Some(_), Some(_)) => BaseRelation::Mismatch,
        _ => BaseRelation::Unknown,
    };
    let mut limitations = Vec::new();
    if base_relation == BaseRelation::Unknown {
        limitations.push(
            "adapter base relationship could not be verified from declared identities".into(),
        );
    }
    Ok(AdapterAssessment {
        component: ComponentIdentity {
            role: ComponentRole::Adapter,
            name: root
                .file_name()
                .and_then(|v| v.to_str())
                .unwrap_or("adapter")
                .into(),
            identity: digest.clone(),
            sha256: Some(digest),
            declared_base: declared_base.clone(),
            source: None,
            completeness: if base_relation == BaseRelation::Unknown {
                AnalysisCompleteness::Partial
            } else {
                AnalysisCompleteness::Complete
            },
            limitations,
        },
        declared_base,
        base_relation,
        target_modules,
        observed_modules,
        unexpected_modules,
        report,
    })
}

fn module_name(tensor: &str) -> Option<String> {
    for suffix in [
        ".lora_A.weight",
        ".lora_B.weight",
        ".lora_embedding_A",
        ".lora_embedding_B",
    ] {
        if let Some(value) = tensor.strip_suffix(suffix) {
            return Some(value.trim_start_matches("base_model.model.").to_owned());
        }
    }
    None
}

fn module_matches(observed: &str, target: &str) -> bool {
    observed == target
        || observed.ends_with(&format!(".{target}"))
        || observed.contains(&format!(".{target}."))
}

fn normalized_tail(value: &str) -> &str {
    value
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or(value)
}
