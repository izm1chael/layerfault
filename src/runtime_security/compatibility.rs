use super::{
    AdvisoryApplicability, ExploitabilityState, ModelSecurityContext, RuntimeCapabilities,
    RuntimeInstallation, RuntimePosture, SupportState,
};
use crate::assurance::AnalysisCompleteness;
use crate::finding_evidence::{EvidenceKind, FindingBuilder, FindingEvidence};
use crate::intelligence::IntelligencePack;
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatibilityState {
    Compatible,
    CompatibleWithConditions,
    Incompatible,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatibilityCondition {
    pub id: String,
    pub satisfied: Option<bool>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelRuntimeCompatibility {
    pub runtime: RuntimeInstallation,
    pub model_identity: String,
    pub state: CompatibilityState,
    pub conditions: Vec<CompatibilityCondition>,
    pub completeness: AnalysisCompleteness,
    pub findings: Vec<LayerScanResult>,
}

fn requires_custom_code(model: &ModelSecurityContext) -> bool {
    model.rules_present.iter().any(|id| {
        matches!(
            id.as_str(),
            "LF-PACKAGE-CODE"
                | "LF-CODE-AUTO-MAP"
                | "LF-CONFIG-DYNAMIC-IMPORT"
                | "LF-CONFIG-CUSTOM-CLASS"
        )
    })
}

fn model_identity(model: &ModelSecurityContext) -> String {
    model
        .subject
        .sha256
        .clone()
        .or_else(|| model.subject.identity.clone())
        .unwrap_or_else(|| "unknown".into())
}

fn condition(
    id: &str,
    satisfied: Option<bool>,
    detail: impl Into<String>,
) -> CompatibilityCondition {
    CompatibilityCondition {
        id: id.into(),
        satisfied,
        detail: detail.into(),
    }
}

fn finding(
    model: &ModelSecurityContext,
    state: CompatibilityState,
    detail: &str,
) -> Option<LayerScanResult> {
    let (rule, status) = match state {
        CompatibilityState::Incompatible => ("LF-RUNTIME-COMPAT-INCOMPATIBLE", ScanStatus::Fail),
        CompatibilityState::CompatibleWithConditions => {
            ("LF-RUNTIME-COMPAT-CONDITIONAL", ScanStatus::Warn)
        }
        CompatibilityState::Unknown => ("LF-RUNTIME-COMPAT-UNKNOWN", ScanStatus::Warn),
        CompatibilityState::Compatible => return None,
    };
    Some(
        FindingBuilder::new(rule, CheckType::RuntimeCompatibility, status)
            .class(FindingClass::Compatibility)
            .confidence(Confidence::High)
            .subject(model.subject.clone())
            .detail(detail)
            .evidence(FindingEvidence::new(
                EvidenceKind::RuntimeConfiguration,
                model.subject.clone(),
                detail,
            ))
            .finish(),
    )
}

pub fn assess_one(
    runtime: &RuntimePosture,
    model: &ModelSecurityContext,
    exploitability: &[AdvisoryApplicability],
) -> ModelRuntimeCompatibility {
    let caps = RuntimeCapabilities::for_runtime(runtime.installation.runtime);
    let mut conditions = Vec::new();
    let format = model.format.as_deref().map(str::to_ascii_lowercase);
    let format_state = match format.as_deref() {
        Some(value) if caps.formats.iter().any(|f| f.eq_ignore_ascii_case(value)) => Some(true),
        Some(_) if !caps.formats.is_empty() => Some(false),
        _ => None,
    };
    conditions.push(condition(
        "format_support",
        format_state,
        format
            .as_deref()
            .map(|v| format!("model format: {v}"))
            .unwrap_or_else(|| "model format unavailable".into()),
    ));

    let custom = requires_custom_code(model);
    let custom_state = if !custom {
        Some(true)
    } else {
        match caps.supports_custom_code {
            SupportState::Supported => Some(true),
            SupportState::Unsupported => Some(false),
            SupportState::Conditional | SupportState::Unknown => None,
        }
    };
    conditions.push(condition(
        "custom_code",
        custom_state,
        if custom {
            format!(
                "model requires executable/custom loading; runtime capability is {:?}",
                caps.supports_custom_code
            )
        } else {
            "no executable custom-code requirement detected".into()
        },
    ));

    let auto_map = model.rules_present.contains("LF-CODE-AUTO-MAP");
    let auto_map_state = if !auto_map {
        Some(true)
    } else {
        match caps.supports_auto_map {
            SupportState::Supported => Some(true),
            SupportState::Unsupported => Some(false),
            _ => None,
        }
    };
    conditions.push(condition(
        "declarative_dynamic_import",
        auto_map_state,
        if auto_map {
            format!(
                "auto_map present; runtime capability is {:?}",
                caps.supports_auto_map
            )
        } else {
            "no auto_map requirement detected".into()
        },
    ));

    let arch_state = match model.architecture.as_deref() {
        None => None,
        Some(_) if caps.architectures.is_empty() => None,
        Some(arch) => Some(
            caps.architectures
                .iter()
                .any(|known| known.eq_ignore_ascii_case(arch)),
        ),
    };
    conditions.push(condition(
        "architecture_support",
        arch_state,
        model
            .architecture
            .as_deref()
            .map(|a| format!("architecture: {a}"))
            .unwrap_or_else(|| "architecture unavailable".into()),
    ));

    let exploit_block = exploitability
        .iter()
        .any(|a| a.state == ExploitabilityState::PreconditionsMet);
    let exploit_unknown = exploitability.iter().any(|a| {
        matches!(
            a.state,
            ExploitabilityState::PreconditionsPartiallyKnown | ExploitabilityState::RuntimeAffected
        )
    });
    conditions.push(condition(
        "runtime_exploitability",
        if exploit_block {
            Some(false)
        } else if exploit_unknown {
            None
        } else {
            Some(true)
        },
        if exploit_block {
            "an affected runtime advisory has all encoded exploitability preconditions met"
        } else if exploit_unknown {
            "runtime exploitability is only partially known"
        } else {
            "no blocking contextual exploitability found"
        },
    ));

    let any_false = conditions.iter().any(|c| c.satisfied == Some(false));
    let any_unknown = conditions.iter().any(|c| c.satisfied.is_none());
    let state = if any_false || exploit_block {
        CompatibilityState::Incompatible
    } else if any_unknown || !model.coverage.complete || !runtime.coverage.complete {
        CompatibilityState::CompatibleWithConditions
    } else {
        CompatibilityState::Compatible
    };
    let completeness = if model.coverage.complete && runtime.coverage.complete && !any_unknown {
        AnalysisCompleteness::Complete
    } else if model.coverage.complete || runtime.coverage.complete {
        AnalysisCompleteness::Partial
    } else {
        AnalysisCompleteness::Unknown
    };
    let detail = match state {
        CompatibilityState::Compatible => "complete known compatibility conditions are satisfied",
        CompatibilityState::CompatibleWithConditions => {
            "runtime/model compatibility requires unresolved conditions"
        }
        CompatibilityState::Incompatible => {
            "one or more runtime/model admission conditions are not satisfied"
        }
        CompatibilityState::Unknown => "runtime/model compatibility could not be established",
    };
    let findings = finding(model, state, detail).into_iter().collect();
    ModelRuntimeCompatibility {
        runtime: runtime.installation.clone(),
        model_identity: model_identity(model),
        state,
        conditions,
        completeness,
        findings,
    }
}

pub fn matrix(
    runtimes: &[RuntimePosture],
    model: &ModelSecurityContext,
    pack: &IntelligencePack,
) -> Vec<ModelRuntimeCompatibility> {
    let mut rows = runtimes
        .iter()
        .map(|runtime| {
            let exploitability = super::assess_from_pack(runtime, model, pack);
            assess_one(runtime, model, &exploitability)
        })
        .collect::<Vec<_>>();
    rows.sort_by(|a, b| {
        a.runtime
            .runtime
            .as_str()
            .cmp(b.runtime.runtime.as_str())
            .then_with(|| a.runtime.executable.cmp(&b.runtime.executable))
    });
    rows
}
