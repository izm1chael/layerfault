use super::advisory::AdvisoryPrecondition;
use super::{ModelSecurityContext, NormalizedFact, PostureState, RuntimePosture};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreconditionState {
    Satisfied,
    NotSatisfied,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreconditionEvaluation {
    pub condition: AdvisoryPrecondition,
    pub state: PreconditionState,
    pub reason: String,
}

fn string_values(fact: &NormalizedFact) -> Vec<&str> {
    match fact {
        NormalizedFact::String(v) => vec![v],
        NormalizedFact::StringList(v) => v.iter().map(String::as_str).collect(),
        _ => Vec::new(),
    }
}

pub fn evaluate_precondition(
    condition: &AdvisoryPrecondition,
    model: &ModelSecurityContext,
    runtime: &RuntimePosture,
) -> PreconditionState {
    match condition {
        AdvisoryPrecondition::ArtifactFormat { format } => match model.format.as_deref() {
            Some(value) if value.eq_ignore_ascii_case(format) => PreconditionState::Satisfied,
            Some(_) => PreconditionState::NotSatisfied,
            None => PreconditionState::Unknown,
        },
        AdvisoryPrecondition::RulePresent { rule_id } => {
            if model.rules_present.contains(rule_id) {
                PreconditionState::Satisfied
            } else if model.coverage.complete {
                PreconditionState::NotSatisfied
            } else {
                PreconditionState::Unknown
            }
        }
        AdvisoryPrecondition::ConfigFieldPresent { path } => {
            if model.config.contains_key(path) {
                PreconditionState::Satisfied
            } else if model.coverage.complete {
                PreconditionState::NotSatisfied
            } else {
                PreconditionState::Unknown
            }
        }
        AdvisoryPrecondition::ConfigFieldEquals { path, value } => match model.config.get(path) {
            Some(fact) if string_values(fact).iter().any(|v| *v == value) => {
                PreconditionState::Satisfied
            }
            Some(NormalizedFact::Bool(v)) if v.to_string() == *value => {
                PreconditionState::Satisfied
            }
            Some(NormalizedFact::Integer(v)) if v.to_string() == *value => {
                PreconditionState::Satisfied
            }
            Some(_) => PreconditionState::NotSatisfied,
            None => PreconditionState::Unknown,
        },
        AdvisoryPrecondition::ConfigFieldPrefix { path, prefix } => match model.config.get(path) {
            Some(fact) if string_values(fact).iter().any(|v| v.starts_with(prefix)) => {
                PreconditionState::Satisfied
            }
            Some(_) => PreconditionState::NotSatisfied,
            None => PreconditionState::Unknown,
        },
        AdvisoryPrecondition::RuntimeFlagPresent { flag } => {
            if runtime
                .configuration
                .command_args
                .iter()
                .any(|arg| arg == flag || arg.starts_with(&format!("{flag}=")))
            {
                PreconditionState::Satisfied
            } else if runtime.coverage.complete {
                PreconditionState::NotSatisfied
            } else {
                PreconditionState::Unknown
            }
        }
        AdvisoryPrecondition::RuntimeFlagAbsent { flag } => {
            if runtime
                .configuration
                .command_args
                .iter()
                .any(|arg| arg == flag || arg.starts_with(&format!("{flag}=")))
            {
                PreconditionState::NotSatisfied
            } else if runtime.coverage.complete {
                PreconditionState::Satisfied
            } else {
                PreconditionState::Unknown
            }
        }
        AdvisoryPrecondition::RuntimeExecutableName { names } => match runtime
            .installation
            .executable
            .as_deref()
            .and_then(|p| Path::new(p).file_name())
            .and_then(|n| n.to_str())
        {
            Some(name) => {
                #[cfg(windows)]
                let matched = names
                    .iter()
                    .any(|candidate| candidate.eq_ignore_ascii_case(name));
                #[cfg(not(windows))]
                let matched = names.iter().any(|candidate| candidate == name);
                if matched {
                    PreconditionState::Satisfied
                } else {
                    PreconditionState::NotSatisfied
                }
            }
            None => PreconditionState::Unknown,
        },
        AdvisoryPrecondition::EnvironmentBoolean { name, value } => {
            if name == "PYTHONOPTIMIZE" {
                match runtime.configuration.python_optimized {
                    Some(v) if v == *value => PreconditionState::Satisfied,
                    Some(_) => PreconditionState::NotSatisfied,
                    None => PreconditionState::Unknown,
                }
            } else {
                PreconditionState::Unknown
            }
        }
        AdvisoryPrecondition::NetworkExposed => match runtime.configuration.network_exposure {
            PostureState::Enabled => PreconditionState::Satisfied,
            PostureState::Disabled => PreconditionState::NotSatisfied,
            _ => PreconditionState::Unknown,
        },
        AdvisoryPrecondition::ArchitectureIn { values } => match model.architecture.as_deref() {
            Some(architecture) if values.iter().any(|v| v.eq_ignore_ascii_case(architecture)) => {
                PreconditionState::Satisfied
            }
            Some(_) => PreconditionState::NotSatisfied,
            None => PreconditionState::Unknown,
        },
    }
}

pub fn evaluate_with_reason(
    condition: &AdvisoryPrecondition,
    model: &ModelSecurityContext,
    runtime: &RuntimePosture,
) -> PreconditionEvaluation {
    let state = evaluate_precondition(condition, model, runtime);
    PreconditionEvaluation {
        condition: condition.clone(),
        state,
        reason: match state {
            PreconditionState::Satisfied => "required fact was observed".into(),
            PreconditionState::NotSatisfied => {
                "observed fact does not satisfy the condition".into()
            }
            PreconditionState::Unknown => "required fact could not be established safely".into(),
        },
    }
}
