//! Stable transformation claim vocabulary used by lineage evidence.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LineageState {
    Verified,
    Consistent,
    Unverified,
    Contradicted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DerivedIntegrityState {
    Verified,
    Consistent,
    Unverified,
    Anomalous,
    Contradicted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BehaviourState {
    NotRun,
    NoSuspiciousObserved,
    Suspicious,
    HighRisk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DifferentialBehaviourState {
    NotRun,
    Expected,
    NeutralVariation,
    CapabilityChange,
    SecurityRegression,
    SuspiciousTrigger,
    HighRiskBehaviour,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransformationType {
    FineTune,
    LoraAdapter,
    LoraMerge,
    Quantization,
    Conversion,
    TokenizerModification,
    TemplateModification,
    Repackaging,
    Other,
}

impl TransformationType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FineTune => "finetune",
            Self::LoraAdapter => "lora",
            Self::LoraMerge => "lora-merge",
            Self::Quantization => "quantization",
            Self::Conversion => "conversion",
            Self::TokenizerModification => "tokenizer-modification",
            Self::TemplateModification => "template-modification",
            Self::Repackaging => "repackaging",
            Self::Other => "other",
        }
    }
}
