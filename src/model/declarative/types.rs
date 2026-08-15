use crate::assurance::AnalysisCompleteness;
use crate::runtime_security::RuntimeKind;
use crate::scanner::Confidence;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionEdge {
    pub source_member: String,
    pub field_path: String,
    pub raw_value: String,
    pub normalized_target: Option<String>,
    pub sink: ExecutionSink,
    pub confidence: Confidence,
    pub completeness: AnalysisCompleteness,
    #[serde(default)]
    pub runtime_relevance: Vec<RuntimeKind>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionSink {
    DynamicImport,
    CustomClass,
    CustomOperator,
    NativeLibrary,
    TemplateExecution,
    ProcessorModule,
    TokenizerModule,
    ActivationFunction,
}

#[derive(Debug, Clone)]
pub struct ConfigFact {
    pub member: String,
    pub field_path: String,
    pub values: Vec<String>,
}
