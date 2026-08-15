use super::{ExecutionEdge, ExecutionSink};
use crate::finding_evidence::{EvidenceKind, EvidenceSubject, FindingBuilder, FindingEvidence};
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};

pub(crate) fn findings(edges: &[ExecutionEdge], identity: &str) -> Vec<LayerScanResult> {
    edges.iter().filter_map(|e|{
    if e.field_path.starts_with("auto_map."){return None}
    let (rule,status)=match e.sink{ExecutionSink::ActivationFunction=>("LF-CONFIG-ACTIVATION-IMPORT",ScanStatus::Warn),ExecutionSink::DynamicImport=>("LF-CONFIG-DYNAMIC-IMPORT",ScanStatus::Fail),ExecutionSink::CustomClass|ExecutionSink::ProcessorModule|ExecutionSink::TokenizerModule=>("LF-CONFIG-CUSTOM-CLASS",ScanStatus::Warn),_=>return None};
    let subject=EvidenceSubject::identity(identity,"application/vnd.layerfault.package+json").with_package_relative_path(Some(e.source_member.clone()));
    Some(FindingBuilder::new(rule,CheckType::DeclarativeExecution,status).class(FindingClass::ContentIndicator).confidence(if status==ScanStatus::Fail{Confidence::High}else{Confidence::Medium}).subject(subject.clone()).detail(format!("{} can reach {:?}: {}",e.field_path,e.sink,e.normalized_target.as_deref().unwrap_or("unresolved"))).evidence(FindingEvidence::new(EvidenceKind::ExecutionEdge,subject,"Declarative configuration to executable sink").structured(serde_json::json!({"field_path":e.field_path,"value":e.raw_value,"target":e.normalized_target,"sink":e.sink,"runtime_relevance":e.runtime_relevance}))).finish())
}).collect()
}
