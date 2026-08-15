use super::{normalize_qualified_target, ConfigFact, ExecutionEdge, ExecutionSink};
use crate::assurance::AnalysisCompleteness;
use crate::intelligence::IntelligencePack;
use crate::runtime_security::RuntimeKind;
use crate::scanner::Confidence;

fn add(
    edges: &mut Vec<ExecutionEdge>,
    fact: &ConfigFact,
    value: &str,
    sink: ExecutionSink,
    runtime_relevance: Vec<RuntimeKind>,
) {
    let normalized = normalize_qualified_target(value);
    let complete = if normalized.is_some() {
        AnalysisCompleteness::Complete
    } else {
        AnalysisCompleteness::Partial
    };
    edges.push(ExecutionEdge {
        source_member: fact.member.clone(),
        field_path: fact.field_path.clone(),
        raw_value: value.chars().take(16 * 1024).collect(),
        normalized_target: normalized,
        sink,
        confidence: Confidence::Medium,
        completeness: complete,
        runtime_relevance,
    });
}
fn field_matches(rule: &str, path: &str) -> bool {
    rule.strip_suffix(".*").map_or(rule == path, |prefix| {
        path.starts_with(&format!("{prefix}.")) && path.len() > prefix.len() + 1
    })
}

fn sink(kind: crate::intelligence::DeclarativeSinkKind) -> ExecutionSink {
    match kind {
        crate::intelligence::DeclarativeSinkKind::DynamicImport => ExecutionSink::DynamicImport,
        crate::intelligence::DeclarativeSinkKind::CustomClass => ExecutionSink::CustomClass,
        crate::intelligence::DeclarativeSinkKind::CustomOperator => ExecutionSink::CustomOperator,
        crate::intelligence::DeclarativeSinkKind::NativeLibrary => ExecutionSink::NativeLibrary,
        crate::intelligence::DeclarativeSinkKind::TemplateExecution => {
            ExecutionSink::TemplateExecution
        }
        crate::intelligence::DeclarativeSinkKind::ProcessorModule => ExecutionSink::ProcessorModule,
        crate::intelligence::DeclarativeSinkKind::TokenizerModule => ExecutionSink::TokenizerModule,
        crate::intelligence::DeclarativeSinkKind::ActivationFunction => {
            ExecutionSink::ActivationFunction
        }
    }
}

pub fn detect(facts: &[ConfigFact], pack: Option<&IntelligencePack>) -> Vec<ExecutionEdge> {
    let mut edges = Vec::new();
    for fact in facts {
        for value in &fact.values {
            if fact.field_path.starts_with("auto_map.") {
                add(
                    &mut edges,
                    fact,
                    value,
                    ExecutionSink::DynamicImport,
                    vec![
                        RuntimeKind::Transformers,
                        RuntimeKind::Vllm,
                        RuntimeKind::TextGenerationInference,
                    ],
                );
                continue;
            }
            if matches!(
                fact.field_path.as_str(),
                "sentence_transformers.activation_fn" | "sbert_ce_default_activation_function"
            ) {
                add(
                    &mut edges,
                    fact,
                    value,
                    ExecutionSink::ActivationFunction,
                    vec![RuntimeKind::Vllm],
                );
                continue;
            }
            if matches!(
                fact.field_path.as_str(),
                "tokenizer_class"
                    | "processor_class"
                    | "feature_extractor_type"
                    | "image_processor_type"
            ) && value.contains('.')
            {
                add(
                    &mut edges,
                    fact,
                    value,
                    if fact.field_path.contains("tokenizer") {
                        ExecutionSink::TokenizerModule
                    } else {
                        ExecutionSink::ProcessorModule
                    },
                    Vec::new(),
                );
            }
            if let Some(pack) = pack {
                for record in &pack.declarative_edges {
                    if (record.source_path == fact.member
                        || fact.member.ends_with(&record.source_path))
                        && field_matches(&record.field_path, &fact.field_path)
                    {
                        add(
                            &mut edges,
                            fact,
                            value,
                            sink(record.sink_kind),
                            record
                                .affected_runtime
                                .as_deref()
                                .and_then(|value| RuntimeKind::parse(value).ok())
                                .into_iter()
                                .collect(),
                        );
                    }
                }
            }
        }
    }
    edges.sort_by(|a, b| {
        a.source_member
            .cmp(&b.source_member)
            .then(a.field_path.cmp(&b.field_path))
            .then(a.normalized_target.cmp(&b.normalized_target))
            .then(a.raw_value.cmp(&b.raw_value))
    });
    edges.dedup_by(|a, b| {
        a.source_member == b.source_member
            && a.field_path == b.field_path
            && a.raw_value == b.raw_value
            && a.sink == b.sink
    });
    edges
}
