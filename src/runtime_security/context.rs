use crate::coverage::Coverage;
use crate::finding_evidence::EvidenceSubject;
use crate::model::metadata::ModelSnapshot;
use crate::scanner::LayerScanResult;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_NORMALIZED_FACTS: usize = 4096;
pub const MAX_NORMALIZED_STRING_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelSecurityContext {
    pub subject: EvidenceSubject,
    pub format: Option<String>,
    pub architecture: Option<String>,
    #[serde(default)]
    pub rules_present: BTreeSet<String>,
    #[serde(default)]
    pub config: BTreeMap<String, NormalizedFact>,
    #[serde(default)]
    pub execution_edges: Vec<crate::model::declarative::ExecutionEdge>,
    pub coverage: Coverage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum NormalizedFact {
    String(String),
    Bool(bool),
    Integer(i64),
    StringList(Vec<String>),
}

impl ModelSecurityContext {
    pub fn from_artifact_report(
        subject: EvidenceSubject,
        format: Option<String>,
        architecture: Option<String>,
        findings: &[LayerScanResult],
        coverage: Coverage,
    ) -> Self {
        Self {
            subject,
            format,
            architecture,
            rules_present: findings.iter().filter_map(|f| f.rule_id.clone()).collect(),
            config: BTreeMap::new(),
            execution_edges: Vec::new(),
            coverage,
        }
    }

    pub fn from_package_report(report: &crate::package::PackageReport) -> Self {
        let subject = EvidenceSubject::identity(
            &report.merkle_identity,
            "application/vnd.layerfault.package+json",
        );
        let mut context = Self::from_artifact_report(
            subject,
            Some("package".to_owned()),
            None,
            &report.findings,
            report.coverage.clone(),
        );
        context.execution_edges = report.execution_edges.clone();
        for finding in &report.findings {
            for evidence in &finding.evidence {
                if let Some(value) = evidence.structured.as_ref() {
                    collect_known_config_facts(value, &mut context.config);
                }
            }
        }
        context
    }

    pub fn merge_snapshot(&mut self, snapshot: &ModelSnapshot) {
        self.format = Some(snapshot.format.clone());
        self.architecture = snapshot.architecture.architecture.clone();
        if let Some(arch) = snapshot.architecture.architecture.as_ref() {
            self.insert_fact(
                "config.architectures",
                NormalizedFact::StringList(vec![arch.clone()]),
            );
        }
        for (key, value) in &snapshot.claims {
            let path = if key.starts_with("config.") {
                key.clone()
            } else {
                format!("config.{key}")
            };
            if let Some(fact) = normalize_json(value) {
                self.insert_fact(&path, fact);
            }
        }
    }

    pub fn insert_fact(&mut self, path: &str, fact: NormalizedFact) {
        if self.config.len() >= MAX_NORMALIZED_FACTS && !self.config.contains_key(path) {
            return;
        }
        if path.len() > MAX_NORMALIZED_STRING_BYTES {
            return;
        }
        if fact_within_bounds(&fact) {
            self.config.insert(path.to_owned(), fact);
        }
    }
}

fn fact_within_bounds(fact: &NormalizedFact) -> bool {
    match fact {
        NormalizedFact::String(v) => v.len() <= MAX_NORMALIZED_STRING_BYTES,
        NormalizedFact::Bool(_) | NormalizedFact::Integer(_) => true,
        NormalizedFact::StringList(values) => {
            values.len() <= 256
                && values
                    .iter()
                    .all(|v| v.len() <= MAX_NORMALIZED_STRING_BYTES)
        }
    }
}

fn normalize_json(value: &serde_json::Value) -> Option<NormalizedFact> {
    match value {
        serde_json::Value::String(v) if v.len() <= MAX_NORMALIZED_STRING_BYTES => {
            Some(NormalizedFact::String(v.clone()))
        }
        serde_json::Value::Bool(v) => Some(NormalizedFact::Bool(*v)),
        serde_json::Value::Number(v) => v.as_i64().map(NormalizedFact::Integer),
        serde_json::Value::Array(values) => {
            let list = values
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .take(256)
                .collect::<Vec<_>>();
            if list.is_empty() {
                None
            } else {
                Some(NormalizedFact::StringList(list))
            }
        }
        serde_json::Value::Object(map) => {
            let mut list = Vec::new();
            for (key, value) in map.iter().take(128) {
                list.push(key.clone());
                if let Some(value) = value.as_str() {
                    list.push(value.to_owned());
                }
                if list.len() >= 256 {
                    break;
                }
            }
            if list.is_empty() {
                None
            } else {
                Some(NormalizedFact::StringList(list))
            }
        }
        _ => None,
    }
}

fn collect_known_config_facts(
    value: &serde_json::Value,
    output: &mut BTreeMap<String, NormalizedFact>,
) {
    fn walk(
        prefix: &str,
        value: &serde_json::Value,
        output: &mut BTreeMap<String, NormalizedFact>,
    ) {
        if output.len() >= MAX_NORMALIZED_FACTS {
            return;
        }
        let watched = [
            "auto_map",
            "architectures",
            "sentence_transformers.activation_fn",
            "sbert_ce_default_activation_function",
            "trust_remote_code",
        ];
        if watched.iter().any(|suffix| prefix.ends_with(suffix)) {
            if let Some(fact) = normalize_json(value) {
                output.insert(format!("config.{prefix}"), fact);
            }
        }
        if let serde_json::Value::Object(map) = value {
            for (key, child) in map.iter().take(512) {
                let next = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                walk(&next, child, output);
            }
        }
    }
    walk("", value, output);
}
