use super::calls::{CallSite, ExecutionContext};
use super::limits::PythonAnalysisLimits;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ReachabilityState {
    Direct,
    ReachableLocal,
    PresentUnreached,
    UnknownDynamic,
}

impl std::fmt::Display for ReachabilityState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct => write!(f, "direct call at module/top scope"),
            Self::ReachableLocal => write!(f, "statically reachable from entry point"),
            Self::PresentUnreached => {
                write!(f, "present in function/class body (unreached statically)")
            }
            Self::UnknownDynamic => write!(f, "dynamic invocation context"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EntryPoint {
    pub name: String,
    pub module_path: String,
    pub is_auto_map: bool,
    pub is_constructor: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PythonRelationship {
    pub source: String,
    pub target: String,
    pub relationship_kind: String,
}

pub struct ReachabilityGraph {
    pub entry_points: Vec<EntryPoint>,
    pub relationships: Vec<PythonRelationship>,
    pub reachability_map: BTreeMap<usize, ReachabilityState>,
}

impl ReachabilityGraph {
    pub fn compute(
        call_sites: &[CallSite],
        auto_map_modules: &BTreeSet<String>,
        relative_path: &str,
        limits: &PythonAnalysisLimits,
    ) -> Self {
        let mut entry_points = Vec::new();
        let mut relationships = Vec::new();
        let mut reachability_map = BTreeMap::new();

        // 1. Check if relative_path matches an auto_map referenced module
        let file_stem = std::path::Path::new(relative_path)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("");

        let is_auto_mapped = auto_map_modules.contains(file_stem);
        if is_auto_mapped {
            entry_points.push(EntryPoint {
                name: format!("auto_map:{}", file_stem),
                module_path: relative_path.to_owned(),
                is_auto_map: true,
                is_constructor: false,
            });
            relationships.push(PythonRelationship {
                source: "config.json:auto_map".to_owned(),
                target: relative_path.to_owned(),
                relationship_kind: "hf_auto_map_module".to_owned(),
            });
        }

        for (idx, call) in call_sites.iter().enumerate() {
            let state = match call.execution_context {
                ExecutionContext::ModuleScope => ReachabilityState::Direct,
                ExecutionContext::Constructor => {
                    if is_auto_mapped {
                        ReachabilityState::ReachableLocal
                    } else {
                        ReachabilityState::PresentUnreached
                    }
                }
                ExecutionContext::FromPretrainedLike | ExecutionContext::ModelInitLike => {
                    if is_auto_mapped {
                        ReachabilityState::ReachableLocal
                    } else {
                        ReachabilityState::PresentUnreached
                    }
                }
                ExecutionContext::ClassBody => ReachabilityState::Direct,
                ExecutionContext::FunctionBody
                | ExecutionContext::ImportHook
                | ExecutionContext::Unknown => ReachabilityState::PresentUnreached,
            };

            reachability_map.insert(idx, state);

            if relationships.len() < limits.max_relationships {
                relationships.push(PythonRelationship {
                    source: format!("{}:L{:?}", relative_path, call.line.unwrap_or(0)),
                    target: if !call.resolved_target.is_empty() {
                        call.resolved_target.clone()
                    } else {
                        call.raw_target.clone()
                    },
                    relationship_kind: format!("{:?}", call.category),
                });
            }
        }

        Self {
            entry_points,
            relationships,
            reachability_map,
        }
    }
}
