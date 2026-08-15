use crate::runtime_security::adapters::generic;
use crate::runtime_security::{RuntimeAdapter, RuntimeConfiguration, RuntimeKind, RuntimeProcess};
use std::collections::BTreeMap;
pub struct TransformersAdapter;
pub static TRANSFORMERS: TransformersAdapter = TransformersAdapter;
impl RuntimeAdapter for TransformersAdapter {
    fn kind(&self) -> RuntimeKind {
        RuntimeKind::Transformers
    }
    fn executable_names(&self) -> &'static [&'static str] {
        &[]
    }
    fn version_args(&self) -> &'static [&'static str] {
        &[]
    }
    fn parse_version(&self, _: &str) -> Option<String> {
        None
    }
    fn inspect_environment(&self, env: &BTreeMap<String, String>) -> RuntimeConfiguration {
        let mut c = generic::unknown_environment(env);
        if let Some(v) = env.get("PYTHONOPTIMIZE") {
            c.python_optimized = Some(!matches!(v.trim(), "" | "0" | "false"));
        }
        c
    }
    fn inspect_process(&self, p: &RuntimeProcess) -> RuntimeConfiguration {
        generic::process_args(p)
    }
}
