use crate::runtime_security::adapters::generic;
use crate::runtime_security::{RuntimeAdapter, RuntimeConfiguration, RuntimeKind, RuntimeProcess};
use std::collections::BTreeMap;
pub struct MlxAdapter;
pub static MLX: MlxAdapter = MlxAdapter;
impl RuntimeAdapter for MlxAdapter {
    fn kind(&self) -> RuntimeKind {
        RuntimeKind::Mlx
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
        generic::unknown_environment(env)
    }
    fn inspect_process(&self, p: &RuntimeProcess) -> RuntimeConfiguration {
        generic::process_args(p)
    }
}
