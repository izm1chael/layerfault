use crate::runtime_security::adapters::generic;
use crate::runtime_security::{RuntimeAdapter, RuntimeConfiguration, RuntimeKind, RuntimeProcess};
use std::collections::BTreeMap;

pub struct KoboldCppAdapter;
pub static KOBOLD_CPP: KoboldCppAdapter = KoboldCppAdapter;
impl RuntimeAdapter for KoboldCppAdapter {
    fn kind(&self) -> RuntimeKind {
        RuntimeKind::KoboldCpp
    }
    fn executable_names(&self) -> &'static [&'static str] {
        &["koboldcpp"]
    }
    fn version_args(&self) -> &'static [&'static str] {
        &[]
    }
    fn parse_version(&self, _raw: &str) -> Option<String> {
        None
    }
    fn inspect_environment(&self, env: &BTreeMap<String, String>) -> RuntimeConfiguration {
        generic::unknown_environment(env)
    }
    fn inspect_process(&self, process: &RuntimeProcess) -> RuntimeConfiguration {
        generic::process_args(process)
    }
}
