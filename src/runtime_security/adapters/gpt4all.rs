use crate::runtime_security::adapters::generic;
use crate::runtime_security::{RuntimeAdapter, RuntimeConfiguration, RuntimeKind, RuntimeProcess};
use std::collections::BTreeMap;

pub struct Gpt4AllAdapter;
pub static GPT4ALL: Gpt4AllAdapter = Gpt4AllAdapter;
impl RuntimeAdapter for Gpt4AllAdapter {
    fn kind(&self) -> RuntimeKind {
        RuntimeKind::Gpt4All
    }
    fn executable_names(&self) -> &'static [&'static str] {
        &["gpt4all"]
    }
    fn version_args(&self) -> &'static [&'static str] {
        &["--version"]
    }
    fn parse_version(&self, raw: &str) -> Option<String> {
        super::extract_semver(raw)
    }
    fn inspect_environment(&self, env: &BTreeMap<String, String>) -> RuntimeConfiguration {
        generic::unknown_environment(env)
    }
    fn inspect_process(&self, process: &RuntimeProcess) -> RuntimeConfiguration {
        generic::process_args(process)
    }
}
