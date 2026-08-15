use crate::runtime_security::adapters::generic;
use crate::runtime_security::{RuntimeAdapter, RuntimeConfiguration, RuntimeKind, RuntimeProcess};
use std::collections::BTreeMap;

pub struct TextGenerationWebUiAdapter;
pub static TEXTGEN_WEBUI: TextGenerationWebUiAdapter = TextGenerationWebUiAdapter;
impl RuntimeAdapter for TextGenerationWebUiAdapter {
    fn kind(&self) -> RuntimeKind {
        RuntimeKind::TextGenerationWebUi
    }
    fn executable_names(&self) -> &'static [&'static str] {
        &["text-generation-webui", "server.py"]
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
