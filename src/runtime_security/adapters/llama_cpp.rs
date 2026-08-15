use super::{extract_build, extract_semver};
use crate::runtime_security::adapter::{
    arg_present, arg_value, classify_host, redact_process_args,
};
use crate::runtime_security::{
    PostureState, RuntimeAdapter, RuntimeConfiguration, RuntimeKind, RuntimeProcess,
};
use std::collections::BTreeMap;

pub struct LlamaCppAdapter;
pub static LLAMA_CPP: LlamaCppAdapter = LlamaCppAdapter;
impl RuntimeAdapter for LlamaCppAdapter {
    fn kind(&self) -> RuntimeKind {
        RuntimeKind::LlamaCpp
    }
    fn executable_names(&self) -> &'static [&'static str] {
        &["llama-cli", "llama-server", "rpc-server"]
    }
    fn version_args(&self) -> &'static [&'static str] {
        &["--version"]
    }
    fn parse_version(&self, raw: &str) -> Option<String> {
        extract_build(raw).or_else(|| extract_semver(raw))
    }
    fn inspect_environment(&self, _env: &BTreeMap<String, String>) -> RuntimeConfiguration {
        RuntimeConfiguration::default()
    }
    fn inspect_process(&self, process: &RuntimeProcess) -> RuntimeConfiguration {
        let mut config = RuntimeConfiguration {
            command_args: redact_process_args(&process.args),
            ..RuntimeConfiguration::default()
        };
        if let Some(host) = arg_value(&process.args, "--host") {
            config.network_exposure = classify_host(&host);
            config.listen_addresses.push(host);
        }
        if let Some(port) = arg_value(&process.args, "--port").and_then(|v| v.parse().ok()) {
            config.listen_ports.push(port);
        }
        config.authentication = if arg_present(&process.args, "--api-key") {
            PostureState::Enabled
        } else {
            PostureState::Disabled
        };
        config.tls = if arg_present(&process.args, "--ssl-key-file")
            && arg_present(&process.args, "--ssl-cert-file")
        {
            PostureState::Enabled
        } else {
            PostureState::Disabled
        };
        config
    }
}
