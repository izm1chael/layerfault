use super::extract_semver;
use crate::runtime_security::adapter::classify_host;
use crate::runtime_security::{
    EnvironmentValueClass, PostureState, RuntimeAdapter, RuntimeConfiguration,
    RuntimeEnvironmentFact, RuntimeKind, RuntimeProcess,
};
use std::collections::BTreeMap;

pub struct OllamaAdapter;
pub static OLLAMA: OllamaAdapter = OllamaAdapter;

impl RuntimeAdapter for OllamaAdapter {
    fn kind(&self) -> RuntimeKind {
        RuntimeKind::Ollama
    }
    fn executable_names(&self) -> &'static [&'static str] {
        &["ollama"]
    }
    fn version_args(&self) -> &'static [&'static str] {
        &["--version"]
    }
    fn parse_version(&self, raw: &str) -> Option<String> {
        extract_semver(raw)
    }

    fn inspect_environment(&self, env: &BTreeMap<String, String>) -> RuntimeConfiguration {
        let mut config = RuntimeConfiguration::default();
        for name in [
            "OLLAMA_HOST",
            "OLLAMA_ORIGINS",
            "OLLAMA_MODELS",
            "OLLAMA_KEEP_ALIVE",
        ] {
            if let Some(value) = env.get(name) {
                let normalized = if name == "OLLAMA_MODELS" {
                    Some("present".to_owned())
                } else {
                    Some(value.chars().take(4096).collect())
                };
                config.environment_facts.push(RuntimeEnvironmentFact {
                    name: name.to_owned(),
                    value_class: if name == "OLLAMA_HOST" {
                        EnvironmentValueClass::Address
                    } else {
                        EnvironmentValueClass::Opaque
                    },
                    present: true,
                    normalized_value: normalized,
                });
            }
        }
        if let Some(host) = env.get("OLLAMA_HOST") {
            let host_part = host
                .strip_prefix("http://")
                .or_else(|| host.strip_prefix("https://"))
                .unwrap_or(host)
                .split(':')
                .next()
                .unwrap_or(host);
            config.listen_addresses.push(host_part.to_owned());
            config.network_exposure = classify_host(host_part);
        }
        config.authentication = PostureState::Unknown;
        config.tls = PostureState::Unknown;
        config
    }

    fn inspect_process(&self, process: &RuntimeProcess) -> RuntimeConfiguration {
        let mut config = self.inspect_environment(&process.environment);
        config.command_args = crate::runtime_security::adapter::redact_process_args(&process.args);
        config
    }
}
