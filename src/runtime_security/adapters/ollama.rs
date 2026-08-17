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
        // Ollama's server has no built-in authentication or TLS mechanism
        // at all in the versions this adapter targets — there is no flag or
        // environment variable to check for, because the capability does
        // not exist. Reporting `Unknown` here (as an earlier version of
        // this adapter did) meant an exposed, wide-open Ollama install
        // never triggered the generic auth/TLS-absent findings, since
        // those only fire on an observed `Disabled` state. The absence
        // itself is the observed fact.
        config.authentication = PostureState::Disabled;
        config.tls = PostureState::Disabled;
        config.cors_wildcard_origin = env
            .get("OLLAMA_ORIGINS")
            .map(|value| value.split(',').any(|origin| origin.trim() == "*"));
        config
    }

    fn inspect_process(&self, process: &RuntimeProcess) -> RuntimeConfiguration {
        let mut config = self.inspect_environment(&process.environment);
        config.command_args = crate::runtime_security::adapter::redact_process_args(&process.args);
        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ollama_has_no_native_auth_or_tls_mechanism_to_observe() {
        // Not `Unknown`: Ollama genuinely has no such flag, and the
        // generic auth/TLS-absent findings only fire on an observed
        // `Disabled`, so this must be reported as `Disabled`, not
        // `Unknown`, for an exposed install to be flagged at all.
        let config = OLLAMA.inspect_environment(&BTreeMap::new());
        assert_eq!(config.authentication, PostureState::Disabled);
        assert_eq!(config.tls, PostureState::Disabled);
    }

    #[test]
    fn ollama_origins_wildcard_is_detected() {
        let mut env = BTreeMap::new();
        env.insert("OLLAMA_ORIGINS".to_owned(), "*".to_owned());
        assert_eq!(
            OLLAMA.inspect_environment(&env).cors_wildcard_origin,
            Some(true)
        );

        let mut env = BTreeMap::new();
        env.insert(
            "OLLAMA_ORIGINS".to_owned(),
            "https://example.invalid,https://other.invalid".to_owned(),
        );
        assert_eq!(
            OLLAMA.inspect_environment(&env).cors_wildcard_origin,
            Some(false)
        );

        assert_eq!(
            OLLAMA
                .inspect_environment(&BTreeMap::new())
                .cors_wildcard_origin,
            None
        );
    }

    #[test]
    fn wildcard_host_is_network_exposed() {
        let mut env = BTreeMap::new();
        env.insert("OLLAMA_HOST".to_owned(), "0.0.0.0:11434".to_owned());
        assert_eq!(
            OLLAMA.inspect_environment(&env).network_exposure,
            PostureState::Enabled
        );
    }

    #[test]
    fn secret_shaped_args_are_redacted() {
        let process = RuntimeProcess {
            pid: 1,
            executable: "ollama".into(),
            args: vec![
                "ollama".into(),
                "serve".into(),
                "--token".into(),
                "secret-value".into(),
            ],
            environment: BTreeMap::new(),
        };
        let json = serde_json::to_string(&OLLAMA.inspect_process(&process)).unwrap();
        assert!(!json.contains("secret-value"));
        assert!(json.contains("<redacted>"));
    }
}
