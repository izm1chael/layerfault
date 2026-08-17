use crate::runtime_security::adapter::{arg_present, arg_value, classify_host};
use crate::runtime_security::adapters::generic;
use crate::runtime_security::{
    PostureState, RuntimeAdapter, RuntimeConfiguration, RuntimeKind, RuntimeProcess,
};
use std::collections::BTreeMap;

pub struct LocalAiAdapter;
pub static LOCAL_AI: LocalAiAdapter = LocalAiAdapter;
impl RuntimeAdapter for LocalAiAdapter {
    fn kind(&self) -> RuntimeKind {
        RuntimeKind::LocalAi
    }
    fn executable_names(&self) -> &'static [&'static str] {
        &["local-ai"]
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
        let mut config = generic::process_args(process);
        // LocalAI's `--address` combines host and port (default
        // ":8080", i.e. all interfaces).
        if let Some(address) = arg_value(&process.args, "--address") {
            let host_part = address
                .rsplit_once(':')
                .map_or(address.as_str(), |(host, _)| host);
            let host_part = if host_part.is_empty() {
                "0.0.0.0"
            } else {
                host_part
            };
            config.network_exposure = classify_host(host_part);
            config.listen_addresses.push(host_part.to_owned());
        } else {
            config.network_exposure = PostureState::Enabled;
            config.listen_addresses.push("0.0.0.0".to_owned());
        }
        config.authentication = if arg_present(&process.args, "--api-keys") {
            PostureState::Enabled
        } else {
            PostureState::Disabled
        };
        config.cors_wildcard_origin = if arg_present(&process.args, "--cors") {
            Some(
                arg_value(&process.args, "--cors-allow-origins")
                    .is_none_or(|value| value.trim() == "*"),
            )
        } else {
            Some(false)
        };
        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(args: &[&str]) -> RuntimeProcess {
        RuntimeProcess {
            pid: 1,
            executable: "local-ai".into(),
            args: args.iter().map(|value| value.to_string()).collect(),
            environment: BTreeMap::new(),
        }
    }

    #[test]
    fn address_with_empty_host_is_wildcard_exposed() {
        let config = LOCAL_AI.inspect_process(&process(&["local-ai", "--address", ":8080"]));
        assert_eq!(config.network_exposure, PostureState::Enabled);
    }

    #[test]
    fn default_address_is_wildcard_exposed() {
        let config = LOCAL_AI.inspect_process(&process(&["local-ai"]));
        assert_eq!(config.network_exposure, PostureState::Enabled);
        assert_eq!(config.listen_addresses, vec!["0.0.0.0".to_owned()]);
    }

    #[test]
    fn address_with_loopback_host_is_not_exposed() {
        let config =
            LOCAL_AI.inspect_process(&process(&["local-ai", "--address", "127.0.0.1:8080"]));
        assert_eq!(config.network_exposure, PostureState::Disabled);
    }

    #[test]
    fn api_keys_flag_enables_authentication() {
        let config =
            LOCAL_AI.inspect_process(&process(&["local-ai", "--api-keys", "key-one,key-two"]));
        assert_eq!(config.authentication, PostureState::Enabled);
        let config = LOCAL_AI.inspect_process(&process(&["local-ai"]));
        assert_eq!(config.authentication, PostureState::Disabled);
    }

    #[test]
    fn cors_without_explicit_origins_defaults_to_wildcard() {
        let config = LOCAL_AI.inspect_process(&process(&["local-ai", "--cors"]));
        assert_eq!(config.cors_wildcard_origin, Some(true));
        let config = LOCAL_AI.inspect_process(&process(&[
            "local-ai",
            "--cors",
            "--cors-allow-origins",
            "https://example.invalid",
        ]));
        assert_eq!(config.cors_wildcard_origin, Some(false));
        let config = LOCAL_AI.inspect_process(&process(&["local-ai"]));
        assert_eq!(config.cors_wildcard_origin, Some(false));
    }
}
