use crate::runtime_security::adapter::{arg_present, arg_value, classify_host};
use crate::runtime_security::adapters::generic;
use crate::runtime_security::{
    PostureState, RuntimeAdapter, RuntimeConfiguration, RuntimeKind, RuntimeProcess,
};
use std::collections::BTreeMap;

pub struct TgiAdapter;
pub static TGI: TgiAdapter = TgiAdapter;
impl RuntimeAdapter for TgiAdapter {
    fn kind(&self) -> RuntimeKind {
        RuntimeKind::TextGenerationInference
    }
    fn executable_names(&self) -> &'static [&'static str] {
        &["text-generation-launcher"]
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
        if let Some(host) = arg_value(&process.args, "--hostname") {
            config.network_exposure = classify_host(&host);
            config.listen_addresses.push(host);
        } else {
            // text-generation-launcher's own documented default is 0.0.0.0
            // when --hostname is not supplied.
            config.network_exposure = PostureState::Enabled;
            config.listen_addresses.push("0.0.0.0".to_owned());
        }
        if let Some(port) = arg_value(&process.args, "--port").and_then(|p| p.parse().ok()) {
            config.listen_ports.push(port);
        }
        // text-generation-launcher has no built-in API-key/authentication
        // flag; access control is expected to be provided by a fronting
        // reverse proxy. As with Ollama, the absence of any such flag is
        // itself the observed fact, not an unknown.
        config.authentication = PostureState::Disabled;
        config.trust_remote_code = Some(arg_present(&process.args, "--trust-remote-code"));
        config.revision_pinned = Some(
            arg_value(&process.args, "--revision")
                .is_some_and(|value| super::immutable_git_revision(&value)),
        );
        config.cors_wildcard_origin =
            arg_value(&process.args, "--cors-allow-origin").map(|value| value.trim() == "*");
        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(args: &[&str]) -> RuntimeProcess {
        RuntimeProcess {
            pid: 1,
            executable: "text-generation-launcher".into(),
            args: args.iter().map(|value| value.to_string()).collect(),
            environment: BTreeMap::new(),
        }
    }

    #[test]
    fn default_hostname_is_wildcard_exposed() {
        let config = TGI.inspect_process(&process(&["text-generation-launcher"]));
        assert_eq!(config.network_exposure, PostureState::Enabled);
        assert_eq!(config.listen_addresses, vec!["0.0.0.0".to_owned()]);
    }

    #[test]
    fn explicit_loopback_hostname_is_not_exposed() {
        let config = TGI.inspect_process(&process(&[
            "text-generation-launcher",
            "--hostname",
            "127.0.0.1",
        ]));
        assert_eq!(config.network_exposure, PostureState::Disabled);
    }

    #[test]
    fn tgi_has_no_native_auth_mechanism_to_observe() {
        let config = TGI.inspect_process(&process(&["text-generation-launcher"]));
        assert_eq!(config.authentication, PostureState::Disabled);
    }

    #[test]
    fn trust_remote_code_and_revision_pinning_are_detected() {
        let config = TGI.inspect_process(&process(&[
            "text-generation-launcher",
            "--trust-remote-code",
            "--revision",
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        ]));
        assert_eq!(config.trust_remote_code, Some(true));
        assert_eq!(config.revision_pinned, Some(true));

        let config = TGI.inspect_process(&process(&[
            "text-generation-launcher",
            "--revision",
            "develop",
        ]));
        assert_eq!(config.revision_pinned, Some(false));

        let config = TGI.inspect_process(&process(&["text-generation-launcher"]));
        assert_eq!(config.trust_remote_code, Some(false));
        assert_eq!(config.revision_pinned, Some(false));
    }

    #[test]
    fn cors_allow_origin_wildcard_is_detected() {
        let config = TGI.inspect_process(&process(&[
            "text-generation-launcher",
            "--cors-allow-origin",
            "*",
        ]));
        assert_eq!(config.cors_wildcard_origin, Some(true));
        let config = TGI.inspect_process(&process(&[
            "text-generation-launcher",
            "--cors-allow-origin",
            "https://example.invalid",
        ]));
        assert_eq!(config.cors_wildcard_origin, Some(false));
    }
}
