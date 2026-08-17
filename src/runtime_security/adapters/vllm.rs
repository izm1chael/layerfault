use super::extract_semver;
use crate::runtime_security::adapter::{
    arg_present, arg_value, classify_host, redact_process_args,
};
use crate::runtime_security::{
    EnvironmentValueClass, PostureState, RuntimeAdapter, RuntimeConfiguration,
    RuntimeEnvironmentFact, RuntimeKind, RuntimeProcess,
};
use std::collections::BTreeMap;

pub struct VllmAdapter;
pub static VLLM: VllmAdapter = VllmAdapter;

fn optimized(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    !normalized.is_empty() && !matches!(normalized.as_str(), "0" | "false" | "no" | "off")
}

impl RuntimeAdapter for VllmAdapter {
    fn kind(&self) -> RuntimeKind {
        RuntimeKind::Vllm
    }
    fn executable_names(&self) -> &'static [&'static str] {
        &["vllm"]
    }
    fn version_args(&self) -> &'static [&'static str] {
        &["--version"]
    }
    fn parse_version(&self, raw: &str) -> Option<String> {
        extract_semver(raw)
    }

    fn inspect_environment(&self, env: &BTreeMap<String, String>) -> RuntimeConfiguration {
        let mut config = RuntimeConfiguration::default();
        if let Some(value) = env.get("PYTHONOPTIMIZE") {
            let state = optimized(value);
            config.python_optimized = Some(state);
            config.environment_facts.push(RuntimeEnvironmentFact {
                name: "PYTHONOPTIMIZE".to_owned(),
                value_class: EnvironmentValueClass::Boolean,
                present: true,
                normalized_value: Some(state.to_string()),
            });
        }
        config
    }

    fn inspect_process(&self, process: &RuntimeProcess) -> RuntimeConfiguration {
        let mut config = self.inspect_environment(&process.environment);
        config.command_args = redact_process_args(&process.args);
        if let Some(host) = arg_value(&process.args, "--host") {
            config.network_exposure = classify_host(&host);
            config.listen_addresses.push(host);
        }
        if let Some(port) = arg_value(&process.args, "--port").and_then(|p| p.parse::<u16>().ok()) {
            config.listen_ports.push(port);
        }
        config.authentication = if arg_present(&process.args, "--api-key") {
            PostureState::Enabled
        } else {
            PostureState::Disabled
        };
        config.tls = if arg_present(&process.args, "--ssl-keyfile")
            && arg_present(&process.args, "--ssl-certfile")
        {
            PostureState::Enabled
        } else {
            PostureState::Disabled
        };
        config.trust_remote_code = Some(arg_present(&process.args, "--trust-remote-code"));

        // Middleware and tool-parser plugins are operator-supplied import
        // paths loaded and executed at startup, distinct from
        // trust_remote_code (which is about code bundled with the model).
        config.custom_code_extension = Some(
            arg_present(&process.args, "--middleware")
                || arg_present(&process.args, "--tool-parser-plugin"),
        );

        // `--load-format pt` deserializes weights via torch.load, which is
        // pickle-based; every other documented load format (auto,
        // safetensors, npcache, dummy, tensorizer, ...) is not.
        config.pickle_weight_loading = arg_value(&process.args, "--load-format")
            .map(|value| value.trim().eq_ignore_ascii_case("pt"));

        // vLLM's OpenAI-compatible server defaults --allowed-origins to a
        // wildcard when the flag is not supplied; an explicit value is only
        // a wildcard if it says so.
        config.cors_wildcard_origin = Some(match arg_value(&process.args, "--allowed-origins") {
            Some(value) => value.contains('*'),
            None => true,
        });

        config.custom_chat_template = Some(arg_present(&process.args, "--chat-template"));

        // A revision is pinned only if an explicit, non-floating value was
        // given; vLLM defaults to the repository's default branch when
        // --revision is absent.
        config.revision_pinned = Some(
            arg_value(&process.args, "--revision")
                .is_some_and(|value| super::immutable_git_revision(&value)),
        );

        config.local_media_access = Some(arg_present(&process.args, "--allowed-local-media-path"));

        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn python_optimize_one_is_true() {
        let mut env = BTreeMap::new();
        env.insert("PYTHONOPTIMIZE".to_owned(), "1".to_owned());
        assert_eq!(VLLM.inspect_environment(&env).python_optimized, Some(true));
    }
    #[test]
    fn api_key_is_redacted() {
        let process = RuntimeProcess {
            pid: 1,
            executable: "vllm".into(),
            args: vec!["vllm".into(), "--api-key".into(), "secret-value".into()],
            environment: BTreeMap::new(),
        };
        let json = serde_json::to_string(&VLLM.inspect_process(&process)).unwrap();
        assert!(!json.contains("secret-value"));
        assert!(json.contains("<redacted>"));
    }

    fn process(args: &[&str]) -> RuntimeProcess {
        RuntimeProcess {
            pid: 1,
            executable: "vllm".into(),
            args: args.iter().map(|value| value.to_string()).collect(),
            environment: BTreeMap::new(),
        }
    }

    #[test]
    fn middleware_and_tool_parser_plugin_are_custom_code_extensions() {
        let config = VLLM.inspect_process(&process(&["vllm", "--middleware", "myapp.mw"]));
        assert_eq!(config.custom_code_extension, Some(true));
        let config = VLLM.inspect_process(&process(&[
            "vllm",
            "--tool-parser-plugin",
            "/opt/plugin.py",
        ]));
        assert_eq!(config.custom_code_extension, Some(true));
        let config = VLLM.inspect_process(&process(&["vllm"]));
        assert_eq!(config.custom_code_extension, Some(false));
    }

    #[test]
    fn pt_load_format_is_pickle_weight_loading_safetensors_is_not() {
        let config = VLLM.inspect_process(&process(&["vllm", "--load-format", "pt"]));
        assert_eq!(config.pickle_weight_loading, Some(true));
        let config = VLLM.inspect_process(&process(&["vllm", "--load-format", "safetensors"]));
        assert_eq!(config.pickle_weight_loading, Some(false));
        let config = VLLM.inspect_process(&process(&["vllm"]));
        assert_eq!(config.pickle_weight_loading, None);
    }

    #[test]
    fn missing_allowed_origins_defaults_to_wildcard_explicit_restriction_does_not() {
        let config = VLLM.inspect_process(&process(&["vllm"]));
        assert_eq!(config.cors_wildcard_origin, Some(true));
        let config = VLLM.inspect_process(&process(&[
            "vllm",
            "--allowed-origins",
            "[\"https://example.invalid\"]",
        ]));
        assert_eq!(config.cors_wildcard_origin, Some(false));
        let config = VLLM.inspect_process(&process(&["vllm", "--allowed-origins", "[\"*\"]"]));
        assert_eq!(config.cors_wildcard_origin, Some(true));
    }

    #[test]
    fn revision_pinning_requires_an_explicit_non_floating_value() {
        let config = VLLM.inspect_process(&process(&["vllm"]));
        assert_eq!(config.revision_pinned, Some(false));
        let config = VLLM.inspect_process(&process(&["vllm", "--revision", "main"]));
        assert_eq!(config.revision_pinned, Some(false));
        let config = VLLM.inspect_process(&process(&["vllm", "--revision", "develop"]));
        assert_eq!(config.revision_pinned, Some(false));
        let config = VLLM.inspect_process(&process(&[
            "vllm",
            "--revision",
            "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        ]));
        assert_eq!(config.revision_pinned, Some(true));
    }

    #[test]
    fn chat_template_and_local_media_flags_are_detected() {
        let config = VLLM.inspect_process(&process(&[
            "vllm",
            "--chat-template",
            "/etc/vllm/template.jinja",
        ]));
        assert_eq!(config.custom_chat_template, Some(true));
        let config = VLLM.inspect_process(&process(&[
            "vllm",
            "--allowed-local-media-path",
            "/data/media",
        ]));
        assert_eq!(config.local_media_access, Some(true));
        let config = VLLM.inspect_process(&process(&["vllm"]));
        assert_eq!(config.custom_chat_template, Some(false));
        assert_eq!(config.local_media_access, Some(false));
    }
}
