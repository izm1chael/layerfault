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
}
