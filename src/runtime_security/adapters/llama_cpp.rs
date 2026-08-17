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
        // `--api-key-file` is an equally valid authentication mechanism to
        // `--api-key`; treating only the latter as "authenticated" would
        // misreport a key-file-authenticated server as unauthenticated.
        config.authentication = if arg_present(&process.args, "--api-key")
            || arg_present(&process.args, "--api-key-file")
        {
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
        // `--slots` enables llama-server's /slots endpoint, which returns
        // the current contents of every active slot — including other
        // clients' in-flight prompts on a shared server. This is
        // llama.cpp's own documented reason the endpoint defaults off.
        config.cross_tenant_state_exposure = Some(arg_present(&process.args, "--slots"));
        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(args: &[&str]) -> RuntimeProcess {
        RuntimeProcess {
            pid: 1,
            executable: "llama-server".into(),
            args: args.iter().map(|value| value.to_string()).collect(),
            environment: BTreeMap::new(),
        }
    }

    #[test]
    fn api_key_file_counts_as_authentication_enabled() {
        let config = LLAMA_CPP.inspect_process(&process(&[
            "llama-server",
            "--api-key-file",
            "/etc/llama/key.txt",
        ]));
        assert_eq!(config.authentication, PostureState::Enabled);
    }

    #[test]
    fn no_auth_flag_is_disabled() {
        let config = LLAMA_CPP.inspect_process(&process(&["llama-server"]));
        assert_eq!(config.authentication, PostureState::Disabled);
    }

    #[test]
    fn slots_flag_is_cross_tenant_state_exposure() {
        let config = LLAMA_CPP.inspect_process(&process(&["llama-server", "--slots"]));
        assert_eq!(config.cross_tenant_state_exposure, Some(true));
        let config = LLAMA_CPP.inspect_process(&process(&["llama-server"]));
        assert_eq!(config.cross_tenant_state_exposure, Some(false));
    }

    #[test]
    fn secret_shaped_args_are_redacted() {
        let process = process(&["llama-server", "--api-key", "secret-value"]);
        let json = serde_json::to_string(&LLAMA_CPP.inspect_process(&process)).unwrap();
        assert!(!json.contains("secret-value"));
        assert!(json.contains("<redacted>"));
    }
}
