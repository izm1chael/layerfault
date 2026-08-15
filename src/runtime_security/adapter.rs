use super::{RuntimeConfiguration, RuntimeKind};
use std::collections::BTreeMap;

pub trait RuntimeAdapter: Sync {
    fn kind(&self) -> RuntimeKind;
    fn executable_names(&self) -> &'static [&'static str];
    fn version_args(&self) -> &'static [&'static str];
    fn parse_version(&self, raw: &str) -> Option<String>;
    fn inspect_environment(&self, env: &BTreeMap<String, String>) -> RuntimeConfiguration;
    fn inspect_process(&self, process: &RuntimeProcess) -> RuntimeConfiguration;
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RuntimeProcess {
    pub pid: u32,
    pub executable: String,
    pub args: Vec<String>,
    pub environment: BTreeMap<String, String>,
}

pub(crate) const SAFE_ENVIRONMENT_NAMES: &[&str] = &[
    "OLLAMA_HOST",
    "OLLAMA_ORIGINS",
    "OLLAMA_MODELS",
    "OLLAMA_KEEP_ALIVE",
    "PYTHONOPTIMIZE",
    "VIRTUAL_ENV",
    "CONDA_PREFIX",
];

pub(crate) fn is_safe_environment_name(name: &str) -> bool {
    SAFE_ENVIRONMENT_NAMES
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(name))
}

fn secret_flag(flag: &str) -> bool {
    matches!(
        flag.to_ascii_lowercase().as_str(),
        "--api-key"
            | "--apikey"
            | "--token"
            | "--auth-token"
            | "--password"
            | "--authorization"
            | "--ssl-keyfile-password"
    )
}

pub(crate) fn redact_process_args(args: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut redact_next = false;
    for arg in args {
        if redact_next {
            out.push("<redacted>".to_owned());
            redact_next = false;
            continue;
        }
        if let Some((key, _)) = arg.split_once('=') {
            if secret_flag(key) {
                out.push(format!("{key}=<redacted>"));
                continue;
            }
        }
        if secret_flag(arg) {
            redact_next = true;
        }
        out.push(arg.clone());
    }
    out
}

pub(crate) fn arg_value(args: &[String], flag: &str) -> Option<String> {
    for (index, arg) in args.iter().enumerate() {
        if arg == flag {
            return args.get(index + 1).cloned();
        }
        let prefix = format!("{flag}=");
        if let Some(value) = arg.strip_prefix(&prefix) {
            return Some(value.to_owned());
        }
    }
    None
}

pub(crate) fn arg_present(args: &[String], flag: &str) -> bool {
    args.iter()
        .any(|arg| arg == flag || arg.starts_with(&format!("{flag}=")))
}

pub(crate) fn classify_host(host: &str) -> super::PostureState {
    let host = host.trim().trim_matches(['[', ']']);
    if host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "::1"
        || host.starts_with("127.")
    {
        super::PostureState::Disabled
    } else if host == "0.0.0.0" || host == "::" || !host.is_empty() {
        super::PostureState::Enabled
    } else {
        super::PostureState::Unknown
    }
}
