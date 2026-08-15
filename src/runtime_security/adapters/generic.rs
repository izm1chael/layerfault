use crate::runtime_security::{RuntimeConfiguration, RuntimeProcess};
use std::collections::BTreeMap;

pub(crate) fn unknown_environment(_env: &BTreeMap<String, String>) -> RuntimeConfiguration {
    RuntimeConfiguration::default()
}

pub(crate) fn process_args(process: &RuntimeProcess) -> RuntimeConfiguration {
    RuntimeConfiguration {
        command_args: crate::runtime_security::adapter::redact_process_args(&process.args),
        ..RuntimeConfiguration::default()
    }
}
