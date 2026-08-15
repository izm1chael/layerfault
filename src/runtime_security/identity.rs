use super::{EnvironmentValueClass, RuntimeConfiguration, RuntimeEnvironmentFact};
use anyhow::Result;
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Serialize)]
struct CanonicalRuntimeConfiguration<'a> {
    listen_addresses: Vec<&'a str>,
    listen_ports: Vec<u16>,
    command_args: &'a [String],
    environment_facts: Vec<CanonicalEnvironmentFact<'a>>,
    python_optimized: Option<bool>,
    trust_remote_code: Option<bool>,
    authentication: super::PostureState,
    tls: super::PostureState,
    network_exposure: super::PostureState,
}

#[derive(Serialize)]
struct CanonicalEnvironmentFact<'a> {
    name: &'a str,
    value_class: EnvironmentValueClass,
    present: bool,
    normalized_value: Option<&'a str>,
}

pub fn configuration_identity(configuration: &RuntimeConfiguration) -> Result<String> {
    let mut listen_addresses = configuration
        .listen_addresses
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    listen_addresses.sort();
    listen_addresses.dedup();
    let mut listen_ports = configuration.listen_ports.clone();
    listen_ports.sort();
    listen_ports.dedup();
    let mut facts = configuration.environment_facts.iter().collect::<Vec<_>>();
    facts.sort_by(|a, b| a.name.cmp(&b.name));
    let facts = facts.into_iter().map(canonical_fact).collect::<Vec<_>>();
    let value = CanonicalRuntimeConfiguration {
        listen_addresses,
        listen_ports,
        command_args: &configuration.command_args,
        environment_facts: facts,
        python_optimized: configuration.python_optimized,
        trust_remote_code: configuration.trust_remote_code,
        authentication: configuration.authentication,
        tls: configuration.tls,
        network_exposure: configuration.network_exposure,
    };
    let mut hasher = Sha256::new();
    hasher.update(b"layerfault:runtime-configuration:v1\0");
    hasher.update(serde_json::to_vec(&value)?);
    Ok(format!(
        "lfruntimeconfig:v1:sha256:{}",
        hex::encode(hasher.finalize())
    ))
}

fn canonical_fact(fact: &RuntimeEnvironmentFact) -> CanonicalEnvironmentFact<'_> {
    CanonicalEnvironmentFact {
        name: &fact.name,
        value_class: fact.value_class,
        present: fact.present,
        normalized_value: match fact.value_class {
            EnvironmentValueClass::Opaque => None,
            _ => fact.normalized_value.as_deref(),
        },
    }
}
