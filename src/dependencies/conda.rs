//! `environment.yml`/`environment.yaml` and Conda lockfile parsing.
//!
//! Parsed with `yaml-rust2`, a safe, tag-free, data-only YAML 1.1 parser: the
//! result is a plain `Yaml` enum tree (Array/Hash/String/Integer/Real/
//! Boolean/Null/BadValue), never an arbitrary Rust type constructed from a
//! YAML tag.

use super::requirements::parse_requirement_line;
use super::risk::{self, RiskFinding};
use super::types::{DependencyEcosystem, DependencyRecord, DependencySource};
use crate::coverage::Coverage;
use crate::finding_evidence::{EvidenceLocation, EvidenceSubject};
use crate::scanner::{Confidence, ScanStatus};
use yaml_rust2::{Yaml, YamlLoader};

const DEFAULT_CHANNELS: &[&str] = &[
    "defaults",
    "conda-forge",
    "nodefaults",
    "pkgs/main",
    "pkgs/free",
];

#[derive(Debug, Default)]
pub struct CondaOutcome {
    pub records: Vec<DependencyRecord>,
    pub issues: Vec<RiskFinding>,
}

pub fn parse_environment_yaml(
    relative_path: &str,
    source: &str,
    coverage: &mut Coverage,
) -> CondaOutcome {
    let mut outcome = CondaOutcome::default();
    let subject = EvidenceSubject::member(relative_path);

    let docs = match YamlLoader::load_from_str(source) {
        Ok(docs) => docs,
        Err(error) => {
            coverage.parser_failure(&format!("'{relative_path}' is not valid YAML: {error}"));
            return outcome;
        }
    };
    let Some(doc) = docs.first() else {
        return outcome;
    };

    for channel in doc["channels"].as_vec().into_iter().flatten() {
        if let Some(channel) = channel.as_str() {
            if channel.contains("://") {
                outcome.issues.extend(risk::index_finding(
                    relative_path,
                    &subject,
                    None,
                    channel,
                    "channels",
                ));
            } else if !DEFAULT_CHANNELS.contains(&channel) {
                outcome.issues.push(RiskFinding {
                    rule_id: "LF-DEP-ALT-INDEX",
                    status: ScanStatus::Warn,
                    confidence: Confidence::Low,
                    detail: format!(
                        "'{relative_path}' declares non-default Conda channel '{channel}'"
                    ),
                    evidence: vec![crate::finding_evidence::config_value(
                        subject.clone(),
                        "channels",
                        serde_json::Value::String(channel.to_owned()),
                        "Non-default Conda channel declared",
                    )
                    .at(EvidenceLocation::Metadata {
                        key: "channels".to_owned(),
                    })],
                });
            }
        }
    }

    if let Some(deps) = doc["dependencies"].as_vec() {
        for (index, item) in deps.iter().enumerate() {
            if let Some(spec) = item.as_str() {
                outcome
                    .records
                    .push(parse_conda_spec(relative_path, spec, index as u64));
                continue;
            }
            if let Yaml::Hash(map) = item {
                for (key, value) in map {
                    if key.as_str() == Some("pip") {
                        for pip_item in value.as_vec().into_iter().flatten() {
                            if let Some(spec) = pip_item.as_str() {
                                let mut record = parse_requirement_line(spec, relative_path);
                                record.ecosystem = Some(DependencyEcosystem::Pip);
                                record.location = Some(EvidenceLocation::Record {
                                    index: index as u64,
                                });
                                outcome.records.push(record);
                            }
                        }
                    }
                }
            }
        }
    }

    outcome
}

fn parse_conda_spec(declared_in: &str, spec: &str, index: u64) -> DependencyRecord {
    let mut record = DependencyRecord::new(declared_in, spec);
    record.ecosystem = Some(DependencyEcosystem::Conda);
    record.location = Some(EvidenceLocation::Record { index });

    const OPERATORS: [&str; 6] = ["==", "=", "!=", ">=", "<=", ">"];
    let mut best: Option<(usize, &str)> = None;
    for op in OPERATORS {
        if let Some(idx) = spec.find(op) {
            if best.map(|(current, _)| idx < current).unwrap_or(true) {
                best = Some((idx, op));
            }
        }
    }
    let (name, constraint) = match best {
        Some((idx, _)) => (spec[..idx].trim(), Some(spec[idx..].trim().to_owned())),
        None => (spec.trim(), None),
    };
    record.name = Some(name.to_owned());
    record.version_constraint = constraint.clone();
    record.source = Some(DependencySource::Registry {
        index_url: None,
        extra_index: false,
    });
    record.is_floating = !constraint.as_deref().is_some_and(|c| c.starts_with('='));
    record
}

/// Parse a Conda lockfile (`conda-lock.yml`, `*.conda-lock.yml`). Locked
/// entries are exact resolved distributions, so they are never floating.
pub fn parse_conda_lock(
    relative_path: &str,
    source: &str,
    coverage: &mut Coverage,
) -> CondaOutcome {
    let mut outcome = CondaOutcome::default();
    let subject = EvidenceSubject::member(relative_path);
    let docs = match YamlLoader::load_from_str(source) {
        Ok(docs) => docs,
        Err(error) => {
            coverage.parser_failure(&format!("'{relative_path}' is not valid YAML: {error}"));
            return outcome;
        }
    };
    let Some(doc) = docs.first() else {
        return outcome;
    };
    for (index, item) in doc["package"].as_vec().into_iter().flatten().enumerate() {
        let name = item["name"].as_str().unwrap_or("<unknown>").to_owned();
        let manager = item["manager"].as_str().unwrap_or("conda");
        let mut record = DependencyRecord::new(relative_path, &name);
        record.ecosystem = Some(if manager == "pip" {
            DependencyEcosystem::Pip
        } else {
            DependencyEcosystem::Conda
        });
        record.name = Some(name);
        record.location = Some(EvidenceLocation::Record {
            index: index as u64,
        });
        record.is_floating = false;
        record.has_hash_pin = !item["hash"].is_badvalue();
        if let Some(url) = item["url"].as_str() {
            let redacted = risk::redact_url(url);
            record.source = Some(DependencySource::DirectUrl {
                url: redacted.normalized.clone(),
                has_hash: record.has_hash_pin,
            });
            if redacted.is_plaintext_http {
                outcome.issues.push(RiskFinding {
                    rule_id: "LF-DEP-INSECURE-TRANSPORT",
                    status: ScanStatus::Warn,
                    confidence: Confidence::High,
                    detail: format!(
                        "'{relative_path}' locks a package distribution over a non-HTTPS transport"
                    ),
                    evidence: vec![crate::finding_evidence::config_value(
                        subject.clone(),
                        "package.url",
                        serde_json::Value::String(redacted.normalized),
                        "Insecure transport for locked package distribution",
                    )
                    .at(EvidenceLocation::Record {
                        index: index as u64,
                    })],
                });
            }
        } else {
            record.source = Some(DependencySource::Registry {
                index_url: None,
                extra_index: false,
            });
        }
        outcome.records.push(record);
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_channel_is_flagged() {
        let mut coverage = Coverage::complete(1, 1);
        let outcome = parse_environment_yaml(
            "environment.yml",
            "name: env\nchannels:\n  - my-private-channel\ndependencies:\n  - numpy\n",
            &mut coverage,
        );
        assert!(outcome
            .issues
            .iter()
            .any(|issue| issue.rule_id == "LF-DEP-ALT-INDEX"));
    }

    #[test]
    fn nested_pip_direct_url_parses() {
        let mut coverage = Coverage::complete(1, 1);
        let outcome = parse_environment_yaml(
            "environment.yml",
            "dependencies:\n  - python\n  - pip:\n    - git+https://github.com/x/y.git\n",
            &mut coverage,
        );
        assert!(outcome
            .records
            .iter()
            .any(|record| matches!(record.source, Some(DependencySource::Vcs { .. }))));
    }

    #[test]
    fn malformed_yaml_is_incomplete() {
        let mut coverage = Coverage::complete(1, 1);
        let _ = parse_environment_yaml(
            "environment.yml",
            "dependencies: [unterminated",
            &mut coverage,
        );
        assert!(!coverage.complete);
    }

    #[test]
    fn pinned_conda_spec_is_not_floating() {
        let mut coverage = Coverage::complete(1, 1);
        let outcome = parse_environment_yaml(
            "environment.yml",
            "dependencies:\n  - numpy=1.21.0\n",
            &mut coverage,
        );
        assert!(!outcome.records[0].is_floating);
    }
}
