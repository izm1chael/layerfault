//! `pyproject.toml`, `poetry.lock` and `uv.lock` parsing.
//!
//! Parsed structurally with the `toml` crate (a data-only value tree; no
//! arbitrary type construction), never by scanning for substrings.

use super::requirements::{apply_pin_state, parse_requirement_line};
use super::risk::{self, RiskFinding};
use super::types::{DependencyEcosystem, DependencyRecord, DependencySource};
use crate::coverage::Coverage;
use crate::finding_evidence::{config_value, EvidenceLocation, EvidenceSubject};
use crate::scanner::{Confidence, ScanStatus};
use toml::Value;

#[derive(Debug, Default)]
pub struct PyprojectOutcome {
    pub records: Vec<DependencyRecord>,
    pub issues: Vec<RiskFinding>,
}

pub fn parse_pyproject_toml(
    relative_path: &str,
    source: &str,
    coverage: &mut Coverage,
) -> PyprojectOutcome {
    let mut outcome = PyprojectOutcome::default();
    let subject = EvidenceSubject::member(relative_path);

    let table: toml::Table = match source.parse() {
        Ok(table) => table,
        Err(error) => {
            coverage.parser_failure(&format!("'{relative_path}' is not valid TOML: {error}"));
            return outcome;
        }
    };

    if let Some(project) = table.get("project").and_then(Value::as_table) {
        for item in project
            .get("dependencies")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(spec) = item.as_str() {
                let mut record = parse_requirement_line(spec, relative_path);
                record.location = Some(EvidenceLocation::Metadata {
                    key: "project.dependencies".to_owned(),
                });
                outcome.records.push(record);
            }
        }
        if let Some(optional) = project
            .get("optional-dependencies")
            .and_then(Value::as_table)
        {
            for (group, deps) in optional {
                for item in deps.as_array().into_iter().flatten() {
                    if let Some(spec) = item.as_str() {
                        let mut record = parse_requirement_line(spec, relative_path);
                        record.location = Some(EvidenceLocation::Metadata {
                            key: format!("project.optional-dependencies.{group}"),
                        });
                        outcome.records.push(record);
                    }
                }
            }
        }
    }

    if let Some(build_system) = table.get("build-system").and_then(Value::as_table) {
        let backend = build_system.get("build-backend").and_then(Value::as_str);
        let is_setuptools = backend.map(|b| b.starts_with("setuptools")).unwrap_or(true);
        if !is_setuptools {
            let backend_name = backend.unwrap_or("<unspecified>");
            outcome.issues.push(RiskFinding {
                rule_id: "LF-DEP-BUILD-BACKEND",
                status: ScanStatus::Warn,
                confidence: Confidence::Medium,
                detail: format!(
                    "'{relative_path}' declares a custom build backend '{backend_name}'; \
                     build backends run code during install/build"
                ),
                evidence: vec![config_value(
                    subject.clone(),
                    "build-system.build-backend",
                    serde_json::Value::String(backend_name.to_owned()),
                    "Custom build backend declared",
                )
                .at(EvidenceLocation::Metadata {
                    key: "build-system.build-backend".to_owned(),
                })],
            });
        }
        for item in build_system
            .get("requires")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(spec) = item.as_str() {
                let mut record = parse_requirement_line(spec, relative_path);
                record.location = Some(EvidenceLocation::Metadata {
                    key: "build-system.requires".to_owned(),
                });
                outcome.records.push(record);
            }
        }
    }

    if let Some(poetry) = table
        .get("tool")
        .and_then(Value::as_table)
        .and_then(|tool| tool.get("poetry"))
        .and_then(Value::as_table)
    {
        if let Some(deps) = poetry.get("dependencies").and_then(Value::as_table) {
            for (name, spec) in deps {
                if name == "python" {
                    continue;
                }
                outcome
                    .records
                    .push(parse_poetry_dependency(relative_path, name, spec));
            }
        }
        for source in poetry
            .get("source")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(url) = source
                .as_table()
                .and_then(|t| t.get("url"))
                .and_then(Value::as_str)
            {
                outcome.issues.extend(risk::index_finding(
                    relative_path,
                    &subject,
                    Some(EvidenceLocation::Metadata {
                        key: "tool.poetry.source".to_owned(),
                    }),
                    url,
                    "tool.poetry.source",
                ));
            }
        }
    }

    outcome
}

fn parse_poetry_dependency(declared_in: &str, name: &str, value: &Value) -> DependencyRecord {
    let mut record = DependencyRecord::new(declared_in, &format!("{name} = {value}"));
    record.name = Some(name.to_owned());
    record.location = Some(EvidenceLocation::Metadata {
        key: format!("tool.poetry.dependencies.{name}"),
    });

    match value {
        Value::String(spec) => {
            record.version_constraint = Some(spec.clone());
            record.source = Some(DependencySource::Registry {
                index_url: None,
                extra_index: false,
            });
        }
        Value::Table(fields) => {
            if let Some(git) = fields.get("git").and_then(Value::as_str) {
                let reference = fields
                    .get("rev")
                    .or_else(|| fields.get("tag"))
                    .or_else(|| fields.get("branch"))
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                let is_full_commit_sha = reference
                    .as_deref()
                    .map(risk::is_full_commit_sha)
                    .unwrap_or(false);
                record.source = Some(DependencySource::Vcs {
                    vcs: "git".to_owned(),
                    url: risk::redact_url(git).normalized,
                    reference,
                    is_full_commit_sha,
                });
            } else if let Some(url) = fields.get("url").and_then(Value::as_str) {
                record.source = Some(DependencySource::DirectUrl {
                    url: risk::redact_url(url).normalized,
                    has_hash: false,
                });
            } else if let Some(path) = fields.get("path").and_then(Value::as_str) {
                let editable = fields
                    .get("develop")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                record.source = Some(risk::classify_local_path(path, editable));
            } else if let Some(spec) = fields.get("version").and_then(Value::as_str) {
                record.version_constraint = Some(spec.to_owned());
                record.source = Some(DependencySource::Registry {
                    index_url: None,
                    extra_index: false,
                });
            } else {
                record.source = Some(DependencySource::Unresolved {
                    raw: value.to_string(),
                });
            }
        }
        _ => {
            record.source = Some(DependencySource::Unresolved {
                raw: value.to_string(),
            });
        }
    }

    let constraint = record.version_constraint.clone();
    apply_pin_state(&mut record, constraint.as_deref());
    record
}

/// Parse `poetry.lock`: exact resolved versions, so lockfile entries are never
/// floating by definition.
pub fn parse_poetry_lock(
    relative_path: &str,
    source: &str,
    coverage: &mut Coverage,
) -> PyprojectOutcome {
    let mut outcome = PyprojectOutcome::default();
    let table: toml::Table = match source.parse() {
        Ok(table) => table,
        Err(error) => {
            coverage.parser_failure(&format!("'{relative_path}' is not valid TOML: {error}"));
            return outcome;
        }
    };
    for (index, package) in table
        .get("package")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let Some(package) = package.as_table() else {
            continue;
        };
        let name = package
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("<unknown>")
            .to_owned();
        let mut record = DependencyRecord::new(relative_path, &name);
        record.name = Some(name);
        record.ecosystem = Some(DependencyEcosystem::Poetry);
        record.location = Some(EvidenceLocation::Record {
            index: index as u64,
        });
        record.is_floating = false;
        record.has_hash_pin = package.get("files").is_some();

        record.source = match package.get("source").and_then(Value::as_table) {
            Some(source_table) => {
                let source_type = source_table
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let url = source_table
                    .get("url")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                match source_type {
                    "git" => {
                        let reference = source_table
                            .get("resolved_reference")
                            .or_else(|| source_table.get("reference"))
                            .and_then(Value::as_str)
                            .map(str::to_owned);
                        let is_full_commit_sha = reference
                            .as_deref()
                            .map(risk::is_full_commit_sha)
                            .unwrap_or(false);
                        Some(DependencySource::Vcs {
                            vcs: "git".to_owned(),
                            url: risk::redact_url(url).normalized,
                            reference,
                            is_full_commit_sha,
                        })
                    }
                    "url" => Some(DependencySource::DirectUrl {
                        url: risk::redact_url(url).normalized,
                        has_hash: record.has_hash_pin,
                    }),
                    "directory" | "file" => Some(risk::classify_local_path(url, false)),
                    _ => Some(DependencySource::Registry {
                        index_url: None,
                        extra_index: false,
                    }),
                }
            }
            None => Some(DependencySource::Registry {
                index_url: None,
                extra_index: false,
            }),
        };
        outcome.records.push(record);
    }
    outcome
}

/// Parse `uv.lock`: exact resolved versions, so lockfile entries are never
/// floating by definition.
pub fn parse_uv_lock(
    relative_path: &str,
    source: &str,
    coverage: &mut Coverage,
) -> PyprojectOutcome {
    let mut outcome = PyprojectOutcome::default();
    let table: toml::Table = match source.parse() {
        Ok(table) => table,
        Err(error) => {
            coverage.parser_failure(&format!("'{relative_path}' is not valid TOML: {error}"));
            return outcome;
        }
    };
    for (index, package) in table
        .get("package")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let Some(package) = package.as_table() else {
            continue;
        };
        let name = package
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("<unknown>")
            .to_owned();
        let mut record = DependencyRecord::new(relative_path, &name);
        record.name = Some(name);
        record.ecosystem = Some(DependencyEcosystem::Uv);
        record.location = Some(EvidenceLocation::Record {
            index: index as u64,
        });
        record.is_floating = false;
        record.has_hash_pin = package.get("sdist").is_some() || package.get("wheels").is_some();

        record.source = match package.get("source").and_then(Value::as_table) {
            Some(source_table) => {
                if let Some(git) = source_table.get("git").and_then(Value::as_str) {
                    let reference = source_table
                        .get("rev")
                        .or_else(|| source_table.get("tag"))
                        .or_else(|| source_table.get("branch"))
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                    let is_full_commit_sha = reference
                        .as_deref()
                        .map(risk::is_full_commit_sha)
                        .unwrap_or(false);
                    Some(DependencySource::Vcs {
                        vcs: "git".to_owned(),
                        url: risk::redact_url(git).normalized,
                        reference,
                        is_full_commit_sha,
                    })
                } else if let Some(url) = source_table.get("url").and_then(Value::as_str) {
                    Some(DependencySource::DirectUrl {
                        url: risk::redact_url(url).normalized,
                        has_hash: record.has_hash_pin,
                    })
                } else if let Some(editable) = source_table.get("editable").and_then(Value::as_str)
                {
                    Some(risk::classify_local_path(editable, true))
                } else {
                    Some(DependencySource::Registry {
                        index_url: source_table
                            .get("registry")
                            .and_then(Value::as_str)
                            .map(str::to_owned),
                        extra_index: false,
                    })
                }
            }
            None => Some(DependencySource::Registry {
                index_url: None,
                extra_index: false,
            }),
        };
        outcome.records.push(record);
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_build_backend_is_flagged() {
        let mut coverage = Coverage::complete(1, 1);
        let outcome = parse_pyproject_toml(
            "pyproject.toml",
            "[build-system]\nrequires = [\"flit_core\"]\nbuild-backend = \"flit_core.buildapi\"\n",
            &mut coverage,
        );
        assert!(outcome
            .issues
            .iter()
            .any(|issue| issue.rule_id == "LF-DEP-BUILD-BACKEND"));
    }

    #[test]
    fn setuptools_backend_is_not_flagged() {
        let mut coverage = Coverage::complete(1, 1);
        let outcome = parse_pyproject_toml(
            "pyproject.toml",
            "[build-system]\nrequires = [\"setuptools\", \"wheel\"]\nbuild-backend = \"setuptools.build_meta\"\n",
            &mut coverage,
        );
        assert!(!outcome
            .issues
            .iter()
            .any(|issue| issue.rule_id == "LF-DEP-BUILD-BACKEND"));
    }

    #[test]
    fn project_dependencies_parse_direct_url() {
        let mut coverage = Coverage::complete(1, 1);
        let outcome = parse_pyproject_toml(
            "pyproject.toml",
            "[project]\ndependencies = [\"pkg @ https://example.com/pkg.whl\"]\n",
            &mut coverage,
        );
        assert!(matches!(
            outcome.records[0].source,
            Some(DependencySource::DirectUrl { .. })
        ));
    }

    #[test]
    fn malformed_toml_is_incomplete() {
        let mut coverage = Coverage::complete(1, 1);
        let _ = parse_pyproject_toml("pyproject.toml", "not = [valid toml", &mut coverage);
        assert!(!coverage.complete);
    }

    #[test]
    fn poetry_lock_entries_are_not_floating() {
        let mut coverage = Coverage::complete(1, 1);
        let outcome = parse_poetry_lock(
            "poetry.lock",
            "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n",
            &mut coverage,
        );
        assert!(!outcome.records[0].is_floating);
    }
}
