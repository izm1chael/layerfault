//! Static dependency and installation supply-chain analysis.
//!
//! Every parser in this module reads manifest/lockfile bytes only: nothing
//! here installs a package, resolves a version, contacts a registry/VCS host,
//! or executes `setup.py`. A dependency declared outside the scanned package
//! (a floating version, a Git ref, a direct URL) is not covered by the
//! package's content fingerprint; that boundary is expressed through
//! [`crate::coverage::Coverage`] rather than a bespoke field, so an
//! unresolved external reference always shows up as incomplete coverage
//! rather than a silent clean scan.

pub mod conda;
pub mod limits;
pub mod package_json;
pub mod pyproject;
pub mod requirements;
pub mod risk;
pub mod setup_py;
pub mod types;
pub mod wheel;

use crate::coverage::Coverage;
use crate::finding_evidence::{EvidenceSubject, FindingBuilder};
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use limits::{DependencyBudgetTracker, DependencyParseLimits};
use risk::RiskFinding;
use std::collections::BTreeSet;
use std::path::Path;
use std::time::Instant;

pub const DEPENDENCY_MEDIA_TYPE: &str = "application/vnd.layerfault.dependency-manifest";

/// Which manifest/lockfile parser a recognized filename dispatches to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestKind {
    Requirements,
    Pyproject,
    SetupPy,
    PoetryLock,
    UvLock,
    EnvironmentYaml,
    WheelMetadata,
    CondaLock,
    PackageJson,
}

/// Recognize a package-relative filename as a dependency manifest/lockfile.
///
/// `lower` is the lowercased package-relative path; `ext` is the lowercased
/// extension. Filenames not recognized here fall through to Layerfault's
/// existing generic text/config scanning, unchanged.
pub fn classify_manifest(lower: &str, ext: &str) -> Option<ManifestKind> {
    let filename = lower.rsplit('/').next().unwrap_or(lower);
    match filename {
        "poetry.lock" => return Some(ManifestKind::PoetryLock),
        "uv.lock" => return Some(ManifestKind::UvLock),
        "pyproject.toml" => return Some(ManifestKind::Pyproject),
        "setup.py" => return Some(ManifestKind::SetupPy),
        "package.json" => return Some(ManifestKind::PackageJson),
        "environment.yml" | "environment.yaml" => return Some(ManifestKind::EnvironmentYaml),
        "metadata" if lower.contains(".dist-info/") => return Some(ManifestKind::WheelMetadata),
        _ => {}
    }
    if filename.ends_with("conda-lock.yml") || filename.ends_with("conda-lock.yaml") {
        return Some(ManifestKind::CondaLock);
    }
    if filename == "requirements.lock" {
        return Some(ManifestKind::Requirements);
    }
    if filename.starts_with("requirements") && ext == "txt" {
        return Some(ManifestKind::Requirements);
    }
    None
}

/// Inspect one recognized dependency manifest/lockfile member.
///
/// `package_root` is `None` when scanning a single file outside a package
/// walk (e.g. `layerfault scan <file>`); `-r`/`-c` includes cannot be
/// resolved in that mode and are reported as incomplete coverage instead of
/// silently ignored.
pub fn inspect_member(
    package_root: Option<&Path>,
    relative_path: &str,
    file: &std::fs::File,
    digest: &str,
    kind: ManifestKind,
    auto_map_modules: &BTreeSet<String>,
) -> anyhow::Result<Vec<LayerScanResult>> {
    let limits = DependencyParseLimits::default();
    let bytes = crate::safeio::read_all_from_file(file, limits.max_manifest_bytes)?;
    let subject = EvidenceSubject::member(relative_path)
        .with_sha256(Some(digest.to_owned()))
        .with_media_type(DEPENDENCY_MEDIA_TYPE);
    let mut coverage = Coverage::complete(1, bytes.len() as u64);

    if kind == ManifestKind::SetupPy {
        let started = Instant::now();
        let text = match std::str::from_utf8(&bytes) {
            Ok(text) => text,
            Err(_) => {
                coverage.parser_failure(&format!("'{relative_path}' is not valid UTF-8 text"));
                return Ok(vec![analysis_incomplete_finding(
                    digest, &subject, &coverage,
                )]);
            }
        };
        return Ok(setup_py::analyze_setup_py(
            relative_path,
            text,
            digest,
            auto_map_modules,
            started,
        ));
    }

    if kind == ManifestKind::PackageJson {
        let text = match std::str::from_utf8(&bytes) {
            Ok(text) => text,
            Err(_) => {
                coverage.parser_failure(&format!("'{relative_path}' is not valid UTF-8 text"));
                return Ok(vec![analysis_incomplete_finding(
                    digest, &subject, &coverage,
                )]);
            }
        };
        if let Err(error) = serde_json::from_str::<serde_json::Value>(text) {
            coverage.parser_failure(&format!(
                "Unable to parse '{relative_path}' as JSON: {error}"
            ));
            return Ok(vec![analysis_incomplete_finding(
                digest, &subject, &coverage,
            )]);
        }
        return Ok(package_json::analyze_package_json(
            relative_path,
            text,
            digest,
        ));
    }

    let text = match std::str::from_utf8(&bytes) {
        Ok(text) => text,
        Err(_) => {
            coverage.parser_failure(&format!("'{relative_path}' is not valid UTF-8 text"));
            return Ok(vec![analysis_incomplete_finding(
                digest, &subject, &coverage,
            )]);
        }
    };

    let mut issues: Vec<RiskFinding> = Vec::new();
    match kind {
        ManifestKind::Requirements => {
            let mut tracker = DependencyBudgetTracker::new(limits.clone());
            let outcome = requirements::parse_requirements_file(
                package_root,
                relative_path,
                text,
                &mut tracker,
                &mut coverage,
            );
            issues.extend(outcome.issues);
            for record in &outcome.records {
                issues.extend(risk::classify(record, &subject));
            }
        }
        ManifestKind::Pyproject => {
            let outcome = pyproject::parse_pyproject_toml(relative_path, text, &mut coverage);
            issues.extend(outcome.issues);
            for record in &outcome.records {
                issues.extend(risk::classify(record, &subject));
            }
        }
        ManifestKind::PoetryLock => {
            let outcome = pyproject::parse_poetry_lock(relative_path, text, &mut coverage);
            issues.extend(outcome.issues);
            for record in &outcome.records {
                issues.extend(risk::classify(record, &subject));
            }
        }
        ManifestKind::UvLock => {
            let outcome = pyproject::parse_uv_lock(relative_path, text, &mut coverage);
            issues.extend(outcome.issues);
            for record in &outcome.records {
                issues.extend(risk::classify(record, &subject));
            }
        }
        ManifestKind::EnvironmentYaml => {
            let outcome = conda::parse_environment_yaml(relative_path, text, &mut coverage);
            issues.extend(outcome.issues);
            for record in &outcome.records {
                issues.extend(risk::classify(record, &subject));
            }
        }
        ManifestKind::CondaLock => {
            let outcome = conda::parse_conda_lock(relative_path, text, &mut coverage);
            issues.extend(outcome.issues);
            for record in &outcome.records {
                issues.extend(risk::classify(record, &subject));
            }
        }
        ManifestKind::WheelMetadata => {
            let outcome = wheel::parse_metadata(relative_path, text, &mut coverage);
            issues.extend(outcome.issues);
            for record in &outcome.records {
                issues.extend(risk::classify(record, &subject));
            }
        }
        ManifestKind::SetupPy | ManifestKind::PackageJson => unreachable!("handled above"),
    }

    let mut findings: Vec<LayerScanResult> = issues
        .into_iter()
        .map(|issue| risk_to_finding(digest, &subject, issue))
        .collect();

    if !coverage.complete {
        findings.push(analysis_incomplete_finding(digest, &subject, &coverage));
    }

    Ok(findings)
}

fn risk_to_finding(digest: &str, subject: &EvidenceSubject, issue: RiskFinding) -> LayerScanResult {
    let mut builder = FindingBuilder::new(issue.rule_id, CheckType::PackageSecurity, issue.status)
        .class(finding_class_for(issue.rule_id))
        .confidence(issue.confidence)
        .digest(digest)
        .media_type(DEPENDENCY_MEDIA_TYPE)
        .subject(subject.clone())
        .detail(issue.detail);
    for evidence in issue.evidence {
        builder = builder.evidence(evidence);
    }
    builder.finish()
}

fn finding_class_for(rule_id: &str) -> FindingClass {
    match rule_id {
        "LF-DEP-PATH-ESCAPE" | "LF-DEP-INCLUDE-MISSING" | "LF-DEP-ANALYSIS-INCOMPLETE" => {
            FindingClass::Structural
        }
        "LF-DEP-INSTALL-HOOK" | "LF-DEP-RUNTIME-INSTALL" => FindingClass::ContentIndicator,
        _ => FindingClass::Policy,
    }
}

fn analysis_incomplete_finding(
    digest: &str,
    subject: &EvidenceSubject,
    coverage: &Coverage,
) -> LayerScanResult {
    let evidence = coverage.gap_evidence(subject);
    FindingBuilder::new(
        "LF-DEP-ANALYSIS-INCOMPLETE",
        CheckType::PackageSecurity,
        ScanStatus::Warn,
    )
    .class(FindingClass::Structural)
    .confidence(Confidence::Medium)
    .digest(digest)
    .media_type(DEPENDENCY_MEDIA_TYPE)
    .subject(subject.clone())
    .detail("Dependency manifest analysis was incomplete; see attached coverage evidence")
    .evidence_all(evidence)
    .finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_recognizes_supported_manifests() {
        assert_eq!(
            classify_manifest("requirements.txt", "txt"),
            Some(ManifestKind::Requirements)
        );
        assert_eq!(
            classify_manifest("requirements-dev.txt", "txt"),
            Some(ManifestKind::Requirements)
        );
        assert_eq!(
            classify_manifest("pyproject.toml", "toml"),
            Some(ManifestKind::Pyproject)
        );
        assert_eq!(
            classify_manifest("setup.py", "py"),
            Some(ManifestKind::SetupPy)
        );
        assert_eq!(
            classify_manifest("poetry.lock", "lock"),
            Some(ManifestKind::PoetryLock)
        );
        assert_eq!(
            classify_manifest("uv.lock", "lock"),
            Some(ManifestKind::UvLock)
        );
        assert_eq!(
            classify_manifest("environment.yml", "yml"),
            Some(ManifestKind::EnvironmentYaml)
        );
        assert_eq!(
            classify_manifest("pkg.dist-info/metadata", ""),
            Some(ManifestKind::WheelMetadata)
        );
        assert_eq!(
            classify_manifest("package.json", "json"),
            Some(ManifestKind::PackageJson)
        );
        assert_eq!(classify_manifest("readme.md", "md"), None);
    }
}
