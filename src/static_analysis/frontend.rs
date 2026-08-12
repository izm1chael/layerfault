//! Extension-based script-language dispatch.
//!
//! This module owns the size-check → read → UTF-8 decode → budget-consume →
//! analyze sequence that used to be duplicated inline at three call sites
//! (`src/package.rs`, `src/archive/zip.rs`, `src/archive/tar.rs`). Python,
//! Shell, PowerShell and JavaScript/TypeScript all have real semantic
//! frontends now. `scan_text_streaming`'s textual heuristic fallback in
//! `src/package.rs` still runs alongside every language's semantic frontend
//! (both may fire on the same file); it is the only coverage for a language
//! extension that has no `LanguageId` variant at all.

use anyhow::{anyhow, Result};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Seek, SeekFrom};

/// A script language recognized by extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LanguageId {
    Python,
    Shell,
    PowerShell,
    JavaScript,
}

impl LanguageId {
    /// Resolve a language from a lowercased file extension (no leading dot).
    pub fn from_ext(ext: &str) -> Option<Self> {
        match ext {
            "py" | "pyw" => Some(Self::Python),
            "sh" | "bash" | "zsh" => Some(Self::Shell),
            "ps1" | "psm1" | "psd1" => Some(Self::PowerShell),
            "js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx" => Some(Self::JavaScript),
            _ => None,
        }
    }

    /// Content-cache parser discriminator for this language's semantic
    /// frontend. Distinct per language so cached facts from one frontend can
    /// never be mistaken for another's, mirroring
    /// `python_static::PYTHON_CONTENT_CACHE_DISCRIMINATOR`.
    pub fn cache_discriminator(self) -> &'static str {
        match self {
            Self::Python => "python-ast:v2",
            Self::Shell => "shell-ast:v1",
            Self::PowerShell => "powershell-ast:v1",
            Self::JavaScript => "js-ast:v1",
        }
    }
}

/// Run the semantic frontend for `ext`, if one exists, over the member
/// identified by `file`/`rel`/`digest`.
///
/// Returns an empty vector when: the extension is not a recognized script
/// language, the source exceeds the size limit, the file cannot be read, or
/// the content is not valid UTF-8 — all of these mirror the previous inline
/// Python-only behavior, which silently skipped semantic analysis rather
/// than failing the scan. Budget exhaustion is propagated as an `Err`,
/// matching the prior inline call sites exactly.
#[allow(clippy::too_many_arguments)]
pub fn scan_language_member(
    ext: &str,
    rel: &str,
    file: &File,
    size: u64,
    digest: &str,
    auto_map_modules: &BTreeSet<String>,
    budget: &crate::budget::ScanBudget,
) -> Result<Vec<crate::scanner::LayerScanResult>> {
    let Some(language) = LanguageId::from_ext(ext) else {
        return Ok(Vec::new());
    };

    let max_source_bytes = match language {
        LanguageId::Python => {
            crate::static_analysis::python::limits::PythonAnalysisLimits::default().max_source_bytes
        }
        LanguageId::Shell => {
            crate::static_analysis::shell::limits::ShellAnalysisLimits::default().max_source_bytes
        }
        LanguageId::PowerShell => {
            crate::static_analysis::powershell::limits::PowerShellAnalysisLimits::default()
                .max_source_bytes
        }
        LanguageId::JavaScript => {
            crate::static_analysis::javascript::limits::JavaScriptAnalysisLimits::default()
                .max_source_bytes
        }
    };
    if size > max_source_bytes as u64 {
        return Ok(Vec::new());
    }

    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let source_bytes = match crate::safeio::read_all_from_file(&reader, max_source_bytes as u64) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(Vec::new()),
    };
    let source_str = match std::str::from_utf8(&source_bytes) {
        Ok(text) => text,
        Err(_) => return Ok(Vec::new()),
    };

    budget
        .consume(
            crate::budget::BudgetDimension::ParserWorkUnits,
            source_bytes.len() as u64,
            "script parser",
        )
        .map_err(|error| anyhow!("global scan budget exhausted: {error}"))?;
    budget
        .consume(crate::budget::BudgetDimension::AstNodes, 1, "script AST")
        .map_err(|error| anyhow!("global scan budget exhausted: {error}"))?;

    let started = std::time::Instant::now();
    let result = match language {
        LanguageId::Python => {
            let limits = crate::static_analysis::python::limits::PythonAnalysisLimits::default();
            crate::static_analysis::python::analyze_and_convert_findings(
                rel,
                source_str,
                digest,
                auto_map_modules,
                &limits,
                started,
            )
        }
        LanguageId::Shell => {
            let limits = crate::static_analysis::shell::limits::ShellAnalysisLimits::default();
            crate::static_analysis::shell::analyze_and_convert_findings(
                rel, source_str, digest, &limits, started,
            )
        }
        LanguageId::PowerShell => {
            let limits =
                crate::static_analysis::powershell::limits::PowerShellAnalysisLimits::default();
            crate::static_analysis::powershell::analyze_and_convert_findings(
                rel, source_str, digest, &limits, started,
            )
        }
        LanguageId::JavaScript => {
            let limits =
                crate::static_analysis::javascript::limits::JavaScriptAnalysisLimits::default();
            crate::static_analysis::javascript::analyze_and_convert_findings(
                rel, source_str, digest, ext, &limits, started,
            )
        }
    };
    match result {
        Ok(findings) => Ok(findings),
        Err(_) => Ok(Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_ext_recognizes_all_language_families() {
        assert_eq!(LanguageId::from_ext("py"), Some(LanguageId::Python));
        assert_eq!(LanguageId::from_ext("pyw"), Some(LanguageId::Python));
        assert_eq!(LanguageId::from_ext("sh"), Some(LanguageId::Shell));
        assert_eq!(LanguageId::from_ext("bash"), Some(LanguageId::Shell));
        assert_eq!(LanguageId::from_ext("zsh"), Some(LanguageId::Shell));
        assert_eq!(LanguageId::from_ext("ps1"), Some(LanguageId::PowerShell));
        assert_eq!(LanguageId::from_ext("psm1"), Some(LanguageId::PowerShell));
        assert_eq!(LanguageId::from_ext("psd1"), Some(LanguageId::PowerShell));
        assert_eq!(LanguageId::from_ext("js"), Some(LanguageId::JavaScript));
        assert_eq!(LanguageId::from_ext("mjs"), Some(LanguageId::JavaScript));
        assert_eq!(LanguageId::from_ext("cjs"), Some(LanguageId::JavaScript));
        assert_eq!(LanguageId::from_ext("ts"), Some(LanguageId::JavaScript));
        assert_eq!(LanguageId::from_ext("tsx"), Some(LanguageId::JavaScript));
        assert_eq!(LanguageId::from_ext("jsx"), Some(LanguageId::JavaScript));
        assert_eq!(LanguageId::from_ext("json"), None);
        assert_eq!(LanguageId::from_ext(""), None);
    }

    #[test]
    fn cache_discriminators_are_distinct_per_language() {
        let discriminators = [
            LanguageId::Python.cache_discriminator(),
            LanguageId::Shell.cache_discriminator(),
            LanguageId::PowerShell.cache_discriminator(),
            LanguageId::JavaScript.cache_discriminator(),
        ];
        let mut unique: Vec<&str> = discriminators.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), discriminators.len());
        assert_eq!(LanguageId::Python.cache_discriminator(), "python-ast:v2");
    }

    #[test]
    fn unrecognized_extensions_produce_no_findings() {
        let budget =
            crate::budget::ScanBudget::new(crate::budget::ScanBudgetProfile::Default.limits())
                .expect("budget");
        let mut file = tempfile::tempfile().expect("tempfile");
        let source = b"eval(require('child_process').execSync('id'))";
        std::io::Write::write_all(&mut file, source).expect("write");
        let auto_map = BTreeSet::new();
        let findings = scan_language_member(
            "txt",
            "notes.txt",
            &file,
            source.len() as u64,
            "deadbeef",
            &auto_map,
            &budget,
        )
        .expect("no error for unsupported language");
        assert!(findings.is_empty());
    }

    #[test]
    fn javascript_extension_produces_semantic_findings() {
        let budget =
            crate::budget::ScanBudget::new(crate::budget::ScanBudgetProfile::Default.limits())
                .expect("budget");
        let mut file = tempfile::tempfile().expect("tempfile");
        let source = b"eval(require('child_process').execSync('id'))";
        std::io::Write::write_all(&mut file, source).expect("write");
        let auto_map = BTreeSet::new();
        let findings = scan_language_member(
            "js",
            "install.js",
            &file,
            source.len() as u64,
            "deadbeef",
            &auto_map,
            &budget,
        )
        .expect("javascript frontend runs");
        assert!(!findings.is_empty());
    }

    #[test]
    fn powershell_extension_produces_semantic_findings() {
        let budget =
            crate::budget::ScanBudget::new(crate::budget::ScanBudgetProfile::Default.limits())
                .expect("budget");
        let mut file = tempfile::tempfile().expect("tempfile");
        let source = b"iex (New-Object Net.WebClient).DownloadString('x')";
        std::io::Write::write_all(&mut file, source).expect("write");
        let auto_map = BTreeSet::new();
        let findings = scan_language_member(
            "ps1",
            "install.ps1",
            &file,
            source.len() as u64,
            "deadbeef",
            &auto_map,
            &budget,
        )
        .expect("powershell frontend runs");
        assert!(!findings.is_empty());
    }
}
