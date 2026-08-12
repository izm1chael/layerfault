//! JavaScript/TypeScript semantic capability frontend.
//!
//! Structural mirror of `python_static`, minus the taint engine and
//! reachability graph (module/function scope + one-hop import-alias
//! resolution only) — this is
//! the closest structural sibling to Python among the three non-Python
//! frontends, because it gets a real AST via `oxc_parser`, the same way
//! Python gets one via `rustpython-parser`, rather than shell/PowerShell's
//! hand-rolled bounded tokenizers.
//!
//! **Corpus-gate write-up (reasoned, not measured — no corpus tooling exists
//! in this sandbox; `scripts/corpus/detector-quality-gate.py` is a
//! regression gate against fixed fixtures, not a measurement tool):** npm
//! `postinstall`/`preinstall` hooks that shell out or run arbitrary JS at
//! install time are a well-documented supply-chain-attack vector, and before
//! this frontend `.js`/`.ts` files had **zero** capability coverage in this
//! codebase: they were not even a `is_text_candidate`/`is_native_or_script`
//! match before this analyzer, so `scan_text_streaming`'s substring
//! `dangerous` table never ran over them at all (confirmed by reading
//! `package.rs` directly). The textual heuristic layer
//! (`LF-JS-CHILD-PROCESS`/`LF-JS-REQUIRE-CHILD-PROCESS`, plus the shared
//! `LF-CODE-EVAL` needle) remains active alongside this frontend; both may
//! fire on the same file. This frontend's AST-based call-site extraction
//! structurally rules out the textual layer's false-positive class (a
//! dangerous identifier sitting inside a `//`/`/* */` comment or an
//! unexecuted string literal cannot be a `CallExpression` node).

pub mod calls;
pub mod findings;
pub mod limits;
pub mod parser;
pub mod symbols;

use anyhow::Result;
use calls::CallSiteExtractor;
use limits::JavaScriptAnalysisLimits;
use oxc_allocator::Allocator;
use parser::{parse_js_source, JsCoverage, JsSyntaxState, LineIndex};
use script_capability::ScriptCallSite;
use std::time::Instant;
use symbols::{ImportBinding, SymbolCollector};

use crate::script_capability;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JavaScriptAnalysis {
    pub relative_path: String,
    pub syntax_state: JsSyntaxState,
    pub imports: Vec<ImportBinding>,
    pub call_sites: Vec<ScriptCallSite>,
    pub coverage: JsCoverage,
}

/// Content-intrinsic JS/TS facts: parsing, symbol table and call-site
/// extraction over exact source bytes. No `relative_path`/contextual input
/// is baked in, so this is safe to reuse across paths/packages for identical
/// (content, extension) pairs via `crate::content_cache`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct JsContentFacts {
    syntax_state: JsSyntaxState,
    imports: Vec<ImportBinding>,
    call_sites: Vec<ScriptCallSite>,
    coverage: JsCoverage,
}

/// Matches `LanguageId::JavaScript.cache_discriminator()` in
/// `crate::language_frontend`.
const JS_CONTENT_CACHE_DISCRIMINATOR: &str = "js-ast:v1";

fn analyze_content(source: &str, ext: &str, limits: &JavaScriptAnalysisLimits) -> JsContentFacts {
    let allocator = Allocator::default();
    let parse_res = parse_js_source(&allocator, source, ext, limits);
    let line_index = LineIndex::new(source);

    let mut imports = Vec::new();
    let mut call_sites = Vec::new();

    if let Some(ref program) = parse_res.program {
        let mut collector = SymbolCollector::new(&line_index, limits);
        collector.collect(program);
        let symbol_table = collector.into_table();

        let mut extractor = CallSiteExtractor::new(&symbol_table, limits, &line_index, source);
        extractor.extract(program);
        call_sites = extractor.call_sites;
        imports = symbol_table.imports.into_values().collect();
    }

    JsContentFacts {
        syntax_state: parse_res.syntax_state,
        imports,
        call_sites,
        coverage: parse_res.coverage,
    }
}

/// Content facts, from the content cache when eligible and available,
/// otherwise computed fresh (and opportunistically cached for next time).
/// `sha256` must already be a verified content digest for `source`'s exact
/// bytes — never recomputed here.
///
/// Note: the cache key is `(sha256, size, discriminator)` and does not
/// include `ext`. Identical byte-for-byte content parsed once as `.js` and
/// once as `.ts` (an unusual but possible rename/duplicate scenario) could
/// in principle produce different `oxc` parse results (TS-only syntax would
/// fail as plain JS) yet share a cache entry. This mirrors the same
/// structural limitation already accepted by every other content-cached
/// frontend in this codebase (content cache is keyed by bytes, not by any
/// per-path parsing mode); it is called out here because JS/TS is the first
/// frontend where `ext` actually changes parser behavior for otherwise
/// identical bytes.
fn content_facts(
    source: &str,
    sha256: &str,
    ext: &str,
    limits: &JavaScriptAnalysisLimits,
) -> JsContentFacts {
    let size = source.len() as u64;
    if crate::content_cache::eligible(size) {
        if let Ok(Some(cached)) = crate::content_cache::lookup::<JsContentFacts>(
            sha256,
            size,
            JS_CONTENT_CACHE_DISCRIMINATOR,
        ) {
            return cached;
        }
        let facts = analyze_content(source, ext, limits);
        let _ = crate::content_cache::store(sha256, size, JS_CONTENT_CACHE_DISCRIMINATOR, &facts);
        return facts;
    }
    analyze_content(source, ext, limits)
}

pub fn analyze(
    relative_path: &str,
    source: &str,
    sha256: &str,
    ext: &str,
    limits: &JavaScriptAnalysisLimits,
) -> Result<JavaScriptAnalysis> {
    let facts = content_facts(source, sha256, ext, limits);
    Ok(JavaScriptAnalysis {
        relative_path: relative_path.to_owned(),
        syntax_state: facts.syntax_state,
        imports: facts.imports,
        call_sites: facts.call_sites,
        coverage: facts.coverage,
    })
}

pub fn analyze_and_convert_findings(
    relative_path: &str,
    source: &str,
    digest: &str,
    ext: &str,
    limits: &JavaScriptAnalysisLimits,
    started: Instant,
) -> Result<Vec<crate::scanner::LayerScanResult>> {
    let analysis = analyze(relative_path, source, digest, ext, limits)?;
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
    use crate::script_capability::{ScriptCapability, ScriptScope};

    use crate::content_cache::ENV_TEST_LOCK as ENV_LOCK;

    struct ContentCacheEnvGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        root: std::path::PathBuf,
    }

    impl ContentCacheEnvGuard {
        fn new(name: &str) -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
            let root = std::env::temp_dir().join(format!(
                "layerfault-js-content-cache-{name}-{}-{}",
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
    fn js_content_facts_are_stable_across_cache_round_trip() {
        let _guard = ContentCacheEnvGuard::new("stability");
        let code = "const { exec } = require('child_process');\nexec('id');\n";
        let limits = JavaScriptAnalysisLimits::default();
        let sha256 = "sha256:js-content-facts-test";

        let first = analyze("install.js", code, sha256, "js", &limits).unwrap();
        let second = analyze("install.js", code, sha256, "js", &limits).unwrap();

        assert_eq!(first.call_sites.len(), second.call_sites.len());
        assert_eq!(first.syntax_state, second.syntax_state);
        assert!(first
            .call_sites
            .iter()
            .any(|c| c.capability == ScriptCapability::Process));
    }

    // --- 1. Alias/import-variant resolution ---

    #[test]
    fn test_destructured_require_resolution() {
        let code = "const { exec } = require('child_process');\nexec('id');\n";
        let limits = JavaScriptAnalysisLimits::default();
        let res = analyze("install.js", code, "sha256", "js", &limits).unwrap();
        assert_eq!(res.syntax_state, JsSyntaxState::Valid);
        let site = res
            .call_sites
            .iter()
            .find(|c| c.capability == ScriptCapability::Process)
            .expect("process call site");
        assert_eq!(site.resolved_target.as_deref(), Some("child_process.exec"));
    }

    #[test]
    fn test_esm_named_import_resolution() {
        let code = "import { exec } from 'child_process';\nexec('id');\n";
        let limits = JavaScriptAnalysisLimits::default();
        let res = analyze("install.js", code, "sha256", "mjs", &limits).unwrap();
        assert_eq!(res.syntax_state, JsSyntaxState::Valid);
        let site = res
            .call_sites
            .iter()
            .find(|c| c.capability == ScriptCapability::Process)
            .expect("process call site");
        assert_eq!(site.resolved_target.as_deref(), Some("child_process.exec"));
    }

    #[test]
    fn test_esm_namespace_import_resolution() {
        let code = "import * as cp from 'child_process';\ncp.exec('id');\n";
        let limits = JavaScriptAnalysisLimits::default();
        let res = analyze("install.js", code, "sha256", "mjs", &limits).unwrap();
        assert_eq!(res.syntax_state, JsSyntaxState::Valid);
        let site = res
            .call_sites
            .iter()
            .find(|c| c.capability == ScriptCapability::Process)
            .expect("process call site");
        assert_eq!(site.resolved_target.as_deref(), Some("child_process.exec"));
    }

    #[test]
    fn test_one_hop_rebinding_resolution() {
        // One-hop rebinding: `run` aliases the already-resolved
        // `child_process.exec` target. Multi-hop rebinding (an alias of an
        // alias) is out of scope, matching the plan's stated one-hop
        // requirement.
        let code =
            "const child_process = require('child_process');\nconst run = child_process.exec;\nrun('id');\n";
        let limits = JavaScriptAnalysisLimits::default();
        let res = analyze("install.js", code, "sha256", "js", &limits).unwrap();
        assert_eq!(res.syntax_state, JsSyntaxState::Valid);
        let site = res
            .call_sites
            .iter()
            .find(|c| c.capability == ScriptCapability::Process)
            .expect("process call site");
        assert_eq!(site.resolved_target.as_deref(), Some("child_process.exec"));
    }

    #[test]
    fn test_node_prefix_normalization() {
        let code = "import * as fs from 'node:fs';\nfs.writeFileSync('/etc/passwd', 'x');\n";
        let limits = JavaScriptAnalysisLimits::default();
        let res = analyze("install.js", code, "sha256", "mjs", &limits).unwrap();
        let site = res
            .call_sites
            .iter()
            .find(|c| c.capability == ScriptCapability::FilesystemWrite)
            .expect("filesystem write call site");
        assert_eq!(site.resolved_target.as_deref(), Some("fs.writeFileSync"));
    }

    // --- 2. Scope classification ---

    #[test]
    fn test_scope_classification() {
        let code = r#"
eval("top");

function helper() {
  eval("inner");
}

const arrow = () => {
  eval("arrow_inner");
};
"#;
        let limits = JavaScriptAnalysisLimits::default();
        let res = analyze("script.js", code, "sha256", "js", &limits).unwrap();
        let module_hits = res
            .call_sites
            .iter()
            .filter(|c| {
                c.capability == ScriptCapability::DynamicCode && c.scope == ScriptScope::Module
            })
            .count();
        let function_hits = res
            .call_sites
            .iter()
            .filter(|c| {
                c.capability == ScriptCapability::DynamicCode && c.scope == ScriptScope::Function
            })
            .count();
        assert_eq!(module_hits, 1);
        assert_eq!(function_hits, 2);
    }

    // --- 3. Comment/string false-positive suppression ---

    #[test]
    fn test_comment_and_string_suppression() {
        let code =
            "// child_process.exec('rm -rf /')\nconst s = \"child_process.exec('rm -rf /')\";\n";
        let limits = JavaScriptAnalysisLimits::default();
        let res = analyze("script.js", code, "sha256", "js", &limits).unwrap();
        assert_eq!(res.syntax_state, JsSyntaxState::Valid);
        assert!(res.call_sites.is_empty());
    }

    // --- 4. Malformed source -> SEMANTIC-INCOMPLETE fallback ---

    #[test]
    fn test_invalid_js_syntax() {
        let code = "function broken( {\n  return 1;\n";
        let limits = JavaScriptAnalysisLimits::default();
        let res = analyze("script.js", code, "sha256", "js", &limits).unwrap();
        assert!(matches!(res.syntax_state, JsSyntaxState::Invalid { .. }));
        assert!(matches!(res.coverage, JsCoverage::Incomplete { .. }));

        let started = Instant::now();
        let findings =
            analyze_and_convert_findings("script.js", code, "sha256", "js", &limits, started)
                .unwrap();
        assert!(findings
            .iter()
            .any(|f| crate::policy::rule_id(f) == "LF-JS-SEMANTIC-INCOMPLETE"));
    }

    // --- 5. Huge/deep input budget (three independent tests) ---

    #[test]
    fn test_exceeds_max_source_bytes() {
        let code = "const x = 1;\n".repeat(1000);
        let limits = JavaScriptAnalysisLimits {
            max_source_bytes: 4,
            ..Default::default()
        };
        let res = analyze("script.js", &code, "sha256", "js", &limits).unwrap();
        assert!(matches!(
            res.syntax_state,
            JsSyntaxState::ExceededLimits { .. }
        ));
        let started = Instant::now();
        let findings =
            analyze_and_convert_findings("script.js", &code, "sha256", "js", &limits, started)
                .unwrap();
        assert!(findings
            .iter()
            .any(|f| crate::policy::rule_id(f) == "LF-JS-SEMANTIC-INCOMPLETE"));
    }

    #[test]
    fn test_exceeds_max_ast_nodes() {
        let code = "let x = ".to_owned() + &"1 + ".repeat(2000) + "1;";
        let limits = JavaScriptAnalysisLimits {
            max_ast_nodes: 10,
            ..Default::default()
        };
        let res = analyze("script.js", &code, "sha256", "js", &limits).unwrap();
        assert!(matches!(
            res.syntax_state,
            JsSyntaxState::ExceededLimits { .. }
        ));
        let started = Instant::now();
        let findings =
            analyze_and_convert_findings("script.js", &code, "sha256", "js", &limits, started)
                .unwrap();
        assert!(findings
            .iter()
            .any(|f| crate::policy::rule_id(f) == "LF-JS-SEMANTIC-INCOMPLETE"));
    }

    #[test]
    fn test_exceeds_max_ast_depth() {
        let mut code = String::new();
        for _ in 0..500 {
            code.push_str("if (true) {\n");
        }
        code.push_str("eval('deep');\n");
        for _ in 0..500 {
            code.push_str("}\n");
        }
        let limits = JavaScriptAnalysisLimits {
            max_ast_depth: 10,
            ..Default::default()
        };
        let res = analyze("script.js", &code, "sha256", "js", &limits).unwrap();
        assert!(matches!(
            res.syntax_state,
            JsSyntaxState::ExceededLimits { .. }
        ));
        let started = Instant::now();
        let findings =
            analyze_and_convert_findings("script.js", &code, "sha256", "js", &limits, started)
                .unwrap();
        assert!(findings
            .iter()
            .any(|f| crate::policy::rule_id(f) == "LF-JS-SEMANTIC-INCOMPLETE"));
    }

    // --- 6. Source-span evidence correctness ---

    #[test]
    fn test_source_span_evidence_line_and_column() {
        let code = "const a = 1;\nconst b = 2;\neval(\"danger\");\n";
        let limits = JavaScriptAnalysisLimits::default();
        let res = analyze("script.js", code, "sha256", "js", &limits).unwrap();
        let eval_site = res
            .call_sites
            .iter()
            .find(|c| c.capability == ScriptCapability::DynamicCode)
            .expect("eval call site present");
        assert_eq!(eval_site.line, Some(3));
        assert_eq!(eval_site.column, Some(1));
    }

    // --- 8. TypeScript-specific ---

    #[test]
    fn test_typescript_syntax_does_not_break_detection() {
        let code = r#"
interface Options {
  cmd: string;
}

function run(opts: Options): void {
  const cp: typeof import('child_process') = require('child_process');
  cp.exec(opts.cmd);
}
"#;
        let limits = JavaScriptAnalysisLimits::default();
        let res = analyze("install.ts", code, "sha256", "ts", &limits).unwrap();
        assert_eq!(res.syntax_state, JsSyntaxState::Valid);
        assert!(res
            .call_sites
            .iter()
            .any(|c| c.capability == ScriptCapability::Process));
    }
}
