pub mod calls;
pub mod findings;
pub mod limits;
pub mod parser;
pub mod reachability;
pub mod symbols;
pub mod taint;

use anyhow::Result;
use calls::{CallSite, CallSiteExtractor, ExecutionContext};
use limits::PythonAnalysisLimits;
use parser::{parse_python_source, LineIndex, PythonCoverage, PythonSyntaxState};
use reachability::{EntryPoint, PythonRelationship, ReachabilityGraph};
use rustpython_parser::ast::{self, Stmt, Suite};
use std::collections::BTreeSet;
use std::time::Instant;
use symbols::{Definition, DefinitionKind, ImportBinding, SymbolTable};
use taint::{TaintAnalysisResult, TaintEngine};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PythonAnalysis {
    pub relative_path: String,
    pub syntax_state: PythonSyntaxState,
    pub imports: Vec<ImportBinding>,
    pub call_sites: Vec<CallSite>,
    pub definitions: Vec<Definition>,
    pub entry_points: Vec<EntryPoint>,
    pub relationships: Vec<PythonRelationship>,
    pub coverage: PythonCoverage,
    pub taint_result: TaintAnalysisResult,
}

/// Content-intrinsic Python facts: parsing, symbol table and call-site
/// extraction over exact source bytes. Contains no `relative_path` or
/// `auto_map_modules` influence, so it is safe to reuse across paths and
/// packages for identical source bytes via [`crate::content_cache`].
///
/// Reachability (`entry_points`/`relationships`, and any auto_map-flavoured
/// finding derived from them) is deliberately *not* part of this struct: it
/// depends on `auto_map_modules`, which is contextual per-package
/// configuration, and must always be recomputed fresh.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PythonContentFacts {
    syntax_state: PythonSyntaxState,
    imports: Vec<ImportBinding>,
    call_sites: Vec<CallSite>,
    definitions: Vec<Definition>,
    coverage: PythonCoverage,
    taint_result: TaintAnalysisResult,
}

const PYTHON_CONTENT_CACHE_DISCRIMINATOR: &str = "python-ast:v2";
/// Fixed source label used only for parser error-message text when computing
/// cacheable content facts, so the cached record never embeds a real path.
const CONTENT_FACTS_SOURCE_LABEL: &str = "<content>";

fn analyze_content(source: &str, limits: &PythonAnalysisLimits) -> PythonContentFacts {
    let parse_res = parse_python_source(source, CONTENT_FACTS_SOURCE_LABEL, limits);
    let line_index = LineIndex::new(source);
    let mut symbol_table = SymbolTable::new();
    let mut call_sites = Vec::new();
    let mut taint_result = TaintAnalysisResult {
        flows: Vec::new(),
        incomplete: false,
        incomplete_reason: None,
    };

    if let Some(ref suite) = parse_res.ast {
        // Step 1: Collect symbols & imports
        collect_symbols_suite(suite, &mut symbol_table, None, limits, &line_index);

        // Step 2: Extract call sites
        let mut extractor = CallSiteExtractor::new(&symbol_table, limits, &line_index);
        extractor.extract_suite(suite, ExecutionContext::ModuleScope);
        call_sites = extractor.call_sites;

        // Step 3: Run taint flow analysis
        let mut taint_engine = TaintEngine::new(&symbol_table, limits, &line_index, false);
        taint_result = taint_engine.analyze_suite(suite);
    }

    let imports = symbol_table.imports.into_values().collect();
    let definitions = symbol_table.definitions;

    PythonContentFacts {
        syntax_state: parse_res.syntax_state,
        imports,
        call_sites,
        definitions,
        coverage: parse_res.coverage,
        taint_result,
    }
}

/// Content facts, from the content cache when eligible and available,
/// otherwise computed fresh (and opportunistically cached for next time).
/// `sha256` must already be a verified content digest for `source`'s exact
/// bytes — never recomputed here.
fn content_facts(source: &str, sha256: &str, limits: &PythonAnalysisLimits) -> PythonContentFacts {
    let size = source.len() as u64;
    if crate::content_cache::eligible(size) {
        if let Ok(Some(cached)) = crate::content_cache::lookup::<PythonContentFacts>(
            sha256,
            size,
            PYTHON_CONTENT_CACHE_DISCRIMINATOR,
        ) {
            return cached;
        }
        let facts = analyze_content(source, limits);
        let _ =
            crate::content_cache::store(sha256, size, PYTHON_CONTENT_CACHE_DISCRIMINATOR, &facts);
        return facts;
    }
    analyze_content(source, limits)
}

pub fn analyze(
    relative_path: &str,
    source: &str,
    sha256: &str,
    auto_map_modules: &BTreeSet<String>,
    limits: &PythonAnalysisLimits,
) -> Result<PythonAnalysis> {
    let facts = content_facts(source, sha256, limits);

    // Reachability and auto_map relationships are always recomputed fresh:
    // they depend on `auto_map_modules`, which is contextual (per-package)
    // configuration that must never be baked into cached content facts.
    let (entry_points, relationships) = match facts.syntax_state {
        PythonSyntaxState::Valid => {
            let reach_graph = ReachabilityGraph::compute(
                &facts.call_sites,
                auto_map_modules,
                relative_path,
                limits,
            );
            (reach_graph.entry_points, reach_graph.relationships)
        }
        _ => (Vec::new(), Vec::new()),
    };

    Ok(PythonAnalysis {
        relative_path: relative_path.to_owned(),
        syntax_state: facts.syntax_state,
        imports: facts.imports,
        call_sites: facts.call_sites,
        definitions: facts.definitions,
        entry_points,
        relationships,
        coverage: facts.coverage,
        taint_result: facts.taint_result,
    })
}

pub fn analyze_and_convert_findings(
    relative_path: &str,
    source: &str,
    digest: &str,
    auto_map_modules: &BTreeSet<String>,
    limits: &PythonAnalysisLimits,
    started: Instant,
) -> Result<Vec<crate::scanner::LayerScanResult>> {
    let analysis = analyze(relative_path, source, digest, auto_map_modules, limits)?;

    let file_stem = std::path::Path::new(relative_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let is_auto_mapped = auto_map_modules.contains(file_stem);

    let reach_graph = ReachabilityGraph::compute(
        &analysis.call_sites,
        auto_map_modules,
        relative_path,
        limits,
    );

    let findings = findings::convert_analysis_to_findings(
        relative_path,
        digest,
        &analysis.syntax_state,
        &analysis.call_sites,
        &reach_graph.reachability_map,
        &analysis.taint_result,
        is_auto_mapped,
        started,
    );

    Ok(findings)
}

fn collect_symbols_suite(
    suite: &Suite,
    symbol_table: &mut SymbolTable,
    current_class: Option<&str>,
    limits: &PythonAnalysisLimits,
    line_index: &LineIndex,
) {
    for stmt in suite {
        if symbol_table.imports.len() >= limits.max_import_bindings
            || symbol_table.definitions.len() >= limits.max_definitions
        {
            break;
        }

        match stmt {
            Stmt::Import(imp) => {
                for alias in &imp.names {
                    let local_name = alias
                        .asname
                        .as_ref()
                        .map(|a| a.as_str().to_owned())
                        .unwrap_or_else(|| alias.name.as_str().to_owned());
                    let line = line_index.line_number(usize::from(alias.range.start()));
                    symbol_table.add_import(ImportBinding {
                        local_name,
                        target_module: alias.name.as_str().to_owned(),
                        target_member: None,
                        shadowed: false,
                        line: Some(line),
                    });
                }
            }
            Stmt::ImportFrom(imp_from) => {
                let module = imp_from.module.as_ref().map(|m| m.as_str()).unwrap_or("");
                for alias in &imp_from.names {
                    let local_name = alias
                        .asname
                        .as_ref()
                        .map(|a| a.as_str().to_owned())
                        .unwrap_or_else(|| alias.name.as_str().to_owned());
                    let line = line_index.line_number(usize::from(alias.range.start()));
                    symbol_table.add_import(ImportBinding {
                        local_name,
                        target_module: module.to_owned(),
                        target_member: Some(alias.name.as_str().to_owned()),
                        shadowed: false,
                        line: Some(line),
                    });
                }
            }
            Stmt::FunctionDef(f) => {
                let name = f.name.as_str().to_owned();
                let qualname = if let Some(cls) = current_class {
                    format!("{}.{}", cls, name)
                } else {
                    name.clone()
                };
                let kind = if current_class.is_some() {
                    DefinitionKind::Method
                } else {
                    DefinitionKind::Function
                };
                let line = line_index.line_number(usize::from(f.range.start()));

                // If function redefines an imported symbol name, mark it shadowed
                symbol_table.mark_shadowed(&name);

                symbol_table.definitions.push(Definition {
                    name,
                    qualname,
                    kind,
                    parent_class: current_class.map(ToOwned::to_owned),
                    line: Some(line),
                });

                collect_symbols_suite(&f.body, symbol_table, current_class, limits, line_index);
            }
            Stmt::AsyncFunctionDef(f) => {
                let name = f.name.as_str().to_owned();
                let qualname = if let Some(cls) = current_class {
                    format!("{}.{}", cls, name)
                } else {
                    name.clone()
                };
                let line = line_index.line_number(usize::from(f.range.start()));

                symbol_table.mark_shadowed(&name);

                symbol_table.definitions.push(Definition {
                    name,
                    qualname,
                    kind: DefinitionKind::AsyncFunction,
                    parent_class: current_class.map(ToOwned::to_owned),
                    line: Some(line),
                });

                collect_symbols_suite(&f.body, symbol_table, current_class, limits, line_index);
            }
            Stmt::ClassDef(c) => {
                let name = c.name.as_str().to_owned();
                let line = line_index.line_number(usize::from(c.range.start()));

                symbol_table.mark_shadowed(&name);

                symbol_table.definitions.push(Definition {
                    name: name.clone(),
                    qualname: name.clone(),
                    kind: DefinitionKind::Class,
                    parent_class: current_class.map(ToOwned::to_owned),
                    line: Some(line),
                });

                collect_symbols_suite(&c.body, symbol_table, Some(&name), limits, line_index);
            }
            Stmt::Assign(a) => {
                for target in &a.targets {
                    if let ast::Expr::Name(n) = target {
                        symbol_table.mark_shadowed(n.id.as_str());
                    }
                }
            }
            Stmt::AugAssign(a) => {
                if let ast::Expr::Name(n) = &*a.target {
                    symbol_table.mark_shadowed(n.id.as_str());
                }
            }
            Stmt::AnnAssign(a) => {
                if let ast::Expr::Name(n) = &*a.target {
                    symbol_table.mark_shadowed(n.id.as_str());
                }
            }
            Stmt::If(i) => {
                collect_symbols_suite(&i.body, symbol_table, current_class, limits, line_index);
                collect_symbols_suite(&i.orelse, symbol_table, current_class, limits, line_index);
            }
            Stmt::For(f) => {
                collect_symbols_suite(&f.body, symbol_table, current_class, limits, line_index);
                collect_symbols_suite(&f.orelse, symbol_table, current_class, limits, line_index);
            }
            Stmt::While(w) => {
                collect_symbols_suite(&w.body, symbol_table, current_class, limits, line_index);
                collect_symbols_suite(&w.orelse, symbol_table, current_class, limits, line_index);
            }
            Stmt::With(w) => {
                collect_symbols_suite(&w.body, symbol_table, current_class, limits, line_index);
            }
            Stmt::Try(t) => {
                collect_symbols_suite(&t.body, symbol_table, current_class, limits, line_index);
                for handler in &t.handlers {
                    let ast::ExceptHandler::ExceptHandler(h) = handler;
                    collect_symbols_suite(&h.body, symbol_table, current_class, limits, line_index);
                }
                collect_symbols_suite(&t.orelse, symbol_table, current_class, limits, line_index);
                collect_symbols_suite(
                    &t.finalbody,
                    symbol_table,
                    current_class,
                    limits,
                    line_index,
                );
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use calls::{ExecutionContext, PythonCapabilityCategory};
    use std::collections::BTreeSet;

    // Shared with `content_cache`'s own tests: env vars are process-global
    // and `cargo test` runs all tests in one process, so both modules must
    // serialize through the same lock.
    use crate::content_cache::ENV_TEST_LOCK as ENV_LOCK;

    struct ContentCacheEnvGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        root: std::path::PathBuf,
    }

    impl ContentCacheEnvGuard {
        fn new(name: &str) -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
            let root = std::env::temp_dir().join(format!(
                "layerfault-python-content-cache-{name}-{}-{}",
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
    fn python_content_facts_ignore_auto_map() {
        let _guard = ContentCacheEnvGuard::new("auto-map-independence");
        let code = r#"
import subprocess

class CustomModel:
    def __init__(self):
        subprocess.run(["echo", "hi"])
"#;
        let limits = PythonAnalysisLimits::default();
        let sha256 = "sha256:python-content-facts-test";

        let mut mapped = BTreeSet::new();
        mapped.insert("modeling_custom".to_owned());
        let with_auto_map = analyze("modeling_custom.py", code, sha256, &mapped, &limits).unwrap();

        let without_auto_map = analyze(
            "modeling_custom.py",
            code,
            sha256,
            &BTreeSet::new(),
            &limits,
        )
        .unwrap();

        // Content-intrinsic facts (parsed/cached under the same content
        // sha256) must be identical regardless of auto_map configuration.
        assert_eq!(
            with_auto_map.call_sites.len(),
            without_auto_map.call_sites.len()
        );
        assert_eq!(with_auto_map.imports.len(), without_auto_map.imports.len());
        assert_eq!(
            with_auto_map.definitions.len(),
            without_auto_map.definitions.len()
        );
        assert!(matches!(
            with_auto_map.syntax_state,
            PythonSyntaxState::Valid
        ));
        assert!(matches!(
            without_auto_map.syntax_state,
            PythonSyntaxState::Valid
        ));

        // Reachability/auto_map relationships are always recomputed fresh
        // and must differ: the mapped call sees an auto_map entry point,
        // the unmapped call does not.
        assert!(with_auto_map.entry_points.iter().any(|ep| ep.is_auto_map));
        assert!(without_auto_map
            .entry_points
            .iter()
            .all(|ep| !ep.is_auto_map));
    }

    #[test]
    fn test_import_alias_resolution() {
        let code = r#"
import subprocess as sp
sp.run(["id"])
"#;
        let limits = PythonAnalysisLimits::default();
        let auto_map = BTreeSet::new();
        let res = analyze("test.py", code, "sha256", &auto_map, &limits).unwrap();
        assert_eq!(res.syntax_state, PythonSyntaxState::Valid);
        assert_eq!(res.call_sites.len(), 1);
        let cs = &res.call_sites[0];
        assert_eq!(cs.raw_target, "sp.run");
        assert_eq!(cs.resolved_target, "subprocess.run");
        assert_eq!(cs.category, PythonCapabilityCategory::ProcessExecution);
        assert_eq!(cs.executable_name.as_deref(), Some("id"));
    }

    #[test]
    fn test_member_import_alias() {
        let code = r#"
from subprocess import Popen as Launch
Launch(["whoami"])
"#;
        let limits = PythonAnalysisLimits::default();
        let auto_map = BTreeSet::new();
        let res = analyze("test.py", code, "sha256", &auto_map, &limits).unwrap();
        assert_eq!(res.call_sites.len(), 1);
        let cs = &res.call_sites[0];
        assert_eq!(cs.raw_target, "Launch");
        assert_eq!(cs.resolved_target, "subprocess.Popen");
        assert_eq!(cs.category, PythonCapabilityCategory::ProcessExecution);
        assert_eq!(cs.executable_name.as_deref(), Some("whoami"));
    }

    #[test]
    fn test_getattr_reflection_resolution() {
        let code = r#"
import os
getattr(os, "system")("id")
"#;
        let limits = PythonAnalysisLimits::default();
        let auto_map = BTreeSet::new();
        let res = analyze("test.py", code, "sha256", &auto_map, &limits).unwrap();
        assert_eq!(res.call_sites.len(), 1);
        let cs = &res.call_sites[0];
        assert_eq!(cs.resolved_target, "os.system");
        assert!(cs.reflection_resolved);
        assert_eq!(cs.category, PythonCapabilityCategory::ProcessExecution);
    }

    #[test]
    fn test_symbol_shadowing() {
        let code = r#"
from subprocess import run
run = lambda x: x
run("safe")
"#;
        let limits = PythonAnalysisLimits::default();
        let auto_map = BTreeSet::new();
        let res = analyze("test.py", code, "sha256", &auto_map, &limits).unwrap();
        // Since `run` was shadowed by reassignment `run = ...`, `run("safe")` is not resolved to `subprocess.run`
        assert!(res.call_sites.is_empty() || res.call_sites[0].resolved_target != "subprocess.run");
    }

    #[test]
    fn test_execution_context_classification() {
        let code = r#"
import os

os.system("import_scope")

def helper():
    os.system("func_scope")

class Model:
    def __init__(self):
        os.system("constructor_scope")
"#;
        let limits = PythonAnalysisLimits::default();
        let auto_map = BTreeSet::new();
        let res = analyze("test.py", code, "sha256", &auto_map, &limits).unwrap();
        assert_eq!(res.call_sites.len(), 3);
        assert_eq!(
            res.call_sites[0].execution_context,
            ExecutionContext::ModuleScope
        );
        assert_eq!(
            res.call_sites[1].execution_context,
            ExecutionContext::FunctionBody
        );
        assert_eq!(
            res.call_sites[2].execution_context,
            ExecutionContext::Constructor
        );
    }

    #[test]
    fn test_auto_map_correlation() {
        let code = r#"
import subprocess

class CustomModel:
    def __init__(self):
        subprocess.run(["echo", "correlated"])
"#;
        let limits = PythonAnalysisLimits::default();
        let mut auto_map = BTreeSet::new();
        auto_map.insert("modeling_custom".to_owned());

        let started = Instant::now();
        let findings = analyze_and_convert_findings(
            "modeling_custom.py",
            code,
            "sha256",
            &auto_map,
            &limits,
            started,
        )
        .unwrap();

        assert!(findings
            .iter()
            .any(|f| crate::policy::rule_id(f) == "LF-CORR-HF-LOADER-PROCESS"));
    }

    #[test]
    fn test_invalid_python_syntax() {
        let code = "def broken_func(:\n  return 42";
        let limits = PythonAnalysisLimits::default();
        let auto_map = BTreeSet::new();
        let res = analyze("test.py", code, "sha256", &auto_map, &limits).unwrap();
        assert!(matches!(
            res.syntax_state,
            PythonSyntaxState::Invalid { .. }
        ));
        assert!(matches!(res.coverage, PythonCoverage::Incomplete { .. }));
    }

    #[test]
    fn test_hard_limits_node_cap() {
        let code = "x = ".to_owned() + &"1 + ".repeat(100) + "1";
        let limits = PythonAnalysisLimits {
            max_ast_nodes: 10,
            ..Default::default()
        };
        let auto_map = BTreeSet::new();
        let res = analyze("test.py", &code, "sha256", &auto_map, &limits).unwrap();
        assert!(matches!(
            res.syntax_state,
            PythonSyntaxState::ExceededLimits { .. }
        ));
        assert!(matches!(res.coverage, PythonCoverage::Incomplete { .. }));
    }
}
