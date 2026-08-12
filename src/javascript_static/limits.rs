//! Bounded-analysis limits for the JavaScript/TypeScript semantic frontend.
//!
//! Field names are 1:1 with
//! [`crate::python_static::limits::PythonAnalysisLimits`]'s non-taint fields
//! (this frontend has no taint engine).
//! `max_ast_nodes`/`max_ast_depth` are enforced against `oxc`'s real AST via
//! a bounded pre-walk (see `javascript_static::parser`), the same shape as
//! Python's `check_ast_limits_suite/stmt/expr`, just driven by `oxc`'s
//! `enter_node`/`leave_node` visitor hooks instead of a hand-written
//! per-node-kind match (see the parser module doc for why).

pub const DEFAULT_MAX_JS_SOURCE_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_MAX_AST_NODES: usize = 500_000;
pub const DEFAULT_MAX_AST_DEPTH: usize = 256;
pub const DEFAULT_MAX_IMPORT_BINDINGS: usize = 10_000;
pub const DEFAULT_MAX_CALL_SITES: usize = 10_000;
pub const DEFAULT_MAX_DEFINITIONS: usize = 10_000;
pub const DEFAULT_MAX_STRING_LITERAL_BYTES: usize = 1_024;
pub const DEFAULT_MAX_CAPABILITY_FINDINGS_PER_FILE: usize = 1_000;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct JavaScriptAnalysisLimits {
    pub max_source_bytes: usize,
    pub max_ast_nodes: usize,
    pub max_ast_depth: usize,
    pub max_import_bindings: usize,
    pub max_call_sites: usize,
    pub max_definitions: usize,
    pub max_string_literal_bytes: usize,
    pub max_capability_findings_per_file: usize,
}

impl Default for JavaScriptAnalysisLimits {
    fn default() -> Self {
        Self {
            max_source_bytes: DEFAULT_MAX_JS_SOURCE_BYTES,
            max_ast_nodes: DEFAULT_MAX_AST_NODES,
            max_ast_depth: DEFAULT_MAX_AST_DEPTH,
            max_import_bindings: DEFAULT_MAX_IMPORT_BINDINGS,
            max_call_sites: DEFAULT_MAX_CALL_SITES,
            max_definitions: DEFAULT_MAX_DEFINITIONS,
            max_string_literal_bytes: DEFAULT_MAX_STRING_LITERAL_BYTES,
            max_capability_findings_per_file: DEFAULT_MAX_CAPABILITY_FINDINGS_PER_FILE,
        }
    }
}
