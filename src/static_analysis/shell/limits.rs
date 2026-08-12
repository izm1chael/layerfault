//! Bounded-analysis limits for the shell/POSIX semantic frontend.
//!
//! Mirrors the const-then-struct-then-`Default` shape of
//! [`crate::static_analysis::python::limits::PythonAnalysisLimits`]. Shell has no true
//! AST, so `max_tokens` caps the total number of lexical tokens (words and
//! operators) scanned, in place of Python's `max_ast_nodes`, and
//! `max_nesting_depth` caps control-structure/function/brace nesting in
//! place of `max_ast_depth`.

pub const DEFAULT_MAX_SHELL_SOURCE_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_MAX_TOKENS: usize = 500_000;
pub const DEFAULT_MAX_NESTING_DEPTH: usize = 64;
pub const DEFAULT_MAX_CALL_SITES: usize = 10_000;
pub const DEFAULT_MAX_STRING_LITERAL_BYTES: usize = 1_024;
pub const DEFAULT_MAX_CAPABILITY_FINDINGS_PER_FILE: usize = 1_000;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ShellAnalysisLimits {
    pub max_source_bytes: usize,
    pub max_tokens: usize,
    pub max_nesting_depth: usize,
    pub max_call_sites: usize,
    pub max_string_literal_bytes: usize,
    pub max_capability_findings_per_file: usize,
}

impl Default for ShellAnalysisLimits {
    fn default() -> Self {
        Self {
            max_source_bytes: DEFAULT_MAX_SHELL_SOURCE_BYTES,
            max_tokens: DEFAULT_MAX_TOKENS,
            max_nesting_depth: DEFAULT_MAX_NESTING_DEPTH,
            max_call_sites: DEFAULT_MAX_CALL_SITES,
            max_string_literal_bytes: DEFAULT_MAX_STRING_LITERAL_BYTES,
            max_capability_findings_per_file: DEFAULT_MAX_CAPABILITY_FINDINGS_PER_FILE,
        }
    }
}
