//! Bounded-analysis limits for the PowerShell semantic frontend.
//!
//! Mirrors the const-then-struct-then-`Default` shape of
//! [`crate::shell_static::limits::ShellAnalysisLimits`]. PowerShell has no
//! true AST here either, so `max_tokens` caps the total number of lexical
//! tokens (words/operators/statements) scanned, and `max_nesting_depth` caps
//! script-block/`if`/`foreach`/`while`/function-body brace nesting.

pub const DEFAULT_MAX_POWERSHELL_SOURCE_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_MAX_TOKENS: usize = 500_000;
pub const DEFAULT_MAX_NESTING_DEPTH: usize = 64;
pub const DEFAULT_MAX_CALL_SITES: usize = 10_000;
pub const DEFAULT_MAX_STRING_LITERAL_BYTES: usize = 1_024;
pub const DEFAULT_MAX_CAPABILITY_FINDINGS_PER_FILE: usize = 1_000;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PowerShellAnalysisLimits {
    pub max_source_bytes: usize,
    pub max_tokens: usize,
    pub max_nesting_depth: usize,
    pub max_call_sites: usize,
    pub max_string_literal_bytes: usize,
    pub max_capability_findings_per_file: usize,
}

impl Default for PowerShellAnalysisLimits {
    fn default() -> Self {
        Self {
            max_source_bytes: DEFAULT_MAX_POWERSHELL_SOURCE_BYTES,
            max_tokens: DEFAULT_MAX_TOKENS,
            max_nesting_depth: DEFAULT_MAX_NESTING_DEPTH,
            max_call_sites: DEFAULT_MAX_CALL_SITES,
            max_string_literal_bytes: DEFAULT_MAX_STRING_LITERAL_BYTES,
            max_capability_findings_per_file: DEFAULT_MAX_CAPABILITY_FINDINGS_PER_FILE,
        }
    }
}
