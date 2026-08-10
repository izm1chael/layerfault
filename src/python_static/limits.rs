pub const DEFAULT_MAX_PYTHON_SOURCE_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_MAX_AST_NODES: usize = 500_000;
pub const DEFAULT_MAX_AST_DEPTH: usize = 256;
pub const DEFAULT_MAX_IMPORT_BINDINGS: usize = 10_000;
pub const DEFAULT_MAX_CALL_SITES: usize = 10_000;
pub const DEFAULT_MAX_DEFINITIONS: usize = 10_000;
pub const DEFAULT_MAX_STRING_LITERAL_EVIDENCE_BYTES: usize = 1_024;
pub const DEFAULT_MAX_RELATIONSHIPS: usize = 10_000;
pub const DEFAULT_MAX_CAPABILITY_FINDINGS_PER_FILE: usize = 1_000;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PythonAnalysisLimits {
    pub max_source_bytes: usize,
    pub max_ast_nodes: usize,
    pub max_ast_depth: usize,
    pub max_import_bindings: usize,
    pub max_call_sites: usize,
    pub max_definitions: usize,
    pub max_string_literal_bytes: usize,
    pub max_relationships: usize,
    pub max_capability_findings_per_file: usize,
}

impl Default for PythonAnalysisLimits {
    fn default() -> Self {
        Self {
            max_source_bytes: DEFAULT_MAX_PYTHON_SOURCE_BYTES,
            max_ast_nodes: DEFAULT_MAX_AST_NODES,
            max_ast_depth: DEFAULT_MAX_AST_DEPTH,
            max_import_bindings: DEFAULT_MAX_IMPORT_BINDINGS,
            max_call_sites: DEFAULT_MAX_CALL_SITES,
            max_definitions: DEFAULT_MAX_DEFINITIONS,
            max_string_literal_bytes: DEFAULT_MAX_STRING_LITERAL_EVIDENCE_BYTES,
            max_relationships: DEFAULT_MAX_RELATIONSHIPS,
            max_capability_findings_per_file: DEFAULT_MAX_CAPABILITY_FINDINGS_PER_FILE,
        }
    }
}
