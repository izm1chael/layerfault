//! Bounded resource limits and coverage tracking metrics for Jinja template static analysis.

#[derive(Debug, Clone)]
pub struct TemplateLimits {
    pub max_template_bytes: usize,
    pub max_node_count: usize,
    pub max_ast_depth: usize,
    pub max_macro_count: usize,
    pub max_expression_depth: usize,
    pub max_evidence_items: usize,
}

impl Default for TemplateLimits {
    fn default() -> Self {
        Self {
            max_template_bytes: 1_048_576, // 1 MB
            max_node_count: 5_000,
            max_ast_depth: 64,
            max_macro_count: 64,
            max_expression_depth: 32,
            max_evidence_items: 32,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct TemplateMetrics {
    pub node_count: usize,
    pub macro_count: usize,
    pub incomplete_coverage: bool,
    pub incomplete_reason: Option<String>,
}

impl TemplateMetrics {
    pub fn mark_incomplete(&mut self, reason: impl Into<String>) {
        self.incomplete_coverage = true;
        if self.incomplete_reason.is_none() {
            self.incomplete_reason = Some(reason.into());
        }
    }
}
