//! Bounded semantic analyzer for Jinja templates.
//!
//! Evaluates object graph traversals, dunder access chains, dynamic imports/includes,
//! and ensures fallback textual scanning when coverage is incomplete.

use crate::static_analysis::template::ast::*;
use crate::static_analysis::template::limits::*;
use crate::static_analysis::template::parser::{Parser, Tokenizer};
use regex::Regex;

lazy_static::lazy_static! {
    static ref DANGEROUS_SSTI_PRIMITIVES: [&'static str; 10] = [
        "__subclasses__",
        "__globals__",
        "__builtins__",
        "__code__",
        "__import__",
        "cycler.__init__",
        "namespace.__init__",
        "lipsum.__globals__",
        "joiner.__init__",
        "__init__",
    ];

    static ref INTROSPECTION_PRIMITIVES: [&'static str; 5] = [
        "__class__",
        "__mro__",
        "__bases__",
        "__doc__",
        "__dict__",
    ];

    static ref FALLBACK_DANGEROUS: Regex = Regex::new(
        r"(?is)(\{\{[^}]{0,2048}(?:__class__|__mro__|__subclasses__|__globals__|__builtins__|cycler\.__init__|joiner\.__init__|namespace\.__init__|lipsum\.__globals__)[^}]{0,2048}\}\})"
    ).unwrap();

    static ref FALLBACK_IMPORT: Regex = Regex::new(
        r"(?is)\{%\s*(?:import|from|include)\b[^%]{0,2048}%\}"
    ).unwrap();
}

#[derive(Debug, Clone, PartialEq)]
pub enum TemplateFindingRule {
    Ssti,           // LF-TEMPLATE-SSTI
    Introspection,  // LF-TEMPLATE-INTROSPECTION
    DynamicInclude, // LF-TEMPLATE-DYNAMIC-INCLUDE
}

impl TemplateFindingRule {
    pub fn rule_id(&self) -> &'static str {
        match self {
            TemplateFindingRule::Ssti => "LF-TEMPLATE-SSTI",
            TemplateFindingRule::Introspection => "LF-TEMPLATE-INTROSPECTION",
            TemplateFindingRule::DynamicInclude => "LF-TEMPLATE-DYNAMIC-INCLUDE",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum TargetClassification {
    StaticLiteral,
    DynamicExpression,
    PathTraversalLiteral,
    ParsedExpression,
    IncompleteCoverageFallback,
}

impl TargetClassification {
    pub fn as_str(&self) -> &'static str {
        match self {
            TargetClassification::StaticLiteral => "static_literal",
            TargetClassification::DynamicExpression => "dynamic_expression",
            TargetClassification::PathTraversalLiteral => "path_traversal_literal",
            TargetClassification::ParsedExpression => "parsed_expression",
            TargetClassification::IncompleteCoverageFallback => "incomplete_coverage_fallback",
        }
    }
}

#[derive(Debug, Clone)]
pub struct TemplateSemanticFinding {
    pub rule: TemplateFindingRule,
    pub detail: String,
    pub excerpt: String,
    pub span: SourceSpan,
    pub classification: TargetClassification,
}

#[derive(Debug, Clone, Default)]
pub struct TemplateAnalysisResult {
    pub findings: Vec<TemplateSemanticFinding>,
    pub metrics: TemplateMetrics,
}

pub fn analyze_template(
    content: &str,
    source_context: &str,
    limits: &TemplateLimits,
) -> TemplateAnalysisResult {
    let mut result = TemplateAnalysisResult::default();

    if content.len() > limits.max_template_bytes {
        result.metrics.mark_incomplete(format!(
            "Template size {} exceeds limit {}",
            content.len(),
            limits.max_template_bytes
        ));
        fallback_text_scan(content, source_context, &mut result);
        return result;
    }

    let mut tokenizer = Tokenizer::new(content);
    let tokens = match tokenizer.tokenize_all(limits) {
        Ok(t) => t,
        Err(err) => {
            result.metrics.mark_incomplete(err.to_string());
            fallback_text_scan(content, source_context, &mut result);
            return result;
        }
    };

    let mut parser = Parser::new(tokens, limits);
    let (stmts, metrics) = match parser.parse_program() {
        Ok(res) => res,
        Err(err) => {
            result.metrics.mark_incomplete(err.to_string());
            fallback_text_scan(content, source_context, &mut result);
            return result;
        }
    };

    result.metrics = metrics;

    let mut analyzer = StmtAnalyzer::new(content, source_context, limits);
    analyzer.analyze_stmts(&stmts);
    result.findings.extend(analyzer.findings);

    if result.metrics.incomplete_coverage && result.findings.is_empty() {
        fallback_text_scan(content, source_context, &mut result);
    }

    result
}

struct StmtAnalyzer<'a> {
    content: &'a str,
    source_context: &'a str,
    limits: &'a TemplateLimits,
    findings: Vec<TemplateSemanticFinding>,
}

impl<'a> StmtAnalyzer<'a> {
    fn new(content: &'a str, source_context: &'a str, limits: &'a TemplateLimits) -> Self {
        Self {
            content,
            source_context,
            limits,
            findings: Vec::new(),
        }
    }

    fn extract_excerpt(&self, span: &SourceSpan) -> String {
        let start = span.offset as usize;
        let end = (span.offset + span.length) as usize;
        if start < self.content.len() {
            let end_bounded = end.min(self.content.len());
            self.content[start..end_bounded].trim().to_owned()
        } else {
            String::new()
        }
    }

    fn analyze_stmts(&mut self, stmts: &[Stmt]) {
        for stmt in stmts {
            if self.findings.len() >= self.limits.max_evidence_items {
                break;
            }
            match stmt {
                Stmt::Output { expr, .. } => {
                    self.analyze_expr(expr);
                }
                Stmt::Include { target, span, .. } => {
                    self.classify_include_target(target, span, "include");
                    self.analyze_expr(target);
                }
                Stmt::Import { target, span, .. } => {
                    self.classify_include_target(target, span, "import");
                    self.analyze_expr(target);
                }
                Stmt::FromImport { target, span, .. } => {
                    self.classify_include_target(target, span, "from-import");
                    self.analyze_expr(target);
                }
                Stmt::Set { value, .. } => {
                    self.analyze_expr(value);
                }
                Stmt::For { iter, body, .. } => {
                    self.analyze_expr(iter);
                    self.analyze_stmts(body);
                }
                Stmt::If {
                    condition,
                    body,
                    elifs,
                    else_body,
                    ..
                } => {
                    self.analyze_expr(condition);
                    self.analyze_stmts(body);
                    for (cond, e_body) in elifs {
                        self.analyze_expr(cond);
                        self.analyze_stmts(e_body);
                    }
                    if let Some(eb) = else_body {
                        self.analyze_stmts(eb);
                    }
                }
                Stmt::Macro { body, .. } => {
                    self.analyze_stmts(body);
                }
                Stmt::FilterBlock { body, .. } => {
                    self.analyze_stmts(body);
                }
                Stmt::RawText { .. } => {}
            }
        }
    }

    fn classify_include_target(&mut self, target: &Expr, span: &SourceSpan, directive: &str) {
        let excerpt = self.extract_excerpt(span);
        match target {
            Expr::Literal {
                val: LiteralValue::String(s),
                ..
            } => {
                if s.contains("..") || s.starts_with('/') || s.starts_with('\\') {
                    self.findings.push(TemplateSemanticFinding {
                        rule: TemplateFindingRule::DynamicInclude,
                        detail: format!(
                            "Template directive '{}' in '{}' contains a path-traversal target literal '{}'",
                            directive, self.source_context, s
                        ),
                        excerpt,
                        span: *span,
                        classification: TargetClassification::PathTraversalLiteral,
                    });
                }
            }
            _ => {
                self.findings.push(TemplateSemanticFinding {
                    rule: TemplateFindingRule::DynamicInclude,
                    detail: format!(
                        "Template directive '{}' in '{}' uses a dynamic target expression requiring review",
                        directive, self.source_context
                    ),
                    excerpt,
                    span: *span,
                    classification: TargetClassification::DynamicExpression,
                });
            }
        }
    }

    fn analyze_expr(&mut self, expr: &Expr) {
        self.analyze_expr_internal(expr, true);
    }

    fn analyze_expr_internal(&mut self, expr: &Expr, is_chain_root: bool) {
        if self.findings.len() >= self.limits.max_evidence_items {
            return;
        }

        if is_chain_root
            && matches!(
                expr,
                Expr::Attribute { .. } | Expr::ItemAccess { .. } | Expr::Call { .. }
            )
        {
            let mut steps = Vec::new();
            self.collect_traversal_chain(expr, &mut steps);

            if !steps.is_empty() {
                let has_ssti = steps.iter().any(|step| {
                    DANGEROUS_SSTI_PRIMITIVES
                        .iter()
                        .any(|prim| step.eq_ignore_ascii_case(prim))
                });
                let has_introspection = steps.iter().any(|step| {
                    INTROSPECTION_PRIMITIVES
                        .iter()
                        .any(|prim| step.eq_ignore_ascii_case(prim))
                });

                if has_ssti {
                    let excerpt = self.extract_excerpt(&expr.span());
                    self.findings.push(TemplateSemanticFinding {
                        rule: TemplateFindingRule::Ssti,
                        detail: format!(
                            "Jinja template object-graph traversal in '{}' reaches SSTI primitive sequence: {:?}",
                            self.source_context, steps
                        ),
                        excerpt,
                        span: expr.span(),
                        classification: TargetClassification::ParsedExpression,
                    });
                }
                if has_introspection {
                    let excerpt = self.extract_excerpt(&expr.span());
                    self.findings.push(TemplateSemanticFinding {
                        rule: TemplateFindingRule::Introspection,
                        detail: format!(
                            "Jinja template contains Python introspection traversal sequence in '{}': {:?}",
                            self.source_context, steps
                        ),
                        excerpt,
                        span: expr.span(),
                        classification: TargetClassification::ParsedExpression,
                    });
                }
            }
        }

        // Recurse into sub-expressions, marking child object/callee nodes as non-roots
        match expr {
            Expr::Attribute { obj, .. } => self.analyze_expr_internal(obj, false),
            Expr::ItemAccess { obj, item, .. } => {
                self.analyze_expr_internal(obj, false);
                self.analyze_expr_internal(item, true);
            }
            Expr::Call {
                callee,
                args,
                kwargs,
                ..
            } => {
                self.analyze_expr_internal(callee, false);
                for arg in args {
                    self.analyze_expr_internal(arg, true);
                }
                for (_, val) in kwargs {
                    self.analyze_expr_internal(val, true);
                }
            }
            Expr::Filter {
                expr: inner, args, ..
            } => {
                self.analyze_expr_internal(inner, true);
                for arg in args {
                    self.analyze_expr_internal(arg, true);
                }
            }
            Expr::Test {
                expr: inner, args, ..
            } => {
                self.analyze_expr_internal(inner, true);
                for arg in args {
                    self.analyze_expr_internal(arg, true);
                }
            }
            Expr::List { items, .. } => {
                for item in items {
                    self.analyze_expr_internal(item, true);
                }
            }
            Expr::Dict { entries, .. } => {
                for (k, v) in entries {
                    self.analyze_expr_internal(k, true);
                    self.analyze_expr_internal(v, true);
                }
            }
            Expr::Tuple { items, .. } => {
                for item in items {
                    self.analyze_expr_internal(item, true);
                }
            }
            Expr::Unary { expr: inner, .. } => self.analyze_expr_internal(inner, true),
            Expr::Binary { left, right, .. } => {
                self.analyze_expr_internal(left, true);
                self.analyze_expr_internal(right, true);
            }
            _ => {}
        }
    }

    fn collect_traversal_chain(&self, expr: &Expr, steps: &mut Vec<String>) {
        match expr {
            Expr::Attribute { obj, attr, .. } => {
                self.collect_traversal_chain(obj, steps);
                steps.push(attr.clone());
            }
            Expr::ItemAccess { obj, item, .. } => {
                self.collect_traversal_chain(obj, steps);
                if let Expr::Literal {
                    val: LiteralValue::String(s),
                    ..
                } = item.as_ref()
                {
                    steps.push(s.clone());
                }
            }
            Expr::Call { callee, .. } => {
                self.collect_traversal_chain(callee, steps);
            }
            _ => {}
        }
    }
}

fn fallback_text_scan(content: &str, source_context: &str, result: &mut TemplateAnalysisResult) {
    let lower = content.to_ascii_lowercase();
    let has_ssti = DANGEROUS_SSTI_PRIMITIVES.iter().any(|p| lower.contains(p));
    let has_intro = INTROSPECTION_PRIMITIVES.iter().any(|p| lower.contains(p));
    let has_import = ["import", "include", "from"]
        .iter()
        .any(|p| lower.contains(p));

    if has_ssti {
        let span = SourceSpan::new(1, 1, 0, content.len() as u64);
        let excerpt = content.lines().next().unwrap_or("").trim().to_owned();
        result.findings.push(TemplateSemanticFinding {
            rule: TemplateFindingRule::Ssti,
            detail: format!(
                "Jinja object-graph traversal matched in '{}' [incomplete semantic coverage: fallback text scanner active]",
                source_context
            ),
            excerpt,
            span,
            classification: TargetClassification::IncompleteCoverageFallback,
        });
    } else if has_intro {
        let span = SourceSpan::new(1, 1, 0, content.len() as u64);
        let excerpt = content.lines().next().unwrap_or("").trim().to_owned();
        result.findings.push(TemplateSemanticFinding {
            rule: TemplateFindingRule::Introspection,
            detail: format!(
                "Jinja introspection primitive matched in '{}' [incomplete semantic coverage: fallback text scanner active]",
                source_context
            ),
            excerpt,
            span,
            classification: TargetClassification::IncompleteCoverageFallback,
        });
    } else if has_import {
        let span = SourceSpan::new(1, 1, 0, content.len() as u64);
        let excerpt = content.lines().next().unwrap_or("").trim().to_owned();
        result.findings.push(TemplateSemanticFinding {
            rule: TemplateFindingRule::DynamicInclude,
            detail: format!(
                "Jinja import/include directive matched in '{}' [incomplete semantic coverage: fallback text scanner active]",
                source_context
            ),
            excerpt,
            span,
            classification: TargetClassification::IncompleteCoverageFallback,
        });
    }
}
