//! `oxc_parser`-backed parsing and bounded AST-limit enforcement for
//! JavaScript/TypeScript source.
//!
//! Structural mirror of `python_static::parser`: a `<Lang>SyntaxState`/
//! `<Lang>Coverage` pair, a bounded pre-walk enforcing AST node/depth caps
//! before real analysis runs, and [`LineIndex`] (reused verbatim from
//! `python_static::parser`, which is pure-string and already reused by both
//! `shell_static` and `powershell_static`) for span-to-line/column mapping.
//!
//! ## Why the bounded pre-walk looks different from Python's
//!
//! Python's `check_ast_limits_suite/stmt/expr` is a hand-written recursive
//! match over `rustpython_parser`'s (comparatively small) `Stmt`/`Expr`
//! enums, and can abort mid-walk the instant a limit is exceeded. `oxc`'s
//! AST is far larger (dozens of statement/expression/TypeScript-syntax node
//! kinds) and its parser crate does not expose a hand-matchable enum walk of
//! that size as a public, stable surface; the maintained, idiomatic way to
//! visit "every node" is [`oxc_ast_visit::Visit`], whose generated
//! `enter_node`/`leave_node` hooks fire for effectively every AST node
//! (confirmed by reading the generated visitor source: every `walk_*`
//! helper calls `enter_node` before, and `leave_node` after, recursing into
//! children). [`LimitsVisitor`] below uses exactly those two hooks to count
//! nodes and track nesting depth, which is behaviorally equivalent to
//! Python's node-count/depth bound.
//!
//! One real difference: this pre-walk does not abort *mid-traversal* the
//! way Python's does, because `Visit`'s methods are infallible (`-> ()`)
//! with no short-circuit signal. This is an accepted, documented trade-off:
//! `max_source_bytes` (16 MiB) already bounds total parse+walk cost to a
//! single linear pass over a capped input before this pre-walk ever runs, so
//! the difference is a constant-factor performance one, not a correctness or
//! DoS-safety one — the walk still always terminates, and the limit is still
//! always enforced (just after a full O(n) pass rather than aborting at
//! node number `max_ast_nodes + 1`).
//!
//! Function/arrow-function scope tracking (used by `calls.rs`) is done the
//! same way: checking `AstKind::Function`/`AstKind::ArrowFunctionExpression`
//! inside `enter_node`/`leave_node`, rather than overriding
//! `visit_function`/`visit_arrow_function_expression` directly (which would
//! require also depending on `oxc_syntax` for the `ScopeFlags` parameter
//! type those methods take, for no benefit here).

use super::limits::JavaScriptAnalysisLimits;
use oxc_allocator::Allocator;
use oxc_ast::ast::Program;
use oxc_ast::ast_kind::AstKind;
use oxc_ast_visit::Visit;
use oxc_parser::Parser;
use oxc_span::SourceType;

pub use crate::static_analysis::python::parser::LineIndex;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum JsSyntaxState {
    Valid,
    Invalid {
        error: String,
        line: Option<usize>,
        column: Option<usize>,
    },
    ExceededLimits {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum JsCoverage {
    Complete,
    Incomplete { reason: String },
}

impl std::fmt::Display for JsSyntaxState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Valid => write!(f, "Valid"),
            Self::Invalid {
                error,
                line,
                column,
            } => {
                if let (Some(l), Some(c)) = (line, column) {
                    write!(
                        f,
                        "Invalid JavaScript/TypeScript syntax at L{l}:{c}: {error}"
                    )
                } else {
                    write!(f, "Invalid JavaScript/TypeScript syntax: {error}")
                }
            }
            Self::ExceededLimits { reason } => write!(f, "Exceeded limits: {reason}"),
        }
    }
}

/// Resolve an `oxc` [`SourceType`] from a lowercased file extension (no
/// leading dot). Falls back to plain `.js` semantics for any extension this
/// frontend is dispatched for but `oxc` doesn't recognize by name, so
/// parsing is always attempted rather than skipped.
fn source_type_for_ext(ext: &str) -> SourceType {
    SourceType::from_extension(ext).unwrap_or_else(|_| SourceType::from_extension("js").unwrap())
}

pub struct JsParseResult<'a> {
    pub syntax_state: JsSyntaxState,
    pub coverage: JsCoverage,
    pub program: Option<Program<'a>>,
}

/// Parse `source` (already known to be `<= limits.max_source_bytes`, checked
/// by the caller alongside the global scheduler budget in
/// `language_frontend`) into an `oxc` [`Program`], enforcing
/// `max_source_bytes` again defensively and then the AST node/depth bounds
/// via [`LimitsVisitor`].
pub fn parse_js_source<'a>(
    allocator: &'a Allocator,
    source: &'a str,
    ext: &str,
    limits: &JavaScriptAnalysisLimits,
) -> JsParseResult<'a> {
    if source.len() > limits.max_source_bytes {
        return JsParseResult {
            syntax_state: JsSyntaxState::ExceededLimits {
                reason: format!(
                    "Source byte size ({} bytes) exceeds limit ({} bytes)",
                    source.len(),
                    limits.max_source_bytes
                ),
            },
            coverage: JsCoverage::Incomplete {
                reason: format!("File size exceeds cap of {} bytes", limits.max_source_bytes),
            },
            program: None,
        };
    }

    let source_type = source_type_for_ext(ext);
    let ret = Parser::new(allocator, source, source_type).parse();

    if ret.panicked || !ret.errors.is_empty() {
        let line_index = LineIndex::new(source);
        let (line, column) = ret
            .errors
            .first()
            .and_then(|diagnostic| diagnostic.labels.as_ref())
            .and_then(|labels| labels.first())
            .map(|label| line_index.line_col(label.offset(), source))
            .map(|(l, c)| (Some(l), Some(c)))
            .unwrap_or((None, None));
        let error_str = ret
            .errors
            .first()
            .map(|diagnostic| diagnostic.to_string())
            .unwrap_or_else(|| "unknown parse error".to_owned());
        return JsParseResult {
            syntax_state: JsSyntaxState::Invalid {
                error: error_str.clone(),
                line,
                column,
            },
            coverage: JsCoverage::Incomplete {
                reason: format!("JavaScript/TypeScript syntax error: {error_str}"),
            },
            program: None,
        };
    }

    let mut limits_visitor = LimitsVisitor::new(limits);
    limits_visitor.visit_program(&ret.program);
    if limits_visitor.exceeded {
        return JsParseResult {
            syntax_state: JsSyntaxState::ExceededLimits {
                reason: format!(
                    "AST node count ({}) or max depth ({}) exceeded configured limits (max nodes {}, max depth {})",
                    limits_visitor.node_count,
                    limits_visitor.max_depth,
                    limits.max_ast_nodes,
                    limits.max_ast_depth
                ),
            },
            coverage: JsCoverage::Incomplete {
                reason: "AST complexity limit exceeded".to_owned(),
            },
            program: None,
        };
    }

    JsParseResult {
        syntax_state: JsSyntaxState::Valid,
        coverage: JsCoverage::Complete,
        program: Some(ret.program),
    }
}

/// Bounded pre-walk enforcing `max_ast_nodes`/`max_ast_depth` before real
/// (symbol/call-site) analysis runs. See module doc for why this counts the
/// whole tree rather than aborting mid-walk.
struct LimitsVisitor<'a> {
    limits: &'a JavaScriptAnalysisLimits,
    node_count: usize,
    depth: usize,
    max_depth: usize,
    exceeded: bool,
}

impl<'a> LimitsVisitor<'a> {
    fn new(limits: &'a JavaScriptAnalysisLimits) -> Self {
        Self {
            limits,
            node_count: 0,
            depth: 0,
            max_depth: 0,
            exceeded: false,
        }
    }
}

impl<'a> Visit<'a> for LimitsVisitor<'_> {
    fn enter_node(&mut self, _kind: AstKind<'a>) {
        self.node_count += 1;
        self.depth += 1;
        if self.depth > self.max_depth {
            self.max_depth = self.depth;
        }
        if self.node_count > self.limits.max_ast_nodes || self.depth > self.limits.max_ast_depth {
            self.exceeded = true;
        }
    }

    fn leave_node(&mut self, _kind: AstKind<'a>) {
        self.depth = self.depth.saturating_sub(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_source_parses() {
        let allocator = Allocator::default();
        let limits = JavaScriptAnalysisLimits::default();
        let res = parse_js_source(&allocator, "const x = 1;\n", "js", &limits);
        assert_eq!(res.syntax_state, JsSyntaxState::Valid);
        assert!(res.program.is_some());
    }

    #[test]
    fn malformed_source_is_invalid() {
        let allocator = Allocator::default();
        let limits = JavaScriptAnalysisLimits::default();
        let res = parse_js_source(&allocator, "function broken( {\n", "js", &limits);
        assert!(matches!(res.syntax_state, JsSyntaxState::Invalid { .. }));
        assert!(matches!(res.coverage, JsCoverage::Incomplete { .. }));
    }

    #[test]
    fn typescript_syntax_parses_via_ts_extension() {
        let allocator = Allocator::default();
        let limits = JavaScriptAnalysisLimits::default();
        let code = "interface Foo { bar: string }\nconst x: number = 1;\n";
        let res = parse_js_source(&allocator, code, "ts", &limits);
        assert_eq!(res.syntax_state, JsSyntaxState::Valid);
        assert!(res.program.is_some());
    }
}
