use super::limits::PythonAnalysisLimits;
use rustpython_parser::ast::{self, Expr, Stmt, Suite};
use rustpython_parser::{parse, Mode};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PythonSyntaxState {
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
pub enum PythonCoverage {
    Complete,
    Incomplete { reason: String },
}

impl fmt::Display for PythonSyntaxState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Valid => write!(f, "Valid"),
            Self::Invalid {
                error,
                line,
                column,
            } => {
                if let (Some(l), Some(c)) = (line, column) {
                    write!(f, "Invalid Python syntax at L{}:{}: {}", l, c, error)
                } else {
                    write!(f, "Invalid Python syntax: {}", error)
                }
            }
            Self::ExceededLimits { reason } => write!(f, "Exceeded limits: {}", reason),
        }
    }
}

pub struct ParseResult {
    pub syntax_state: PythonSyntaxState,
    pub coverage: PythonCoverage,
    pub ast: Option<Suite>,
}

#[derive(Debug, Clone)]
pub struct LineIndex {
    line_offsets: Vec<usize>,
}

impl LineIndex {
    pub fn new(source: &str) -> Self {
        let mut line_offsets = vec![0];
        for (idx, byte) in source.bytes().enumerate() {
            if byte == b'\n' {
                line_offsets.push(idx + 1);
            }
        }
        Self { line_offsets }
    }

    pub fn line_number(&self, offset_bytes: usize) -> usize {
        match self.line_offsets.binary_search(&offset_bytes) {
            Ok(idx) => idx + 1,
            Err(idx) => idx,
        }
    }

    pub fn line_col(&self, offset_bytes: usize, source: &str) -> (usize, usize) {
        let line = self.line_number(offset_bytes);
        let line_start = if line > 0 && line - 1 < self.line_offsets.len() {
            self.line_offsets[line - 1]
        } else {
            0
        };
        let col = if offset_bytes >= line_start {
            source[line_start..offset_bytes.min(source.len())]
                .chars()
                .count()
                + 1
        } else {
            1
        };
        (line, col)
    }
}

pub fn parse_python_source(
    source: &str,
    relative_path: &str,
    limits: &PythonAnalysisLimits,
) -> ParseResult {
    if source.len() > limits.max_source_bytes {
        return ParseResult {
            syntax_state: PythonSyntaxState::ExceededLimits {
                reason: format!(
                    "Source byte size ({} bytes) exceeds limit ({} bytes)",
                    source.len(),
                    limits.max_source_bytes
                ),
            },
            coverage: PythonCoverage::Incomplete {
                reason: format!("File size exceeds cap of {} bytes", limits.max_source_bytes),
            },
            ast: None,
        };
    }

    match parse(source, Mode::Module, relative_path) {
        Ok(ast::Mod::Module(m)) => {
            let suite = m.body;
            let mut node_count = 0;
            let mut max_depth = 0;
            if check_ast_limits_suite(&suite, 1, &mut node_count, &mut max_depth, limits) {
                ParseResult {
                    syntax_state: PythonSyntaxState::Valid,
                    coverage: PythonCoverage::Complete,
                    ast: Some(suite),
                }
            } else {
                ParseResult {
                    syntax_state: PythonSyntaxState::ExceededLimits {
                        reason: format!(
                            "AST node count ({}) or max depth ({}) exceeded configured limits (max nodes {}, max depth {})",
                            node_count, max_depth, limits.max_ast_nodes, limits.max_ast_depth
                        ),
                    },
                    coverage: PythonCoverage::Incomplete {
                        reason: "AST complexity limit exceeded".to_owned(),
                    },
                    ast: None,
                }
            }
        }
        Ok(_) => ParseResult {
            syntax_state: PythonSyntaxState::Valid,
            coverage: PythonCoverage::Complete,
            ast: Some(Vec::new()),
        },
        Err(err) => {
            let error_str = err.to_string();
            let offset_bytes = usize::from(err.offset);
            let line_index = LineIndex::new(source);
            let (line, col) = line_index.line_col(offset_bytes, source);
            ParseResult {
                syntax_state: PythonSyntaxState::Invalid {
                    error: error_str.clone(),
                    line: Some(line),
                    column: Some(col),
                },
                coverage: PythonCoverage::Incomplete {
                    reason: format!("Python syntax error: {}", error_str),
                },
                ast: None,
            }
        }
    }
}

fn check_ast_limits_suite(
    suite: &Suite,
    depth: usize,
    node_count: &mut usize,
    max_depth: &mut usize,
    limits: &PythonAnalysisLimits,
) -> bool {
    if depth > limits.max_ast_depth {
        return false;
    }
    if depth > *max_depth {
        *max_depth = depth;
    }
    for stmt in suite {
        if !check_ast_limits_stmt(stmt, depth, node_count, max_depth, limits) {
            return false;
        }
    }
    true
}

fn check_ast_limits_stmt(
    stmt: &Stmt,
    depth: usize,
    node_count: &mut usize,
    max_depth: &mut usize,
    limits: &PythonAnalysisLimits,
) -> bool {
    *node_count += 1;
    if *node_count > limits.max_ast_nodes || depth > limits.max_ast_depth {
        return false;
    }
    if depth > *max_depth {
        *max_depth = depth;
    }

    match stmt {
        Stmt::FunctionDef(f) => {
            for _arg in f
                .args
                .args
                .iter()
                .chain(f.args.posonlyargs.iter())
                .chain(f.args.kwonlyargs.iter())
            {
                *node_count += 1;
            }
            for decorator in &f.decorator_list {
                if !check_ast_limits_expr(decorator, depth + 1, node_count, max_depth, limits) {
                    return false;
                }
            }
            check_ast_limits_suite(&f.body, depth + 1, node_count, max_depth, limits)
        }
        Stmt::AsyncFunctionDef(f) => {
            for decorator in &f.decorator_list {
                if !check_ast_limits_expr(decorator, depth + 1, node_count, max_depth, limits) {
                    return false;
                }
            }
            check_ast_limits_suite(&f.body, depth + 1, node_count, max_depth, limits)
        }
        Stmt::ClassDef(c) => {
            for base in &c.bases {
                if !check_ast_limits_expr(base, depth + 1, node_count, max_depth, limits) {
                    return false;
                }
            }
            for decorator in &c.decorator_list {
                if !check_ast_limits_expr(decorator, depth + 1, node_count, max_depth, limits) {
                    return false;
                }
            }
            check_ast_limits_suite(&c.body, depth + 1, node_count, max_depth, limits)
        }
        Stmt::Return(r) => {
            if let Some(val) = &r.value {
                if !check_ast_limits_expr(val, depth + 1, node_count, max_depth, limits) {
                    return false;
                }
            }
            true
        }
        Stmt::Delete(d) => {
            for target in &d.targets {
                if !check_ast_limits_expr(target, depth + 1, node_count, max_depth, limits) {
                    return false;
                }
            }
            true
        }
        Stmt::Assign(a) => {
            for target in &a.targets {
                if !check_ast_limits_expr(target, depth + 1, node_count, max_depth, limits) {
                    return false;
                }
            }
            check_ast_limits_expr(&a.value, depth + 1, node_count, max_depth, limits)
        }
        Stmt::AugAssign(a) => {
            if !check_ast_limits_expr(&a.target, depth + 1, node_count, max_depth, limits) {
                return false;
            }
            check_ast_limits_expr(&a.value, depth + 1, node_count, max_depth, limits)
        }
        Stmt::AnnAssign(a) => {
            if !check_ast_limits_expr(&a.target, depth + 1, node_count, max_depth, limits) {
                return false;
            }
            if let Some(val) = &a.value {
                if !check_ast_limits_expr(val, depth + 1, node_count, max_depth, limits) {
                    return false;
                }
            }
            true
        }
        Stmt::For(f) => {
            if !check_ast_limits_expr(&f.target, depth + 1, node_count, max_depth, limits)
                || !check_ast_limits_expr(&f.iter, depth + 1, node_count, max_depth, limits)
            {
                return false;
            }
            if !check_ast_limits_suite(&f.body, depth + 1, node_count, max_depth, limits)
                || !check_ast_limits_suite(&f.orelse, depth + 1, node_count, max_depth, limits)
            {
                return false;
            }
            true
        }
        Stmt::AsyncFor(f) => {
            if !check_ast_limits_expr(&f.target, depth + 1, node_count, max_depth, limits)
                || !check_ast_limits_expr(&f.iter, depth + 1, node_count, max_depth, limits)
            {
                return false;
            }
            if !check_ast_limits_suite(&f.body, depth + 1, node_count, max_depth, limits)
                || !check_ast_limits_suite(&f.orelse, depth + 1, node_count, max_depth, limits)
            {
                return false;
            }
            true
        }
        Stmt::While(w) => {
            if !check_ast_limits_expr(&w.test, depth + 1, node_count, max_depth, limits) {
                return false;
            }
            if !check_ast_limits_suite(&w.body, depth + 1, node_count, max_depth, limits)
                || !check_ast_limits_suite(&w.orelse, depth + 1, node_count, max_depth, limits)
            {
                return false;
            }
            true
        }
        Stmt::If(i) => {
            if !check_ast_limits_expr(&i.test, depth + 1, node_count, max_depth, limits) {
                return false;
            }
            if !check_ast_limits_suite(&i.body, depth + 1, node_count, max_depth, limits)
                || !check_ast_limits_suite(&i.orelse, depth + 1, node_count, max_depth, limits)
            {
                return false;
            }
            true
        }
        Stmt::With(w) => {
            for item in &w.items {
                if !check_ast_limits_expr(
                    &item.context_expr,
                    depth + 1,
                    node_count,
                    max_depth,
                    limits,
                ) {
                    return false;
                }
            }
            check_ast_limits_suite(&w.body, depth + 1, node_count, max_depth, limits)
        }
        Stmt::AsyncWith(w) => {
            for item in &w.items {
                if !check_ast_limits_expr(
                    &item.context_expr,
                    depth + 1,
                    node_count,
                    max_depth,
                    limits,
                ) {
                    return false;
                }
            }
            check_ast_limits_suite(&w.body, depth + 1, node_count, max_depth, limits)
        }
        Stmt::Raise(r) => {
            if let Some(exc) = &r.exc {
                if !check_ast_limits_expr(exc, depth + 1, node_count, max_depth, limits) {
                    return false;
                }
            }
            true
        }
        Stmt::Try(t) => {
            if !check_ast_limits_suite(&t.body, depth + 1, node_count, max_depth, limits) {
                return false;
            }
            for handler in &t.handlers {
                let ast::ExceptHandler::ExceptHandler(h) = handler;
                if let Some(type_) = &h.type_ {
                    if !check_ast_limits_expr(type_, depth + 1, node_count, max_depth, limits) {
                        return false;
                    }
                }
                if !check_ast_limits_suite(&h.body, depth + 1, node_count, max_depth, limits) {
                    return false;
                }
            }
            if !check_ast_limits_suite(&t.orelse, depth + 1, node_count, max_depth, limits)
                || !check_ast_limits_suite(&t.finalbody, depth + 1, node_count, max_depth, limits)
            {
                return false;
            }
            true
        }
        Stmt::Assert(a) => {
            if !check_ast_limits_expr(&a.test, depth + 1, node_count, max_depth, limits) {
                return false;
            }
            if let Some(msg) = &a.msg {
                if !check_ast_limits_expr(msg, depth + 1, node_count, max_depth, limits) {
                    return false;
                }
            }
            true
        }
        Stmt::Expr(e) => check_ast_limits_expr(&e.value, depth + 1, node_count, max_depth, limits),
        _ => true,
    }
}

fn check_ast_limits_expr(
    expr: &Expr,
    depth: usize,
    node_count: &mut usize,
    max_depth: &mut usize,
    limits: &PythonAnalysisLimits,
) -> bool {
    *node_count += 1;
    if *node_count > limits.max_ast_nodes || depth > limits.max_ast_depth {
        return false;
    }
    if depth > *max_depth {
        *max_depth = depth;
    }

    match expr {
        Expr::BoolOp(b) => {
            for value in &b.values {
                if !check_ast_limits_expr(value, depth + 1, node_count, max_depth, limits) {
                    return false;
                }
            }
            true
        }
        Expr::BinOp(b) => {
            check_ast_limits_expr(&b.left, depth + 1, node_count, max_depth, limits)
                && check_ast_limits_expr(&b.right, depth + 1, node_count, max_depth, limits)
        }
        Expr::UnaryOp(u) => {
            check_ast_limits_expr(&u.operand, depth + 1, node_count, max_depth, limits)
        }
        Expr::Lambda(l) => check_ast_limits_expr(&l.body, depth + 1, node_count, max_depth, limits),
        Expr::IfExp(i) => {
            check_ast_limits_expr(&i.test, depth + 1, node_count, max_depth, limits)
                && check_ast_limits_expr(&i.body, depth + 1, node_count, max_depth, limits)
                && check_ast_limits_expr(&i.orelse, depth + 1, node_count, max_depth, limits)
        }
        Expr::Dict(d) => {
            for key in d.keys.iter().flatten() {
                if !check_ast_limits_expr(key, depth + 1, node_count, max_depth, limits) {
                    return false;
                }
            }
            for val in &d.values {
                if !check_ast_limits_expr(val, depth + 1, node_count, max_depth, limits) {
                    return false;
                }
            }
            true
        }
        Expr::Set(s) => {
            for el in &s.elts {
                if !check_ast_limits_expr(el, depth + 1, node_count, max_depth, limits) {
                    return false;
                }
            }
            true
        }
        Expr::List(l) => {
            for el in &l.elts {
                if !check_ast_limits_expr(el, depth + 1, node_count, max_depth, limits) {
                    return false;
                }
            }
            true
        }
        Expr::Tuple(t) => {
            for el in &t.elts {
                if !check_ast_limits_expr(el, depth + 1, node_count, max_depth, limits) {
                    return false;
                }
            }
            true
        }
        Expr::Compare(c) => {
            if !check_ast_limits_expr(&c.left, depth + 1, node_count, max_depth, limits) {
                return false;
            }
            for comparator in &c.comparators {
                if !check_ast_limits_expr(comparator, depth + 1, node_count, max_depth, limits) {
                    return false;
                }
            }
            true
        }
        Expr::Call(c) => {
            if !check_ast_limits_expr(&c.func, depth + 1, node_count, max_depth, limits) {
                return false;
            }
            for arg in &c.args {
                if !check_ast_limits_expr(arg, depth + 1, node_count, max_depth, limits) {
                    return false;
                }
            }
            for kw in &c.keywords {
                if !check_ast_limits_expr(&kw.value, depth + 1, node_count, max_depth, limits) {
                    return false;
                }
            }
            true
        }
        Expr::Attribute(a) => {
            check_ast_limits_expr(&a.value, depth + 1, node_count, max_depth, limits)
        }
        Expr::Subscript(s) => {
            check_ast_limits_expr(&s.value, depth + 1, node_count, max_depth, limits)
                && check_ast_limits_expr(&s.slice, depth + 1, node_count, max_depth, limits)
        }
        Expr::Starred(s) => {
            check_ast_limits_expr(&s.value, depth + 1, node_count, max_depth, limits)
        }
        _ => true,
    }
}
