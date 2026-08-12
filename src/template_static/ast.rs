//! Data-only AST representations and source-span definitions for Jinja template static analysis.

#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy, Default)]
pub struct SourceSpan {
    pub line: u64,
    pub column: u64,
    pub offset: u64,
    pub length: u64,
}

impl SourceSpan {
    pub fn new(line: u64, column: u64, offset: u64, length: u64) -> Self {
        Self {
            line,
            column,
            offset,
            length,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum LiteralValue {
    String(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    None,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Identifier {
        name: String,
        span: SourceSpan,
    },
    Literal {
        val: LiteralValue,
        span: SourceSpan,
    },
    Attribute {
        obj: Box<Expr>,
        attr: String,
        span: SourceSpan,
    },
    ItemAccess {
        obj: Box<Expr>,
        item: Box<Expr>,
        span: SourceSpan,
    },
    Call {
        callee: Box<Expr>,
        args: Vec<Expr>,
        kwargs: Vec<(String, Expr)>,
        span: SourceSpan,
    },
    Filter {
        expr: Box<Expr>,
        name: String,
        args: Vec<Expr>,
        span: SourceSpan,
    },
    Test {
        expr: Box<Expr>,
        name: String,
        args: Vec<Expr>,
        negated: bool,
        span: SourceSpan,
    },
    List {
        items: Vec<Expr>,
        span: SourceSpan,
    },
    Dict {
        entries: Vec<(Expr, Expr)>,
        span: SourceSpan,
    },
    Tuple {
        items: Vec<Expr>,
        span: SourceSpan,
    },
    Unary {
        op: String,
        expr: Box<Expr>,
        span: SourceSpan,
    },
    Binary {
        left: Box<Expr>,
        op: String,
        right: Box<Expr>,
        span: SourceSpan,
    },
}

impl Expr {
    pub fn span(&self) -> SourceSpan {
        match self {
            Expr::Identifier { span, .. } => *span,
            Expr::Literal { span, .. } => *span,
            Expr::Attribute { span, .. } => *span,
            Expr::ItemAccess { span, .. } => *span,
            Expr::Call { span, .. } => *span,
            Expr::Filter { span, .. } => *span,
            Expr::Test { span, .. } => *span,
            Expr::List { span, .. } => *span,
            Expr::Dict { span, .. } => *span,
            Expr::Tuple { span, .. } => *span,
            Expr::Unary { span, .. } => *span,
            Expr::Binary { span, .. } => *span,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Stmt {
    Output {
        expr: Expr,
        span: SourceSpan,
    },
    Include {
        target: Expr,
        ignore_missing: bool,
        span: SourceSpan,
    },
    Import {
        target: Expr,
        alias: Option<String>,
        span: SourceSpan,
    },
    FromImport {
        target: Expr,
        names: Vec<(String, Option<String>)>,
        span: SourceSpan,
    },
    Set {
        name: String,
        value: Expr,
        span: SourceSpan,
    },
    For {
        target: String,
        iter: Expr,
        body: Vec<Stmt>,
        span: SourceSpan,
    },
    If {
        condition: Expr,
        body: Vec<Stmt>,
        elifs: Vec<(Expr, Vec<Stmt>)>,
        else_body: Option<Vec<Stmt>>,
        span: SourceSpan,
    },
    Macro {
        name: String,
        args: Vec<String>,
        body: Vec<Stmt>,
        span: SourceSpan,
    },
    FilterBlock {
        filter_name: String,
        body: Vec<Stmt>,
        span: SourceSpan,
    },
    RawText {
        text: String,
        span: SourceSpan,
    },
}

impl Stmt {
    pub fn span(&self) -> SourceSpan {
        match self {
            Stmt::Output { span, .. } => *span,
            Stmt::Include { span, .. } => *span,
            Stmt::Import { span, .. } => *span,
            Stmt::FromImport { span, .. } => *span,
            Stmt::Set { span, .. } => *span,
            Stmt::For { span, .. } => *span,
            Stmt::If { span, .. } => *span,
            Stmt::Macro { span, .. } => *span,
            Stmt::FilterBlock { span, .. } => *span,
            Stmt::RawText { span, .. } => *span,
        }
    }
}
