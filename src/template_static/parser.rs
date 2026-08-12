//! Data-only tokenizer and recursive-descent AST parser for Jinja template static analysis.

use crate::template_static::ast::*;
use crate::template_static::limits::*;
use std::fmt;

#[derive(Debug, Clone)]
pub enum ParseError {
    UnexpectedToken(String, SourceSpan),
    UnclosedTag(SourceSpan),
    LimitExceeded(String),
    SyntaxError(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::UnexpectedToken(msg, span) => {
                write!(f, "Unexpected token at line {}: {}", span.line, msg)
            }
            ParseError::UnclosedTag(span) => {
                write!(f, "Unclosed tag starting at line {}", span.line)
            }
            ParseError::LimitExceeded(msg) => write!(f, "Limit exceeded: {}", msg),
            ParseError::SyntaxError(msg) => write!(f, "Syntax error: {}", msg),
        }
    }
}

impl std::error::Error for ParseError {}

#[derive(Debug, Clone, PartialEq)]
pub enum TokenKind {
    TagOpenOutput,  // {{
    TagCloseOutput, // }}
    TagOpenBlock,   // {%
    TagCloseBlock,  // %}
    Identifier(String),
    StringLit(String),
    IntLit(i64),
    FloatLit(f64),
    BoolLit(bool),
    NoneLit,
    Dot,
    Comma,
    Colon,
    Pipe,
    LParen,
    RParen,
    LBracket,
    RBracket,
    LBrace,
    RBrace,
    OpAssign,
    OpEq,
    OpNe,
    OpLt,
    OpGt,
    OpLe,
    OpGe,
    OpPlus,
    OpMinus,
    OpMul,
    OpDiv,
    KwFor,
    KwIn,
    KwIf,
    KwElif,
    KwElse,
    KwEndif,
    KwEndfor,
    KwMacro,
    KwEndmacro,
    KwImport,
    KwFrom,
    KwInclude,
    KwSet,
    KwEndset,
    KwFilter,
    KwEndfilter,
    KwAs,
    KwIs,
    KwNot,
    KwAnd,
    KwOr,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Token {
    pub kind: TokenKind,
    pub span: SourceSpan,
}

pub struct Tokenizer<'a> {
    bytes: &'a [u8],
    pos: usize,
    line: u64,
    col: u64,
}

impl<'a> Tokenizer<'a> {
    pub fn new(input: &'a str) -> Self {
        Self {
            bytes: input.as_bytes(),
            pos: 0,
            line: 1,
            col: 1,
        }
    }

    fn peek(&self) -> Option<u8> {
        if self.pos < self.bytes.len() {
            Some(self.bytes[self.pos])
        } else {
            None
        }
    }

    fn advance(&mut self) -> Option<u8> {
        if self.pos >= self.bytes.len() {
            return None;
        }
        let b = self.bytes[self.pos];
        self.pos += 1;
        if b == b'\n' {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
        Some(b)
    }

    fn skip_whitespace(&mut self) {
        while let Some(b) = self.peek() {
            if b.is_ascii_whitespace() {
                self.advance();
            } else {
                break;
            }
        }
    }

    pub fn tokenize_all(&mut self, limits: &TemplateLimits) -> Result<Vec<Token>, ParseError> {
        if self.bytes.len() > limits.max_template_bytes {
            return Err(ParseError::LimitExceeded(format!(
                "Template size {} exceeds max {}",
                self.bytes.len(),
                limits.max_template_bytes
            )));
        }

        let mut tokens = Vec::new();
        while self.pos < self.bytes.len() {
            let start_pos = self.pos;
            let start_line = self.line;
            let start_col = self.col;

            // Check for tag openings: {{ , {% , {#
            if self.pos + 1 < self.bytes.len() {
                let b0 = self.bytes[self.pos];
                let b1 = self.bytes[self.pos + 1];
                if b0 == b'{' && b1 == b'#' {
                    // Comment tag: {# ... #} -> skip without emitting tokens
                    self.skip_comment()?;
                    continue;
                } else if b0 == b'{' && (b1 == b'{' || b1 == b'%') {
                    let is_output = b1 == b'{';
                    self.advance();
                    self.advance();
                    // Check for trim dash {{- or {%-
                    if self.peek() == Some(b'-') {
                        self.advance();
                    }
                    let tag_open_span = SourceSpan::new(
                        start_line,
                        start_col,
                        start_pos as u64,
                        (self.pos - start_pos) as u64,
                    );
                    tokens.push(Token {
                        kind: if is_output {
                            TokenKind::TagOpenOutput
                        } else {
                            TokenKind::TagOpenBlock
                        },
                        span: tag_open_span,
                    });

                    // Tokenize inside tag until }} or %}
                    self.tokenize_tag_contents(is_output, &mut tokens)?;
                    continue;
                }
            }

            // Outside tag: advance one byte
            self.advance();
        }

        Ok(tokens)
    }

    fn skip_comment(&mut self) -> Result<(), ParseError> {
        let start_span = SourceSpan::new(self.line, self.col, self.pos as u64, 2);
        self.advance(); // {
        self.advance(); // #
        while self.pos < self.bytes.len() {
            if self.bytes[self.pos] == b'#'
                && self.pos + 1 < self.bytes.len()
                && self.bytes[self.pos + 1] == b'}'
            {
                self.advance(); // #
                self.advance(); // }
                return Ok(());
            }
            self.advance();
        }
        Err(ParseError::UnclosedTag(start_span))
    }

    fn tokenize_tag_contents(
        &mut self,
        is_output: bool,
        tokens: &mut Vec<Token>,
    ) -> Result<(), ParseError> {
        let close_b0 = if is_output { b'}' } else { b'%' };

        while self.pos < self.bytes.len() {
            self.skip_whitespace();
            if self.pos >= self.bytes.len() {
                break;
            }

            let start_pos = self.pos;
            let start_line = self.line;
            let start_col = self.col;

            let b = self.bytes[self.pos];

            // Check for trim dash before close: -}} or -%}
            if b == b'-'
                && self.pos + 2 < self.bytes.len()
                && self.bytes[self.pos + 1] == close_b0
                && self.bytes[self.pos + 2] == b'}'
            {
                self.advance(); // -
                self.advance(); // close_b0
                self.advance(); // }
                let span = SourceSpan::new(start_line, start_col, start_pos as u64, 3);
                tokens.push(Token {
                    kind: if is_output {
                        TokenKind::TagCloseOutput
                    } else {
                        TokenKind::TagCloseBlock
                    },
                    span,
                });
                return Ok(());
            }

            // Check for normal tag close: }} or %}
            if b == close_b0 && self.pos + 1 < self.bytes.len() && self.bytes[self.pos + 1] == b'}'
            {
                self.advance(); // close_b0
                self.advance(); // }
                let span = SourceSpan::new(start_line, start_col, start_pos as u64, 2);
                tokens.push(Token {
                    kind: if is_output {
                        TokenKind::TagCloseOutput
                    } else {
                        TokenKind::TagCloseBlock
                    },
                    span,
                });
                return Ok(());
            }

            // Single character punctuation
            match b {
                b'.' => {
                    self.advance();
                    tokens.push(Token {
                        kind: TokenKind::Dot,
                        span: SourceSpan::new(start_line, start_col, start_pos as u64, 1),
                    });
                    continue;
                }
                b',' => {
                    self.advance();
                    tokens.push(Token {
                        kind: TokenKind::Comma,
                        span: SourceSpan::new(start_line, start_col, start_pos as u64, 1),
                    });
                    continue;
                }
                b':' => {
                    self.advance();
                    tokens.push(Token {
                        kind: TokenKind::Colon,
                        span: SourceSpan::new(start_line, start_col, start_pos as u64, 1),
                    });
                    continue;
                }
                b'|' => {
                    self.advance();
                    tokens.push(Token {
                        kind: TokenKind::Pipe,
                        span: SourceSpan::new(start_line, start_col, start_pos as u64, 1),
                    });
                    continue;
                }
                b'(' => {
                    self.advance();
                    tokens.push(Token {
                        kind: TokenKind::LParen,
                        span: SourceSpan::new(start_line, start_col, start_pos as u64, 1),
                    });
                    continue;
                }
                b')' => {
                    self.advance();
                    tokens.push(Token {
                        kind: TokenKind::RParen,
                        span: SourceSpan::new(start_line, start_col, start_pos as u64, 1),
                    });
                    continue;
                }
                b'[' => {
                    self.advance();
                    tokens.push(Token {
                        kind: TokenKind::LBracket,
                        span: SourceSpan::new(start_line, start_col, start_pos as u64, 1),
                    });
                    continue;
                }
                b']' => {
                    self.advance();
                    tokens.push(Token {
                        kind: TokenKind::RBracket,
                        span: SourceSpan::new(start_line, start_col, start_pos as u64, 1),
                    });
                    continue;
                }
                b'{' => {
                    self.advance();
                    tokens.push(Token {
                        kind: TokenKind::LBrace,
                        span: SourceSpan::new(start_line, start_col, start_pos as u64, 1),
                    });
                    continue;
                }
                b'}' => {
                    self.advance();
                    tokens.push(Token {
                        kind: TokenKind::RBrace,
                        span: SourceSpan::new(start_line, start_col, start_pos as u64, 1),
                    });
                    continue;
                }
                b'+' => {
                    self.advance();
                    tokens.push(Token {
                        kind: TokenKind::OpPlus,
                        span: SourceSpan::new(start_line, start_col, start_pos as u64, 1),
                    });
                    continue;
                }
                b'-' => {
                    self.advance();
                    tokens.push(Token {
                        kind: TokenKind::OpMinus,
                        span: SourceSpan::new(start_line, start_col, start_pos as u64, 1),
                    });
                    continue;
                }
                b'*' => {
                    self.advance();
                    tokens.push(Token {
                        kind: TokenKind::OpMul,
                        span: SourceSpan::new(start_line, start_col, start_pos as u64, 1),
                    });
                    continue;
                }
                b'/' => {
                    self.advance();
                    tokens.push(Token {
                        kind: TokenKind::OpDiv,
                        span: SourceSpan::new(start_line, start_col, start_pos as u64, 1),
                    });
                    continue;
                }
                b'=' => {
                    self.advance();
                    if self.peek() == Some(b'=') {
                        self.advance();
                        tokens.push(Token {
                            kind: TokenKind::OpEq,
                            span: SourceSpan::new(start_line, start_col, start_pos as u64, 2),
                        });
                    } else {
                        tokens.push(Token {
                            kind: TokenKind::OpAssign,
                            span: SourceSpan::new(start_line, start_col, start_pos as u64, 1),
                        });
                    }
                    continue;
                }
                b'!' => {
                    self.advance();
                    if self.peek() == Some(b'=') {
                        self.advance();
                        tokens.push(Token {
                            kind: TokenKind::OpNe,
                            span: SourceSpan::new(start_line, start_col, start_pos as u64, 2),
                        });
                        continue;
                    }
                }
                b'<' => {
                    self.advance();
                    if self.peek() == Some(b'=') {
                        self.advance();
                        tokens.push(Token {
                            kind: TokenKind::OpLe,
                            span: SourceSpan::new(start_line, start_col, start_pos as u64, 2),
                        });
                    } else {
                        tokens.push(Token {
                            kind: TokenKind::OpLt,
                            span: SourceSpan::new(start_line, start_col, start_pos as u64, 1),
                        });
                    }
                    continue;
                }
                b'>' => {
                    self.advance();
                    if self.peek() == Some(b'=') {
                        self.advance();
                        tokens.push(Token {
                            kind: TokenKind::OpGe,
                            span: SourceSpan::new(start_line, start_col, start_pos as u64, 2),
                        });
                    } else {
                        tokens.push(Token {
                            kind: TokenKind::OpGt,
                            span: SourceSpan::new(start_line, start_col, start_pos as u64, 1),
                        });
                    }
                    continue;
                }
                _ => {}
            }

            // String literals
            if b == b'\'' || b == b'"' {
                let quote = b;
                self.advance();
                let mut s = String::new();
                let mut escaped = false;
                while let Some(ch) = self.peek() {
                    self.advance();
                    if escaped {
                        match ch {
                            b'n' => s.push('\n'),
                            b't' => s.push('\t'),
                            b'r' => s.push('\r'),
                            b'\\' => s.push('\\'),
                            b'\'' => s.push('\''),
                            b'"' => s.push('"'),
                            other => {
                                s.push('\\');
                                s.push(other as char);
                            }
                        }
                        escaped = false;
                    } else if ch == b'\\' {
                        escaped = true;
                    } else if ch == quote {
                        break;
                    } else {
                        s.push(ch as char);
                    }
                }
                let len = (self.pos - start_pos) as u64;
                tokens.push(Token {
                    kind: TokenKind::StringLit(s),
                    span: SourceSpan::new(start_line, start_col, start_pos as u64, len),
                });
                continue;
            }

            // Numeric literals
            if b.is_ascii_digit() {
                let mut num_str = String::new();
                let mut is_float = false;
                while let Some(ch) = self.peek() {
                    if ch.is_ascii_digit() {
                        num_str.push(ch as char);
                        self.advance();
                    } else if ch == b'.' && !is_float {
                        // Look ahead to ensure it's not a dot attribute call
                        if self.pos + 1 < self.bytes.len()
                            && self.bytes[self.pos + 1].is_ascii_digit()
                        {
                            is_float = true;
                            num_str.push('.');
                            self.advance();
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                let len = (self.pos - start_pos) as u64;
                let span = SourceSpan::new(start_line, start_col, start_pos as u64, len);
                if is_float {
                    let val = num_str.parse::<f64>().unwrap_or(0.0);
                    tokens.push(Token {
                        kind: TokenKind::FloatLit(val),
                        span,
                    });
                } else {
                    let val = num_str.parse::<i64>().unwrap_or(0);
                    tokens.push(Token {
                        kind: TokenKind::IntLit(val),
                        span,
                    });
                }
                continue;
            }

            // Identifiers / Keywords
            if b.is_ascii_alphabetic() || b == b'_' {
                let mut ident = String::new();
                while let Some(ch) = self.peek() {
                    if ch.is_ascii_alphanumeric() || ch == b'_' {
                        ident.push(ch as char);
                        self.advance();
                    } else {
                        break;
                    }
                }
                let len = (self.pos - start_pos) as u64;
                let span = SourceSpan::new(start_line, start_col, start_pos as u64, len);
                let kind = match ident.as_str() {
                    "true" | "True" => TokenKind::BoolLit(true),
                    "false" | "False" => TokenKind::BoolLit(false),
                    "none" | "None" => TokenKind::NoneLit,
                    "for" => TokenKind::KwFor,
                    "in" => TokenKind::KwIn,
                    "if" => TokenKind::KwIf,
                    "elif" => TokenKind::KwElif,
                    "else" => TokenKind::KwElse,
                    "endif" => TokenKind::KwEndif,
                    "endfor" => TokenKind::KwEndfor,
                    "macro" => TokenKind::KwMacro,
                    "endmacro" => TokenKind::KwEndmacro,
                    "import" => TokenKind::KwImport,
                    "from" => TokenKind::KwFrom,
                    "include" => TokenKind::KwInclude,
                    "set" => TokenKind::KwSet,
                    "endset" => TokenKind::KwEndset,
                    "filter" => TokenKind::KwFilter,
                    "endfilter" => TokenKind::KwEndfilter,
                    "as" => TokenKind::KwAs,
                    "is" => TokenKind::KwIs,
                    "not" => TokenKind::KwNot,
                    "and" => TokenKind::KwAnd,
                    "or" => TokenKind::KwOr,
                    _ => TokenKind::Identifier(ident),
                };
                tokens.push(Token { kind, span });
                continue;
            }

            // Unknown character inside tag
            self.advance();
        }

        Err(ParseError::UnclosedTag(SourceSpan::new(
            self.line,
            self.col,
            self.pos as u64,
            1,
        )))
    }
}

pub struct Parser<'a> {
    tokens: Vec<Token>,
    pos: usize,
    limits: &'a TemplateLimits,
    metrics: TemplateMetrics,
    current_depth: usize,
}

impl<'a> Parser<'a> {
    pub fn new(tokens: Vec<Token>, limits: &'a TemplateLimits) -> Self {
        Self {
            tokens,
            pos: 0,
            limits,
            metrics: TemplateMetrics::default(),
            current_depth: 0,
        }
    }

    fn check_bounds(&mut self) -> Result<(), ParseError> {
        self.metrics.node_count += 1;
        if self.metrics.node_count > self.limits.max_node_count {
            return Err(ParseError::LimitExceeded(format!(
                "Node count limit {} exceeded",
                self.limits.max_node_count
            )));
        }
        if self.current_depth > self.limits.max_ast_depth {
            return Err(ParseError::LimitExceeded(format!(
                "AST depth limit {} exceeded",
                self.limits.max_ast_depth
            )));
        }
        Ok(())
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn advance(&mut self) -> Option<Token> {
        if self.pos < self.tokens.len() {
            let tok = self.tokens[self.pos].clone();
            self.pos += 1;
            Some(tok)
        } else {
            None
        }
    }

    pub fn parse_program(&mut self) -> Result<(Vec<Stmt>, TemplateMetrics), ParseError> {
        let mut stmts = Vec::new();
        while self.pos < self.tokens.len() {
            let tok = self.peek().cloned();
            let Some(tok) = tok else { break };
            match tok.kind {
                TokenKind::TagOpenOutput => {
                    self.advance();
                    let expr = self.parse_expr(0)?;
                    let close_span = if matches!(
                        self.peek().map(|t| &t.kind),
                        Some(TokenKind::TagCloseOutput)
                    ) {
                        self.advance().unwrap().span
                    } else {
                        expr.span()
                    };
                    let span = SourceSpan::new(
                        tok.span.line,
                        tok.span.column,
                        tok.span.offset,
                        close_span.offset + close_span.length - tok.span.offset,
                    );
                    stmts.push(Stmt::Output { expr, span });
                }
                TokenKind::TagOpenBlock => {
                    self.advance();
                    let stmt = self.parse_block_stmt(tok.span)?;
                    stmts.push(stmt);
                }
                _ => {
                    self.advance();
                }
            }
        }

        Ok((stmts, self.metrics.clone()))
    }

    fn parse_block_stmt(&mut self, open_span: SourceSpan) -> Result<Stmt, ParseError> {
        self.check_bounds()?;
        let next = self.peek().cloned();
        let Some(tok) = next else {
            return Err(ParseError::UnclosedTag(open_span));
        };

        match tok.kind {
            TokenKind::KwInclude => {
                self.advance();
                let target = self.parse_expr(0)?;
                let mut ignore_missing = false;
                if let Some(t) = self.peek() {
                    if let TokenKind::Identifier(ref id) = t.kind {
                        if id == "ignore" {
                            self.advance();
                            if let Some(t2) = self.peek() {
                                if let TokenKind::Identifier(ref id2) = t2.kind {
                                    if id2 == "missing" {
                                        self.advance();
                                        ignore_missing = true;
                                    }
                                }
                            }
                        }
                    }
                }
                self.skip_until_block_close()?;
                Ok(Stmt::Include {
                    target,
                    ignore_missing,
                    span: open_span,
                })
            }
            TokenKind::KwImport => {
                self.advance();
                let target = self.parse_expr(0)?;
                let mut alias = None;
                if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::KwAs)) {
                    self.advance();
                    if let Some(t) = self.advance() {
                        if let TokenKind::Identifier(id) = t.kind {
                            alias = Some(id);
                        }
                    }
                }
                self.skip_until_block_close()?;
                Ok(Stmt::Import {
                    target,
                    alias,
                    span: open_span,
                })
            }
            TokenKind::KwFrom => {
                self.advance();
                let target = self.parse_expr(0)?;
                if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::KwImport)) {
                    self.advance();
                }
                let mut names = Vec::new();
                while let Some(t) = self.peek().cloned() {
                    if matches!(t.kind, TokenKind::TagCloseBlock) {
                        break;
                    }
                    if let TokenKind::Identifier(name) = t.kind {
                        self.advance();
                        let mut alias = None;
                        if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::KwAs)) {
                            self.advance();
                            if let Some(t_alias) = self.advance() {
                                if let TokenKind::Identifier(a) = t_alias.kind {
                                    alias = Some(a);
                                }
                            }
                        }
                        names.push((name, alias));
                        if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::Comma)) {
                            self.advance();
                        }
                    } else {
                        self.advance();
                    }
                }
                self.skip_until_block_close()?;
                Ok(Stmt::FromImport {
                    target,
                    names,
                    span: open_span,
                })
            }
            TokenKind::KwSet => {
                self.advance();
                let mut name = String::new();
                if let Some(t) = self.advance() {
                    if let TokenKind::Identifier(id) = t.kind {
                        name = id;
                    }
                }
                let mut value = Expr::Literal {
                    val: LiteralValue::None,
                    span: open_span,
                };
                if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::OpAssign)) {
                    self.advance();
                    value = self.parse_expr(0)?;
                }
                self.skip_until_block_close()?;
                Ok(Stmt::Set {
                    name,
                    value,
                    span: open_span,
                })
            }
            TokenKind::KwFor => {
                self.advance();
                let mut target = String::new();
                if let Some(t) = self.advance() {
                    if let TokenKind::Identifier(id) = t.kind {
                        target = id;
                    }
                }
                if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::KwIn)) {
                    self.advance();
                }
                let iter = self.parse_expr(0)?;
                self.skip_until_block_close()?;
                let body = self.parse_until_block_tag(&["endfor"])?;
                Ok(Stmt::For {
                    target,
                    iter,
                    body,
                    span: open_span,
                })
            }
            TokenKind::KwIf => {
                self.advance();
                let condition = self.parse_expr(0)?;
                self.skip_until_block_close()?;
                let (body, end_tag) = self.parse_until_block_tags(&["elif", "else", "endif"])?;
                let mut elifs = Vec::new();
                let mut else_body = None;
                let mut current_tag = end_tag;

                while current_tag == "elif" {
                    let cond = self.parse_expr(0)?;
                    self.skip_until_block_close()?;
                    let (e_body, next_tag) =
                        self.parse_until_block_tags(&["elif", "else", "endif"])?;
                    elifs.push((cond, e_body));
                    current_tag = next_tag;
                }

                if current_tag == "else" {
                    self.skip_until_block_close()?;
                    let (eb, _) = self.parse_until_block_tags(&["endif"])?;
                    else_body = Some(eb);
                }

                Ok(Stmt::If {
                    condition,
                    body,
                    elifs,
                    else_body,
                    span: open_span,
                })
            }
            TokenKind::KwMacro => {
                self.metrics.macro_count += 1;
                if self.metrics.macro_count > self.limits.max_macro_count {
                    return Err(ParseError::LimitExceeded(format!(
                        "Macro count limit {} exceeded",
                        self.limits.max_macro_count
                    )));
                }
                self.advance();
                let mut name = String::new();
                if let Some(t) = self.advance() {
                    if let TokenKind::Identifier(id) = t.kind {
                        name = id;
                    }
                }
                let mut args = Vec::new();
                if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::LParen)) {
                    self.advance();
                    while let Some(t) = self.peek().cloned() {
                        if matches!(t.kind, TokenKind::RParen | TokenKind::TagCloseBlock) {
                            break;
                        }
                        if let TokenKind::Identifier(arg) = t.kind {
                            args.push(arg);
                            self.advance();
                            if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::Comma)) {
                                self.advance();
                            }
                        } else {
                            self.advance();
                        }
                    }
                    if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::RParen)) {
                        self.advance();
                    }
                }
                self.skip_until_block_close()?;
                let body = self.parse_until_block_tag(&["endmacro"])?;
                Ok(Stmt::Macro {
                    name,
                    args,
                    body,
                    span: open_span,
                })
            }
            TokenKind::KwFilter => {
                self.advance();
                let mut filter_name = String::new();
                if let Some(t) = self.advance() {
                    if let TokenKind::Identifier(id) = t.kind {
                        filter_name = id;
                    }
                }
                self.skip_until_block_close()?;
                let body = self.parse_until_block_tag(&["endfilter"])?;
                Ok(Stmt::FilterBlock {
                    filter_name,
                    body,
                    span: open_span,
                })
            }
            _ => {
                self.skip_until_block_close()?;
                Ok(Stmt::RawText {
                    text: String::new(),
                    span: open_span,
                })
            }
        }
    }

    fn skip_until_block_close(&mut self) -> Result<(), ParseError> {
        while let Some(t) = self.peek() {
            if matches!(t.kind, TokenKind::TagCloseBlock) {
                self.advance();
                return Ok(());
            }
            self.advance();
        }
        Ok(())
    }

    fn parse_until_block_tag(&mut self, tags: &[&str]) -> Result<Vec<Stmt>, ParseError> {
        let (stmts, _) = self.parse_until_block_tags(tags)?;
        Ok(stmts)
    }

    fn parse_until_block_tags(&mut self, tags: &[&str]) -> Result<(Vec<Stmt>, String), ParseError> {
        let mut stmts = Vec::new();
        while self.pos < self.tokens.len() {
            let tok = self.peek().cloned();
            let Some(tok) = tok else { break };

            if matches!(tok.kind, TokenKind::TagOpenBlock) {
                let next_kind = self.tokens.get(self.pos + 1).map(|t| t.kind.clone());
                if let Some(kind) = next_kind {
                    if let TokenKind::Identifier(id) = kind {
                        if tags.contains(&id.as_str())
                            || (id == "endfor" && tags.contains(&"endfor"))
                            || (id == "endif" && tags.contains(&"endif"))
                            || (id == "endmacro" && tags.contains(&"endmacro"))
                            || (id == "endfilter" && tags.contains(&"endfilter"))
                        {
                            self.advance(); // {%
                            self.advance(); // tag
                            let tag_name = id.clone();
                            self.skip_until_block_close()?;
                            return Ok((stmts, tag_name));
                        }
                    } else if matches!(
                        kind,
                        TokenKind::KwEndfor
                            | TokenKind::KwEndif
                            | TokenKind::KwEndmacro
                            | TokenKind::KwEndfilter
                            | TokenKind::KwElse
                            | TokenKind::KwElif
                    ) {
                        let tag_name = match kind {
                            TokenKind::KwEndfor => "endfor",
                            TokenKind::KwEndif => "endif",
                            TokenKind::KwEndmacro => "endmacro",
                            TokenKind::KwEndfilter => "endfilter",
                            TokenKind::KwElse => "else",
                            TokenKind::KwElif => "elif",
                            _ => "",
                        };
                        if tags.contains(&tag_name) {
                            self.advance(); // {%
                            self.advance(); // tag
                            self.skip_until_block_close()?;
                            return Ok((stmts, tag_name.to_owned()));
                        }
                    }
                }
                self.advance(); // {%
                let stmt = self.parse_block_stmt(tok.span)?;
                stmts.push(stmt);
            } else if matches!(tok.kind, TokenKind::TagOpenOutput) {
                self.advance();
                let expr = self.parse_expr(0)?;
                let close_span = if matches!(
                    self.peek().map(|t| &t.kind),
                    Some(TokenKind::TagCloseOutput)
                ) {
                    self.advance().unwrap().span
                } else {
                    expr.span()
                };
                let span = SourceSpan::new(
                    tok.span.line,
                    tok.span.column,
                    tok.span.offset,
                    close_span.offset + close_span.length - tok.span.offset,
                );
                stmts.push(Stmt::Output { expr, span });
            } else {
                self.advance();
            }
        }
        Ok((stmts, String::new()))
    }

    fn parse_expr(&mut self, min_bp: u8) -> Result<Expr, ParseError> {
        self.current_depth += 1;
        if self.current_depth > self.limits.max_expression_depth {
            self.current_depth -= 1;
            return Err(ParseError::LimitExceeded(format!(
                "Expression depth limit {} exceeded",
                self.limits.max_expression_depth
            )));
        }
        self.check_bounds()?;

        let mut lhs = self.parse_primary_expr()?;

        while let Some(tok) = self.peek().cloned() {
            if matches!(
                tok.kind,
                TokenKind::TagCloseOutput | TokenKind::TagCloseBlock | TokenKind::Comma
            ) {
                break;
            }

            // Postfix operators: .attr, [item], (args), | filter, is test
            match tok.kind {
                TokenKind::Dot => {
                    self.advance();
                    let mut attr_name = String::new();
                    let mut attr_span = tok.span;

                    if let Some(next) = self.peek().cloned() {
                        if let TokenKind::Identifier(id) = next.kind {
                            attr_name = id;
                            attr_span = next.span;
                            self.advance();
                        } else if matches!(next.kind, TokenKind::LParen) {
                            // Support parenthesized attribute: obj . ( __class__ )
                            self.advance();
                            let inner_expr = self.parse_expr(0)?;
                            if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::RParen)) {
                                self.advance();
                            }
                            if let Expr::Identifier { name, span } = inner_expr {
                                attr_name = name;
                                attr_span = span;
                            } else if let Expr::Literal {
                                val: LiteralValue::String(s),
                                span,
                            } = inner_expr
                            {
                                attr_name = s;
                                attr_span = span;
                            }
                        }
                    }

                    let span = SourceSpan::new(
                        lhs.span().line,
                        lhs.span().column,
                        lhs.span().offset,
                        attr_span.offset + attr_span.length - lhs.span().offset,
                    );
                    lhs = Expr::Attribute {
                        obj: Box::new(lhs),
                        attr: attr_name,
                        span,
                    };
                    continue;
                }
                TokenKind::LBracket => {
                    self.advance();
                    let item = self.parse_expr(0)?;
                    let close_span =
                        if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::RBracket)) {
                            self.advance().unwrap().span
                        } else {
                            item.span()
                        };
                    let span = SourceSpan::new(
                        lhs.span().line,
                        lhs.span().column,
                        lhs.span().offset,
                        close_span.offset + close_span.length - lhs.span().offset,
                    );
                    lhs = Expr::ItemAccess {
                        obj: Box::new(lhs),
                        item: Box::new(item),
                        span,
                    };
                    continue;
                }
                TokenKind::LParen => {
                    self.advance();
                    let mut args = Vec::new();
                    let mut kwargs = Vec::new();
                    let mut close_span = tok.span;

                    while let Some(t) = self.peek().cloned() {
                        if matches!(
                            t.kind,
                            TokenKind::RParen
                                | TokenKind::TagCloseOutput
                                | TokenKind::TagCloseBlock
                        ) {
                            if matches!(t.kind, TokenKind::RParen) {
                                close_span = self.advance().unwrap().span;
                            }
                            break;
                        }
                        // Check if kwarg key=val
                        if let TokenKind::Identifier(id) = &t.kind {
                            if let Some(next2) = self.tokens.get(self.pos + 1) {
                                if matches!(next2.kind, TokenKind::OpAssign) {
                                    let key = id.clone();
                                    self.advance(); // id
                                    self.advance(); // =
                                    let val = self.parse_expr(0)?;
                                    kwargs.push((key, val));
                                    if matches!(
                                        self.peek().map(|t| &t.kind),
                                        Some(TokenKind::Comma)
                                    ) {
                                        self.advance();
                                    }
                                    continue;
                                }
                            }
                        }
                        let arg = self.parse_expr(0)?;
                        args.push(arg);
                        if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::Comma)) {
                            self.advance();
                        }
                    }

                    let span = SourceSpan::new(
                        lhs.span().line,
                        lhs.span().column,
                        lhs.span().offset,
                        close_span.offset + close_span.length - lhs.span().offset,
                    );
                    lhs = Expr::Call {
                        callee: Box::new(lhs),
                        args,
                        kwargs,
                        span,
                    };
                    continue;
                }
                TokenKind::Pipe => {
                    self.advance();
                    let mut name = String::new();
                    if let Some(t) = self.advance() {
                        if let TokenKind::Identifier(id) = t.kind {
                            name = id;
                        }
                    }
                    let mut args = Vec::new();
                    if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::LParen)) {
                        self.advance();
                        while let Some(t) = self.peek().cloned() {
                            if matches!(
                                t.kind,
                                TokenKind::RParen
                                    | TokenKind::TagCloseOutput
                                    | TokenKind::TagCloseBlock
                            ) {
                                if matches!(t.kind, TokenKind::RParen) {
                                    self.advance();
                                }
                                break;
                            }
                            let arg = self.parse_expr(0)?;
                            args.push(arg);
                            if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::Comma)) {
                                self.advance();
                            }
                        }
                    }
                    let span = lhs.span();
                    lhs = Expr::Filter {
                        expr: Box::new(lhs),
                        name,
                        args,
                        span,
                    };
                    continue;
                }
                TokenKind::KwIs => {
                    self.advance();
                    let mut negated = false;
                    if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::KwNot)) {
                        self.advance();
                        negated = true;
                    }
                    let mut name = String::new();
                    if let Some(t) = self.advance() {
                        if let TokenKind::Identifier(id) = t.kind {
                            name = id;
                        }
                    }
                    let mut args = Vec::new();
                    if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::LParen)) {
                        self.advance();
                        while let Some(t) = self.peek().cloned() {
                            if matches!(
                                t.kind,
                                TokenKind::RParen
                                    | TokenKind::TagCloseOutput
                                    | TokenKind::TagCloseBlock
                            ) {
                                if matches!(t.kind, TokenKind::RParen) {
                                    self.advance();
                                }
                                break;
                            }
                            let arg = self.parse_expr(0)?;
                            args.push(arg);
                            if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::Comma)) {
                                self.advance();
                            }
                        }
                    }
                    let span = lhs.span();
                    lhs = Expr::Test {
                        expr: Box::new(lhs),
                        name,
                        args,
                        negated,
                        span,
                    };
                    continue;
                }
                _ => {}
            }

            // Infix binary operators
            let (l_bp, r_bp, op_str) = match tok.kind {
                TokenKind::OpPlus => (1, 2, "+"),
                TokenKind::OpMinus => (1, 2, "-"),
                TokenKind::OpMul => (3, 4, "*"),
                TokenKind::OpDiv => (3, 4, "/"),
                TokenKind::OpEq => (5, 6, "=="),
                TokenKind::OpNe => (5, 6, "!="),
                TokenKind::OpLt => (5, 6, "<"),
                TokenKind::OpGt => (5, 6, ">"),
                TokenKind::OpLe => (5, 6, "<="),
                TokenKind::OpGe => (5, 6, ">="),
                TokenKind::KwAnd => (7, 8, "and"),
                TokenKind::KwOr => (9, 10, "or"),
                _ => break,
            };

            if l_bp < min_bp {
                break;
            }

            self.advance();
            let rhs = self.parse_expr(r_bp)?;
            let span = SourceSpan::new(
                lhs.span().line,
                lhs.span().column,
                lhs.span().offset,
                rhs.span().offset + rhs.span().length - lhs.span().offset,
            );
            lhs = Expr::Binary {
                left: Box::new(lhs),
                op: op_str.to_owned(),
                right: Box::new(rhs),
                span,
            };
        }

        self.current_depth -= 1;
        Ok(lhs)
    }

    fn parse_primary_expr(&mut self) -> Result<Expr, ParseError> {
        let tok = self.advance().ok_or_else(|| {
            ParseError::SyntaxError("Unexpected end of expression tokens".to_owned())
        })?;

        match tok.kind {
            TokenKind::Identifier(name) => Ok(Expr::Identifier {
                name,
                span: tok.span,
            }),
            TokenKind::StringLit(s) => Ok(Expr::Literal {
                val: LiteralValue::String(s),
                span: tok.span,
            }),
            TokenKind::IntLit(i) => Ok(Expr::Literal {
                val: LiteralValue::Int(i),
                span: tok.span,
            }),
            TokenKind::FloatLit(f) => Ok(Expr::Literal {
                val: LiteralValue::Float(f),
                span: tok.span,
            }),
            TokenKind::BoolLit(b) => Ok(Expr::Literal {
                val: LiteralValue::Bool(b),
                span: tok.span,
            }),
            TokenKind::NoneLit => Ok(Expr::Literal {
                val: LiteralValue::None,
                span: tok.span,
            }),
            TokenKind::LParen => {
                let inner = self.parse_expr(0)?;
                if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::RParen)) {
                    self.advance();
                }
                Ok(inner)
            }
            TokenKind::LBracket => {
                let mut items = Vec::new();
                while let Some(t) = self.peek().cloned() {
                    if matches!(
                        t.kind,
                        TokenKind::RBracket | TokenKind::TagCloseOutput | TokenKind::TagCloseBlock
                    ) {
                        if matches!(t.kind, TokenKind::RBracket) {
                            self.advance();
                        }
                        break;
                    }
                    let item = self.parse_expr(0)?;
                    items.push(item);
                    if matches!(self.peek().map(|t| &t.kind), Some(TokenKind::Comma)) {
                        self.advance();
                    }
                }
                Ok(Expr::List {
                    items,
                    span: tok.span,
                })
            }
            TokenKind::KwNot => {
                let expr = self.parse_expr(11)?;
                Ok(Expr::Unary {
                    op: "not".to_owned(),
                    expr: Box::new(expr),
                    span: tok.span,
                })
            }
            _ => Ok(Expr::Literal {
                val: LiteralValue::None,
                span: tok.span,
            }),
        }
    }
}
