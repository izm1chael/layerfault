//! Bounded, hand-rolled PowerShell tokenizer and shallow parser.
//!
//! **This is explicitly not a full PowerShell grammar.** No crate on
//! crates.io provides PowerShell parsing (confirmed during design research
//! for the supported syntax), so this module hand-rolls a narrow, bounded scanner,
//! mirroring the `shell_static::parser` precedent of an own hand-rolled
//! parser with no crate.
//!
//! Known fidelity gaps, by design:
//! - Parameter binding, splatting (`@args`), and pipeline object-property
//!   flow are not modeled; a "word" is a maximal run of non-whitespace
//!   text with balanced `(...)`/`[...]` absorbed into it, which is enough
//!   to keep member-invocation (`$x.Method(...)`) and static-method
//!   (`[Type]::Method(...)`) syntax intact as single tokens for pattern
//!   matching in `calls.rs`, but does not parse expressions.
//! - `$(...)` subexpressions occurring inside a word are balanced by raw
//!   paren counting, ignoring quoting, exactly like `shell_static`'s
//!   `$(...)` handling; a `)` inside a quoted string nested inside a
//!   subexpression can end it early.
//! - `{ ... }` script blocks (bare, or passed as a cmdlet argument such as
//!   `ForEach-Object { ... }`) are recursed into as nested statement
//!   sequences bounded by `max_nesting_depth`, exactly like
//!   `shell_static`'s brace handling, but are not otherwise understood as
//!   scriptblock values (e.g. not tracked through a variable assignment).
//! - Variable-to-constructed-object tracking (`$v = New-Object X`) is one
//!   hop only: `$v.Method(...)` is resolved against the most recent
//!   `New-Object` assignment to `$v` textually preceding it, not real
//!   control-flow-sensitive data-flow.
//! - Command-name and flag matching is case-insensitive throughout
//!   (`calls.rs`/`symbols.rs`), matching real PowerShell semantics.
//!
//! Because of these gaps, findings produced from this analysis default to
//! a lower confidence than equivalent-category Python findings, matching
//! shell's precedent (see `powershell_static::calls`).
//!
//! Only a word that was read as a single unquoted, unescaped literal token
//! (`bare == true`) is ever compared against a command name, keyword, or
//! flag. A dangerous name appearing only inside a `'...'`/`"..."` string
//! literal, a `#`/`<# #>` comment, or a here-string is never in that
//! position, which structurally suppresses that class of false positive
//! (see the `test_comment_and_string_suppression` test in `mod.rs`).

use crate::static_analysis::common::capability::ScriptScope;
use std::fmt;

pub use crate::static_analysis::python::parser::LineIndex;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum PowerShellSyntaxState {
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
pub enum PowerShellCoverage {
    Complete,
    Incomplete { reason: String },
}

impl fmt::Display for PowerShellSyntaxState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Valid => write!(f, "Valid"),
            Self::Invalid {
                error,
                line,
                column,
            } => {
                if let (Some(l), Some(c)) = (line, column) {
                    write!(f, "Invalid PowerShell syntax at L{}:{}: {}", l, c, error)
                } else {
                    write!(f, "Invalid PowerShell syntax: {}", error)
                }
            }
            Self::ExceededLimits { reason } => write!(f, "Exceeded limits: {}", reason),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PowerShellWord {
    pub text: String,
    /// True only when the word was a bare, unquoted, unescaped literal
    /// token, so it is safe to compare against cmdlet/keyword names.
    pub bare: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PowerShellStatement {
    pub words: Vec<PowerShellWord>,
    pub line: usize,
    pub scope: ScriptScope,
    pub pipeline_id: u64,
    pub pipeline_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PowerShellFunctionDef {
    pub name: String,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ParsedPowerShell {
    pub syntax_state: PowerShellSyntaxState,
    pub coverage: PowerShellCoverage,
    pub statements: Vec<PowerShellStatement>,
    pub functions: Vec<PowerShellFunctionDef>,
    /// `(alias_name, target_cmdlet, line)` from `Set-Alias`, in source order.
    pub set_aliases: Vec<(String, String, usize)>,
}

enum Frame {
    Brace,
    FunctionBrace,
}

pub fn parse_powershell_source(
    source: &str,
    limits: &super::limits::PowerShellAnalysisLimits,
) -> ParsedPowerShell {
    if source.len() > limits.max_source_bytes {
        return ParsedPowerShell {
            syntax_state: PowerShellSyntaxState::ExceededLimits {
                reason: format!(
                    "Source byte size ({} bytes) exceeds limit ({} bytes)",
                    source.len(),
                    limits.max_source_bytes
                ),
            },
            coverage: PowerShellCoverage::Incomplete {
                reason: format!("File size exceeds cap of {} bytes", limits.max_source_bytes),
            },
            statements: Vec::new(),
            functions: Vec::new(),
            set_aliases: Vec::new(),
        };
    }

    let line_index = LineIndex::new(source);
    let mut parser = Parser::new(source, limits, &line_index, 0, 0);
    parser.run();
    parser.finish_statement();
    parser.into_result()
}

struct Parser<'a> {
    source: &'a str,
    limits: &'a super::limits::PowerShellAnalysisLimits,
    line_index: &'a LineIndex,
    pos: usize,
    depth: usize,
    tokens: usize,
    pipeline_counter: u64,
    exceeded: Option<String>,
    invalid: Option<(String, Option<usize>, Option<usize>)>,
    statements: Vec<PowerShellStatement>,
    functions: Vec<PowerShellFunctionDef>,
    set_aliases: Vec<(String, String, usize)>,
    scope_stack: Vec<ScriptScope>,
    frame_stack: Vec<Frame>,
    current: Option<PowerShellStatement>,
    current_pipeline_id: u64,
}

impl<'a> Parser<'a> {
    fn new(
        source: &'a str,
        limits: &'a super::limits::PowerShellAnalysisLimits,
        line_index: &'a LineIndex,
        start_depth: usize,
        start_tokens: usize,
    ) -> Self {
        Self {
            source,
            limits,
            line_index,
            pos: 0,
            depth: start_depth,
            tokens: start_tokens,
            pipeline_counter: 1,
            exceeded: None,
            invalid: None,
            statements: Vec::new(),
            functions: Vec::new(),
            set_aliases: Vec::new(),
            scope_stack: vec![ScriptScope::Module],
            frame_stack: Vec::new(),
            current: None,
            current_pipeline_id: 1,
        }
    }

    fn into_result(self) -> ParsedPowerShell {
        let syntax_state = if let Some((error, line, column)) = self.invalid {
            PowerShellSyntaxState::Invalid {
                error,
                line,
                column,
            }
        } else if let Some(reason) = self.exceeded {
            PowerShellSyntaxState::ExceededLimits { reason }
        } else {
            PowerShellSyntaxState::Valid
        };
        let coverage = match &syntax_state {
            PowerShellSyntaxState::Valid => PowerShellCoverage::Complete,
            PowerShellSyntaxState::Invalid { error, .. } => PowerShellCoverage::Incomplete {
                reason: format!("PowerShell syntax error: {error}"),
            },
            PowerShellSyntaxState::ExceededLimits { .. } => PowerShellCoverage::Incomplete {
                reason: "PowerShell tokenizer complexity limit exceeded".to_owned(),
            },
        };
        ParsedPowerShell {
            syntax_state,
            coverage,
            statements: self.statements,
            functions: self.functions,
            set_aliases: self.set_aliases,
        }
    }

    fn should_stop(&self) -> bool {
        self.exceeded.is_some() || self.invalid.is_some()
    }

    fn cur_scope(&self) -> ScriptScope {
        *self.scope_stack.last().unwrap_or(&ScriptScope::Module)
    }

    fn at_end(&self) -> bool {
        self.pos >= self.source.len()
    }

    fn peek(&self) -> Option<char> {
        self.source[self.pos..].chars().next()
    }

    fn peek_at(&self, chars_ahead: usize) -> Option<char> {
        self.source[self.pos..].chars().nth(chars_ahead)
    }

    fn advance(&mut self) -> Option<char> {
        let c = self.peek()?;
        self.pos += c.len_utf8();
        Some(c)
    }

    fn line_at(&self, pos: usize) -> usize {
        self.line_index.line_number(pos)
    }

    fn bump_token(&mut self) {
        self.tokens += 1;
        if self.tokens > self.limits.max_tokens {
            self.exceeded = Some(format!(
                "Token count ({}) exceeds limit ({})",
                self.tokens, self.limits.max_tokens
            ));
        }
    }

    fn push_depth(&mut self, frame: Frame) {
        self.depth += 1;
        if self.depth > self.limits.max_nesting_depth {
            self.exceeded = Some(format!(
                "Nesting depth ({}) exceeds limit ({})",
                self.depth, self.limits.max_nesting_depth
            ));
        }
        self.frame_stack.push(frame);
    }

    fn pop_depth(&mut self) {
        self.depth = self.depth.saturating_sub(1);
        if let Some(Frame::FunctionBrace) = self.frame_stack.pop() {
            self.scope_stack.pop();
        }
    }

    fn next_pipeline_id(&mut self) -> u64 {
        self.pipeline_counter += 1;
        self.pipeline_counter
    }

    // -- top-level driver -----------------------------------------------

    fn run(&mut self) {
        loop {
            if self.should_stop() {
                return;
            }
            self.skip_ws_and_comment();
            if self.should_stop() || self.at_end() {
                return;
            }
            match self.peek() {
                Some('\n') => {
                    self.advance();
                    self.finish_statement();
                    self.current_pipeline_id = self.next_pipeline_id();
                }
                Some(';') => {
                    self.advance();
                    self.bump_token();
                    self.finish_statement();
                    self.current_pipeline_id = self.next_pipeline_id();
                }
                Some('{') => {
                    self.advance();
                    self.bump_token();
                    self.finish_statement();
                    self.push_depth(Frame::Brace);
                }
                Some('}') => {
                    self.advance();
                    self.bump_token();
                    self.finish_statement();
                    self.pop_depth();
                }
                _ => self.step(),
            }
        }
    }

    fn skip_ws_and_comment(&mut self) {
        loop {
            match self.peek() {
                Some(' ') | Some('\t') | Some('\r') => {
                    self.advance();
                }
                Some('#') => {
                    while let Some(c) = self.peek() {
                        if c == '\n' {
                            break;
                        }
                        self.advance();
                    }
                    return;
                }
                Some('<') if self.peek_at(1) == Some('#') => {
                    let start_line = self.line_at(self.pos);
                    self.advance();
                    self.advance();
                    loop {
                        match self.peek() {
                            Some('#') if self.peek_at(1) == Some('>') => {
                                self.advance();
                                self.advance();
                                break;
                            }
                            Some(_) => {
                                self.advance();
                            }
                            None => {
                                self.invalid = Some((
                                    "Unterminated block comment '<# ... #>'".to_owned(),
                                    Some(start_line),
                                    None,
                                ));
                                return;
                            }
                        }
                    }
                }
                _ => return,
            }
        }
    }

    fn finish_statement(&mut self) {
        if let Some(stmt) = self.current.take() {
            if !stmt.words.is_empty() {
                self.statements.push(stmt);
            }
        }
    }

    /// Parse one statement-position token: a `function`/`filter` header
    /// handled structurally, `Set-Alias` handled structurally to capture
    /// the alias binding, or an ordinary statement read word-by-word to
    /// its terminator.
    fn step(&mut self) {
        if self.current.is_some() {
            self.continue_statement();
            return;
        }

        let Some(word) = self.read_word() else {
            if !self.at_end() {
                self.advance();
            }
            return;
        };
        self.bump_token();
        if self.should_stop() {
            return;
        }

        if word.bare
            && matches!(
                word.text.to_ascii_lowercase().as_str(),
                "function" | "filter"
            )
        {
            self.skip_ws_and_comment();
            let Some(name_word) = self.read_word() else {
                return;
            };
            self.bump_token();
            let name = name_word.text;
            let line = name_word.line;
            self.skip_ws_and_comment();
            // Skip an optional parameter list `(...)`, already absorbed
            // into the name word only if attached without whitespace; if
            // separated by whitespace it reads as its own word here.
            if self.peek() == Some('(') {
                if let Some(_params) = self.read_word() {
                    self.bump_token();
                }
                self.skip_ws_and_comment();
            }
            if self.peek() == Some('{') {
                self.advance();
                self.bump_token();
                self.push_depth(Frame::FunctionBrace);
                self.scope_stack.push(ScriptScope::Function);
                self.functions.push(PowerShellFunctionDef { name, line });
            }
            return;
        }

        if word.bare && word.text.eq_ignore_ascii_case("set-alias") {
            self.parse_set_alias_tail(word.line);
            return;
        }

        // Ordinary statement.
        let scope = self.cur_scope();
        self.current = Some(PowerShellStatement {
            words: vec![PowerShellWord {
                text: word.text,
                bare: word.bare,
            }],
            line: word.line,
            scope,
            pipeline_id: self.current_pipeline_id,
            pipeline_index: 0,
        });
        self.continue_statement();
    }

    fn parse_set_alias_tail(&mut self, line: usize) {
        let mut positional: Vec<String> = Vec::new();
        let mut name: Option<String> = None;
        let mut value: Option<String> = None;
        loop {
            self.skip_ws_and_comment();
            match self.peek() {
                None | Some('\n') | Some(';') | Some('|') | Some('{') | Some('}') => break,
                _ => {}
            }
            let Some(word) = self.read_word() else {
                break;
            };
            self.bump_token();
            if self.should_stop() {
                return;
            }
            if word.bare && word.text.eq_ignore_ascii_case("-name") {
                self.skip_ws_and_comment();
                if let Some(w) = self.read_word() {
                    self.bump_token();
                    name = Some(w.text);
                }
                continue;
            }
            if word.bare && word.text.eq_ignore_ascii_case("-value") {
                self.skip_ws_and_comment();
                if let Some(w) = self.read_word() {
                    self.bump_token();
                    value = Some(w.text);
                }
                continue;
            }
            if word.bare && word.text.starts_with('-') {
                continue; // skip unrecognized flags
            }
            positional.push(word.text);
        }
        if name.is_none() && !positional.is_empty() {
            name = Some(positional.remove(0));
        }
        if value.is_none() && !positional.is_empty() {
            value = Some(positional.remove(0));
        }
        if let (Some(n), Some(v)) = (name, value) {
            self.set_aliases.push((n, v, line));
        }
        // Consume a single terminator character if present, matching the
        // caller's expectation that `step`/`run` re-enters cleanly.
        if matches!(self.peek(), Some(';') | Some('\n')) {
            self.advance();
            self.current_pipeline_id = self.next_pipeline_id();
        }
    }

    fn continue_statement(&mut self) {
        loop {
            if self.should_stop() {
                return;
            }
            self.skip_ws_and_comment();
            if self.should_stop() {
                return;
            }
            match self.peek() {
                None | Some('\n') => {
                    self.finish_statement();
                    return;
                }
                Some(';') => {
                    self.advance();
                    self.bump_token();
                    self.finish_statement();
                    self.current_pipeline_id = self.next_pipeline_id();
                    return;
                }
                Some('{') | Some('}') => {
                    // A bare/unattached brace ends the current statement;
                    // the outer `run`/block loop handles the brace itself.
                    self.finish_statement();
                    return;
                }
                Some('|') => {
                    self.advance();
                    self.bump_token();
                    let pipeline_id = self
                        .current
                        .as_ref()
                        .map(|c| c.pipeline_id)
                        .unwrap_or(self.current_pipeline_id);
                    let next_index = self
                        .current
                        .as_ref()
                        .map(|c| c.pipeline_index + 1)
                        .unwrap_or(0);
                    self.finish_statement();
                    self.skip_ws_and_comment();
                    let Some(word) = self.read_word() else {
                        return;
                    };
                    self.bump_token();
                    if self.should_stop() {
                        return;
                    }
                    let scope = self.cur_scope();
                    self.current = Some(PowerShellStatement {
                        words: vec![PowerShellWord {
                            text: word.text,
                            bare: word.bare,
                        }],
                        line: word.line,
                        scope,
                        pipeline_id,
                        pipeline_index: next_index,
                    });
                    // loop continues to read the rest of this statement
                }
                Some('(') | Some(')') | Some('[') | Some(']') => {
                    // Stray bracket at statement position (not modeled
                    // precisely); make progress rather than stalling.
                    self.advance();
                    self.bump_token();
                }
                _ => {
                    let Some(word) = self.read_word() else {
                        self.finish_statement();
                        return;
                    };
                    self.bump_token();
                    if self.should_stop() {
                        return;
                    }
                    if let Some(stmt) = self.current.as_mut() {
                        stmt.words.push(PowerShellWord {
                            text: word.text,
                            bare: word.bare,
                        });
                    }
                }
            }
        }
    }

    // -- word reading ------------------------------------------------------

    fn read_word(&mut self) -> Option<RawWord> {
        if self.at_end() {
            return None;
        }

        if self.peek() == Some('@') && matches!(self.peek_at(1), Some('"') | Some('\'')) {
            return self.read_here_string();
        }

        let start = self.pos;
        let start_line = self.line_at(start);
        let mut text = String::new();
        let mut bare = true;
        let mut any = false;
        let mut depth: usize = 0;

        loop {
            if self.should_stop() {
                break;
            }
            let Some(c) = self.peek() else {
                if depth > 0 {
                    let line = self.line_at(self.pos);
                    self.invalid = Some((
                        "Unterminated parenthesis or bracket".to_owned(),
                        Some(line),
                        None,
                    ));
                    return None;
                }
                break;
            };
            match c {
                ' ' | '\t' | '\r' | '\n' if depth == 0 => break,
                ';' | '|' if depth == 0 => break,
                '{' | '}' if depth == 0 => break,
                '#' if depth == 0 => break,
                ')' | ']' if depth == 0 => break,
                '\'' => {
                    bare = false;
                    any = true;
                    self.advance();
                    if !self.read_single_quoted(&mut text) {
                        return None;
                    }
                }
                '"' => {
                    bare = false;
                    any = true;
                    self.advance();
                    if !self.read_double_quoted(&mut text) {
                        return None;
                    }
                }
                '`' => {
                    bare = false;
                    any = true;
                    self.advance();
                    match self.advance() {
                        Some('\n') | None => {}
                        Some(next) => text.push(next),
                    }
                }
                '(' | '[' => {
                    any = true;
                    depth += 1;
                    text.push(c);
                    self.advance();
                }
                ')' | ']' => {
                    // depth > 0 here (depth == 0 handled above)
                    any = true;
                    depth = depth.saturating_sub(1);
                    text.push(c);
                    self.advance();
                }
                _ => {
                    any = true;
                    text.push(c);
                    self.advance();
                }
            }
        }

        if !any {
            return None;
        }
        Some(RawWord {
            text,
            line: start_line,
            bare,
        })
    }

    fn read_single_quoted(&mut self, text: &mut String) -> bool {
        loop {
            match self.advance() {
                Some('\'') => {
                    if self.peek() == Some('\'') {
                        // `''` inside a single-quoted string is an escaped
                        // literal single quote.
                        text.push('\'');
                        self.advance();
                        continue;
                    }
                    return true;
                }
                Some(c) => text.push(c),
                None => {
                    let line = self.line_at(self.pos);
                    self.invalid = Some((
                        "Unterminated single-quoted string".to_owned(),
                        Some(line),
                        None,
                    ));
                    return false;
                }
            }
        }
    }

    fn read_double_quoted(&mut self, text: &mut String) -> bool {
        loop {
            match self.peek() {
                Some('"') => {
                    self.advance();
                    if self.peek() == Some('"') {
                        // `""` inside a double-quoted string is an escaped
                        // literal double quote.
                        text.push('"');
                        self.advance();
                        continue;
                    }
                    return true;
                }
                Some('`') => {
                    self.advance();
                    if let Some(next) = self.advance() {
                        text.push(next);
                    }
                }
                Some('$') if self.peek_at(1) == Some('(') => {
                    if !self.read_dollar_paren(text) {
                        return false;
                    }
                }
                Some(c) => {
                    text.push(c);
                    self.advance();
                }
                None => {
                    let line = self.line_at(self.pos);
                    self.invalid = Some((
                        "Unterminated double-quoted string".to_owned(),
                        Some(line),
                        None,
                    ));
                    return false;
                }
            }
        }
    }

    /// Consumes `$(...)` inside a double-quoted string, balancing raw
    /// parens without honoring nested quoting (documented fidelity gap).
    fn read_dollar_paren(&mut self, text: &mut String) -> bool {
        self.advance(); // '$'
        self.advance(); // '('
        text.push_str("$(");
        let mut paren_depth = 1usize;
        loop {
            match self.advance() {
                Some('(') => {
                    paren_depth += 1;
                    text.push('(');
                }
                Some(')') => {
                    paren_depth -= 1;
                    text.push(')');
                    if paren_depth == 0 {
                        return true;
                    }
                }
                Some(c) => text.push(c),
                None => {
                    let line = self.line_at(self.pos);
                    self.invalid = Some((
                        "Unterminated subexpression '$(...)'".to_owned(),
                        Some(line),
                        None,
                    ));
                    return false;
                }
            }
        }
    }

    /// Consumes a here-string (`@"..."@` or `@'...'@`), skipping its body
    /// as opaque text: the closing delimiter must appear at the very start
    /// of a line, per PowerShell grammar.
    fn read_here_string(&mut self) -> Option<RawWord> {
        let start_line = self.line_at(self.pos);
        let quote = self.peek_at(1).unwrap();
        self.advance(); // '@'
        self.advance(); // opening quote
                        // The rest of the opening line (if non-whitespace) is not valid
                        // here-string syntax, but this scanner is lenient: skip to the
                        // next newline before scanning for the closing delimiter.
        while let Some(c) = self.peek() {
            if c == '\n' {
                break;
            }
            self.advance();
        }
        let mut text = String::new();
        loop {
            if self.at_end() {
                self.invalid = Some((
                    format!("Unterminated here-string (missing closing '{}@')", quote),
                    Some(start_line),
                    None,
                ));
                return None;
            }
            let line_start = self.pos;
            let bytes = self.source.as_bytes();
            let mut end = line_start;
            while end < bytes.len() && bytes[end] != b'\n' {
                end += 1;
            }
            let line_text = &self.source[line_start..end];
            let closer = if quote == '"' { "\"@" } else { "'@" };
            if line_text.starts_with(closer) {
                self.pos = line_start + closer.len();
                return Some(RawWord {
                    text,
                    line: start_line,
                    bare: false,
                });
            }
            if text.len() < super::limits::DEFAULT_MAX_STRING_LITERAL_BYTES {
                text.push_str(line_text);
                text.push('\n');
            }
            self.pos = if end < bytes.len() { end + 1 } else { end };
        }
    }
}

struct RawWord {
    text: String,
    line: usize,
    bare: bool,
}
