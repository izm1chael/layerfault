//! Bounded, hand-rolled shell/POSIX tokenizer and shallow parser.
//!
//! **This is explicitly not a full POSIX grammar.** There is no crate on
//! crates.io suitable for this job (`yash-syntax` is GPL-3.0-or-later,
//! copyleft-incompatible with this MIT project; `conch-parser` is
//! permissively licensed but unmaintained since ~2018), so this module
//! hand-rolls a narrow, bounded scanner instead, mirroring the
//! `template_static` precedent of an own hand-rolled parser with no crate.
//!
//! Known fidelity gaps, by design:
//! - Nested `$(...)`/backtick command substitution is recognized and
//!   recursively re-tokenized (bounded by `max_nesting_depth`), but paren
//!   balancing inside a substitution ignores quoting, so a `)` inside a
//!   quoted string within `$(...)` can end the substitution early.
//! - Here-documents (`<<WORD` / `<<-WORD`) are recognized and their bodies
//!   are skipped as opaque text (never tokenized as commands), but here-doc
//!   *expansion* (`${var}` substitution inside the body) is not modeled —
//!   irrelevant here since bodies are never treated as executable content.
//! - `case` pattern labels (e.g. `foo)`) are not distinguished from ordinary
//!   commands; a case label that happens to match a dangerous command name
//!   could, in principle, misclassify. `case`/`esac` still correctly bracket
//!   nesting depth.
//! - `${var//pattern/repl}` and other parameter-expansion operators are not
//!   modeled; `$var`/`${var}` are recognized only for whole-variable
//!   substitution when a word is a bare `$NAME` used as a command name.
//! - Call sites recovered from inside a `$(...)`/backtick substitution
//!   report a line number relative to the substitution's own content, not
//!   the enclosing file, since the nested re-tokenization pass is a fresh
//!   `Parser` over just that substring.
//!
//! Because of these gaps, findings produced from shell analysis default to
//! a lower confidence than equivalent-category Python/JavaScript findings
//! (see `shell_static::calls`).
//!
//! A hand-rolled word-splitter was chosen over the `shlex` crate (which the
//! plan allowed as an option): this module already needs a single-pass
//! scanner with cursor-level control for heredoc-body skipping, embedded
//! command-substitution recursion and redirect-target capture, none of
//! which `shlex`'s flat word-splitting API provides. Introducing `shlex`
//! only for a leaf-level "split this already-isolated string into words"
//! helper (alias/assignment right-hand sides) would add a dependency for a
//! few lines of `split_whitespace`-shaped logic this module already needs
//! elsewhere, so it was not added.

use crate::static_analysis::common::capability::ScriptScope;
use std::fmt;

pub use crate::static_analysis::python::parser::LineIndex;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ShellSyntaxState {
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
pub enum ShellCoverage {
    Complete,
    Incomplete { reason: String },
}

impl fmt::Display for ShellSyntaxState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Valid => write!(f, "Valid"),
            Self::Invalid {
                error,
                line,
                column,
            } => {
                if let (Some(l), Some(c)) = (line, column) {
                    write!(f, "Invalid shell syntax at L{}:{}: {}", l, c, error)
                } else {
                    write!(f, "Invalid shell syntax: {}", error)
                }
            }
            Self::ExceededLimits { reason } => write!(f, "Exceeded limits: {}", reason),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RedirectKind {
    In,
    Out,
    Append,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ShellWord {
    pub text: String,
    pub quoted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ShellSimpleCommand {
    pub words: Vec<ShellWord>,
    pub line: usize,
    pub scope: ScriptScope,
    pub pipeline_id: u64,
    pub pipeline_index: usize,
    pub backgrounded: bool,
    pub redirects: Vec<(RedirectKind, String)>,
    /// `NAME=value` assignments prefixing this simple command directly
    /// (e.g. `LD_PRELOAD=/x/evil.so ls`), one shot for this command only.
    pub env_prefix: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ShellFunctionDef {
    pub name: String,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ParsedShell {
    pub syntax_state: ShellSyntaxState,
    pub coverage: ShellCoverage,
    pub commands: Vec<ShellSimpleCommand>,
    pub functions: Vec<ShellFunctionDef>,
    /// `(name, value, line)`, in source order; later entries override
    /// earlier ones for the same name when resolving one level of `$VAR`
    /// indirection (see `shell_static::symbols`).
    pub assignments: Vec<(String, String, usize)>,
    /// `(name, value, line)`, in source order, from `alias name=value`.
    pub aliases: Vec<(String, String, usize)>,
}

const KEYWORDS_OPEN: &[&str] = &["if", "for", "while", "until", "case"];
const KEYWORDS_CLOSE: &[&str] = &["fi", "done", "esac"];
const KEYWORDS_NOOP: &[&str] = &["then", "do", "else", "elif"];

enum Frame {
    Control,
    Brace,
    FunctionBrace,
}

struct RawWord {
    text: String,
    line: usize,
    quoted: bool,
    /// True only when the word was a bare, unquoted, unescaped, non-expanded
    /// literal token (so it is safe to compare against shell keywords or
    /// treat as `NAME=value`/`NAME()` syntax).
    bare: bool,
}

pub fn parse_shell_source(
    source: &str,
    limits: &super::limits::ShellAnalysisLimits,
) -> ParsedShell {
    if source.len() > limits.max_source_bytes {
        return ParsedShell {
            syntax_state: ShellSyntaxState::ExceededLimits {
                reason: format!(
                    "Source byte size ({} bytes) exceeds limit ({} bytes)",
                    source.len(),
                    limits.max_source_bytes
                ),
            },
            coverage: ShellCoverage::Incomplete {
                reason: format!("File size exceeds cap of {} bytes", limits.max_source_bytes),
            },
            commands: Vec::new(),
            functions: Vec::new(),
            assignments: Vec::new(),
            aliases: Vec::new(),
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
    limits: &'a super::limits::ShellAnalysisLimits,
    line_index: &'a LineIndex,
    pos: usize,
    depth: usize,
    tokens: usize,
    pipeline_counter: u64,
    exceeded: Option<String>,
    invalid: Option<(String, Option<usize>, Option<usize>)>,
    commands: Vec<ShellSimpleCommand>,
    functions: Vec<ShellFunctionDef>,
    assignments: Vec<(String, String, usize)>,
    aliases: Vec<(String, String, usize)>,
    scope_stack: Vec<ScriptScope>,
    frame_stack: Vec<Frame>,
    pending_heredocs: Vec<(String, bool)>,
    pending_env_prefix: Vec<(String, String)>,
    current: Option<ShellSimpleCommand>,
    current_pipeline_id: u64,
}

impl<'a> Parser<'a> {
    fn new(
        source: &'a str,
        limits: &'a super::limits::ShellAnalysisLimits,
        line_index: &'a LineIndex,
        start_depth: usize,
        start_tokens: usize,
    ) -> Self {
        let pipeline_counter = 1;
        Self {
            source,
            limits,
            line_index,
            pos: 0,
            depth: start_depth,
            tokens: start_tokens,
            pipeline_counter,
            exceeded: None,
            invalid: None,
            commands: Vec::new(),
            functions: Vec::new(),
            assignments: Vec::new(),
            aliases: Vec::new(),
            scope_stack: vec![ScriptScope::Module],
            frame_stack: Vec::new(),
            pending_heredocs: Vec::new(),
            pending_env_prefix: Vec::new(),
            current: None,
            current_pipeline_id: pipeline_counter,
        }
    }

    fn into_result(self) -> ParsedShell {
        let syntax_state = if let Some((error, line, column)) = self.invalid {
            ShellSyntaxState::Invalid {
                error,
                line,
                column,
            }
        } else if let Some(reason) = self.exceeded {
            ShellSyntaxState::ExceededLimits { reason }
        } else {
            ShellSyntaxState::Valid
        };
        let coverage = match &syntax_state {
            ShellSyntaxState::Valid => ShellCoverage::Complete,
            ShellSyntaxState::Invalid { error, .. } => ShellCoverage::Incomplete {
                reason: format!("Shell syntax error: {error}"),
            },
            ShellSyntaxState::ExceededLimits { .. } => ShellCoverage::Incomplete {
                reason: "Shell tokenizer complexity limit exceeded".to_owned(),
            },
        };
        ParsedShell {
            syntax_state,
            coverage,
            commands: self.commands,
            functions: self.functions,
            assignments: self.assignments,
            aliases: self.aliases,
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
                    self.consume_pending_heredocs();
                    self.current_pipeline_id = self.next_pipeline_id();
                }
                _ => self.step(),
            }
        }
    }

    fn next_pipeline_id(&mut self) -> u64 {
        self.pipeline_counter += 1;
        self.pipeline_counter
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
                _ => return,
            }
        }
    }

    fn finish_statement(&mut self) {
        if let Some(cmd) = self.current.take() {
            if !cmd.words.is_empty() {
                self.commands.push(cmd);
            }
        }
    }

    fn consume_pending_heredocs(&mut self) {
        let pending = std::mem::take(&mut self.pending_heredocs);
        for (delim, strip_tabs) in pending {
            loop {
                if self.at_end() {
                    let line = self.line_at(self.pos);
                    self.invalid = Some((
                        format!("Unterminated here-document (missing '{delim}' delimiter)"),
                        Some(line),
                        None,
                    ));
                    return;
                }
                let line_start = self.pos;
                let bytes = self.source.as_bytes();
                let mut end = line_start;
                while end < bytes.len() && bytes[end] != b'\n' {
                    end += 1;
                }
                let mut line_text = &self.source[line_start..end];
                if strip_tabs {
                    line_text = line_text.trim_start_matches('\t');
                }
                let matched = line_text == delim;
                self.pos = if end < bytes.len() { end + 1 } else { end };
                if matched {
                    break;
                }
            }
        }
    }

    /// Parse one command-position token: either a keyword/brace handled
    /// structurally, or the start of a simple command that is then read to
    /// completion (through its terminator).
    fn step(&mut self) {
        if self.current.is_some() {
            self.continue_command();
            return;
        }

        // Fresh command position: handle bare structural operators directly
        // (they can never become a `read_word` result, since `read_word`
        // stops immediately -- and consumes nothing -- at any of these
        // characters; leaving them unhandled here would stall the cursor).
        match self.peek() {
            Some(';') => {
                self.advance();
                self.bump_token();
                self.pending_env_prefix.clear();
                self.current_pipeline_id = self.next_pipeline_id();
                return;
            }
            Some('&') if self.peek_at(1) == Some('&') => {
                self.advance();
                self.advance();
                self.bump_token();
                self.pending_env_prefix.clear();
                self.current_pipeline_id = self.next_pipeline_id();
                return;
            }
            Some('|') if self.peek_at(1) == Some('|') => {
                self.advance();
                self.advance();
                self.bump_token();
                self.pending_env_prefix.clear();
                self.current_pipeline_id = self.next_pipeline_id();
                return;
            }
            Some('&') => {
                self.advance();
                self.bump_token();
                self.pending_env_prefix.clear();
                self.current_pipeline_id = self.next_pipeline_id();
                return;
            }
            Some('|') => {
                // Stray pipe with no preceding command; make progress and move on.
                self.advance();
                self.bump_token();
                return;
            }
            Some('(') | Some(')') => {
                self.advance();
                self.bump_token();
                return;
            }
            Some('{') => {
                self.advance();
                self.bump_token();
                self.pending_env_prefix.clear();
                self.push_depth(Frame::Brace);
                return;
            }
            Some('}') => {
                self.advance();
                self.bump_token();
                self.pending_env_prefix.clear();
                self.pop_depth();
                return;
            }
            Some('<') | Some('>') => {
                self.skip_bare_redirect();
                return;
            }
            _ => {}
        }

        let Some(word) = self.read_word() else {
            // Defensive: guarantee forward progress even for a character
            // this scanner does not explicitly recognize.
            if !self.at_end() {
                self.advance();
            }
            return;
        };
        self.bump_token();
        if self.should_stop() {
            return;
        }

        if word.bare && KEYWORDS_OPEN.contains(&word.text.as_str()) {
            self.pending_env_prefix.clear();
            self.push_depth(Frame::Control);
            return;
        }
        if word.bare && KEYWORDS_CLOSE.contains(&word.text.as_str()) {
            self.pending_env_prefix.clear();
            if matches!(self.frame_stack.last(), Some(Frame::Control)) {
                self.pop_depth();
            } else {
                self.depth = self.depth.saturating_sub(1);
            }
            return;
        }
        if word.bare && KEYWORDS_NOOP.contains(&word.text.as_str()) {
            self.pending_env_prefix.clear();
            return;
        }
        if word.bare && word.text == "function" {
            self.pending_env_prefix.clear();
            self.skip_ws_and_comment();
            let Some(name_word) = self.read_word() else {
                return;
            };
            self.bump_token();
            let mut name = name_word.text;
            self.skip_ws_and_comment();
            if self.peek() == Some('(') && self.peek_at(1) == Some(')') {
                self.advance();
                self.advance();
                self.skip_ws_and_comment();
            }
            self.maybe_open_function_body(&mut name, name_word.line);
            return;
        }
        if word.bare && word.text == "alias" {
            self.pending_env_prefix.clear();
            self.parse_alias_tail();
            return;
        }
        if word.bare && looks_like_assignment(&word.text) {
            self.record_assignment(&word.text, word.line);
            if let Some((name, value)) = word.text.split_once('=') {
                self.pending_env_prefix
                    .push((name.to_owned(), value.to_owned()));
            }
            return; // continue loop: next word re-enters `step` at command position
        }
        if word.bare
            && self.peek() == Some('(')
            && self.peek_at(1) == Some(')')
            && is_identifier(&word.text)
        {
            self.pending_env_prefix.clear();
            self.advance();
            self.advance();
            self.skip_ws_and_comment();
            let mut name = word.text;
            let line = word.line;
            self.maybe_open_function_body(&mut name, line);
            return;
        }

        // Ordinary command name.
        let scope = self.cur_scope();
        let env_prefix = std::mem::take(&mut self.pending_env_prefix);
        self.current = Some(ShellSimpleCommand {
            words: vec![ShellWord {
                text: word.text,
                quoted: word.quoted,
            }],
            line: word.line,
            scope,
            pipeline_id: self.current_pipeline_id,
            pipeline_index: 0,
            backgrounded: false,
            redirects: Vec::new(),
            env_prefix,
        });
        self.continue_command();
    }

    fn skip_bare_redirect(&mut self) {
        match self.peek() {
            Some('<') if self.peek_at(1) == Some('<') => {
                self.advance();
                self.advance();
                self.bump_token();
                let strip_tabs = if self.peek() == Some('-') {
                    self.advance();
                    true
                } else {
                    false
                };
                self.skip_ws_and_comment();
                if let Some(word) = self.read_word() {
                    self.bump_token();
                    self.pending_heredocs.push((word.text, strip_tabs));
                }
            }
            Some('<') => {
                self.advance();
                self.bump_token();
                self.skip_ws_and_comment();
                if self.read_word().is_some() {
                    self.bump_token();
                }
            }
            Some('>') if self.peek_at(1) == Some('>') => {
                self.advance();
                self.advance();
                self.bump_token();
                self.skip_ws_and_comment();
                if self.read_word().is_some() {
                    self.bump_token();
                }
            }
            Some('>') => {
                self.advance();
                self.bump_token();
                self.skip_ws_and_comment();
                if self.read_word().is_some() {
                    self.bump_token();
                }
            }
            _ => {}
        }
    }

    fn maybe_open_function_body(&mut self, name: &mut String, line: usize) {
        // Allow the `{` to be on the following line.
        loop {
            match self.peek() {
                Some('\n') => {
                    self.advance();
                }
                Some(' ') | Some('\t') | Some('\r') => {
                    self.advance();
                }
                _ => break,
            }
        }
        if self.peek() == Some('{') {
            self.advance();
            self.push_depth(Frame::FunctionBrace);
            self.scope_stack.push(ScriptScope::Function);
            self.functions.push(ShellFunctionDef {
                name: std::mem::take(name),
                line,
            });
        }
    }

    fn parse_alias_tail(&mut self) {
        loop {
            self.skip_ws_and_comment();
            match self.peek() {
                None | Some('\n') | Some(';') | Some('&') | Some('|') => {
                    if matches!(self.peek(), Some(';') | Some('&') | Some('|')) {
                        self.consume_terminator_char();
                    }
                    return;
                }
                _ => {}
            }
            let Some(word) = self.read_word() else {
                return;
            };
            self.bump_token();
            if self.should_stop() {
                return;
            }
            if let Some((name, value)) = word.text.split_once('=') {
                if is_identifier(name) {
                    self.aliases
                        .push((name.to_owned(), value.to_owned(), word.line));
                }
            }
        }
    }

    fn record_assignment(&mut self, text: &str, line: usize) {
        if let Some((name, value)) = text.split_once('=') {
            self.assignments
                .push((name.to_owned(), value.to_owned(), line));
        }
    }

    fn continue_command(&mut self) {
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
                Some('&') if self.peek_at(1) == Some('&') => {
                    self.advance();
                    self.advance();
                    self.bump_token();
                    self.finish_statement();
                    self.current_pipeline_id = self.next_pipeline_id();
                    return;
                }
                Some('|') if self.peek_at(1) == Some('|') => {
                    self.advance();
                    self.advance();
                    self.bump_token();
                    self.finish_statement();
                    self.current_pipeline_id = self.next_pipeline_id();
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
                    self.current = Some(ShellSimpleCommand {
                        words: vec![ShellWord {
                            text: word.text,
                            quoted: word.quoted,
                        }],
                        line: word.line,
                        scope,
                        pipeline_id,
                        pipeline_index: next_index,
                        backgrounded: false,
                        redirects: Vec::new(),
                        env_prefix: Vec::new(),
                    });
                    // loop continues to read the rest of this command
                }
                Some('&') => {
                    self.advance();
                    self.bump_token();
                    if let Some(cmd) = self.current.as_mut() {
                        cmd.backgrounded = true;
                    }
                    self.finish_statement();
                    self.current_pipeline_id = self.next_pipeline_id();
                    return;
                }
                Some('<') if self.peek_at(1) == Some('<') => {
                    self.advance();
                    self.advance();
                    self.bump_token();
                    let strip_tabs = if self.peek() == Some('-') {
                        self.advance();
                        true
                    } else {
                        false
                    };
                    self.skip_ws_and_comment();
                    if let Some(word) = self.read_word() {
                        self.bump_token();
                        self.pending_heredocs.push((word.text, strip_tabs));
                    }
                }
                Some('<') => {
                    self.advance();
                    self.bump_token();
                    self.skip_ws_and_comment();
                    if let Some(word) = self.read_word() {
                        self.bump_token();
                        if let Some(cmd) = self.current.as_mut() {
                            cmd.redirects.push((RedirectKind::In, word.text));
                        }
                    }
                }
                Some('>') if self.peek_at(1) == Some('>') => {
                    self.advance();
                    self.advance();
                    self.bump_token();
                    self.skip_ws_and_comment();
                    if let Some(word) = self.read_word() {
                        self.bump_token();
                        if let Some(cmd) = self.current.as_mut() {
                            cmd.redirects.push((RedirectKind::Append, word.text));
                        }
                    }
                }
                Some('>') => {
                    self.advance();
                    self.bump_token();
                    self.skip_ws_and_comment();
                    if let Some(word) = self.read_word() {
                        self.bump_token();
                        if let Some(cmd) = self.current.as_mut() {
                            cmd.redirects.push((RedirectKind::Out, word.text));
                        }
                    }
                }
                Some('(') | Some(')') | Some('{') | Some('}') => {
                    // Not modeled precisely (subshell grouping); treat as a
                    // soft no-op separator rather than crashing, per this
                    // module's documented bounded-fidelity stance.
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
                    if let Some(cmd) = self.current.as_mut() {
                        cmd.words.push(ShellWord {
                            text: word.text,
                            quoted: word.quoted,
                        });
                    }
                }
            }
        }
    }

    fn consume_terminator_char(&mut self) {
        match self.peek() {
            Some('&') if self.peek_at(1) == Some('&') => {
                self.advance();
                self.advance();
            }
            Some('|') if self.peek_at(1) == Some('|') => {
                self.advance();
                self.advance();
            }
            Some(_) => {
                self.advance();
            }
            None => {}
        }
        self.current_pipeline_id = self.next_pipeline_id();
    }

    // -- word reading ------------------------------------------------------

    fn read_word(&mut self) -> Option<RawWord> {
        if self.at_end() {
            return None;
        }
        let start = self.pos;
        let start_line = self.line_at(start);
        let mut text = String::new();
        let mut bare = true;
        let mut any = false;

        loop {
            if self.should_stop() {
                break;
            }
            let Some(c) = self.peek() else { break };
            match c {
                ' ' | '\t' | '\r' | '\n' => break,
                ';' | '&' | '|' | '<' | '>' | '(' | ')' | '{' | '}' => break,
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
                '\\' => {
                    bare = false;
                    any = true;
                    self.advance();
                    match self.advance() {
                        Some('\n') | None => {}
                        Some(next) => text.push(next),
                    }
                }
                '$' if self.peek_at(1) == Some('(') => {
                    bare = false;
                    any = true;
                    if !self.read_dollar_paren(&mut text) {
                        return None;
                    }
                }
                '`' => {
                    bare = false;
                    any = true;
                    if !self.read_backtick(&mut text) {
                        return None;
                    }
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
            quoted: !bare,
            bare,
        })
    }

    fn read_single_quoted(&mut self, text: &mut String) -> bool {
        loop {
            match self.advance() {
                Some('\'') => return true,
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
                    return true;
                }
                Some('\\') => {
                    self.advance();
                    match self.peek() {
                        Some(next @ ('$' | '`' | '"' | '\\')) => {
                            text.push(next);
                            self.advance();
                        }
                        Some('\n') => {
                            self.advance();
                        }
                        _ => text.push('\\'),
                    }
                }
                Some('$') if self.peek_at(1) == Some('(') => {
                    if !self.read_dollar_paren(text) {
                        return false;
                    }
                }
                Some('`') => {
                    if !self.read_backtick(text) {
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

    /// Consumes `$(...)`, recursively re-tokenizing the inner text as its
    /// own nested command stream (bounded by `max_nesting_depth`).
    fn read_dollar_paren(&mut self, text: &mut String) -> bool {
        self.advance(); // '$'
        self.advance(); // '('
        let inner_start = self.pos;
        let mut paren_depth = 1usize;
        while paren_depth > 0 {
            match self.advance() {
                Some('(') => paren_depth += 1,
                Some(')') => paren_depth -= 1,
                Some(_) => {}
                None => {
                    let line = self.line_at(self.pos);
                    self.invalid = Some((
                        "Unterminated command substitution '$(...)'".to_owned(),
                        Some(line),
                        None,
                    ));
                    return false;
                }
            }
        }
        let inner_end = self.pos - 1; // position of the matching ')'
        let inner = &self.source[inner_start..inner_end];
        text.push_str("$(");
        text.push_str(inner);
        text.push(')');
        self.recurse_into(inner);
        true
    }

    /// Consumes `` `...` ``, recursively re-tokenizing the inner text.
    fn read_backtick(&mut self, text: &mut String) -> bool {
        self.advance(); // opening '`'
        let inner_start = self.pos;
        loop {
            match self.advance() {
                Some('`') => break,
                Some('\\') => {
                    self.advance();
                }
                Some(_) => {}
                None => {
                    let line = self.line_at(self.pos);
                    self.invalid = Some((
                        "Unterminated command substitution '`...`'".to_owned(),
                        Some(line),
                        None,
                    ));
                    return false;
                }
            }
        }
        let inner_end = self.pos - 1;
        let inner = &self.source[inner_start..inner_end];
        text.push('`');
        text.push_str(inner);
        text.push('`');
        self.recurse_into(inner);
        true
    }

    fn recurse_into(&mut self, inner: &str) {
        if self.should_stop() {
            return;
        }
        let next_depth = self.depth + 1;
        if next_depth > self.limits.max_nesting_depth {
            self.exceeded = Some(format!(
                "Nesting depth ({}) exceeds limit ({}) inside command substitution",
                next_depth, self.limits.max_nesting_depth
            ));
            return;
        }
        let nested_line_index = LineIndex::new(inner);
        let mut nested = Parser::new(
            inner,
            self.limits,
            &nested_line_index,
            next_depth,
            self.tokens,
        );
        nested.scope_stack = self.scope_stack.clone();
        nested.run();
        nested.finish_statement();
        self.tokens = nested.tokens;
        if let Some(reason) = nested.exceeded.take() {
            self.exceeded = Some(reason);
        }
        if let Some(invalid) = nested.invalid.take() {
            self.invalid = Some(invalid);
        }
        self.commands.extend(nested.commands);
        self.functions.extend(nested.functions);
        self.assignments.extend(nested.assignments);
        self.aliases.extend(nested.aliases);
    }
}

fn is_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn looks_like_assignment(text: &str) -> bool {
    let Some((name, _)) = text.split_once('=') else {
        return false;
    };
    !name.is_empty() && is_identifier(name)
}
