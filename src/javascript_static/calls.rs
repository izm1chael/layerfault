//! Capability-classifying call-site extraction for JavaScript/TypeScript.
//!
//! Walks the `oxc` AST via [`oxc_ast_visit::Visit`], resolving call/`new`
//! targets through [`super::symbols::SymbolTable`] (import-alias
//! resolution) and classifying them with [`classify_js_capability`], a
//! qualified-name match table mirroring
//! `python_static::calls::classify_target_capability`'s shape. Produces
//! [`crate::script_capability::ScriptCallSite`] directly — unlike
//! shell/PowerShell, JS's required rule set has no composite pattern needing
//! extra per-site boolean flags, so no bespoke wrapper struct is needed
//! here.
//!
//! Scope model: [`ScriptScope::Module`] (script top level) vs
//! [`ScriptScope::Function`] (inside any function body — regular
//! `function`, arrow, method, class constructor all collapse into this one
//! bucket). Tracked via `enter_node`/
//! `leave_node` on `AstKind::Function`/`AstKind::ArrowFunctionExpression`,
//! the same mechanism `parser::LimitsVisitor` uses for depth (see that
//! module's doc for why: avoids needing `oxc_syntax` just for the
//! `ScopeFlags` parameter type `visit_function` takes).
//!
//! `CredentialAccess` (`process.env.<CREDENTIAL_SHAPED_NAME>`) is not a call
//! site at all — it is a member-expression *read* — so it is detected in
//! `visit_static_member_expression` rather than `visit_call_expression`.

use super::limits::JavaScriptAnalysisLimits;
use super::parser::LineIndex;
use super::symbols::SymbolTable;
use crate::script_capability::{ScriptCallSite, ScriptCapability, ScriptConfidence, ScriptScope};
use oxc_ast::ast::{
    Argument, ArrayExpressionElement, CallExpression, Expression, NewExpression, Program,
    StaticMemberExpression,
};
use oxc_ast::ast_kind::AstKind;
use oxc_ast_visit::{walk, Visit};

const CREDENTIAL_SHAPED_SUBSTRINGS: &[&str] = &["SECRET", "TOKEN", "PASSWORD", "KEY", "CREDENTIAL"];

const INSTALL_TOOLS: &[&str] = &["npm", "pip", "yarn", "pnpm", "git", "curl", "wget"];

/// Package names whose mere `require(...)` is itself a native-code-loading
/// signal (native-binding-loader packages), independent of a `.node`-suffixed
/// argument.
const NATIVE_LOADER_PACKAGES: &[&str] = &["ffi-napi", "node-ffi", "ref-napi", "node-gyp-build"];

pub struct CallSiteExtractor<'a> {
    symbol_table: &'a SymbolTable,
    limits: &'a JavaScriptAnalysisLimits,
    line_index: &'a LineIndex,
    source: &'a str,
    scope_depth: usize,
    pub call_sites: Vec<ScriptCallSite>,
}

impl<'a> CallSiteExtractor<'a> {
    pub fn new(
        symbol_table: &'a SymbolTable,
        limits: &'a JavaScriptAnalysisLimits,
        line_index: &'a LineIndex,
        source: &'a str,
    ) -> Self {
        Self {
            symbol_table,
            limits,
            line_index,
            source,
            scope_depth: 0,
            call_sites: Vec::new(),
        }
    }

    pub fn extract(&mut self, program: &Program<'a>) {
        self.visit_program(program);
    }

    fn at_capacity(&self) -> bool {
        self.call_sites.len() >= self.limits.max_call_sites
    }

    fn current_scope(&self) -> ScriptScope {
        if self.scope_depth > 0 {
            ScriptScope::Function
        } else {
            ScriptScope::Module
        }
    }

    /// Resolve a callee expression to `(raw_target, resolved_target)`.
    /// Mirrors `python_static::calls::CallSiteExtractor::resolve_call_target`
    /// (minus reflection resolution, which JS's `obj['attr']` computed-member
    /// analog is not modeled by this frontend).
    fn resolve_target(&self, expr: &Expression) -> (String, Option<String>) {
        match expr {
            Expression::Identifier(id) => {
                let name = id.name.as_str().to_owned();
                let resolved = self.symbol_table.resolve_full_target(&name);
                (name, resolved)
            }
            Expression::StaticMemberExpression(_) => {
                if let Some(path) = dotted_path(expr) {
                    let resolved = self.symbol_table.resolve_full_target(&path);
                    (path, resolved)
                } else {
                    (String::new(), None)
                }
            }
            _ => (String::new(), None),
        }
    }

    fn record_call_site(
        &mut self,
        raw_target: String,
        resolved_target: Option<String>,
        span_start: u32,
        arguments: &[Argument],
    ) {
        if self.at_capacity() || (raw_target.is_empty() && resolved_target.is_none()) {
            return;
        }
        let target_for_lookup = resolved_target.as_deref().unwrap_or(&raw_target);
        let Some(mut capability) = classify_js_capability(target_for_lookup) else {
            return;
        };

        let (line, column) = self.line_col(span_start);
        let (literal_evidence, first_literal) =
            extract_argument_evidence(arguments, self.limits.max_string_literal_bytes);

        if capability == ScriptCapability::Process {
            if let Some(ref first_word) = first_literal {
                if is_install_tool(first_word) {
                    capability = ScriptCapability::PackageInstall;
                }
            }
        }

        let confidence = if resolved_target.is_some() {
            ScriptConfidence::High
        } else {
            ScriptConfidence::Medium
        };

        self.call_sites.push(ScriptCallSite {
            capability,
            scope: self.current_scope(),
            raw_target,
            resolved_target,
            line: Some(line),
            column: Some(column),
            literal_arg_evidence: literal_evidence,
            confidence,
        });
    }

    fn line_col(&self, span_start: u32) -> (usize, usize) {
        self.line_index.line_col(span_start as usize, self.source)
    }

    fn inspect_call(&mut self, call: &CallExpression) {
        // `require(...)`: NativeLoad signal when the argument names a known
        // native-binding-loader package or ends in `.node`.
        if let Expression::Identifier(callee) = &call.callee {
            if callee.name.as_str() == "require" {
                if let Some(Argument::StringLiteral(lit)) = call.arguments.first() {
                    let module = lit.value.as_str();
                    if module.ends_with(".node")
                        || NATIVE_LOADER_PACKAGES.contains(&module.trim_start_matches("node:"))
                    {
                        self.record_call_site(
                            "require".to_owned(),
                            Some(module.to_owned()),
                            call.span.start,
                            &call.arguments,
                        );
                    }
                }
                return;
            }
        }

        let (raw_target, resolved_target) = self.resolve_target(&call.callee);
        self.record_call_site(
            raw_target,
            resolved_target,
            call.span.start,
            &call.arguments,
        );
    }

    fn inspect_new(&mut self, new_expr: &NewExpression) {
        let (raw_target, resolved_target) = self.resolve_target(&new_expr.callee);
        self.record_call_site(
            raw_target,
            resolved_target,
            new_expr.span.start,
            &new_expr.arguments,
        );
    }

    fn inspect_static_member(&mut self, member: &StaticMemberExpression) {
        // `process.env.<CREDENTIAL_SHAPED_NAME>`: a read, not a call.
        let Expression::StaticMemberExpression(inner) = &member.object else {
            return;
        };
        let Expression::Identifier(base) = &inner.object else {
            return;
        };
        if base.name.as_str() != "process" || inner.property.name.as_str() != "env" {
            return;
        }
        let env_var = member.property.name.as_str();
        if !is_credential_shaped(env_var) {
            return;
        }
        if self.at_capacity() {
            return;
        }
        let (line, column) = self.line_col(member.span.start);
        self.call_sites.push(ScriptCallSite {
            capability: ScriptCapability::CredentialAccess,
            scope: self.current_scope(),
            raw_target: format!("process.env.{env_var}"),
            resolved_target: Some(format!("process.env.{env_var}")),
            line: Some(line),
            column: Some(column),
            literal_arg_evidence: None,
            confidence: ScriptConfidence::High,
        });
    }
}

impl<'a> Visit<'a> for CallSiteExtractor<'a> {
    fn enter_node(&mut self, kind: AstKind<'a>) {
        if matches!(
            kind,
            AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
        ) {
            self.scope_depth += 1;
        }
    }

    fn leave_node(&mut self, kind: AstKind<'a>) {
        if matches!(
            kind,
            AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
        ) {
            self.scope_depth = self.scope_depth.saturating_sub(1);
        }
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        self.inspect_call(it);
        walk::walk_call_expression(self, it);
    }

    fn visit_new_expression(&mut self, it: &NewExpression<'a>) {
        self.inspect_new(it);
        walk::walk_new_expression(self, it);
    }

    fn visit_static_member_expression(&mut self, it: &StaticMemberExpression<'a>) {
        self.inspect_static_member(it);
        walk::walk_static_member_expression(self, it);
    }
}

fn dotted_path(expr: &Expression) -> Option<String> {
    match expr {
        Expression::Identifier(id) => Some(id.name.as_str().to_owned()),
        Expression::StaticMemberExpression(member) => {
            let base = dotted_path(&member.object)?;
            Some(format!("{base}.{}", member.property.name.as_str()))
        }
        _ => None,
    }
}

fn is_credential_shaped(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    CREDENTIAL_SHAPED_SUBSTRINGS
        .iter()
        .any(|needle| upper.contains(needle))
}

fn is_install_tool(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    INSTALL_TOOLS.contains(&lower.as_str())
}

/// Extract literal-argument evidence for a call/`new` site: the first
/// string-literal argument (or first element of a string-literal array
/// argument, `spawn('cmd', ['a', 'b'])`-style), truncated/sanitized the same
/// way `python_static::calls::sanitize_and_truncate` does. Returns
/// `(evidence_string, first_word_of_first_literal)` — the second element
/// feeds `is_install_tool`.
fn extract_argument_evidence(
    arguments: &[Argument],
    max_bytes: usize,
) -> (Option<String>, Option<String>) {
    let Some(first) = arguments.first() else {
        return (None, None);
    };
    match first {
        Argument::StringLiteral(lit) => {
            let raw = lit.value.as_str();
            let first_word = raw.split_whitespace().next().map(ToOwned::to_owned);
            let mut evidence = raw.to_owned();
            if arguments.len() > 1 {
                if let Argument::ArrayExpression(arr) = &arguments[1] {
                    let parts: Vec<&str> = arr
                        .elements
                        .iter()
                        .map(|el| match el {
                            ArrayExpressionElement::StringLiteral(s) => s.value.as_str(),
                            _ => "<dynamic>",
                        })
                        .collect();
                    if !parts.is_empty() {
                        evidence = format!("{evidence} {}", parts.join(" "));
                    }
                }
            }
            (
                Some(sanitize_and_truncate(&evidence, max_bytes)),
                first_word,
            )
        }
        Argument::ArrayExpression(arr) => {
            let mut first_word = None;
            let parts: Vec<&str> = arr
                .elements
                .iter()
                .enumerate()
                .map(|(idx, el)| match el {
                    ArrayExpressionElement::StringLiteral(s) => {
                        if idx == 0 {
                            first_word = s
                                .value
                                .as_str()
                                .split_whitespace()
                                .next()
                                .map(ToOwned::to_owned);
                        }
                        s.value.as_str()
                    }
                    _ => "<dynamic>",
                })
                .collect();
            if parts.is_empty() {
                (None, None)
            } else {
                (
                    Some(sanitize_and_truncate(&parts.join(" "), max_bytes)),
                    first_word,
                )
            }
        }
        _ => (None, None),
    }
}

fn sanitize_and_truncate(s: &str, max_bytes: usize) -> String {
    let sanitized: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if sanitized.len() > max_bytes {
        let mut truncated: String = sanitized.chars().take(max_bytes).collect();
        truncated.push_str("...[truncated]");
        truncated
    } else {
        sanitized
    }
}

/// Qualified-name match table, mirroring
/// `python_static::calls::classify_target_capability`'s shape.
pub fn classify_js_capability(target: &str) -> Option<ScriptCapability> {
    let lower = target.to_ascii_lowercase();

    // Process execution.
    if matches!(
        lower.as_str(),
        "child_process.exec"
            | "child_process.execsync"
            | "child_process.spawn"
            | "child_process.spawnsync"
            | "child_process.fork"
            | "child_process.execfile"
            | "child_process.execfilesync"
    ) {
        return Some(ScriptCapability::Process);
    }

    // Dynamic code evaluation.
    if matches!(
        lower.as_str(),
        "eval" | "function" | "vm.runinthiscontext" | "vm.runinnewcontext" | "vm.script"
    ) {
        return Some(ScriptCapability::DynamicCode);
    }

    // Filesystem mutation.
    if matches!(
        lower.as_str(),
        "fs.writefile"
            | "fs.writefilesync"
            | "fs.appendfile"
            | "fs.appendfilesync"
            | "fs.chmod"
            | "fs.chmodsync"
    ) {
        return Some(ScriptCapability::FilesystemWrite);
    }

    // Network access.
    if lower == "fetch"
        || lower == "http.request"
        || lower == "https.request"
        || lower == "net.connect"
        || lower == "net.socket"
        || lower == "axios"
        || lower.starts_with("axios.")
    {
        return Some(ScriptCapability::Network);
    }

    // Native library/module loading.
    if lower == "process.dlopen" {
        return Some(ScriptCapability::NativeLoad);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_process_capability() {
        assert_eq!(
            classify_js_capability("child_process.exec"),
            Some(ScriptCapability::Process)
        );
        assert_eq!(
            classify_js_capability("child_process.spawnSync"),
            Some(ScriptCapability::Process)
        );
    }

    #[test]
    fn classifies_dynamic_code_capability() {
        assert_eq!(
            classify_js_capability("eval"),
            Some(ScriptCapability::DynamicCode)
        );
        assert_eq!(
            classify_js_capability("vm.Script"),
            Some(ScriptCapability::DynamicCode)
        );
    }

    #[test]
    fn classifies_network_capability() {
        assert_eq!(
            classify_js_capability("fetch"),
            Some(ScriptCapability::Network)
        );
        assert_eq!(
            classify_js_capability("axios.get"),
            Some(ScriptCapability::Network)
        );
        assert_eq!(
            classify_js_capability("axios"),
            Some(ScriptCapability::Network)
        );
    }

    #[test]
    fn unrelated_targets_are_not_classified() {
        assert_eq!(classify_js_capability("console.log"), None);
        assert_eq!(classify_js_capability("Math.max"), None);
    }

    #[test]
    fn install_tool_detection_is_case_insensitive() {
        assert!(is_install_tool("NPM"));
        assert!(is_install_tool("pip"));
        assert!(!is_install_tool("node"));
    }

    #[test]
    fn credential_shaped_detection_is_case_insensitive() {
        assert!(is_credential_shaped("api_secret"));
        assert!(is_credential_shaped("AWS_SECRET_ACCESS_KEY"));
        assert!(!is_credential_shaped("HOME"));
    }
}
