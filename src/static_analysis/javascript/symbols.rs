//! JavaScript/TypeScript import/require binding tracking.
//!
//! Direct analog of [`crate::static_analysis::python::symbols::ImportBinding`]/
//! `SymbolTable`: a local name resolves (at most one hop) to a
//! `(target_module, target_member)` pair. Covers:
//! - CommonJS `require('mod')`, both `const x = require('mod')` and
//!   destructured `const { a, b: c } = require('mod')`.
//! - CommonJS chained access off a bare require: `const x =
//!   require('mod').member`.
//! - ESM `import x from 'mod'`, `import { a } from 'mod'`, `import * as ns
//!   from 'mod'`.
//! - Dynamic `import('mod')` used as a declarator initializer (best-effort;
//!   this is a `Promise`-returning form at runtime, but the module
//!   reference itself is still worth tracking as a one-hop binding, the
//!   same way `require('mod')` is).
//! - One-hop rebinding of an already-resolved target, e.g. `const run =
//!   child_process.exec;` after `const child_process = require(...)`.
//!   Multi-hop rebinding (an alias of an alias) is out of scope.
//!
//! Shadowing is tracked the same way Python's `mark_shadowed` does: a plain
//! assignment (`name = ...`) to a name that already has an import binding
//! marks that binding shadowed, so a later call through that name does not
//! resolve to the original import. This is deliberately simpler than a full
//! scope-aware shadow check (no per-scope shadow stack), consistent with the
//! other script frontends' one-level resolution.

use super::limits::JavaScriptAnalysisLimits;
use super::parser::LineIndex;
use oxc_ast::ast::{
    Argument, AssignmentExpression, AssignmentTarget, BindingPattern, Expression,
    ImportDeclaration, ImportDeclarationSpecifier, ModuleExportName, Program, PropertyKey,
    VariableDeclarator,
};
use oxc_ast_visit::{walk, Visit};
use oxc_span::GetSpan;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ImportBinding {
    pub local_name: String,
    pub target_module: String,
    pub target_member: Option<String>,
    pub shadowed: bool,
    pub line: Option<usize>,
}

#[derive(Debug, Default)]
pub struct SymbolTable {
    pub imports: BTreeMap<String, ImportBinding>,
}

impl SymbolTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_import(&mut self, binding: ImportBinding) {
        self.imports.insert(binding.local_name.clone(), binding);
    }

    pub fn mark_shadowed(&mut self, local_name: &str) {
        if let Some(binding) = self.imports.get_mut(local_name) {
            binding.shadowed = true;
        }
    }

    /// Resolve `local_name` (bare, e.g. `"cp"`) or `local_name.attr`
    /// (e.g. `"cp.exec"`) to its underlying import binding, one hop only.
    pub fn resolve_symbol<'a>(
        &'a self,
        expression: &'a str,
    ) -> Option<(&'a ImportBinding, Option<&'a str>)> {
        if let Some((base, attr)) = expression.split_once('.') {
            if let Some(binding) = self.imports.get(base) {
                if !binding.shadowed {
                    return Some((binding, Some(attr)));
                }
            }
        } else if let Some(binding) = self.imports.get(expression) {
            if !binding.shadowed {
                return Some((binding, None));
            }
        }
        None
    }

    pub fn resolve_full_target(&self, expression: &str) -> Option<String> {
        let (binding, attr) = self.resolve_symbol(expression)?;
        let mut full = binding.target_module.clone();
        if let Some(member) = &binding.target_member {
            full.push('.');
            full.push_str(member);
        }
        if let Some(extra_attr) = attr {
            full.push('.');
            full.push_str(extra_attr);
        }
        Some(full)
    }
}

/// Node's `node:` URL-style prefix for core modules (`node:fs` == `fs`).
/// Normalizing at binding time means every downstream consumer (call target
/// resolution, findings text) sees one canonical module name regardless of
/// which spelling the source used.
fn normalize_module(name: &str) -> String {
    name.strip_prefix("node:").unwrap_or(name).to_owned()
}

fn module_export_name_str(name: &ModuleExportName) -> String {
    match name {
        ModuleExportName::IdentifierName(id) => id.name.as_str().to_owned(),
        ModuleExportName::IdentifierReference(id) => id.name.as_str().to_owned(),
        ModuleExportName::StringLiteral(lit) => lit.value.as_str().to_owned(),
    }
}

fn property_key_name(key: &PropertyKey) -> Option<String> {
    match key {
        PropertyKey::StaticIdentifier(id) => Some(id.name.as_str().to_owned()),
        PropertyKey::StringLiteral(lit) => Some(lit.value.as_str().to_owned()),
        _ => None,
    }
}

/// `require('mod')` -> `Some("mod")` (normalized). Anything else -> `None`.
fn require_module_arg(expr: &Expression) -> Option<String> {
    let Expression::CallExpression(call) = expr else {
        return None;
    };
    let Expression::Identifier(callee) = &call.callee else {
        return None;
    };
    if callee.name.as_str() != "require" {
        return None;
    }
    match call.arguments.first()? {
        Argument::StringLiteral(lit) => Some(normalize_module(lit.value.as_str())),
        _ => None,
    }
}

/// `foo.bar.baz` -> `Some("foo.bar.baz")`. Mirrors
/// `python_static::calls::format_attribute_path`.
fn expression_dotted_path(expr: &Expression) -> Option<String> {
    match expr {
        Expression::Identifier(id) => Some(id.name.as_str().to_owned()),
        Expression::StaticMemberExpression(member) => {
            let base = expression_dotted_path(&member.object)?;
            Some(format!("{base}.{}", member.property.name.as_str()))
        }
        _ => None,
    }
}

pub struct SymbolCollector<'a> {
    table: SymbolTable,
    line_index: &'a LineIndex,
    limits: &'a JavaScriptAnalysisLimits,
}

impl<'a> SymbolCollector<'a> {
    pub fn new(line_index: &'a LineIndex, limits: &'a JavaScriptAnalysisLimits) -> Self {
        Self {
            table: SymbolTable::new(),
            line_index,
            limits,
        }
    }

    pub fn collect(&mut self, program: &Program<'a>) {
        self.visit_program(program);
    }

    pub fn into_table(self) -> SymbolTable {
        self.table
    }

    fn at_capacity(&self) -> bool {
        self.table.imports.len() >= self.limits.max_import_bindings
    }

    fn bind_pattern(&mut self, id: &BindingPattern, module: &str, line: Option<usize>) {
        match id {
            BindingPattern::BindingIdentifier(bind_id) => {
                if self.at_capacity() {
                    return;
                }
                self.table.add_import(ImportBinding {
                    local_name: bind_id.name.as_str().to_owned(),
                    target_module: module.to_owned(),
                    target_member: None,
                    shadowed: false,
                    line,
                });
            }
            BindingPattern::ObjectPattern(pattern) => {
                for prop in &pattern.properties {
                    if self.at_capacity() {
                        return;
                    }
                    let Some(key_name) = property_key_name(&prop.key) else {
                        continue;
                    };
                    if let BindingPattern::BindingIdentifier(local_id) = &prop.value {
                        self.table.add_import(ImportBinding {
                            local_name: local_id.name.as_str().to_owned(),
                            target_module: module.to_owned(),
                            target_member: Some(key_name),
                            shadowed: false,
                            line,
                        });
                    }
                }
            }
            _ => {}
        }
    }

    fn handle_declarator_init(&mut self, id: &BindingPattern, init: &Expression) {
        if self.at_capacity() {
            return;
        }
        let line = Some(self.line_index.line_number(init.span().start as usize));

        // `const x = require('mod')` / `const { a } = require('mod')`.
        if let Some(module) = require_module_arg(init) {
            self.bind_pattern(id, &module, line);
            return;
        }

        // `const x = require('mod').member`.
        if let Expression::StaticMemberExpression(member) = init {
            if let Some(module) = require_module_arg(&member.object) {
                if let BindingPattern::BindingIdentifier(bind_id) = id {
                    self.table.add_import(ImportBinding {
                        local_name: bind_id.name.as_str().to_owned(),
                        target_module: module,
                        target_member: Some(member.property.name.as_str().to_owned()),
                        shadowed: false,
                        line,
                    });
                }
                return;
            }
        }

        // `const x = await import('mod')` / `const x = import('mod')`.
        if let Expression::ImportExpression(import_expr) = init {
            if let Expression::StringLiteral(source) = &import_expr.source {
                let module = normalize_module(source.value.as_str());
                self.bind_pattern(id, &module, line);
            }
            return;
        }

        // One-hop rebinding of an already-resolved target:
        // `const run = child_process.exec;`
        if let BindingPattern::BindingIdentifier(bind_id) = id {
            if let Some(path) = expression_dotted_path(init) {
                if let Some(resolved) = self.table.resolve_full_target(&path) {
                    self.table.add_import(ImportBinding {
                        local_name: bind_id.name.as_str().to_owned(),
                        target_module: resolved,
                        target_member: None,
                        shadowed: false,
                        line,
                    });
                }
            }
        }
    }
}

impl<'a> Visit<'a> for SymbolCollector<'a> {
    fn visit_import_declaration(&mut self, it: &ImportDeclaration<'a>) {
        let module = normalize_module(it.source.value.as_str());
        let line = Some(self.line_index.line_number(it.span.start as usize));
        if let Some(specifiers) = &it.specifiers {
            for specifier in specifiers {
                if self.at_capacity() {
                    break;
                }
                match specifier {
                    ImportDeclarationSpecifier::ImportSpecifier(spec) => {
                        self.table.add_import(ImportBinding {
                            local_name: spec.local.name.as_str().to_owned(),
                            target_module: module.clone(),
                            target_member: Some(module_export_name_str(&spec.imported)),
                            shadowed: false,
                            line,
                        });
                    }
                    ImportDeclarationSpecifier::ImportDefaultSpecifier(spec) => {
                        self.table.add_import(ImportBinding {
                            local_name: spec.local.name.as_str().to_owned(),
                            target_module: module.clone(),
                            target_member: None,
                            shadowed: false,
                            line,
                        });
                    }
                    ImportDeclarationSpecifier::ImportNamespaceSpecifier(spec) => {
                        self.table.add_import(ImportBinding {
                            local_name: spec.local.name.as_str().to_owned(),
                            target_module: module.clone(),
                            target_member: None,
                            shadowed: false,
                            line,
                        });
                    }
                }
            }
        }
        walk::walk_import_declaration(self, it);
    }

    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        if let Some(init) = &it.init {
            self.handle_declarator_init(&it.id, init);
        }
        walk::walk_variable_declarator(self, it);
    }

    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'a>) {
        if let AssignmentTarget::AssignmentTargetIdentifier(id) = &it.left {
            self.table.mark_shadowed(id.name.as_str());
        }
        walk::walk_assignment_expression(self, it);
    }
}
