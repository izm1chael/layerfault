//! Shell symbol tracking: variable assignments, aliases and function
//! definitions.
//!
//! Much thinner than Python's `symbols.rs`: shell has no import system, so
//! there is no `ImportBinding` equivalent. Resolution is intentionally
//! one-level-only (an alias/variable value is not itself re-resolved
//! through another alias/variable).

use super::parser::ShellFunctionDef;
use std::collections::BTreeMap;

#[derive(Debug, Default)]
pub struct SymbolTable {
    /// `NAME` -> last-assigned value, in source order (later assignments
    /// win, matching ordinary shell variable semantics).
    pub assignments: BTreeMap<String, String>,
    /// `NAME` -> alias value, from `alias NAME=value`.
    pub aliases: BTreeMap<String, String>,
    pub functions: Vec<ShellFunctionDef>,
}

impl SymbolTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_parsed(
        assignments: &[(String, String, usize)],
        aliases: &[(String, String, usize)],
        functions: &[ShellFunctionDef],
    ) -> Self {
        let mut table = Self::new();
        for (name, value, _line) in assignments {
            table.assignments.insert(name.clone(), value.clone());
        }
        for (name, value, _line) in aliases {
            table.aliases.insert(name.clone(), value.clone());
        }
        table.functions = functions.to_vec();
        table
    }

    /// Resolve a bare `$NAME`/`${NAME}` word to its most recently assigned
    /// value, one level only (the resolved value is not itself re-resolved).
    pub fn resolve_variable(&self, word: &str) -> Option<&str> {
        let name = word.strip_prefix('$')?;
        let name = name
            .strip_prefix('{')
            .and_then(|inner| inner.strip_suffix('}'))
            .unwrap_or(name);
        self.assignments.get(name).map(String::as_str)
    }

    /// Resolve an alias name to its value, one level only.
    pub fn resolve_alias(&self, name: &str) -> Option<&str> {
        self.aliases.get(name).map(String::as_str)
    }
}
