//! PowerShell symbol tracking: built-in cmdlet aliases, user `Set-Alias`
//! bindings, `New-Object` variable-to-type bindings, and function/filter
//! definitions.
//!
//! Much thinner than Python's `symbols.rs`, mirroring `shell_static::symbols`:
//! PowerShell has no import system here, so resolution is intentionally
//! one-level-only (an alias/variable value is not itself re-resolved
//! through another alias/variable).

use super::parser::PowerShellFunctionDef;
use std::collections::BTreeMap;

/// PowerShell built-in cmdlet aliases relevant to capability detection.
/// These are shipped by PowerShell itself (not `Set-Alias`-derived), so
/// they are hardcoded here rather than discovered from source, matching
/// the plan's explicit instruction: script-defined `Set-Alias` tracking
/// alone would miss these extremely common attack idioms.
const BUILTIN_ALIASES: &[(&str, &str)] = &[
    ("iex", "Invoke-Expression"),
    ("iwr", "Invoke-WebRequest"),
    ("curl", "Invoke-WebRequest"),
    ("wget", "Invoke-WebRequest"),
    ("irm", "Invoke-RestMethod"),
    ("ps", "Get-Process"),
    ("saps", "Start-Process"),
    ("start", "Start-Process"),
];

#[derive(Debug, Default)]
pub struct SymbolTable {
    /// Lowercased alias name -> resolved cmdlet name, from the built-in
    /// table merged with (and overridden by) source-level `Set-Alias`.
    aliases: BTreeMap<String, String>,
    /// Lowercased `$variable` name -> constructed type name, from
    /// `$var = New-Object TypeName`.
    new_object_bindings: BTreeMap<String, String>,
    pub functions: Vec<PowerShellFunctionDef>,
}

impl SymbolTable {
    pub fn new() -> Self {
        let mut aliases = BTreeMap::new();
        for (alias, target) in BUILTIN_ALIASES {
            aliases.insert((*alias).to_owned(), (*target).to_owned());
        }
        Self {
            aliases,
            new_object_bindings: BTreeMap::new(),
            functions: Vec::new(),
        }
    }

    pub fn from_parsed(
        set_aliases: &[(String, String, usize)],
        new_object_bindings: &[(String, String)],
        functions: &[PowerShellFunctionDef],
    ) -> Self {
        let mut table = Self::new();
        for (name, target, _line) in set_aliases {
            table
                .aliases
                .insert(name.to_ascii_lowercase(), target.clone());
        }
        for (var, ty) in new_object_bindings {
            table
                .new_object_bindings
                .insert(var.to_ascii_lowercase(), ty.clone());
        }
        table.functions = functions.to_vec();
        table
    }

    /// Resolve a command name through one level of alias indirection
    /// (built-in or `Set-Alias`-defined), case-insensitively. Returns the
    /// resolved cmdlet name and whether resolution happened.
    pub fn resolve_command_name(&self, raw: &str) -> (String, bool) {
        let lower = raw.to_ascii_lowercase();
        if let Some(target) = self.aliases.get(&lower) {
            return (target.clone(), true);
        }
        (raw.to_owned(), false)
    }

    /// Resolve `$var` to the type name it was last constructed as via
    /// `New-Object`, one level only.
    pub fn resolve_new_object_type(&self, var_name: &str) -> Option<&str> {
        self.new_object_bindings
            .get(&var_name.to_ascii_lowercase())
            .map(String::as_str)
    }
}
