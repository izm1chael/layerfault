use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ImportBinding {
    pub local_name: String,
    pub target_module: String,
    pub target_member: Option<String>,
    pub shadowed: bool,
    pub line: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DefinitionKind {
    Function,
    AsyncFunction,
    Class,
    Method,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Definition {
    pub name: String,
    pub qualname: String,
    pub kind: DefinitionKind,
    pub parent_class: Option<String>,
    pub line: Option<usize>,
}

#[derive(Debug, Default)]
pub struct SymbolTable {
    pub imports: BTreeMap<String, ImportBinding>,
    pub definitions: Vec<Definition>,
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

    pub fn resolve_symbol<'a>(
        &'a self,
        local_name: &'a str,
    ) -> Option<(&'a ImportBinding, Option<&'a str>)> {
        // If symbol matches local_name, or begins with local_name + "."
        if let Some((base, attr)) = local_name.split_once('.') {
            if let Some(binding) = self.imports.get(base) {
                if !binding.shadowed {
                    return Some((binding, Some(attr)));
                }
            }
        } else if let Some(binding) = self.imports.get(local_name) {
            if !binding.shadowed {
                return Some((binding, None));
            }
        }
        None
    }

    pub fn resolve_full_target(&self, expression: &str) -> Option<String> {
        if let Some((binding, attr)) = self.resolve_symbol(expression) {
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
        } else {
            None
        }
    }
}
