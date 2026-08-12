//! Shared normalized capability model for the non-Python script frontends
//! (shell, PowerShell, JavaScript/TypeScript).
//!
//! This module is intentionally pure data: it exists so the shell,
//! PowerShell and JavaScript frontends agree on
//! capability category boundaries and can share a common `findings.rs`
//! conversion helper, mirroring the shape of Python's
//! [`crate::static_analysis::python::calls::PythonCapabilityCategory`] and
//! [`crate::static_analysis::python::calls::CallSite`] without reusing those types
//! directly — Python's enum is deeply embedded in its taint engine and
//! carries Python-specific context variants with no cross-language analog.
//!
//! The shared model keeps capability semantics consistent across frontends.

/// A normalized security-relevant capability a script call site may exercise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ScriptCapability {
    /// Spawning or controlling an external process.
    Process,
    /// Outbound or inbound network access.
    Network,
    /// Dynamic evaluation/construction of code at run time.
    DynamicCode,
    /// Writing to or mutating the filesystem.
    FilesystemWrite,
    /// Reading credentials or credential-shaped environment state.
    CredentialAccess,
    /// Invoking a package manager to install additional code.
    PackageInstall,
    /// Loading a native library/module.
    NativeLoad,
}

/// The lexical scope a call site was observed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ScriptScope {
    /// Script/module top-level, executed simply by loading the file.
    Module,
    /// Inside a function/procedure body, executed only if called.
    Function,
}

/// How confident the frontend is in a given call-site classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ScriptConfidence {
    High,
    Medium,
    Low,
}

/// A single classified capability-relevant call site extracted from a
/// script source file.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ScriptCallSite {
    pub capability: ScriptCapability,
    pub scope: ScriptScope,
    pub raw_target: String,
    pub resolved_target: Option<String>,
    pub line: Option<usize>,
    pub column: Option<usize>,
    pub literal_arg_evidence: Option<String>,
    pub confidence: ScriptConfidence,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Constructs one of each type to document the shared representation.
    #[test]
    fn constructs_one_of_each_type() {
        let site = ScriptCallSite {
            capability: ScriptCapability::Process,
            scope: ScriptScope::Module,
            raw_target: "eval".to_owned(),
            resolved_target: Some("eval".to_owned()),
            line: Some(1),
            column: Some(0),
            literal_arg_evidence: Some("rm -rf /".to_owned()),
            confidence: ScriptConfidence::High,
        };
        assert_eq!(site.capability, ScriptCapability::Process);
        assert_eq!(site.scope, ScriptScope::Module);
        assert_eq!(site.confidence, ScriptConfidence::High);

        let capabilities = [
            ScriptCapability::Process,
            ScriptCapability::Network,
            ScriptCapability::DynamicCode,
            ScriptCapability::FilesystemWrite,
            ScriptCapability::CredentialAccess,
            ScriptCapability::PackageInstall,
            ScriptCapability::NativeLoad,
        ];
        assert_eq!(capabilities.len(), 7);

        let scopes = [ScriptScope::Module, ScriptScope::Function];
        assert_eq!(scopes.len(), 2);

        let confidences = [
            ScriptConfidence::High,
            ScriptConfidence::Medium,
            ScriptConfidence::Low,
        ];
        assert_eq!(confidences.len(), 3);
    }
}
