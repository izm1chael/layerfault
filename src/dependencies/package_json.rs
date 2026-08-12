//! Semantic analysis of `package.json` npm install-hook scripts
//! (`scripts.preinstall`/`scripts.install`/`scripts.postinstall`).
//!
//! `package.json` is parsed as a data-only `serde_json::Value` tree — the
//! same discipline this codebase's TOML/YAML manifest parsers already
//! follow for untrusted manifests (see the `toml`/`yaml-rust2` comments in
//! `Cargo.toml`): no arbitrary type construction, just plain JSON values.
//! `package.json` is never executed by this module.
//!
//! This is npm's install-time-hook analog of
//! [`super::setup_py`]'s setuptools/distutils `Command` subclass detection,
//! but structurally different: a `setup.py` install hook's *own* body lives
//! in the same file the hook finding is attached to, so
//! `crate::correlate::install_hook_capability_chains` can correlate by
//! "same subject". An npm install-hook script is a *reference* to another
//! file (or a shell command string that may itself name one) — closer in
//! shape to `auto_map` pointing at a different Python module — so its
//! correlation lives in a dedicated `crate::correlate` function
//! (`npm_install_hook_chains`) rather than reusing
//! `install_hook_capability_chains`'s same-subject matching.
//!
//! The analysis asks whether `package.json` declares an install-hook script
//! and whether a script file
//! reference be extracted from its command string? Full shell-command
//! parsing of the hook value (`npm run build && node scripts/postinstall.js`)
//! is out of scope; a simple whitespace-split scan for a
//! recognized-script-extension token is enough to catch the common
//! `"postinstall": "node install.js"` / `"postinstall": "./setup.sh"` shapes.

use crate::finding_evidence::{EvidenceSubject, FindingBuilder};
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};

const DEPENDENCY_MEDIA_TYPE: &str = "application/vnd.layerfault.dependency-manifest";

const HOOK_SCRIPT_KEYS: &[&str] = &["preinstall", "install", "postinstall"];
const SCRIPT_EXTENSIONS: &[&str] = &[".js", ".mjs", ".cjs", ".ts", ".sh", ".bash"];

pub fn analyze_package_json(
    relative_path: &str,
    source: &str,
    digest: &str,
) -> Vec<LayerScanResult> {
    let mut out = Vec::new();
    let Ok(value) = serde_json::from_str::<serde_json::Value>(source) else {
        return out;
    };
    let Some(scripts) = value.get("scripts").and_then(serde_json::Value::as_object) else {
        return out;
    };

    let subject = EvidenceSubject::member(relative_path)
        .with_sha256(Some(digest.to_owned()))
        .with_media_type(DEPENDENCY_MEDIA_TYPE);

    for hook_key in HOOK_SCRIPT_KEYS {
        let Some(command) = scripts.get(*hook_key).and_then(serde_json::Value::as_str) else {
            continue;
        };
        if command.trim().is_empty() {
            continue;
        }
        let referenced_script = extract_script_reference(command);

        let mut detail = format!(
            "'{relative_path}' declares an npm '{hook_key}' install-hook script: '{command}'; \
             this runs during `npm install` before a reviewer would normally inspect runtime \
             application code."
        );
        if let Some(ref script) = referenced_script {
            detail.push_str(&format!(" References script '{script}'."));
        }

        let mut structured = serde_json::json!({
            "hook": hook_key,
            "command": command,
        });
        if let Some(ref script) = referenced_script {
            structured["referenced_script"] = serde_json::Value::String(script.clone());
        }

        out.push(
            FindingBuilder::new(
                "LF-DEP-NPM-INSTALL-HOOK",
                CheckType::PackageSecurity,
                ScanStatus::Warn,
            )
            .class(FindingClass::ContentIndicator)
            .confidence(Confidence::Medium)
            .digest(digest)
            .media_type(DEPENDENCY_MEDIA_TYPE)
            .subject(subject.clone())
            .detail(detail)
            .evidence(
                crate::finding_evidence::config_value(
                    subject.clone(),
                    &format!("scripts.{hook_key}"),
                    serde_json::Value::String(command.to_owned()),
                    "npm install-hook script",
                )
                .structured(structured),
            )
            .finish(),
        );
    }

    out
}

/// Best-effort extraction of a referenced script file from an install-hook
/// command string: the first whitespace-separated token that ends in a
/// recognized script extension, with surrounding quotes/`./` stripped.
fn extract_script_reference(command: &str) -> Option<String> {
    for token in command.split_whitespace() {
        let trimmed = token.trim_matches(|c| c == '\'' || c == '"' || c == ';' || c == '&');
        let lower = trimmed.to_ascii_lowercase();
        if SCRIPT_EXTENSIONS.iter().any(|ext| lower.ends_with(ext)) {
            let cleaned = trimmed.strip_prefix("./").unwrap_or(trimmed);
            return Some(cleaned.to_owned());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn postinstall_hook_with_js_reference_is_flagged() {
        let source = r#"{"name": "pkg", "scripts": {"postinstall": "node install.js"}}"#;
        let findings = analyze_package_json("package.json", source, "sha256:test");
        assert_eq!(findings.len(), 1);
        assert_eq!(
            crate::policy::rule_id(&findings[0]),
            "LF-DEP-NPM-INSTALL-HOOK"
        );
        assert!(
            findings[0]
                .evidence
                .first()
                .and_then(|e| e.structured.as_ref())
                .and_then(|s| s.get("referenced_script"))
                .and_then(|v| v.as_str())
                == Some("install.js")
        );
    }

    #[test]
    fn preinstall_and_postinstall_both_flagged() {
        let source = r#"{"scripts": {"preinstall": "echo hi", "postinstall": "sh setup.sh"}}"#;
        let findings = analyze_package_json("package.json", source, "sha256:test");
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn package_json_without_scripts_has_no_hook_finding() {
        let source = r#"{"name": "pkg", "version": "1.0.0"}"#;
        let findings = analyze_package_json("package.json", source, "sha256:test");
        assert!(findings.is_empty());
    }

    #[test]
    fn package_json_without_install_hooks_has_no_hook_finding() {
        let source = r#"{"scripts": {"test": "jest", "build": "tsc"}}"#;
        let findings = analyze_package_json("package.json", source, "sha256:test");
        assert!(findings.is_empty());
    }
}
