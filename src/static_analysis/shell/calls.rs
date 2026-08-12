//! Capability-classifying call-site extraction for shell simple commands.
//!
//! Mirrors the shape of
//! [`crate::static_analysis::python::calls::classify_target_capability`], but
//! consumes the shared [`crate::static_analysis::common::capability::ScriptCapability`]
//! directly (shell has no Python-style baggage, so no
//! separate `ShellCapabilityCategory` enum is needed).
//!
//! Confidence is deliberately capped lower than Python/JS's equivalent
//! categories almost everywhere (see `shell_static::parser`'s module doc
//! for why: the tokenizer is bounded, not a full POSIX grammar). The one
//! exception is the curl/wget-piped-to-a-shell composite
//! (`LF-SHELL-SEMANTIC-CURL-PIPE-SH`), which is high confidence because it
//! is a well-known, low-ambiguity supply-chain signature independent of
//! grammar fidelity.

use super::parser::{ParsedShell, RedirectKind, ShellSimpleCommand};
use super::symbols::SymbolTable;
use crate::static_analysis::common::capability::{
    ScriptCallSite, ScriptCapability, ScriptConfidence,
};

/// A classified call site plus shell-specific flags `findings.rs` needs to
/// pick the right rule id (the composite curl|sh pattern gets its own rule,
/// distinct from a plain Network call site).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ShellCallSite {
    pub site: ScriptCallSite,
    pub is_curl_pipe_sh: bool,
    pub backgrounded: bool,
}

const NO_PROCESS_BUILTINS: &[&str] = &[
    "cd", "exit", "return", "export", "unset", "local", "declare", "readonly", "shift", "set",
    "test", "echo", "printf", "read", "pwd", "true", "false", "break", "continue", "wait", "trap",
    "umask", "type", "unalias", "let", ":", "[", "[[",
];

const HIGH_SIGNAL_PROCESS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "ssh", "sudo", "su", "xargs", "nohup", "disown", "perl",
    "python", "python3", "ruby", "node", "php", "nc", "ncat",
];

const PACKAGE_MANAGERS: &[&str] = &[
    "pip", "pip3", "npm", "yarn", "pnpm", "conda", "poetry", "apt-get", "apt", "yum", "dnf",
    "brew", "gem", "cargo",
];

pub fn extract_call_sites(
    parsed: &ParsedShell,
    limits: &super::limits::ShellAnalysisLimits,
) -> Vec<ShellCallSite> {
    let symbols = SymbolTable::from_parsed(&parsed.assignments, &parsed.aliases, &parsed.functions);
    let mut out = Vec::new();

    for cmd in &parsed.commands {
        if out.len() >= limits.max_call_sites {
            break;
        }
        let Some(first) = cmd.words.first() else {
            continue;
        };
        let (resolved_name, indirected) = resolve_command_name(&first.text, &symbols);
        if resolved_name.is_empty() {
            continue;
        }
        let args: Vec<String> = cmd.words.iter().skip(1).map(|w| w.text.clone()).collect();

        if cmd.env_prefix.iter().any(|(name, _)| name == "LD_PRELOAD") {
            let preload = cmd
                .env_prefix
                .iter()
                .find(|(name, _)| name == "LD_PRELOAD")
                .map(|(_, value)| value.clone())
                .unwrap_or_default();
            out.push(ShellCallSite {
                site: ScriptCallSite {
                    capability: ScriptCapability::NativeLoad,
                    scope: cmd.scope,
                    raw_target: first.text.clone(),
                    resolved_target: Some(resolved_name.clone()),
                    line: Some(cmd.line),
                    column: None,
                    literal_arg_evidence: Some(sanitize_and_truncate(
                        &format!("LD_PRELOAD={preload} {resolved_name}"),
                        limits.max_string_literal_bytes,
                    )),
                    confidence: ScriptConfidence::Low,
                },
                is_curl_pipe_sh: false,
                backgrounded: cmd.backgrounded,
            });
        }

        for (kind, target) in &cmd.redirects {
            if matches!(kind, RedirectKind::Out | RedirectKind::Append)
                && is_sensitive_write_path(target)
            {
                out.push(ShellCallSite {
                    site: ScriptCallSite {
                        capability: ScriptCapability::FilesystemWrite,
                        scope: cmd.scope,
                        raw_target: resolved_name.clone(),
                        resolved_target: Some(resolved_name.clone()),
                        line: Some(cmd.line),
                        column: None,
                        literal_arg_evidence: Some(sanitize_and_truncate(
                            &format!("{resolved_name} > {target}"),
                            limits.max_string_literal_bytes,
                        )),
                        confidence: ScriptConfidence::Medium,
                    },
                    is_curl_pipe_sh: false,
                    backgrounded: cmd.backgrounded,
                });
            }
        }

        if is_download_tool(&resolved_name) {
            if let Some(next_cmd) = find_next_in_pipeline(&parsed.commands, cmd) {
                if let Some(next_first) = next_cmd.words.first() {
                    let (next_resolved, _) = resolve_command_name(&next_first.text, &symbols);
                    if is_shell_interpreter(&next_resolved) {
                        out.push(ShellCallSite {
                            site: ScriptCallSite {
                                capability: ScriptCapability::Network,
                                scope: cmd.scope,
                                raw_target: first.text.clone(),
                                resolved_target: Some(resolved_name.clone()),
                                line: Some(cmd.line),
                                column: None,
                                literal_arg_evidence: build_evidence(&resolved_name, &args, limits),
                                confidence: ScriptConfidence::High,
                            },
                            is_curl_pipe_sh: true,
                            backgrounded: cmd.backgrounded,
                        });
                    }
                }
            }
        }

        if let Some(capability) = classify_shell_capability(&resolved_name, &args) {
            let confidence = base_confidence(capability, &resolved_name);
            out.push(ShellCallSite {
                site: ScriptCallSite {
                    capability,
                    scope: cmd.scope,
                    raw_target: first.text.clone(),
                    resolved_target: if indirected {
                        Some(resolved_name.clone())
                    } else {
                        None
                    },
                    line: Some(cmd.line),
                    column: None,
                    literal_arg_evidence: build_evidence(&resolved_name, &args, limits),
                    confidence,
                },
                is_curl_pipe_sh: false,
                backgrounded: cmd.backgrounded,
            });
        }
    }

    out
}

/// Resolve a command-name word through one level of `$VAR` or alias
/// indirection. Returns `(effective_name, was_indirected)`.
fn resolve_command_name(raw: &str, symbols: &SymbolTable) -> (String, bool) {
    if raw.starts_with('$') {
        if let Some(value) = symbols.resolve_variable(raw) {
            let effective = value.split_whitespace().next().unwrap_or("").to_owned();
            return (effective, true);
        }
        return (String::new(), false);
    }
    if let Some(value) = symbols.resolve_alias(raw) {
        let effective = value.split_whitespace().next().unwrap_or("").to_owned();
        return (effective, true);
    }
    (raw.to_owned(), false)
}

fn find_next_in_pipeline<'a>(
    commands: &'a [ShellSimpleCommand],
    cmd: &ShellSimpleCommand,
) -> Option<&'a ShellSimpleCommand> {
    commands
        .iter()
        .find(|c| c.pipeline_id == cmd.pipeline_id && c.pipeline_index == cmd.pipeline_index + 1)
}

fn is_download_tool(name: &str) -> bool {
    matches!(name.to_ascii_lowercase().as_str(), "curl" | "wget")
}

fn is_shell_interpreter(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "sh" | "bash" | "zsh" | "dash" | "eval"
    )
}

/// Classify a resolved shell command name and its argument words into a
/// [`ScriptCapability`], mirroring the shape of Python's
/// `classify_target_capability`.
pub fn classify_shell_capability(command_name: &str, args: &[String]) -> Option<ScriptCapability> {
    let lower = command_name.to_ascii_lowercase();
    if lower.is_empty() {
        return None;
    }

    if matches!(lower.as_str(), "eval" | "exec" | "source") || lower == "." {
        return Some(ScriptCapability::DynamicCode);
    }

    if args_reference_credentials(args) {
        return Some(ScriptCapability::CredentialAccess);
    }

    if is_package_install(&lower, args) {
        return Some(ScriptCapability::PackageInstall);
    }

    if matches!(
        lower.as_str(),
        "curl" | "wget" | "nc" | "netcat" | "ssh" | "scp" | "sftp"
    ) {
        return Some(ScriptCapability::Network);
    }

    if lower == "rm" && has_force_recursive(args) {
        return Some(ScriptCapability::FilesystemWrite);
    }
    if lower == "chmod" && args.iter().any(|a| is_executable_chmod_flag(a)) {
        return Some(ScriptCapability::FilesystemWrite);
    }
    if matches!(lower.as_str(), "mv" | "dd" | "shred" | "mkfs" | "truncate") {
        return Some(ScriptCapability::FilesystemWrite);
    }

    if NO_PROCESS_BUILTINS.contains(&lower.as_str()) {
        return None;
    }
    Some(ScriptCapability::Process)
}

fn base_confidence(capability: ScriptCapability, name: &str) -> ScriptConfidence {
    match capability {
        ScriptCapability::Process => {
            if HIGH_SIGNAL_PROCESS.contains(&name.to_ascii_lowercase().as_str()) {
                ScriptConfidence::Medium
            } else {
                ScriptConfidence::Low
            }
        }
        ScriptCapability::DynamicCode
        | ScriptCapability::Network
        | ScriptCapability::CredentialAccess
        | ScriptCapability::PackageInstall
        | ScriptCapability::FilesystemWrite => ScriptConfidence::Medium,
        ScriptCapability::NativeLoad => ScriptConfidence::Low,
    }
}

fn is_package_install(cmd: &str, args: &[String]) -> bool {
    if !PACKAGE_MANAGERS.contains(&cmd) {
        return false;
    }
    args.iter()
        .any(|a| a == "install" || a == "add" || a == "i")
}

fn has_force_recursive(args: &[String]) -> bool {
    let mut has_r = false;
    let mut has_f = false;
    for arg in args {
        let lower = arg.to_ascii_lowercase();
        if lower == "--recursive" {
            has_r = true;
        }
        if lower == "--force" {
            has_f = true;
        }
        if lower.starts_with('-') && !lower.starts_with("--") {
            if lower.contains('r') {
                has_r = true;
            }
            if lower.contains('f') {
                has_f = true;
            }
        }
    }
    has_r && has_f
}

fn is_executable_chmod_flag(arg: &str) -> bool {
    let lower = arg.to_ascii_lowercase();
    lower.ends_with("+x") || matches!(lower.as_str(), "755" | "0755" | "777" | "0777")
}

fn args_reference_credentials(args: &[String]) -> bool {
    for arg in args {
        let lower = arg.to_ascii_lowercase();
        if lower.contains(".aws/credentials")
            || lower.contains(".ssh/id_rsa")
            || lower.contains(".ssh/id_ed25519")
            || lower.contains(".ssh/id_ecdsa")
            || lower.contains(".ssh/id_dsa")
            || lower.ends_with(".netrc")
            || lower.contains("/etc/shadow")
        {
            return true;
        }
        if arg.contains('$') {
            let upper = arg.to_ascii_uppercase();
            if upper.contains("SECRET")
                || upper.contains("_TOKEN")
                || upper.contains("PASSWORD")
                || upper.contains("API_KEY")
                || upper.contains("CREDENTIAL")
            {
                return true;
            }
        }
    }
    false
}

fn is_sensitive_write_path(target: &str) -> bool {
    let lower = target.to_ascii_lowercase();
    lower.starts_with("/etc/")
        || lower.contains(".ssh/")
        || lower.contains(".aws/")
        || lower.contains(".bashrc")
        || lower.contains(".bash_profile")
        || lower.contains(".profile")
        || lower.contains("/usr/local/bin/")
}

fn build_evidence(
    resolved_name: &str,
    args: &[String],
    limits: &super::limits::ShellAnalysisLimits,
) -> Option<String> {
    if resolved_name.is_empty() {
        return None;
    }
    let mut parts = vec![resolved_name.to_owned()];
    parts.extend(args.iter().cloned());
    let joined = parts.join(" ");
    Some(sanitize_and_truncate(
        &joined,
        limits.max_string_literal_bytes,
    ))
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
