//! Capability-classifying call-site extraction for PowerShell statements.
//!
//! Mirrors the shape of
//! [`crate::shell_static::calls::classify_shell_capability`], consuming the
//! shared [`crate::script_capability::ScriptCapability`] directly. Unlike
//! shell (where nearly any bare command name spawns a process), most
//! PowerShell cmdlets are in-process .NET calls with no OS process-execution
//! implication, so this module does not default unrecognized command names
//! to [`ScriptCapability::Process`] the way shell does — only the plan's
//! explicit minimum list of dangerous cmdlets/aliases, plus direct
//! executable invocation (`powershell.exe`, `cmd.exe`, `*.exe`, ...), are
//! classified.
//!
//! Confidence is deliberately capped lower than Python's equivalent
//! categories almost everywhere (the tokenizer is bounded, not a full
//! PowerShell grammar — see `powershell_static::parser`'s module doc). The
//! exception is the `irm|iex` / `iwr|iex` download-and-execute composite
//! (`LF-PS-SEMANTIC-DOWNLOAD-EXECUTE`), which is high confidence because it
//! is a well-known, low-ambiguity supply-chain signature independent of
//! grammar fidelity — PowerShell's analog of shell's curl-pipe-sh.

use super::parser::{ParsedPowerShell, PowerShellStatement};
use super::symbols::SymbolTable;
use crate::script_capability::{ScriptCallSite, ScriptCapability, ScriptConfidence};

/// A classified call site plus PowerShell-specific flags `findings.rs`
/// needs to pick the right rule id and evidence wording.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PowerShellCallSite {
    pub site: ScriptCallSite,
    pub is_download_execute: bool,
    pub has_encoded_command: bool,
}

const PROCESS_LAUNCHER_NAMES: &[&str] = &[
    "powershell",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
    "cmd",
    "cmd.exe",
    "cscript",
    "cscript.exe",
    "wscript",
    "wscript.exe",
    "mshta",
    "mshta.exe",
    "rundll32",
    "rundll32.exe",
    "regsvr32",
    "regsvr32.exe",
];

const DOWNLOAD_COMMANDS: &[&str] = &["invoke-webrequest", "invoke-restmethod"];
const EXECUTE_COMMANDS: &[&str] = &["invoke-expression"];

pub fn extract_call_sites(
    parsed: &ParsedPowerShell,
    limits: &super::limits::PowerShellAnalysisLimits,
) -> Vec<PowerShellCallSite> {
    let new_object_bindings = extract_new_object_bindings(&parsed.statements);
    let symbols =
        SymbolTable::from_parsed(&parsed.set_aliases, &new_object_bindings, &parsed.functions);
    let mut out = Vec::new();

    for stmt in &parsed.statements {
        if out.len() >= limits.max_call_sites {
            break;
        }
        let Some(first) = stmt.words.first() else {
            continue;
        };
        if first.text.is_empty() {
            continue;
        }

        if is_assignment_statement(stmt) {
            continue;
        }

        if let Some((ty, method, _args)) = parse_static_call(&first.text) {
            if ty
                .to_ascii_lowercase()
                .contains("system.diagnostics.process")
                && method.eq_ignore_ascii_case("start")
            {
                out.push(PowerShellCallSite {
                    site: ScriptCallSite {
                        capability: ScriptCapability::Process,
                        scope: stmt.scope,
                        raw_target: first.text.clone(),
                        resolved_target: Some(format!("[{ty}]::{method}")),
                        line: Some(stmt.line),
                        column: None,
                        literal_arg_evidence: Some(sanitize_and_truncate(
                            &first.text,
                            limits.max_string_literal_bytes,
                        )),
                        confidence: ScriptConfidence::Medium,
                    },
                    is_download_execute: false,
                    has_encoded_command: false,
                });
            }
            continue;
        }

        if let Some((var, method, _args)) = parse_member_call(&first.text) {
            if let Some(ty) = symbols.resolve_new_object_type(&var) {
                if ty.to_ascii_lowercase().contains("webclient")
                    && matches!(
                        method.to_ascii_lowercase().as_str(),
                        "downloadstring" | "downloadfile"
                    )
                {
                    out.push(PowerShellCallSite {
                        site: ScriptCallSite {
                            capability: ScriptCapability::Network,
                            scope: stmt.scope,
                            raw_target: first.text.clone(),
                            resolved_target: Some(format!("({ty}).{method}")),
                            line: Some(stmt.line),
                            column: None,
                            literal_arg_evidence: Some(sanitize_and_truncate(
                                &first.text,
                                limits.max_string_literal_bytes,
                            )),
                            confidence: ScriptConfidence::Medium,
                        },
                        is_download_execute: false,
                        has_encoded_command: false,
                    });
                }
            }
            continue;
        }

        if !first.bare {
            // Command position occupied by a quoted string/here-string
            // literal, not an invocable name: structurally not a call.
            continue;
        }

        let (resolved_name, indirected) = symbols.resolve_command_name(&first.text);
        let args: Vec<String> = stmt.words.iter().skip(1).map(|w| w.text.clone()).collect();
        let has_encoded_command = args.iter().any(|a| is_encoded_command_flag(a));

        let resolved_lower = resolved_name.to_ascii_lowercase();

        if DOWNLOAD_COMMANDS.contains(&resolved_lower.as_str()) {
            if let Some(next_stmt) = find_next_in_pipeline(&parsed.statements, stmt) {
                if let Some(next_first) = next_stmt.words.first() {
                    if next_first.bare {
                        let (next_resolved, _) = symbols.resolve_command_name(&next_first.text);
                        if EXECUTE_COMMANDS.contains(&next_resolved.to_ascii_lowercase().as_str()) {
                            out.push(PowerShellCallSite {
                                site: ScriptCallSite {
                                    capability: ScriptCapability::Network,
                                    scope: stmt.scope,
                                    raw_target: first.text.clone(),
                                    resolved_target: Some(resolved_name.clone()),
                                    line: Some(stmt.line),
                                    column: None,
                                    literal_arg_evidence: build_evidence(
                                        &resolved_name,
                                        &args,
                                        limits,
                                    ),
                                    confidence: ScriptConfidence::High,
                                },
                                is_download_execute: true,
                                has_encoded_command,
                            });
                            continue;
                        }
                    }
                }
            }
        }

        if resolved_lower == "add-type" {
            let evidence = build_evidence(&resolved_name, &args, limits);
            out.push(PowerShellCallSite {
                site: ScriptCallSite {
                    capability: ScriptCapability::DynamicCode,
                    scope: stmt.scope,
                    raw_target: first.text.clone(),
                    resolved_target: if indirected {
                        Some(resolved_name.clone())
                    } else {
                        None
                    },
                    line: Some(stmt.line),
                    column: None,
                    literal_arg_evidence: evidence.clone(),
                    confidence: ScriptConfidence::Medium,
                },
                is_download_execute: false,
                has_encoded_command,
            });
            out.push(PowerShellCallSite {
                site: ScriptCallSite {
                    capability: ScriptCapability::NativeLoad,
                    scope: stmt.scope,
                    raw_target: first.text.clone(),
                    resolved_target: if indirected {
                        Some(resolved_name.clone())
                    } else {
                        None
                    },
                    line: Some(stmt.line),
                    column: None,
                    literal_arg_evidence: evidence,
                    confidence: ScriptConfidence::Low,
                },
                is_download_execute: false,
                has_encoded_command,
            });
            continue;
        }

        if let Some(capability) = classify_powershell_capability(&resolved_name, &args) {
            let mut confidence = base_confidence(capability, &resolved_lower);
            if has_encoded_command {
                confidence = ScriptConfidence::High;
            }
            out.push(PowerShellCallSite {
                site: ScriptCallSite {
                    capability,
                    scope: stmt.scope,
                    raw_target: first.text.clone(),
                    resolved_target: if indirected {
                        Some(resolved_name.clone())
                    } else {
                        None
                    },
                    line: Some(stmt.line),
                    column: None,
                    literal_arg_evidence: build_evidence(&resolved_name, &args, limits),
                    confidence,
                },
                is_download_execute: false,
                has_encoded_command,
            });
        }
    }

    out
}

/// Pre-pass over statements collecting `$var = New-Object TypeName`
/// bindings, in source order (later assignments override earlier ones for
/// the same variable, matching ordinary PowerShell variable semantics —
/// see [`SymbolTable::from_parsed`]).
fn extract_new_object_bindings(statements: &[PowerShellStatement]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for stmt in statements {
        let Some((var, rhs)) = assignment_parts(stmt) else {
            continue;
        };
        let Some(first_rhs) = rhs.first() else {
            continue;
        };
        if !first_rhs.eq_ignore_ascii_case("new-object") {
            continue;
        }
        if let Some(ty) = rhs.iter().skip(1).find(|w| !w.starts_with('-')) {
            out.push((var, ty.clone()));
        }
    }
    out
}

fn is_assignment_statement(stmt: &PowerShellStatement) -> bool {
    assignment_parts(stmt).is_some()
}

/// Recognize `$name = rhs...` (two-or-more-word form, with `=` as its own
/// word) or `$name=rhs` (single-word form with `=` embedded, no
/// surrounding whitespace). Returns `(var_name_without_$, rhs_words)`.
fn assignment_parts(stmt: &PowerShellStatement) -> Option<(String, Vec<String>)> {
    let first = stmt.words.first()?;
    if !first.bare || !first.text.starts_with('$') {
        return None;
    }
    if let Some(second) = stmt.words.get(1) {
        if second.bare && second.text == "=" {
            let var = first.text.trim_start_matches('$').to_owned();
            let rhs: Vec<String> = stmt.words.iter().skip(2).map(|w| w.text.clone()).collect();
            return Some((var, rhs));
        }
    }
    if let Some((left, right)) = first.text.split_once('=') {
        let var = left.trim_start_matches('$').to_owned();
        if var.is_empty() || !is_identifier(&var) {
            return None;
        }
        let mut rhs = Vec::new();
        if !right.is_empty() {
            rhs.push(right.to_owned());
        }
        rhs.extend(stmt.words.iter().skip(1).map(|w| w.text.clone()));
        return Some((var, rhs));
    }
    None
}

fn is_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn find_next_in_pipeline<'a>(
    statements: &'a [PowerShellStatement],
    stmt: &PowerShellStatement,
) -> Option<&'a PowerShellStatement> {
    statements
        .iter()
        .find(|s| s.pipeline_id == stmt.pipeline_id && s.pipeline_index == stmt.pipeline_index + 1)
}

fn is_encoded_command_flag(arg: &str) -> bool {
    matches!(
        arg.to_ascii_lowercase().as_str(),
        "-encodedcommand" | "-enc"
    )
}

/// Parse a `[TypeName]::MethodName(args)` static-method-call word.
fn parse_static_call(word: &str) -> Option<(String, String, String)> {
    let rest = word.strip_prefix('[')?;
    let close = rest.find(']')?;
    let ty = &rest[..close];
    let after = &rest[close + 1..];
    let after = after.strip_prefix("::")?;
    let paren = after.find('(')?;
    let method = &after[..paren];
    if method.is_empty()
        || !method
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    let args = after[paren + 1..].strip_suffix(')').unwrap_or("");
    Some((ty.to_owned(), method.to_owned(), args.to_owned()))
}

/// Parse a `$var.MethodName(args)` member-invocation word.
fn parse_member_call(word: &str) -> Option<(String, String, String)> {
    let rest = word.strip_prefix('$')?;
    let dot = rest.find('.')?;
    let var = &rest[..dot];
    if var.is_empty() || !is_identifier(var) {
        return None;
    }
    let after = &rest[dot + 1..];
    let paren = after.find('(')?;
    let method = &after[..paren];
    if method.is_empty()
        || !method
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return None;
    }
    let args = after[paren + 1..].strip_suffix(')').unwrap_or("");
    Some((var.to_owned(), method.to_owned(), args.to_owned()))
}

/// Classify a resolved PowerShell command name and its argument words into
/// a [`ScriptCapability`]. Does not special-case `Add-Type`'s dual
/// DynamicCode+NativeLoad classification or the `irm|iex` composite — both
/// are handled directly in [`extract_call_sites`], mirroring how shell
/// handles its curl-pipe-sh composite outside `classify_shell_capability`.
pub fn classify_powershell_capability(
    command_name: &str,
    args: &[String],
) -> Option<ScriptCapability> {
    let lower = command_name.to_ascii_lowercase();
    if lower.is_empty() {
        return None;
    }

    if lower == "invoke-expression" {
        return Some(ScriptCapability::DynamicCode);
    }
    if lower == "set-executionpolicy"
        && args
            .iter()
            .any(|a| matches!(a.to_ascii_lowercase().as_str(), "bypass" | "unrestricted"))
    {
        return Some(ScriptCapability::DynamicCode);
    }

    if lower == "get-credential" || lower == "convertto-securestring" {
        return Some(ScriptCapability::CredentialAccess);
    }
    if args_reference_credentials(args) {
        return Some(ScriptCapability::CredentialAccess);
    }

    if is_package_install(&lower, args) {
        return Some(ScriptCapability::PackageInstall);
    }

    if matches!(lower.as_str(), "invoke-webrequest" | "invoke-restmethod") {
        return Some(ScriptCapability::Network);
    }

    if lower == "start-process" {
        return Some(ScriptCapability::Process);
    }

    if PROCESS_LAUNCHER_NAMES.contains(&lower.as_str()) || lower.ends_with(".exe") {
        return Some(ScriptCapability::Process);
    }

    None
}

fn base_confidence(capability: ScriptCapability, name: &str) -> ScriptConfidence {
    match capability {
        ScriptCapability::Process => {
            if PROCESS_LAUNCHER_NAMES.contains(&name) || name.ends_with(".exe") {
                ScriptConfidence::Medium
            } else {
                ScriptConfidence::Low
            }
        }
        ScriptCapability::DynamicCode
        | ScriptCapability::Network
        | ScriptCapability::CredentialAccess
        | ScriptCapability::PackageInstall => ScriptConfidence::Medium,
        ScriptCapability::FilesystemWrite | ScriptCapability::NativeLoad => ScriptConfidence::Low,
    }
}

fn is_package_install(cmd: &str, args: &[String]) -> bool {
    if matches!(cmd, "install-module" | "install-package") {
        return true;
    }
    if cmd == "choco" {
        return args.iter().any(|a| a.eq_ignore_ascii_case("install"));
    }
    false
}

fn args_reference_credentials(args: &[String]) -> bool {
    for arg in args {
        let lower = arg.to_ascii_lowercase();
        if lower.starts_with("$env:") {
            let upper = arg.to_ascii_uppercase();
            if upper.contains("SECRET")
                || upper.contains("TOKEN")
                || upper.contains("PASSWORD")
                || upper.contains("API_KEY")
                || upper.contains("CREDENTIAL")
            {
                return true;
            }
        }
        if (lower.contains("hkcu:") || lower.contains("hklm:"))
            && (lower.contains("password") || lower.contains("credential"))
        {
            return true;
        }
        if lower.contains("-asplaintext") {
            return true;
        }
    }
    false
}

fn build_evidence(
    resolved_name: &str,
    args: &[String],
    limits: &super::limits::PowerShellAnalysisLimits,
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
