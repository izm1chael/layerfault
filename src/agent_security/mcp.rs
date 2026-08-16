use super::{McpServer, McpTransport, SecurityState, ToolDefinition};
use anyhow::{anyhow, bail, Context, Result};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

const MAX_CONFIG_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SERVERS: usize = 1024;
const MAX_TOOLS_PER_SERVER: usize = 4096;
const MAX_ARGUMENTS_PER_SERVER: usize = 4096;
const MAX_ARGUMENT_BYTES: usize = 64 * 1024;

pub fn inspect_config(path: &Path) -> Result<Vec<McpServer>> {
    let file = crate::safeio::open_readonly_nofollow(path)?;
    let bytes = crate::safeio::read_all_from_file(&file, MAX_CONFIG_BYTES)?;
    let value = parse_data(path, &bytes)?;
    let servers = locate_servers(&value)
        .ok_or_else(|| anyhow!("configuration contains no MCP server map"))?;
    if servers.len() > MAX_SERVERS {
        bail!("MCP configuration exceeds the {MAX_SERVERS}-server safety limit");
    }
    let mut out = Vec::with_capacity(servers.len());
    for (name, raw) in servers {
        out.push(parse_server(name, raw)?);
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

fn parse_data(path: &Path, bytes: &[u8]) -> Result<Value> {
    let ext = path
        .extension()
        .and_then(|v| v.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if ext == "toml" {
        let text =
            std::str::from_utf8(bytes).context("MCP TOML configuration is not valid UTF-8")?;
        let value: toml::Value = toml::from_str(text).context("invalid MCP TOML configuration")?;
        return serde_json::to_value(value).map_err(Into::into);
    }
    serde_json::from_slice(bytes).context("invalid MCP JSON configuration")
}

fn locate_servers(value: &Value) -> Option<&Map<String, Value>> {
    let root = value.as_object()?;
    for key in ["mcpServers", "mcp_servers", "servers"] {
        if let Some(map) = root.get(key).and_then(Value::as_object) {
            return Some(map);
        }
    }
    if let Some(mcp) = root.get("mcp").and_then(Value::as_object) {
        for key in ["servers", "mcpServers"] {
            if let Some(map) = mcp.get(key).and_then(Value::as_object) {
                return Some(map);
            }
        }
    }
    None
}

fn parse_server(name: &str, value: &Value) -> Result<McpServer> {
    if name.trim().is_empty() || name.len() > 16 * 1024 {
        bail!("MCP server name is empty or too long");
    }
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("MCP server '{name}' must be an object"))?;
    let executable = string_field(object, &["command", "executable"]);
    let endpoint = string_field(object, &["url", "endpoint", "serverUrl", "server_url"]);
    let transport_raw = string_field(object, &["transport", "type"]);
    let transport = classify_transport(
        transport_raw.as_deref(),
        executable.as_deref(),
        endpoint.as_deref(),
    );
    let (arguments, argument_limitation) = parse_arguments(object);
    let argument_count = arguments.len() as u64;
    let argument_sha256 = arguments
        .iter()
        .map(|argument| {
            format!(
                "sha256:{}",
                hex::encode(Sha256::digest(argument.as_bytes()))
            )
        })
        .collect();
    let mut credential_names = Vec::new();
    for key in ["env", "headers"] {
        if let Some(map) = object.get(key).and_then(Value::as_object) {
            credential_names.extend(map.keys().filter(|name| credential_like(name)).cloned());
        }
    }
    credential_names.sort();
    credential_names.dedup();
    let authentication = auth_state(object, transport, &credential_names);
    let tls = tls_state(transport, endpoint.as_deref());
    let tools = parse_tools(object)?;
    let mut limitations = Vec::new();
    if tools.is_empty() {
        limitations.push("tool schemas are not present in the static configuration; capability discovery is incomplete until a schema snapshot is supplied".into());
    }
    if transport == McpTransport::Unknown {
        if transport_is_ambiguous(
            transport_raw.as_deref(),
            executable.as_deref(),
            endpoint.as_deref(),
        ) {
            limitations.push("MCP server configuration declares conflicting transport signals (a launch command together with a remote transport/endpoint declaration); transport is treated as ambiguous rather than silently resolved".into());
        } else {
            limitations
                .push("MCP transport could not be determined from static configuration".into());
        }
    }
    if let Some(reason) = argument_limitation {
        limitations.push(reason);
    }
    let completeness = if limitations.is_empty() {
        crate::assurance::AnalysisCompleteness::Complete
    } else {
        crate::assurance::AnalysisCompleteness::Partial
    };
    let mut server = McpServer {
        name: name.to_owned(),
        identity: String::new(),
        transport,
        endpoint,
        executable,
        argument_count,
        argument_sha256,
        authentication,
        tls,
        credential_names,
        tools,
        completeness,
        limitations,
    };
    server.identity = super::identity::server_identity(&server)?;
    Ok(server)
}

/// Parse the `args` array for one server. Unlike most parsing in this
/// module, a malformed `args` value degrades only this server's analysis to
/// `AnalysisCompleteness::Partial` rather than aborting the whole
/// `inspect_config` call: one adversarial or malformed server must not
/// prevent every other server in the same configuration from being
/// analysed. The returned `Option<String>` is a limitation to record when
/// argument analysis stopped early.
fn parse_arguments(object: &Map<String, Value>) -> (Vec<String>, Option<String>) {
    let Some(raw) = object.get("args") else {
        return (Vec::new(), None);
    };
    let Some(values) = raw.as_array() else {
        return (
            Vec::new(),
            Some("MCP server 'args' is present but is not an array; argument analysis for this server is incomplete".to_owned()),
        );
    };
    if values.len() > MAX_ARGUMENTS_PER_SERVER {
        return (
            Vec::new(),
            Some(format!("MCP server argument list exceeds the {MAX_ARGUMENTS_PER_SERVER}-argument safety limit; argument analysis for this server is incomplete")),
        );
    }
    let mut out = Vec::with_capacity(values.len());
    for value in values {
        match value.as_str() {
            Some(argument) if argument.len() <= MAX_ARGUMENT_BYTES => out.push(argument.to_owned()),
            Some(_) => {
                return (
                    out,
                    Some("an MCP server argument exceeds the safety byte limit; argument analysis for this server is incomplete".to_owned()),
                );
            }
            None => {
                return (
                    out,
                    Some("an MCP server argument is not a string; argument analysis for this server is incomplete".to_owned()),
                );
            }
        }
    }
    (out, None)
}

fn parse_tools(object: &Map<String, Value>) -> Result<Vec<ToolDefinition>> {
    let Some(raw) = object.get("tools") else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    match raw {
        Value::Array(values) => {
            if values.len() > MAX_TOOLS_PER_SERVER {
                bail!("MCP tool list exceeds safety limit");
            }
            for value in values {
                out.push(parse_tool(None, value)?);
            }
        }
        Value::Object(values) => {
            if values.len() > MAX_TOOLS_PER_SERVER {
                bail!("MCP tool map exceeds safety limit");
            }
            for (name, value) in values {
                out.push(parse_tool(Some(name), value)?);
            }
        }
        _ => bail!("MCP tools must be an array or object"),
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// `pub(super)` so `crate::agent_security::discovery` can parse `tools/list`
/// entries with the same logic used for statically configured tools,
/// instead of a second parallel implementation.
pub(super) fn parse_tool(name_hint: Option<&String>, value: &Value) -> Result<ToolDefinition> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("MCP tool definition must be an object"))?;
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| name_hint.cloned())
        .ok_or_else(|| anyhow!("MCP tool definition has no name"))?;
    if name.is_empty() || name.len() > 16 * 1024 {
        bail!("MCP tool name is empty or too long");
    }
    let input_schema = object
        .get("inputSchema")
        .or_else(|| object.get("input_schema"))
        .or_else(|| object.get("schema"))
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let annotations = object.get("annotations").cloned().unwrap_or(Value::Null);
    let confirmation_required = object
        .get("confirmation_required")
        .or_else(|| object.get("requiresConfirmation"))
        .and_then(Value::as_bool)
        .or_else(|| {
            annotations
                .get("requiresConfirmation")
                .and_then(Value::as_bool)
        });
    Ok(ToolDefinition {
        name,
        description: object
            .get("description")
            .and_then(Value::as_str)
            .map(str::to_owned),
        input_schema,
        annotations,
        confirmation_required,
    })
}

/// Whether a server declares a launch command together with a remote
/// transport signal (a `type`/`transport` value naming HTTP/SSE, or a
/// remote endpoint) without also explicitly declaring stdio. That is a
/// genuine conflict in the configuration, not something to resolve
/// silently in either direction.
fn transport_is_ambiguous(
    raw: Option<&str>,
    command: Option<&str>,
    endpoint: Option<&str>,
) -> bool {
    if command.is_none() {
        return false;
    }
    let raw = raw.unwrap_or("").to_ascii_lowercase();
    let declares_stdio = raw.contains("stdio");
    let declares_remote = raw.contains("http") || raw.contains("sse") || endpoint.is_some();
    declares_remote && !declares_stdio
}

fn classify_transport(
    raw: Option<&str>,
    command: Option<&str>,
    endpoint: Option<&str>,
) -> McpTransport {
    if command.is_some() {
        if transport_is_ambiguous(raw, command, endpoint) {
            // A launch command combined with a conflicting remote-transport
            // declaration (e.g. `{"command": ..., "type": "http"}`) must not
            // silently resolve to Stdio: that would exempt the server from
            // every auth/TLS check a remote transport would otherwise get.
            return McpTransport::Unknown;
        }
        return McpTransport::Stdio;
    }
    let raw = raw.unwrap_or("").to_ascii_lowercase();
    if raw.contains("stdio") {
        McpTransport::Stdio
    } else if raw.contains("sse") {
        McpTransport::LegacyHttpSse
    } else if raw.contains("http") || endpoint.is_some() {
        McpTransport::StreamableHttp
    } else {
        McpTransport::Unknown
    }
}

fn auth_state(
    object: &Map<String, Value>,
    transport: McpTransport,
    credential_names: &[String],
) -> SecurityState {
    if transport == McpTransport::Stdio {
        return SecurityState::NotApplicable;
    }
    if object.contains_key("authorization")
        || object.contains_key("oauth")
        || object.contains_key("auth")
        || !credential_names.is_empty()
    {
        SecurityState::Present
    } else if matches!(
        transport,
        McpTransport::StreamableHttp | McpTransport::LegacyHttpSse
    ) {
        SecurityState::Absent
    } else {
        SecurityState::Unknown
    }
}

fn tls_state(transport: McpTransport, endpoint: Option<&str>) -> SecurityState {
    if transport == McpTransport::Stdio {
        return SecurityState::NotApplicable;
    }
    match endpoint {
        Some(value) if value.to_ascii_lowercase().starts_with("https://") => SecurityState::Present,
        Some(value) if value.to_ascii_lowercase().starts_with("http://") => SecurityState::Absent,
        Some(_) => SecurityState::Unknown,
        None => SecurityState::Unknown,
    }
}

fn credential_like(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "token",
        "key",
        "secret",
        "password",
        "authorization",
        "credential",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn string_field(map: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| map.get(*key).and_then(Value::as_str).map(str::to_owned))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_without_auth_is_observed_absent() {
        let value = serde_json::json!({"url":"https://example.invalid/mcp","transport":"http"});
        let server = parse_server("remote", &value).unwrap();
        assert_eq!(server.transport, McpTransport::StreamableHttp);
        assert_eq!(server.authentication, SecurityState::Absent);
        assert_eq!(server.tls, SecurityState::Present);
    }

    #[test]
    fn stdio_authorization_is_not_a_remote_transport_property() {
        let value = serde_json::json!({"command":"server"});
        let server = parse_server("local", &value).unwrap();
        assert_eq!(server.authentication, SecurityState::NotApplicable);
    }

    #[test]
    fn credential_values_never_enter_identity() {
        let first = serde_json::json!({"command":"server","env":{"API_TOKEN":"secret-one"}});
        let second = serde_json::json!({"command":"server","env":{"API_TOKEN":"secret-two"}});
        assert_eq!(
            parse_server("local", &first).unwrap().identity,
            parse_server("local", &second).unwrap().identity
        );
    }

    #[test]
    fn command_argument_changes_server_identity_without_exposing_value() {
        let first = serde_json::json!({"command":"npx","args":["trusted-server"]});
        let second = serde_json::json!({"command":"npx","args":["malicious-server"]});
        let first = parse_server("local", &first).unwrap();
        let second = parse_server("local", &second).unwrap();
        assert_ne!(first.identity, second.identity);
        let serialized = serde_json::to_string(&first).unwrap();
        assert!(!serialized.contains("trusted-server"));
    }

    #[test]
    fn conflicting_transport_signals_are_treated_as_ambiguous_not_stdio() {
        let value = serde_json::json!({"command":"server","type":"http"});
        let server = parse_server("local", &value).unwrap();
        assert_eq!(server.transport, McpTransport::Unknown);
        // Ambiguous must not silently fall back to the Stdio exemption: an
        // unresolved transport leaves authentication Unknown, not
        // NotApplicable.
        assert_eq!(server.authentication, SecurityState::Unknown);
        assert_eq!(
            server.completeness,
            crate::assurance::AnalysisCompleteness::Partial
        );
        assert!(server
            .limitations
            .iter()
            .any(|limitation| limitation.contains("conflicting transport")));
    }

    #[test]
    fn command_with_endpoint_is_also_ambiguous() {
        let value = serde_json::json!({"command":"server","url":"https://example.invalid/mcp"});
        let server = parse_server("local", &value).unwrap();
        assert_eq!(server.transport, McpTransport::Unknown);
    }

    #[test]
    fn explicit_stdio_declaration_alongside_command_is_not_ambiguous() {
        let value = serde_json::json!({"command":"server","type":"stdio"});
        let server = parse_server("local", &value).unwrap();
        assert_eq!(server.transport, McpTransport::Stdio);
        assert_eq!(server.authentication, SecurityState::NotApplicable);
    }

    #[test]
    fn malformed_args_degrade_this_server_instead_of_aborting_the_scan() {
        use std::io::Write;
        let mut file = tempfile::Builder::new().suffix(".json").tempfile().unwrap();
        file.write_all(
            serde_json::json!({
                "mcpServers": {
                    "broken": {"command": "server", "args": [123]},
                    "fine": {"command": "server", "args": ["ok"]},
                }
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap();

        let servers = inspect_config(file.path()).expect("scan must not abort");
        assert_eq!(servers.len(), 2);
        let broken = servers
            .iter()
            .find(|server| server.name == "broken")
            .unwrap();
        assert_eq!(broken.argument_count, 0);
        assert_eq!(
            broken.completeness,
            crate::assurance::AnalysisCompleteness::Partial
        );
        assert!(broken
            .limitations
            .iter()
            .any(|limitation| limitation.contains("argument")));
        let fine = servers.iter().find(|server| server.name == "fine").unwrap();
        assert_eq!(fine.argument_count, 1);
    }
}
