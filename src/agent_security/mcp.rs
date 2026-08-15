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
    let arguments = parse_arguments(object)?;
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
        limitations.push("MCP transport could not be determined from static configuration".into());
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

fn parse_arguments(object: &Map<String, Value>) -> Result<Vec<String>> {
    let Some(raw) = object.get("args") else {
        return Ok(Vec::new());
    };
    let values = raw
        .as_array()
        .ok_or_else(|| anyhow!("MCP server args must be an array"))?;
    if values.len() > MAX_ARGUMENTS_PER_SERVER {
        bail!("MCP server argument list exceeds safety limit");
    }
    values
        .iter()
        .map(|value| {
            let argument = value
                .as_str()
                .ok_or_else(|| anyhow!("MCP server arguments must be strings"))?;
            if argument.len() > MAX_ARGUMENT_BYTES {
                bail!("MCP server argument exceeds safety limit");
            }
            Ok(argument.to_owned())
        })
        .collect()
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

fn parse_tool(name_hint: Option<&String>, value: &Value) -> Result<ToolDefinition> {
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

fn classify_transport(
    raw: Option<&str>,
    command: Option<&str>,
    endpoint: Option<&str>,
) -> McpTransport {
    if command.is_some() {
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
}
