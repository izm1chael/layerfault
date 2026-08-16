//! MCP protocol capability snapshots: parsing bounded discovery responses
//! (`initialize`, `tools/list`, `resources/list`, `prompts/list`) into an
//! immutable, canonically hashable record.
//!
//! This module is metadata discovery, not content inspection. `tools/list`,
//! `resources/list` and `prompts/list` yield protocol topology and schemas —
//! never the contents of an arbitrary resource or an instantiated prompt.
//! Reading actual resource/prompt content is a separate, later, explicitly
//! opt-in analysis mode; nothing here should be read as indirect
//! prompt-injection detection, which requires content this module never
//! touches.
//!
//! This top-level module contains **no transport code** itself: it only
//! parses already-obtained JSON-RPC response bodies into typed records,
//! fully testable without spawning a process or opening a socket. The
//! `stdio` submodule is the one place that actually launches a process (a
//! sandboxed MCP server over stdio); the remote HTTP transport is a
//! separate, later addition. Keeping parsing and transport apart means the
//! parsing and digest-canonicalisation logic here does not depend on, or
//! get exercised only through, the higher-risk transport code.

mod remote;
mod stdio;

pub use remote::{discover_remote, RemoteDiscoveryOutcome};
pub use stdio::{discover_stdio, StdioDiscoveryOutcome};

use super::ToolDefinition;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Protocol revisions Layerfault explicitly recognises. An unrecognised
/// `protocolVersion` is not a parse failure — the snapshot is still built —
/// but it does mean `ProtocolInfo::scanner_supported` is `false` and the
/// snapshot's completeness reflects that, rather than silently proceeding
/// as if a known version had been negotiated.
pub const KNOWN_PROTOCOL_VERSIONS: &[&str] = &["2025-03-26", "2025-06-18", "2025-11-25"];

/// `capabilities` keys in an `initialize` response that Layerfault
/// recognises. Any other key is an unknown extension: recorded, not
/// ignored.
const KNOWN_CAPABILITY_KEYS: &[&str] = &[
    "tools",
    "resources",
    "prompts",
    "logging",
    "completions",
    "sampling",
    "roots",
    "elicitation",
];

const MAX_LIST_ENTRIES: usize = 8192;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared_version: Option<String>,
    /// The version this scan actually negotiated. From a single parsed
    /// `initialize` response in isolation, this defaults to the same value
    /// as `declared_version`; a live client that separately tracks what it
    /// requested versus what the server returned should set this
    /// independently.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub negotiated_version: Option<String>,
    pub scanner_supported: bool,
    #[serde(default)]
    pub deprecated_features: Vec<String>,
    #[serde(default)]
    pub unknown_extensions: Vec<String>,
}

/// Completeness of one discoverable primitive category. Not advertising a
/// primitive is not incomplete analysis — it is a server without that
/// primitive — so this is deliberately distinct from "we tried and
/// couldn't tell".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrimitiveState {
    Complete,
    /// The server's advertised `capabilities` did not include this
    /// primitive at all.
    NotAdvertised,
    /// The server advertised this primitive and returned a page with a
    /// pagination cursor Layerfault did not follow (bounded discovery).
    PartialPagination,
    /// The response exceeded Layerfault's local entry budget.
    PartialLimit,
    /// One or more advertised entries were malformed and could not be
    /// represented in the snapshot.
    PartialMalformed,
    /// The primitive was advertised but no response could be parsed.
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrimitiveCompleteness {
    pub tools: PrimitiveState,
    pub resources: PrimitiveState,
    pub prompts: PrimitiveState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceDefinition {
    pub uri: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptArgument {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptDefinition {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub arguments: Vec<PromptArgument>,
}

/// An immutable, point-in-time record of what one MCP server advertised.
/// Tool sets can change dynamically and by authorization, so this is
/// explicitly a snapshot, not a durable fact about the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpCapabilitySnapshot {
    /// Metadata only — deliberately excluded from `content_sha256`. If this
    /// fed the digest, two identical discoveries a minute apart would
    /// produce different digests and drift/capability-expansion detection
    /// built on snapshot diffs would be unusable.
    pub observed_at: u64,
    pub protocol: ProtocolInfo,
    pub server_transport_identity: String,
    /// Set by a later unit once authorization discovery exists. `None`
    /// here does not mean "no authorization" — it means this snapshot
    /// predates that evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_context_identity: Option<String>,
    /// Set by the Supply Chain unit once executable/package identity
    /// resolution exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_identity: Option<String>,
    pub tools: Vec<ToolDefinition>,
    pub resources: Vec<ResourceDefinition>,
    pub prompts: Vec<PromptDefinition>,
    pub completeness: PrimitiveCompleteness,
    /// Canonical digest of everything above except `observed_at`.
    pub content_sha256: String,
}

/// Parse an `initialize` response body into `ProtocolInfo`. Never fails: an
/// unrecognised or missing version is recorded as such, not treated as a
/// parse error, because the objective is to characterise what the server
/// claims, however unusual.
pub fn parse_initialize_response(response: &Value) -> ProtocolInfo {
    let declared_version = response
        .get("protocolVersion")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let scanner_supported = declared_version
        .as_deref()
        .is_some_and(|version| KNOWN_PROTOCOL_VERSIONS.contains(&version));
    let mut unknown_extensions = Vec::new();
    if let Some(capabilities) = response.get("capabilities").and_then(Value::as_object) {
        for key in capabilities.keys() {
            if !KNOWN_CAPABILITY_KEYS.contains(&key.as_str()) {
                unknown_extensions.push(key.clone());
            }
        }
    }
    unknown_extensions.sort();
    ProtocolInfo {
        negotiated_version: declared_version.clone(),
        declared_version,
        scanner_supported,
        deprecated_features: Vec::new(),
        unknown_extensions,
    }
}

fn advertises(initialize_response: &Value, primitive: &str) -> bool {
    initialize_response
        .get("capabilities")
        .and_then(Value::as_object)
        .is_some_and(|capabilities| capabilities.contains_key(primitive))
}

fn has_more_pages(list_response: &Value) -> bool {
    list_response
        .get("nextCursor")
        .and_then(Value::as_str)
        .is_some_and(|cursor| !cursor.is_empty())
}

fn parsed_list_state(
    list_response: &Value,
    advertised_entries: usize,
    parsed_entries: usize,
) -> PrimitiveState {
    if advertised_entries > MAX_LIST_ENTRIES {
        PrimitiveState::PartialLimit
    } else if parsed_entries != advertised_entries {
        PrimitiveState::PartialMalformed
    } else if has_more_pages(list_response) {
        PrimitiveState::PartialPagination
    } else {
        PrimitiveState::Complete
    }
}

/// Parse a `tools/list` response. `list_response` is `None` when discovery
/// did not attempt or could not complete the call (a live client that
/// still received the `initialize` response would pass `None` here rather
/// than fabricate an empty list).
pub fn parse_tools_list(
    initialize_response: &Value,
    list_response: Option<&Value>,
) -> (Vec<ToolDefinition>, PrimitiveState) {
    if !advertises(initialize_response, "tools") {
        return (Vec::new(), PrimitiveState::NotAdvertised);
    }
    let Some(list_response) = list_response else {
        return (Vec::new(), PrimitiveState::Unknown);
    };
    let Some(entries) = list_response.get("tools").and_then(Value::as_array) else {
        return (Vec::new(), PrimitiveState::Unknown);
    };
    let tools: Vec<ToolDefinition> = entries
        .iter()
        .take(MAX_LIST_ENTRIES)
        .filter_map(|entry| super::mcp::parse_tool(None, entry).ok())
        .collect();
    let state = parsed_list_state(list_response, entries.len(), tools.len());
    (tools, state)
}

fn parse_resource_entry(value: &Value) -> Option<ResourceDefinition> {
    let object = value.as_object()?;
    let uri = object.get("uri").and_then(Value::as_str)?.to_owned();
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| uri.clone());
    Some(ResourceDefinition {
        uri,
        name,
        description: object
            .get("description")
            .and_then(Value::as_str)
            .map(str::to_owned),
        mime_type: object
            .get("mimeType")
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

pub fn parse_resources_list(
    initialize_response: &Value,
    list_response: Option<&Value>,
) -> (Vec<ResourceDefinition>, PrimitiveState) {
    if !advertises(initialize_response, "resources") {
        return (Vec::new(), PrimitiveState::NotAdvertised);
    }
    let Some(list_response) = list_response else {
        return (Vec::new(), PrimitiveState::Unknown);
    };
    let Some(entries) = list_response.get("resources").and_then(Value::as_array) else {
        return (Vec::new(), PrimitiveState::Unknown);
    };
    let resources: Vec<ResourceDefinition> = entries
        .iter()
        .take(MAX_LIST_ENTRIES)
        .filter_map(parse_resource_entry)
        .collect();
    let state = parsed_list_state(list_response, entries.len(), resources.len());
    (resources, state)
}

fn parse_prompt_entry(value: &Value) -> Option<PromptDefinition> {
    let object = value.as_object()?;
    let name = object.get("name").and_then(Value::as_str)?.to_owned();
    let arguments = object
        .get("arguments")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .take(256)
                .filter_map(|entry| {
                    let entry = entry.as_object()?;
                    Some(PromptArgument {
                        name: entry.get("name").and_then(Value::as_str)?.to_owned(),
                        description: entry
                            .get("description")
                            .and_then(Value::as_str)
                            .map(str::to_owned),
                        required: entry.get("required").and_then(Value::as_bool),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Some(PromptDefinition {
        name,
        description: object
            .get("description")
            .and_then(Value::as_str)
            .map(str::to_owned),
        arguments,
    })
}

pub fn parse_prompts_list(
    initialize_response: &Value,
    list_response: Option<&Value>,
) -> (Vec<PromptDefinition>, PrimitiveState) {
    if !advertises(initialize_response, "prompts") {
        return (Vec::new(), PrimitiveState::NotAdvertised);
    }
    let Some(list_response) = list_response else {
        return (Vec::new(), PrimitiveState::Unknown);
    };
    let Some(entries) = list_response.get("prompts").and_then(Value::as_array) else {
        return (Vec::new(), PrimitiveState::Unknown);
    };
    let prompts: Vec<PromptDefinition> = entries
        .iter()
        .take(MAX_LIST_ENTRIES)
        .filter_map(parse_prompt_entry)
        .collect();
    let state = parsed_list_state(list_response, entries.len(), prompts.len());
    (prompts, state)
}

/// Assemble a snapshot from already-parsed primitive results. Pure data
/// transformation: no transport, no clock other than the caller-supplied
/// `observed_at`.
pub fn build_snapshot(
    protocol: ProtocolInfo,
    server_transport_identity: String,
    tools: (Vec<ToolDefinition>, PrimitiveState),
    resources: (Vec<ResourceDefinition>, PrimitiveState),
    prompts: (Vec<PromptDefinition>, PrimitiveState),
    observed_at: u64,
) -> Result<McpCapabilitySnapshot> {
    let (tools, tools_state) = tools;
    let (resources, resources_state) = resources;
    let (prompts, prompts_state) = prompts;
    let completeness = PrimitiveCompleteness {
        tools: tools_state,
        resources: resources_state,
        prompts: prompts_state,
    };
    let content_sha256 = compute_content_sha256(
        &protocol,
        &server_transport_identity,
        &tools,
        &resources,
        &prompts,
        &completeness,
    )?;
    Ok(McpCapabilitySnapshot {
        observed_at,
        protocol,
        server_transport_identity,
        authorization_context_identity: None,
        executable_identity: None,
        tools,
        resources,
        prompts,
        completeness,
        content_sha256,
    })
}

/// Run sandboxed stdio discovery against a server command and assemble the
/// result into a snapshot. Returns the snapshot plus any transport-level
/// limitations encountered (e.g. a per-primitive request that timed out) —
/// kept separate from `McpCapabilitySnapshot` itself so that type's shape
/// does not need to change to carry them.
pub fn snapshot_from_stdio(
    command: &str,
    args: &[String],
    server_transport_identity: String,
    observed_at: u64,
) -> Result<(McpCapabilitySnapshot, Vec<String>)> {
    let outcome = discover_stdio(command, args)?;
    let snapshot = snapshot_from_outcome(
        outcome.initialize,
        outcome.tools_list,
        outcome.resources_list,
        outcome.prompts_list,
        server_transport_identity,
        observed_at,
    )?;
    Ok((snapshot, outcome.limitations))
}

/// Run remote HTTP discovery against one explicit endpoint and assemble the
/// result into a snapshot. See `snapshot_from_stdio` for the limitations
/// return.
pub fn snapshot_from_remote(
    endpoint: &str,
    server_transport_identity: String,
    observed_at: u64,
) -> Result<(McpCapabilitySnapshot, Vec<String>)> {
    let outcome = discover_remote(endpoint)?;
    let snapshot = snapshot_from_outcome(
        outcome.initialize,
        outcome.tools_list,
        outcome.resources_list,
        outcome.prompts_list,
        server_transport_identity,
        observed_at,
    )?;
    Ok((snapshot, outcome.limitations))
}

fn snapshot_from_outcome(
    initialize: Option<Value>,
    tools_list: Option<Value>,
    resources_list: Option<Value>,
    prompts_list: Option<Value>,
    server_transport_identity: String,
    observed_at: u64,
) -> Result<McpCapabilitySnapshot> {
    let Some(initialize) = initialize else {
        bail!("MCP discovery did not receive a usable initialize response");
    };
    let protocol = parse_initialize_response(&initialize);
    let tools = parse_tools_list(&initialize, tools_list.as_ref());
    let resources = parse_resources_list(&initialize, resources_list.as_ref());
    let prompts = parse_prompts_list(&initialize, prompts_list.as_ref());
    build_snapshot(
        protocol,
        server_transport_identity,
        tools,
        resources,
        prompts,
        observed_at,
    )
}

fn compute_content_sha256(
    protocol: &ProtocolInfo,
    server_transport_identity: &str,
    tools: &[ToolDefinition],
    resources: &[ResourceDefinition],
    prompts: &[PromptDefinition],
    completeness: &PrimitiveCompleteness,
) -> Result<String> {
    let mut tools_sorted = tools.to_vec();
    tools_sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let mut resources_sorted = resources.to_vec();
    resources_sorted.sort_by(|a, b| a.uri.cmp(&b.uri));
    let mut prompts_sorted = prompts.to_vec();
    prompts_sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let canonical = serde_json::json!({
        "protocol": protocol,
        "server_transport_identity": server_transport_identity,
        "tools": tools_sorted,
        "resources": resources_sorted,
        "prompts": prompts_sorted,
        "completeness": completeness,
    });
    let mut hasher = Sha256::new();
    hasher.update(b"layerfault:mcp-capability-snapshot:v1\0");
    hasher.update(serde_json::to_vec(&canonical)?);
    Ok(format!(
        "lfmcpsnapshot:v1:sha256:{}",
        hex::encode(hasher.finalize())
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn initialize_with(version: &str, capability_keys: &[&str]) -> Value {
        let mut capabilities = serde_json::Map::new();
        for key in capability_keys {
            capabilities.insert((*key).to_owned(), serde_json::json!({}));
        }
        serde_json::json!({"protocolVersion": version, "capabilities": Value::Object(capabilities)})
    }

    #[test]
    fn known_protocol_version_is_supported() {
        let info = parse_initialize_response(&initialize_with("2025-11-25", &["tools"]));
        assert!(info.scanner_supported);
        assert!(info.unknown_extensions.is_empty());
    }

    #[test]
    fn unknown_protocol_version_is_unsupported_not_a_parse_failure() {
        let info = parse_initialize_response(&initialize_with("2099-01-01", &["tools"]));
        assert!(!info.scanner_supported);
        assert_eq!(info.declared_version.as_deref(), Some("2099-01-01"));
    }

    #[test]
    fn unknown_capability_key_is_recorded_not_ignored() {
        let info = parse_initialize_response(&initialize_with(
            "2026-07-28",
            &["tools", "somethingNewAndUnrecognised"],
        ));
        assert_eq!(
            info.unknown_extensions,
            vec!["somethingNewAndUnrecognised".to_owned()]
        );
    }

    #[test]
    fn primitive_not_advertised_is_distinct_from_unknown() {
        let init = initialize_with("2025-11-25", &["tools"]);
        let (resources, state) = parse_resources_list(&init, None);
        assert!(resources.is_empty());
        assert_eq!(state, PrimitiveState::NotAdvertised);
    }

    #[test]
    fn advertised_but_unfetched_primitive_is_unknown_not_absent() {
        let init = initialize_with("2025-11-25", &["resources"]);
        let (resources, state) = parse_resources_list(&init, None);
        assert!(resources.is_empty());
        assert_eq!(state, PrimitiveState::Unknown);
    }

    #[test]
    fn paginated_list_is_partial_pagination() {
        let init = initialize_with("2025-11-25", &["tools"]);
        let list = serde_json::json!({"tools": [], "nextCursor": "page-2"});
        let (_tools, state) = parse_tools_list(&init, Some(&list));
        assert_eq!(state, PrimitiveState::PartialPagination);
    }

    #[test]
    fn malformed_list_entry_is_partial_not_complete() {
        let init = initialize_with("2025-11-25", &["resources"]);
        let list = serde_json::json!({"resources": [
            {"uri": "file:///valid"},
            {"name": "missing-uri"}
        ]});
        let (resources, state) = parse_resources_list(&init, Some(&list));
        assert_eq!(resources.len(), 1);
        assert_eq!(state, PrimitiveState::PartialMalformed);
    }

    #[test]
    fn tools_list_reuses_the_static_tool_parser() {
        let init = initialize_with("2025-11-25", &["tools"]);
        let list = serde_json::json!({"tools": [
            {"name": "read_file", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}}
        ]});
        let (tools, state) = parse_tools_list(&init, Some(&list));
        assert_eq!(state, PrimitiveState::Complete);
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "read_file");
    }

    #[test]
    fn resource_without_declared_name_falls_back_to_uri() {
        let entry = serde_json::json!({"uri": "file:///etc/passwd"});
        let resource = parse_resource_entry(&entry).expect("parsed");
        assert_eq!(resource.name, "file:///etc/passwd");
    }

    #[test]
    fn prompt_arguments_are_parsed() {
        let entry = serde_json::json!({
            "name": "summarize",
            "arguments": [{"name": "text", "required": true}]
        });
        let prompt = parse_prompt_entry(&entry).expect("parsed");
        assert_eq!(prompt.arguments.len(), 1);
        assert_eq!(prompt.arguments[0].name, "text");
        assert_eq!(prompt.arguments[0].required, Some(true));
    }

    #[test]
    fn digest_excludes_observed_at() {
        let init = initialize_with("2025-11-25", &["tools"]);
        let protocol = parse_initialize_response(&init);
        let tools = parse_tools_list(&init, Some(&serde_json::json!({"tools": []})));
        let resources = parse_resources_list(&init, None);
        let prompts = parse_prompts_list(&init, None);

        let first = build_snapshot(
            protocol.clone(),
            "transport-identity".to_owned(),
            tools.clone(),
            resources.clone(),
            prompts.clone(),
            1_000,
        )
        .expect("snapshot");
        let second = build_snapshot(
            protocol,
            "transport-identity".to_owned(),
            tools,
            resources,
            prompts,
            2_000,
        )
        .expect("snapshot");

        assert_ne!(first.observed_at, second.observed_at);
        assert_eq!(first.content_sha256, second.content_sha256);
    }

    #[test]
    fn digest_changes_when_content_actually_changes() {
        let init = initialize_with("2025-11-25", &["tools"]);
        let protocol = parse_initialize_response(&init);
        let empty = parse_tools_list(&init, Some(&serde_json::json!({"tools": []})));
        let with_tool = parse_tools_list(
            &init,
            Some(&serde_json::json!({"tools": [
                {"name": "read_file", "inputSchema": {}}
            ]})),
        );
        let resources = parse_resources_list(&init, None);
        let prompts = parse_prompts_list(&init, None);

        let before = build_snapshot(
            protocol.clone(),
            "t".to_owned(),
            empty,
            resources.clone(),
            prompts.clone(),
            1,
        )
        .expect("snapshot");
        let after = build_snapshot(protocol, "t".to_owned(), with_tool, resources, prompts, 1)
            .expect("snapshot");
        assert_ne!(before.content_sha256, after.content_sha256);
    }
}
