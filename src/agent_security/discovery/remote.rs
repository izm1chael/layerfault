//! Remote HTTP MCP protocol discovery (Streamable HTTP transport).
//!
//! Like `stdio`, this is a transport module: it obtains JSON-RPC response
//! bodies over the network and hands them to `crate::agent_security::discovery`'s
//! pure parsing functions. It never issues `tools/call`, `resources/read` or
//! `prompts/get` — there is no function here capable of it.
//!
//! Safety properties, all enforced before or during connection, not merely
//! documented as intent:
//! - **Explicit endpoint, no redirects.** The client is built with
//!   `redirect::Policy::none()`; a 3xx response is treated as a discovery
//!   failure, not silently followed. An MCP endpoint is an operator-supplied
//!   URL, not something to chase across hosts.
//! - **DNS-rebinding resistant.** The host is resolved once, validated
//!   against `crate::net_safety` (rejecting private/loopback/link-local/
//!   cloud-metadata addresses), and the client is built with that exact
//!   resolved address pinned via `reqwest::ClientBuilder::resolve` — so a
//!   later DNS answer for the same host cannot silently redirect traffic
//!   after validation, unlike a design that only re-checks the hostname
//!   immediately before each request.
//! - **Bounded.** Response bytes, request count and per-request timeout are
//!   all capped.
//! - **No automatic credential reuse, no automatic OAuth login.** This
//!   client never attaches an `Authorization` header, a cookie, or any
//!   other credential to any request — there is no code path that reads or
//!   sends one. A URL containing embedded userinfo credentials
//!   (`https://user:pass@host/...`) is rejected outright rather than used.
//! - **No automatically followed metadata URLs.** Discovery only ever
//!   contacts the one endpoint the operator supplied.

use anyhow::{anyhow, bail, Context, Result};
use reqwest::blocking::{Client, Response};
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde_json::Value;
use std::io::Read;
use std::net::SocketAddr;
use std::time::Duration;
use url::Url;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
/// initialize, notifications/initialized, tools/list, resources/list,
/// prompts/list — five, with headroom for the counter's own bookkeeping.
const MAX_REQUESTS: usize = 8;
const CLIENT_NAME: &str = "layerfault";

#[derive(Debug)]
pub struct RemoteDiscoveryOutcome {
    pub initialize: Option<Value>,
    pub tools_list: Option<Value>,
    pub resources_list: Option<Value>,
    pub prompts_list: Option<Value>,
    pub limitations: Vec<String>,
}

/// Run the bounded discovery sequence against one explicit, operator-
/// supplied MCP endpoint. Never fetches any URL other than `endpoint`
/// itself.
pub fn discover_remote(endpoint: &str) -> Result<RemoteDiscoveryOutcome> {
    let url =
        Url::parse(endpoint).with_context(|| format!("invalid MCP endpoint URL '{endpoint}'"))?;
    let pinned_address = validate_and_resolve(&url)?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("MCP endpoint URL has no host"))?
        .to_owned();
    let port = url.port_or_known_default().unwrap_or(443);
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        // Pin the exact address validated by `validate_and_resolve`: a
        // later DNS answer for the same host during this discovery run
        // cannot silently redirect requests to a different, unvalidated
        // address (DNS rebinding).
        .resolve(&host, SocketAddr::new(pinned_address, port))
        .build()
        .context("unable to build MCP discovery HTTP client")?;

    let mut request_count = 0usize;
    let mut limitations = Vec::new();
    let mut next_id = 1u64;

    let init_body = jsonrpc_request(
        next_id,
        "initialize",
        serde_json::json!({
            "protocolVersion": super::KNOWN_PROTOCOL_VERSIONS.last().copied().unwrap_or("2025-11-25"),
            "capabilities": {},
            "clientInfo": {"name": CLIENT_NAME, "version": env!("CARGO_PKG_VERSION")},
        }),
    );
    next_id += 1;
    let initialize = send_request(&client, &url, &init_body, &mut request_count)
        .ok()
        .and_then(|response| response.get("result").cloned());
    let Some(initialize) = initialize else {
        limitations.push("MCP server did not return a usable initialize response".to_owned());
        return Ok(RemoteDiscoveryOutcome {
            initialize: None,
            tools_list: None,
            resources_list: None,
            prompts_list: None,
            limitations,
        });
    };

    // Required by the spec before further requests; the Streamable HTTP
    // transport still delivers it as a POST, just with no JSON-RPC id and
    // no response body expected.
    let notified_body = jsonrpc_notification("notifications/initialized", serde_json::json!({}));
    let _ = send_request(&client, &url, &notified_body, &mut request_count);

    let capabilities = initialize
        .get("capabilities")
        .cloned()
        .unwrap_or(Value::Null);

    let mut list = |method: &str, next_id: &mut u64| -> Option<Value> {
        let body = jsonrpc_request(*next_id, method, serde_json::json!({}));
        *next_id += 1;
        match send_request(&client, &url, &body, &mut request_count) {
            Ok(response) => response.get("result").cloned(),
            Err(error) => {
                limitations.push(format!("MCP discovery {method} failed: {error}"));
                None
            }
        }
    };

    let tools_list = capabilities
        .get("tools")
        .is_some()
        .then(|| list("tools/list", &mut next_id))
        .flatten();
    let resources_list = capabilities
        .get("resources")
        .is_some()
        .then(|| list("resources/list", &mut next_id))
        .flatten();
    let prompts_list = capabilities
        .get("prompts")
        .is_some()
        .then(|| list("prompts/list", &mut next_id))
        .flatten();

    Ok(RemoteDiscoveryOutcome {
        initialize: Some(initialize),
        tools_list,
        resources_list,
        prompts_list,
        limitations,
    })
}

/// Validate the endpoint URL and resolve its host to exactly one address
/// that is not private/loopback/link-local/cloud-metadata. Returns that
/// address so the caller can pin it.
fn validate_and_resolve(url: &Url) -> Result<std::net::IpAddr> {
    if url.scheme() != "https" && url.scheme() != "http" {
        bail!("MCP endpoint must use http or https");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("MCP endpoint URL must not embed credentials (userinfo)");
    }
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("MCP endpoint URL has no host"))?;
    let port = url.port_or_known_default().unwrap_or(443);
    crate::net_safety::resolve_public_addresses(host, port)?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("MCP endpoint host '{host}' resolved to no addresses"))
}

fn jsonrpc_request(id: u64, method: &str, params: Value) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params,
    }))
    .expect("JSON-RPC request always serializes")
}

fn jsonrpc_notification(method: &str, params: Value) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
    }))
    .expect("JSON-RPC notification always serializes")
}

fn send_request(
    client: &Client,
    url: &Url,
    body: &[u8],
    request_count: &mut usize,
) -> Result<Value> {
    if *request_count >= MAX_REQUESTS {
        bail!("MCP discovery exceeded the bounded request count for this session");
    }
    *request_count += 1;
    let response = client
        .post(url.clone())
        .header(CONTENT_TYPE, "application/json")
        .header(ACCEPT, "application/json")
        .body(body.to_vec())
        .send()
        .with_context(|| format!("MCP discovery request to {url} failed"))?;
    if response.status().is_redirection() {
        bail!(
            "MCP endpoint returned a redirect (HTTP {}); discovery does not follow redirects",
            response.status()
        );
    }
    if !response.status().is_success() {
        bail!("MCP endpoint returned HTTP {}", response.status());
    }
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    if !content_type.contains("application/json") {
        bail!(
            "MCP endpoint responded with unsupported content type '{content_type}' (only application/json discovery responses are supported; text/event-stream is not yet)"
        );
    }
    let bytes = read_response_capped(response, MAX_RESPONSE_BYTES)?;
    serde_json::from_slice(&bytes).context("MCP endpoint response is not valid JSON")
}

fn read_response_capped(mut response: Response, cap: usize) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = response.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        if output.len().saturating_add(read) > cap {
            bail!("MCP discovery response exceeds the {cap} byte cap");
        }
        output.extend_from_slice(&buffer[..read]);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_endpoint_is_rejected_before_connecting() {
        let error =
            discover_remote("http://127.0.0.1:1/mcp").expect_err("loopback must be rejected");
        let text = error.to_string();
        assert!(
            text.contains("blocked") || text.contains("resolve"),
            "unexpected error: {text}"
        );
    }

    #[test]
    fn credential_in_url_is_rejected() {
        let error = discover_remote("https://user:pass@example.invalid/mcp")
            .expect_err("embedded credentials must be rejected");
        assert!(error.to_string().contains("credentials"));
    }

    #[test]
    fn non_http_scheme_is_rejected() {
        let error = discover_remote("ftp://example.invalid/mcp").expect_err("ftp must be rejected");
        assert!(error.to_string().contains("http"));
    }

    #[test]
    fn cloud_metadata_address_is_rejected() {
        let error = discover_remote("http://169.254.169.254/mcp")
            .expect_err("cloud metadata address must be rejected");
        assert!(error.to_string().contains("blocked"));
    }
}
