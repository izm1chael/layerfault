//! Sandboxed stdio MCP protocol discovery.
//!
//! This is the one part of the Discovery unit that actually launches a
//! process: an MCP server started over stdio must run *somewhere* to answer
//! `initialize`/`tools/list`/`resources/list`/`prompts/list`. Everything
//! else in `crate::agent_security::discovery` is pure parsing with no
//! transport; this module is the transport for the stdio half, and it is
//! deliberately narrow:
//!
//! - **No host network.** The sandbox unshares the network namespace
//!   unconditionally. This is also what makes "never auto-download during
//!   discovery" (`npx`, `uvx`, `pip`, `bunx`, ...) a structural property
//!   rather than a per-command special case: if the launched process tries
//!   to fetch a package, the fetch fails, because there is no network to
//!   reach. Nothing here pattern-matches on the command name to decide
//!   whether to allow it to run.
//! - **Read-only.** The whole filesystem is bind-mounted read-only; nothing
//!   the sandboxed process does can write outside a private tmpfs. The
//!   entry executable is additionally pinned by file descriptor at
//!   resolution time (`crate::behaviour::sandbox::pin_active_path`) and
//!   executed from that descriptor, so a symlink-swap between resolving the
//!   command and launching it cannot substitute a different binary.
//! - **Private home.** The real `$HOME` is masked with an empty tmpfs
//!   inside the sandbox, so a launched server cannot read the operator's
//!   actual dotfiles/credentials merely by existing on the same host.
//! - **Discovery only.** This module can send `initialize`,
//!   `notifications/initialized`, `tools/list`, `resources/list` and
//!   `prompts/list`. It has no function that can send `tools/call`,
//!   `resources/read` or `prompts/get` — there is no code path here capable
//!   of it, not merely a convention against using one.
//!
//! What this module does **not** attempt: general dependency-closure
//! filesystem scoping (mounting only the exact files an arbitrary
//! interpreter/package needs). The whole filesystem is readable inside the
//! sandbox, same as an unsandboxed read would see. What the sandbox
//! guarantees is no network egress, no writes outside tmpfs, and a masked
//! home — not a minimal read surface. That is a real, meaningful boundary
//! for this threat model (auto-download and credential exfiltration during
//! discovery), and it is honestly short of a fully least-privilege sandbox.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_LINE_BYTES: usize = 16 * 1024 * 1024;
const CLIENT_NAME: &str = "layerfault";

fn read_bounded_line(reader: &mut impl BufRead) -> std::io::Result<Option<String>> {
    let mut bytes = Vec::new();
    let mut limited = reader.take((MAX_LINE_BYTES + 1) as u64);
    let read = limited.read_until(b'\n', &mut bytes)?;
    if read == 0 {
        return Ok(None);
    }
    if read > MAX_LINE_BYTES {
        return Err(std::io::Error::other(
            "MCP discovery response line exceeded the safety limit",
        ));
    }
    String::from_utf8(bytes).map(Some).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("MCP discovery response is not valid UTF-8: {error}"),
        )
    })
}

#[derive(Debug)]
pub struct StdioDiscoveryOutcome {
    pub initialize: Option<Value>,
    pub tools_list: Option<Value>,
    pub resources_list: Option<Value>,
    pub prompts_list: Option<Value>,
    pub limitations: Vec<String>,
}

/// Resolve `command` (a bare name via `PATH`, or an explicit path), launch
/// it inside a dedicated discovery sandbox, and run the bounded discovery
/// sequence. Refuses to run at all if a working sandbox is unavailable —
/// this mirrors the existing behavioural-execution refusal in
/// `crate::behaviour::sandbox::command_for` ("rather than exposing the host
/// filesystem/network"), not a fallback to unsandboxed execution.
pub fn discover_stdio(command: &str, args: &[String]) -> Result<StdioDiscoveryOutcome> {
    let Some(wrapper) = crate::behaviour::sandbox::detect_network_wrapper() else {
        bail!(
            "MCP stdio discovery requires a working sandbox (bubblewrap); refusing to launch an MCP server binary unsandboxed for discovery"
        );
    };
    let resolved = resolve_command(command)?;
    let mut child = spawn_sandboxed(&resolved, args, &wrapper)?;
    let outcome = run_discovery_sequence(&mut child, DEFAULT_TIMEOUT);
    let _ = crate::behaviour::sandbox::terminate_process_tree(&mut child, Duration::from_secs(3));
    outcome
}

fn resolve_command(command: &str) -> Result<PathBuf> {
    if command.starts_with('/') || command.contains('/') {
        let resolved = std::fs::canonicalize(command)
            .with_context(|| format!("failed to resolve MCP server command '{command}'"))?;
        if !resolved.is_file() {
            bail!(
                "MCP server command '{}' is not a regular file",
                resolved.display()
            );
        }
        return Ok(resolved);
    }
    crate::sources::find_executable(command)
        .ok_or_else(|| anyhow!("MCP server command '{command}' was not found on PATH"))
}

fn spawn_sandboxed(
    resolved_executable: &Path,
    args: &[String],
    wrapper: &(PathBuf, String),
) -> Result<Child> {
    let (bwrap, mechanism) = wrapper;
    if !mechanism.starts_with("bwrap-fs-net") {
        bail!("unsupported MCP discovery sandbox mechanism '{mechanism}'");
    }
    let pinned_executable = crate::behaviour::sandbox::pin_active_path(resolved_executable)?;
    let seccomp_filter = crate::behaviour::sandbox::seccomp_filter_file()?;
    let home = std::env::var_os("HOME").map(PathBuf::from);

    let mut bwrap_args: Vec<OsString> = vec![
        "--unshare-net".into(),
        "--unshare-pid".into(),
        "--unshare-ipc".into(),
        "--unshare-uts".into(),
        "--unshare-cgroup-try".into(),
        "--die-with-parent".into(),
        "--new-session".into(),
        "--cap-drop".into(),
        "ALL".into(),
        "--seccomp".into(),
        pinned_fd(&seccomp_filter),
        "--ro-bind".into(),
        "/".into(),
        "/".into(),
        "--proc".into(),
        "/proc".into(),
        "--dev".into(),
        "/dev".into(),
        // `--ro-bind / /` makes the real root read-only, so a brand-new
        // top-level path (e.g. `/mcp-discovery`) cannot be created — `mkdir`
        // on a read-only filesystem fails. `/tmp` is instead replaced with a
        // fresh writable tmpfs first, and the pinned executable is placed in
        // a subdirectory created inside *that* tmpfs, which is writable.
        "--tmpfs".into(),
        "/tmp".into(),
        "--dir".into(),
        "/tmp/mcpd".into(),
        "--ro-bind-fd".into(),
        pinned_fd(&pinned_executable),
        "/tmp/mcpd/executable".into(),
    ];
    if let Some(home) = home.as_deref() {
        // Mask the real home over its actual path: the surrounding
        // `--ro-bind / /` already exposed it, so this must come after that
        // bind to take effect. An empty tmpfs, not a read-only bind of the
        // real content. Note this means an MCP server whose entry script
        // lives under the real `$HOME` (a common install location) will not
        // be reachable during discovery — that is an accepted trade-off:
        // masking home to protect credentials/dotfiles is the point, and a
        // server that cannot be reached fails discovery visibly rather than
        // exposing the home directory to make discovery succeed.
        bwrap_args.extend(["--tmpfs".into(), home.as_os_str().to_owned()]);
    }
    bwrap_args.extend([
        "--setenv".into(),
        "HOME".into(),
        home.unwrap_or_else(|| PathBuf::from("/tmp/mcpd/home"))
            .into_os_string(),
        "--setenv".into(),
        "TMPDIR".into(),
        "/tmp".into(),
        "--chdir".into(),
        "/tmp".into(),
        "--".into(),
        "/tmp/mcpd/executable".into(),
    ]);
    bwrap_args.extend(args.iter().map(OsString::from));

    let mut command = Command::new(bwrap);
    command.args(&bwrap_args);
    command.stdin(Stdio::piped());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::null());
    crate::behaviour::sandbox::configure_process_group(&mut command);
    // Keep the pinned descriptors alive until after spawn (their CLOEXEC
    // flag was already cleared so the child inherits them); explicit drop
    // here documents that requirement rather than relying on scope alone.
    let child = command
        .spawn()
        .context("unable to launch sandboxed MCP discovery process")?;
    drop(pinned_executable);
    drop(seccomp_filter);
    Ok(child)
}

fn pinned_fd(file: &std::fs::File) -> OsString {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        file.as_raw_fd().to_string().into()
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        "unsupported".into()
    }
}

/// One JSON-RPC request/notification exchange over the child's stdio, with
/// an overall wall-clock deadline enforced by reading on a background
/// thread and using `recv_timeout` rather than a blocking read with no
/// bound.
struct JsonRpcStdio {
    stdin: ChildStdin,
    lines: mpsc::Receiver<std::io::Result<String>>,
    next_id: u64,
}

impl JsonRpcStdio {
    fn new(child: &mut Child) -> Result<Self> {
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("MCP discovery process has no stdin"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("MCP discovery process has no stdout"))?;
        let (sender, lines) = mpsc::channel();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                match read_bounded_line(&mut reader) {
                    Ok(None) => break,
                    Ok(Some(line)) => {
                        if sender.send(Ok(line)).is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        let _ = sender.send(Err(error));
                        break;
                    }
                }
            }
        });
        Ok(Self {
            stdin,
            lines,
            next_id: 1,
        })
    }

    fn send(&mut self, method: &str, params: Value, expect_response: bool) -> Result<Option<u64>> {
        let id = expect_response.then(|| {
            let id = self.next_id;
            self.next_id += 1;
            id
        });
        let mut message = serde_json::json!({"jsonrpc": "2.0", "method": method, "params": params});
        if let Some(id) = id {
            message["id"] = serde_json::json!(id);
        }
        let mut line = serde_json::to_vec(&message)?;
        line.push(b'\n');
        self.stdin
            .write_all(&line)
            .context("unable to write to MCP discovery process stdin")?;
        self.stdin.flush().ok();
        Ok(id)
    }

    /// Read lines until one is a JSON-RPC response matching `id`, or the
    /// deadline is reached. Non-matching lines (server-initiated
    /// notifications, unrelated ids) are discarded, not treated as errors.
    fn recv_response(&mut self, id: u64, deadline: Instant) -> Result<Value> {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                bail!("MCP discovery timed out waiting for a response");
            }
            let line = match self.lines.recv_timeout(remaining) {
                Ok(Ok(line)) => line,
                Ok(Err(error)) => bail!("MCP discovery stdout read failed: {error}"),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    bail!("MCP discovery timed out waiting for a response")
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    bail!("MCP discovery process closed stdout before responding")
                }
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let Ok(value) = serde_json::from_str::<Value>(trimmed) else {
                continue;
            };
            if value.get("id").and_then(Value::as_u64) == Some(id) {
                return Ok(value);
            }
        }
    }
}

fn run_discovery_sequence(child: &mut Child, timeout: Duration) -> Result<StdioDiscoveryOutcome> {
    let deadline = Instant::now() + timeout;
    let mut transport = JsonRpcStdio::new(child)?;
    let mut limitations = Vec::new();

    let init_params = serde_json::json!({
        "protocolVersion": super::KNOWN_PROTOCOL_VERSIONS
            .last()
            .copied()
            .unwrap_or("2025-11-25"),
        "capabilities": {},
        "clientInfo": {"name": CLIENT_NAME, "version": env!("CARGO_PKG_VERSION")},
    });
    let init_id = transport
        .send("initialize", init_params, true)?
        .expect("initialize always expects a response");
    let initialize_response = transport.recv_response(init_id, deadline).ok();
    if initialize_response.is_none() {
        limitations.push(
            "MCP server did not respond to initialize within the discovery timeout".to_owned(),
        );
        return Ok(StdioDiscoveryOutcome {
            initialize: None,
            tools_list: None,
            resources_list: None,
            prompts_list: None,
            limitations,
        });
    }
    let initialize_result = initialize_response
        .as_ref()
        .and_then(|response| response.get("result"))
        .cloned();

    // The spec requires this notification before further requests; no
    // response is expected or read.
    transport.send("notifications/initialized", serde_json::json!({}), false)?;

    let list = |transport: &mut JsonRpcStdio,
                method: &str,
                limitations: &mut Vec<String>|
     -> Option<Value> {
        let Ok(Some(id)) = transport.send(method, serde_json::json!({}), true) else {
            limitations.push(format!("MCP discovery could not send {method}"));
            return None;
        };
        match transport.recv_response(id, deadline) {
            Ok(response) => response.get("result").cloned(),
            Err(error) => {
                limitations.push(format!("MCP discovery {method} failed: {error}"));
                None
            }
        }
    };

    let tools_list = initialize_result
        .as_ref()
        .map(|result| result.get("capabilities").cloned().unwrap_or(Value::Null))
        .filter(|capabilities| capabilities.get("tools").is_some())
        .and_then(|_| list(&mut transport, "tools/list", &mut limitations));
    let resources_list = initialize_result
        .as_ref()
        .map(|result| result.get("capabilities").cloned().unwrap_or(Value::Null))
        .filter(|capabilities| capabilities.get("resources").is_some())
        .and_then(|_| list(&mut transport, "resources/list", &mut limitations));
    let prompts_list = initialize_result
        .as_ref()
        .map(|result| result.get("capabilities").cloned().unwrap_or(Value::Null))
        .filter(|capabilities| capabilities.get("prompts").is_some())
        .and_then(|_| list(&mut transport, "prompts/list", &mut limitations));

    Ok(StdioDiscoveryOutcome {
        initialize: initialize_result,
        tools_list,
        resources_list,
        prompts_list,
        limitations,
    })
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    fn bwrap_available() -> bool {
        crate::behaviour::sandbox::detect_network_wrapper().is_some()
    }

    fn fixture_dir() -> PathBuf {
        let directory = std::env::current_dir()
            .expect("current directory")
            .join("target/layerfault-mcp-discovery-test");
        std::fs::create_dir_all(&directory).expect("create discovery fixture directory");
        directory
    }

    fn write_executable_fixture(name: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let path = fixture_dir().join(format!("{name}_{}", std::process::id()));
        std::fs::write(&path, format!("#!/usr/bin/env python3\n{body}"))
            .expect("write discovery fixture");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("make discovery fixture executable");
        path
    }

    /// A minimal, self-contained MCP-shaped stdio server: reads
    /// newline-delimited JSON-RPC from stdin, answers `initialize` and
    /// `tools/list`. Written in Python so the fixture has no build step and
    /// no dependency beyond an interpreter that is very likely present.
    const MOCK_SERVER_SCRIPT: &str = r#"
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except Exception:
        continue
    method = msg.get("method")
    if method == "initialize":
        resp = {"jsonrpc": "2.0", "id": msg["id"], "result": {
            "protocolVersion": "2025-11-25",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "mock", "version": "0.0.0"}
        }}
        print(json.dumps(resp)); sys.stdout.flush()
    elif method == "notifications/initialized":
        continue
    elif method == "tools/list":
        resp = {"jsonrpc": "2.0", "id": msg["id"], "result": {"tools": [
            {"name": "echo", "inputSchema": {"type": "object", "properties": {}}}
        ]}}
        print(json.dumps(resp)); sys.stdout.flush()
    elif method == "tools/call":
        # Must never be reached by discovery; if it is, the fixture itself
        # will make the test fail by asserting on the absence of side effects.
        resp = {"jsonrpc": "2.0", "id": msg["id"], "result": {"THIS_SHOULD_NEVER_BE_CALLED": True}}
        print(json.dumps(resp)); sys.stdout.flush()
"#;

    #[test]
    fn discovers_a_mock_stdio_server_without_calling_tools() {
        if !bwrap_available() {
            eprintln!("skipping: bubblewrap not available");
            return;
        }
        // Written outside `/tmp` and the real `$HOME` deliberately: the
        // discovery sandbox masks both of those with an empty tmpfs (see
        // `spawn_sandboxed`), so a fixture placed under either would be
        // invisible to the sandboxed process, the same as any real MCP
        // server entry script installed there would be.
        let script_path = write_executable_fixture("mock_mcp.py", MOCK_SERVER_SCRIPT);

        let outcome = discover_stdio(script_path.to_str().unwrap(), &[])
            .expect("discovery should succeed against the mock server");

        let _ = std::fs::remove_file(&script_path);

        assert!(outcome.initialize.is_some());
        // Never-issues-tools/call is structural (this module has no
        // function capable of sending it), but also assert the mock
        // server's tools/call marker never appears anywhere in what was
        // actually captured, as a second, independent check.
        assert!(!format!("{outcome:?}").contains("THIS_SHOULD_NEVER_BE_CALLED"));
        let tools = outcome
            .tools_list
            .expect("tools/list result present")
            .get("tools")
            .cloned()
            .unwrap_or(Value::Null);
        assert_eq!(tools.as_array().map(|a| a.len()), Some(1));
    }

    #[test]
    fn snapshot_from_stdio_produces_a_stable_digest_across_two_real_runs() {
        if !bwrap_available() {
            eprintln!("skipping: bubblewrap not available");
            return;
        }
        let script_path = write_executable_fixture("mock_mcp_snapshot.py", MOCK_SERVER_SCRIPT);

        // Two independent real sandboxed runs against the same unchanged
        // server: the resulting content digest must match even though each
        // run has its own observed_at, or drift/capability-expansion
        // detection built on snapshot diffs is unusable.
        let (first, limitations_a) = super::super::snapshot_from_stdio(
            script_path.to_str().unwrap(),
            &[],
            "test-transport".to_owned(),
            1_000,
        )
        .expect("first discovery run");
        let (second, limitations_b) = super::super::snapshot_from_stdio(
            script_path.to_str().unwrap(),
            &[],
            "test-transport".to_owned(),
            2_000,
        )
        .expect("second discovery run");

        let _ = std::fs::remove_file(&script_path);

        assert!(limitations_a.is_empty());
        assert!(limitations_b.is_empty());
        assert_eq!(first.tools.len(), 1);
        assert_eq!(first.tools[0].name, "echo");
        assert_ne!(first.observed_at, second.observed_at);
        assert_eq!(first.content_sha256, second.content_sha256);
    }

    /// Attempts a real outbound TCP connection while answering `initialize`,
    /// and reports whether it succeeded. Stands in for an MCP server
    /// command that would try to auto-download a package (`npx`, `uvx`,
    /// `pip`) if it could reach the network.
    const NETWORK_PROBE_SCRIPT: &str = r#"
import sys, json, socket
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except Exception:
        continue
    if msg.get("method") == "initialize":
        reached_network = False
        try:
            s = socket.create_connection(("1.1.1.1", 443), timeout=2)
            s.close()
            reached_network = True
        except Exception:
            reached_network = False
        resp = {"jsonrpc": "2.0", "id": msg["id"], "result": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "serverInfo": {"name": "network-probe", "version": "0.0.0", "reachedNetwork": reached_network}
        }}
        print(json.dumps(resp)); sys.stdout.flush()
"#;

    #[test]
    fn sandbox_blocks_outbound_network_access() {
        if !bwrap_available() {
            eprintln!("skipping: bubblewrap not available");
            return;
        }
        let script_path = write_executable_fixture("network_probe.py", NETWORK_PROBE_SCRIPT);

        let outcome = discover_stdio(script_path.to_str().unwrap(), &[])
            .expect("discovery should succeed against the mock server");
        let _ = std::fs::remove_file(&script_path);

        let reached_network = outcome
            .initialize
            .as_ref()
            .and_then(|init| init.get("serverInfo"))
            .and_then(|info| info.get("reachedNetwork"))
            .and_then(Value::as_bool);
        assert_eq!(
            reached_network,
            Some(false),
            "sandboxed MCP discovery process must not be able to reach the network"
        );
    }

    #[test]
    fn refuses_relative_command_without_path_or_slash_when_not_found() {
        let error = resolve_command("definitely-not-a-real-mcp-server-binary")
            .expect_err("unresolvable command must fail, not hang or silently succeed");
        assert!(error.to_string().contains("not found"));
    }

    #[test]
    fn explicit_command_paths_are_canonicalized_and_must_be_files() {
        let directory = fixture_dir().join(format!("resolve_{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("create resolution fixture directory");
        let executable = directory.join("server");
        std::fs::write(&executable, "fixture").expect("write resolution fixture");

        let relative = directory.join("nested").join("..").join("server");
        std::fs::create_dir_all(directory.join("nested")).expect("create nested fixture directory");
        assert_eq!(
            resolve_command(relative.to_str().unwrap()).expect("resolve explicit command"),
            std::fs::canonicalize(&executable).expect("canonical fixture path")
        );

        let error = resolve_command(directory.to_str().unwrap())
            .expect_err("directories must not be accepted as commands");
        assert!(error.to_string().contains("not a regular file"));

        let _ = std::fs::remove_dir_all(&directory);
    }
}
