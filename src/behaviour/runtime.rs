use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct RuntimeResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub duration_ms: u64,
    pub telemetry: super::sandbox::SandboxTelemetry,
}

/// Immutable llama.cpp runtime admission. The executable identity is calculated
/// once here and byte-revalidated immediately before the persistent session is
/// started.
pub struct RuntimeAdapter {
    executable: PathBuf,
    executable_sha256: String,
    version: Option<String>,
    limits: super::BehaviourLimits,
    require_cgroup: bool,
    wrapper: Option<(PathBuf, String)>,
}

impl RuntimeAdapter {
    pub fn new(
        requested: PathBuf,
        limits: &super::BehaviourLimits,
        active: &super::ActiveExecutionOptions,
    ) -> Result<Self> {
        super::sandbox::require_external_execution_stack_options(active)?;
        let executable = resolve_llama_server(&requested)?;
        let executable = std::fs::canonicalize(&executable).with_context(|| {
            format!(
                "unable to canonicalize llama-server '{}'",
                executable.display()
            )
        })?;
        let metadata = std::fs::metadata(&executable)
            .with_context(|| format!("unable to inspect runtime '{}'", executable.display()))?;
        if !metadata.is_file() {
            bail!("llama-server runtime must resolve to a regular file");
        }
        let executable_sha256 = hash_path(&executable)?;
        let version = version_string(&executable);
        let wrapper = super::sandbox::detect_network_wrapper();
        Ok(Self {
            executable,
            executable_sha256,
            version,
            limits: limits.clone(),
            require_cgroup: active.require_cgroup,
            wrapper,
        })
    }

    pub fn identity(&self) -> super::RuntimeIdentity {
        self.identity_with_closure(super::closure::ClosureLevel::Standard)
    }

    pub fn identity_with_closure(
        &self,
        level: super::closure::ClosureLevel,
    ) -> super::RuntimeIdentity {
        let sandbox_caps = super::sandbox::capabilities(self.wrapper.as_ref());
        let closure = super::closure::discover_runtime_closure(
            "llama-cpp",
            &self.executable,
            level,
            &sandbox_caps,
            &[],
            None,
        );
        super::RuntimeIdentity {
            backend: "llama-cpp-server".to_owned(),
            executable: self.executable.display().to_string(),
            executable_sha256: format!("sha256:{}", self.executable_sha256),
            version: self.version.clone(),
            sandbox: sandbox_caps,
            closure: Some(closure),
        }
    }

    pub fn open<'a>(
        &'a self,
        model: &Path,
        canaries: &[&str],
        startup_deadline: Duration,
    ) -> Result<RuntimeSession<'a>> {
        #[cfg(not(unix))]
        {
            let _ = (model, canaries, startup_deadline);
            bail!("persistent llama.cpp active analysis currently requires a Unix host");
        }
        #[cfg(unix)]
        {
            let expected = format!("sha256:{}", self.executable_sha256);
            let runtime_binding =
                crate::binding::stage_verified_executable(&self.executable, &expected)?;
            let workspace = super::sandbox::Workspace::create(canaries)?;
            let socket_host = workspace
                .root
                .join("workspace")
                .join("layerfault-llama.sock");
            let socket_sandbox = PathBuf::from("/workspace/workspace/layerfault-llama.sock");
            // llama-server requires a slot save path for /slots?action=erase.
            let slot_save_path_host = workspace.root.join("workspace").join("slots");
            crate::paths::ensure_private_dir(&slot_save_path_host)?;
            let slot_save_path_sandbox = PathBuf::from("/workspace/workspace/slots");
            let sandboxed = super::sandbox::command_for(
                runtime_binding.path(),
                model,
                None,
                &[],
                &workspace,
                self.wrapper.as_ref(),
                self.limits.timeout_seconds,
            )?;
            let super::sandbox::SandboxedCommand {
                mut command,
                model_argument,
                base_argument: _,
                runtime_support_arguments: _,
                trace_enabled,
                pinned_inputs: _pinned_inputs,
            } = sandboxed;
            command
                .env_clear()
                .env("HOME", &workspace.home)
                .env("TMPDIR", &workspace.root)
                .env(
                    "LAYERFAULT_SYNTHETIC_SECRET_A",
                    canaries.first().copied().unwrap_or("LF_CANARY_A_UNSET"),
                )
                .env(
                    "LAYERFAULT_SYNTHETIC_SECRET_B",
                    canaries.get(1).copied().unwrap_or("LF_CANARY_B_UNSET"),
                )
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .arg("-m")
                .arg(model_argument)
                .arg("--host")
                .arg(&socket_sandbox)
                .arg("--parallel")
                .arg("1")
                .arg("--no-cache-prompt")
                .arg("--no-webui")
                // /slots is off by default in llama.cpp; this instance is
                // private and single-tenant, and infer()'s reset needs it.
                .arg("--slots")
                .arg("--slot-save-path")
                .arg(&slot_save_path_sandbox);
            let started = Instant::now();
            runtime_binding.revalidate()?;
            let host_fs = std::sync::Arc::new(super::cgroup::HostCgroupFs::new());
            let cgroup_caps = super::cgroup::detect_capabilities(host_fs.as_ref());
            let mut cgroup_guard = if cgroup_caps.cgroup_v2
                && cgroup_caps.delegated_writable
                && cgroup_caps.memory_controller
                && cgroup_caps.pids_controller
                && cgroup_caps.cpu_controller
            {
                let limits_cfg = super::cgroup::CgroupLimits {
                    memory_max_bytes: super::sandbox::configured_memory_budget_bytes(),
                    pids_max: 512,
                    ..Default::default()
                };
                match super::cgroup::CgroupGuard::create(
                    host_fs,
                    &cgroup_caps,
                    &limits_cfg,
                    "llama-cpp",
                ) {
                    Ok(guard) => Some(guard),
                    Err(err) if self.require_cgroup => return Err(err),
                    Err(_) => None,
                }
            } else {
                None
            };

            let mut child = command.spawn().with_context(|| {
                format!(
                    "unable to start persistent runtime '{}'",
                    self.executable.display()
                )
            })?;
            if let Some(guard) = cgroup_guard.as_ref() {
                if let Err(err) = guard.attach_process(child.id()) {
                    if self.require_cgroup {
                        let _ = super::sandbox::terminate_process_tree(
                            &mut child,
                            Duration::from_secs(1),
                        );
                        return Err(err);
                    }
                    cgroup_guard = None;
                }
            }
            let stdout = match child.stdout.take() {
                Some(value) => value,
                None => {
                    let _ =
                        super::sandbox::terminate_process_tree(&mut child, Duration::from_secs(1));
                    bail!("llama-server stdout pipe missing");
                }
            };
            let stderr = match child.stderr.take() {
                Some(value) => value,
                None => {
                    let _ =
                        super::sandbox::terminate_process_tree(&mut child, Duration::from_secs(1));
                    bail!("llama-server stderr pipe missing");
                }
            };
            let (stdout_tx, stdout_rx) = mpsc::channel();
            let (stderr_tx, stderr_rx) = mpsc::channel();
            std::thread::spawn(move || {
                let _ = stdout_tx.send(read_capped_drain(stdout, 512 * 1024));
            });
            std::thread::spawn(move || {
                let _ = stderr_tx.send(read_capped_drain(stderr, 1024 * 1024));
            });

            let startup_deadline = startup_deadline.max(Duration::from_secs(1));
            loop {
                if let Some(status) = child.try_wait()? {
                    let stderr = stderr_rx
                        .recv_timeout(Duration::from_millis(100))
                        .ok()
                        .and_then(|value| value.ok())
                        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                        .unwrap_or_default();
                    bail!(
                        "llama-server exited during model load ({:?}): {}",
                        status.code(),
                        stderr.trim()
                    );
                }
                if socket_host.exists() {
                    match unix_http(
                        &socket_host,
                        "GET",
                        "/health",
                        None,
                        Duration::from_secs(2),
                        64 * 1024,
                    ) {
                        Ok((200, _)) => break,
                        Ok((503, _)) | Err(_) => {}
                        Ok((status, _)) => {
                            let _ = super::sandbox::terminate_process_tree(
                                &mut child,
                                Duration::from_secs(2),
                            );
                            bail!("llama-server health endpoint returned HTTP {status}")
                        }
                    }
                }
                if started.elapsed() >= startup_deadline {
                    let _ =
                        super::sandbox::terminate_process_tree(&mut child, Duration::from_secs(2));
                    bail!("persistent llama-server model load exceeded command deadline");
                }
                std::thread::sleep(Duration::from_millis(100));
            }

            let props_check = unix_http(
                &socket_host,
                "GET",
                "/props",
                None,
                Duration::from_secs(5),
                64 * 1024,
            )
            .and_then(|(status, bytes)| verify_model_props(status, &bytes));
            match props_check {
                Ok(ModelPropsCheck::Verified) => {}
                Ok(ModelPropsCheck::Unsupported) => {
                    eprintln!(
                        "Warning: llama-server does not expose /props; model readiness is based on /health"
                    );
                }
                Err(error) => {
                    if let Err(cleanup_error) =
                        super::sandbox::terminate_process_tree(&mut child, Duration::from_secs(2))
                    {
                        return Err(error.context(format!(
                            "llama-server cleanup after readiness failure also failed: {cleanup_error:#}"
                        )));
                    }
                    return Err(error);
                }
            }

            Ok(RuntimeSession {
                adapter: self,
                child,
                workspace,
                socket_host,
                trace_enabled,
                stdout_rx: Some(stdout_rx),
                stderr_rx: Some(stderr_rx),
                _runtime_binding: runtime_binding,
                closed: false,
                cgroup_guard,
            })
        }
    }
}

pub struct RuntimeSession<'a> {
    adapter: &'a RuntimeAdapter,
    child: Child,
    workspace: super::sandbox::Workspace,
    socket_host: PathBuf,
    trace_enabled: bool,
    stdout_rx: Option<mpsc::Receiver<Result<Vec<u8>>>>,
    stderr_rx: Option<mpsc::Receiver<Result<Vec<u8>>>>,
    _runtime_binding: crate::binding::StagedArtifact,
    closed: bool,
    cgroup_guard: Option<super::cgroup::CgroupGuard>,
}

impl RuntimeSession<'_> {
    /// Execute one stateless completion through the already-loaded server. A
    /// fixed single slot is explicitly erased after every request and prompt
    /// caching is disabled both at server and request level.
    pub fn infer(
        &mut self,
        prompt: &str,
        seed: u64,
        max_tokens: u64,
        timeout: Duration,
    ) -> Result<RuntimeResult> {
        if self.closed {
            bail!("llama.cpp behavioural session is already closed");
        }
        if self.child.try_wait()?.is_some() {
            bail!("persistent llama-server exited before probe inference");
        }
        let started = Instant::now();
        let body = serde_json::to_vec(&serde_json::json!({
            "prompt": prompt,
            "seed": seed,
            "temperature": 0.0,
            "n_predict": max_tokens,
            "stream": false,
            "cache_prompt": false,
            "id_slot": 0,
            "response_fields": ["content"]
        }))?;
        let response = unix_http(
            &self.socket_host,
            "POST",
            "/completion",
            Some(&body),
            timeout.max(Duration::from_millis(250)),
            self.adapter
                .limits
                .max_output_bytes
                .saturating_add(128 * 1024),
        );
        // Reset is best-effort here because a failed reset must not hide the
        // original inference error. A successful inference *requires* reset;
        // otherwise the next probe could inherit context.
        let reset = unix_http(
            &self.socket_host,
            "POST",
            "/slots/0?action=erase",
            Some(b"{}"),
            timeout
                .min(Duration::from_secs(30))
                .max(Duration::from_millis(250)),
            64 * 1024,
        );
        let telemetry = self.workspace.collect_telemetry(
            self.trace_enabled,
            self.adapter
                .wrapper
                .as_ref()
                .map(|(path, _)| path.as_path()),
        )?;
        match response {
            Ok((200, bytes)) => {
                if !matches!(reset, Ok((200, _))) {
                    let reason = match reset {
                        Ok((status, body)) => format!(
                            "HTTP {status}: {}",
                            String::from_utf8_lossy(&body)
                                .chars()
                                .take(256)
                                .collect::<String>()
                        ),
                        Err(error) => format!("{error:#}"),
                    };
                    bail!("llama-server completed a probe but context reset failed; refusing stateful continuation ({reason})");
                }
                let value: serde_json::Value = serde_json::from_slice(&bytes)
                    .context("invalid llama-server completion JSON")?;
                let output = value
                    .get("content")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| anyhow!("llama-server completion omitted content"))?;
                if output.len() > self.adapter.limits.max_output_bytes {
                    bail!("llama-server completion exceeded selected output cap");
                }
                Ok(RuntimeResult {
                    stdout: output.to_owned(),
                    stderr: String::new(),
                    exit_code: Some(0),
                    timed_out: false,
                    duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                    telemetry,
                })
            }
            Ok((status, bytes)) => Err(anyhow!(
                "llama-server completion returned HTTP {status}: {}",
                String::from_utf8_lossy(&bytes)
                    .chars()
                    .take(1024)
                    .collect::<String>()
            )),
            Err(error) => {
                let timed_out = error.downcast_ref::<std::io::Error>().is_some_and(|io| {
                    matches!(
                        io.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    )
                });
                if timed_out {
                    let _ = super::sandbox::terminate_process_tree(
                        &mut self.child,
                        Duration::from_secs(2),
                    );
                    self.closed = true;
                    Ok(RuntimeResult {
                        stdout: String::new(),
                        stderr: format!(
                            "persistent llama-server completion request timed out: {error}"
                        ),
                        exit_code: None,
                        timed_out: true,
                        duration_ms: u64::try_from(started.elapsed().as_millis())
                            .unwrap_or(u64::MAX),
                        telemetry,
                    })
                } else {
                    // Include the target endpoint in the error for better debugging
                    Err(error.context("persistent llama-server completion request failed"))
                }
            }
        }
    }

    pub fn close(mut self) -> Result<super::sandbox::SandboxTelemetry> {
        self.shutdown()?;
        let mut telemetry = self.workspace.collect_telemetry(
            self.trace_enabled,
            self.adapter
                .wrapper
                .as_ref()
                .map(|(path, _)| path.as_path()),
        )?;
        if let Some(mut guard) = self.cgroup_guard.take() {
            let mut cg_telemetry = guard.collect_telemetry();
            cg_telemetry.cleanup_state = guard.teardown();
            telemetry.cgroup = Some(cg_telemetry);
        }
        Ok(telemetry)
    }

    fn shutdown(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        super::sandbox::terminate_process_tree(&mut self.child, Duration::from_secs(2))?;
        let _ = self
            .stdout_rx
            .take()
            .and_then(|rx| rx.recv_timeout(Duration::from_secs(1)).ok());
        let _ = self
            .stderr_rx
            .take()
            .and_then(|rx| rx.recv_timeout(Duration::from_secs(1)).ok());
        Ok(())
    }
}

impl Drop for RuntimeSession<'_> {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn resolve_llama_server(requested: &Path) -> Result<PathBuf> {
    let name = requested
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if name.contains("llama-server") {
        return Ok(requested.to_path_buf());
    }
    if let Some(parent) = requested.parent() {
        let sibling = parent.join(if cfg!(windows) {
            "llama-server.exe"
        } else {
            "llama-server"
        });
        if sibling.is_file() {
            return Ok(sibling);
        }
    }
    crate::sources::find_executable("llama-server").ok_or_else(|| {
        anyhow!(
            "persistent llama.cpp analysis requires llama-server alongside llama-cli or on PATH"
        )
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ModelPropsCheck {
    Verified,
    Unsupported,
}

fn verify_model_props(status: u16, body: &[u8]) -> Result<ModelPropsCheck> {
    if matches!(status, 404 | 405) {
        return Ok(ModelPropsCheck::Unsupported);
    }
    if status != 200 {
        let excerpt = String::from_utf8_lossy(body)
            .chars()
            .take(512)
            .collect::<String>();
        bail!(
            "llama-server /props endpoint returned HTTP {status} after health check passed: {excerpt}"
        );
    }

    let props: serde_json::Value =
        serde_json::from_slice(body).context("llama-server /props returned invalid JSON")?;
    let object = props
        .as_object()
        .ok_or_else(|| anyhow!("llama-server /props response must be a JSON object"))?;

    if object.get("model_loaded").and_then(|value| value.as_bool()) == Some(false) {
        bail!("llama-server started but reported model_loaded=false");
    }
    if object
        .get("model")
        .is_some_and(|value| value.is_null() || value.as_str() == Some(""))
    {
        bail!("llama-server started but reported a null or empty model");
    }
    if let Some(error) = object.get("error") {
        let meaningful = !error.is_null()
            && error.as_bool() != Some(false)
            && error.as_str().is_none_or(|value| !value.is_empty());
        if meaningful {
            let excerpt = error.to_string().chars().take(512).collect::<String>();
            bail!("llama-server reported an error during model load: {excerpt}");
        }
    }

    Ok(ModelPropsCheck::Verified)
}

#[cfg(unix)]
fn unix_http(
    socket: &Path,
    method: &str,
    target: &str,
    body: Option<&[u8]>,
    timeout: Duration,
    cap: usize,
) -> Result<(u16, Vec<u8>)> {
    use std::os::unix::net::UnixStream;
    let mut stream = UnixStream::connect(socket).with_context(|| {
        format!(
            "unable to connect llama-server socket '{}'",
            socket.display()
        )
    })?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let payload = body.unwrap_or_default();
    write!(
        stream,
        "{method} {target} HTTP/1.1\r\nHost: layerfault\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        payload.len()
    )?;
    if !payload.is_empty() {
        stream.write_all(payload)?;
    }
    stream.flush()?;
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let count = stream.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        if bytes.len().saturating_add(count) > cap {
            bail!("llama-server HTTP response exceeded byte cap {cap}");
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    // Check for empty response (connection closed without data)
    if bytes.is_empty() {
        bail!("llama-server closed connection without sending a response (empty response)");
    }
    let header_end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| {
            // Log the actual response for debugging
            let excerpt = String::from_utf8_lossy(&bytes[..std::cmp::min(bytes.len(), 512)]);
            anyhow!(
                "malformed llama-server HTTP response: missing header delimiter (\\r\\n\\r\\n). Received {} bytes: {:?}",
                bytes.len(),
                excerpt
            )
        })?;
    let header = std::str::from_utf8(&bytes[..header_end]).with_context(|| {
        let excerpt = String::from_utf8_lossy(&bytes[..std::cmp::min(bytes.len(), 512)]);
        format!(
            "invalid UTF-8 in HTTP response headers. Received {} bytes: {:?}",
            bytes.len(),
            excerpt
        )
    })?;
    let status = header
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| {
            let excerpt = String::from_utf8_lossy(&bytes[..std::cmp::min(bytes.len(), 512)]);
            anyhow!(
                "llama-server HTTP response omitted status line. Received {} bytes: {:?}",
                bytes.len(),
                excerpt
            )
        })?;
    let body = &bytes[header_end + 4..];
    let chunked = header.lines().skip(1).any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.trim().eq_ignore_ascii_case("transfer-encoding")
                && value
                    .split(',')
                    .any(|part| part.trim().eq_ignore_ascii_case("chunked"))
        })
    });
    let body = if chunked {
        decode_chunked(body, cap)?
    } else {
        body.to_vec()
    };
    Ok((status, body))
}

fn decode_chunked(mut input: &[u8], cap: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = input
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| anyhow!("malformed chunked llama-server response"))?;
        let size_text = std::str::from_utf8(&input[..line_end])?;
        let size_token = size_text.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_token, 16)
            .context("invalid chunk size in llama-server response")?;
        input = &input[line_end + 2..];
        if size == 0 {
            return Ok(out);
        }
        if size > input.len() || input.len().saturating_sub(size) < 2 {
            bail!("truncated chunked llama-server response");
        }
        if out.len().saturating_add(size) > cap {
            bail!("decoded llama-server HTTP body exceeded byte cap {cap}");
        }
        out.extend_from_slice(&input[..size]);
        if &input[size..size + 2] != b"\r\n" {
            bail!("malformed chunk terminator in llama-server response");
        }
        input = &input[size + 2..];
    }
}

#[cfg(not(unix))]
fn unix_http(
    _socket: &Path,
    _method: &str,
    _target: &str,
    _body: Option<&[u8]>,
    _timeout: Duration,
    _cap: usize,
) -> Result<(u16, Vec<u8>)> {
    bail!("Unix-domain llama-server transport is unavailable on this platform")
}

fn read_capped_drain<R: Read>(mut reader: R, cap: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        if out.len() < cap {
            let retain = (cap - out.len()).min(count);
            out.extend_from_slice(&buffer[..retain]);
        }
    }
    Ok(out)
}

fn hash_path(path: &Path) -> Result<String> {
    let mut file = crate::safeio::open_readonly_nofollow(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 1024 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn version_string(path: &Path) -> Option<String> {
    let mut command = crate::safeio::command_for_executable(path).ok()?;
    command
        .arg("--version")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    super::sandbox::configure_process_group(&mut command);
    let mut child = command.spawn().ok()?;
    let stdout = child.stdout.take()?;
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(read_capped_drain(stdout, 16 * 1024));
    });
    let started = Instant::now();
    loop {
        if child.try_wait().ok().flatten().is_some() {
            break;
        }
        if started.elapsed() > Duration::from_secs(5) {
            let _ = super::sandbox::terminate_process_tree(&mut child, Duration::from_millis(250));
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let bytes = rx.recv_timeout(Duration::from_secs(1)).ok()?.ok()?;
    let text = String::from_utf8_lossy(&bytes).trim().to_owned();
    if text.is_empty() {
        None
    } else {
        Some(text.chars().take(4096).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_props_parses_semantic_readiness_fields() {
        assert_eq!(
            verify_model_props(200, br#"{"model_loaded": true, "model": "model.gguf"}"#)
                .expect("loaded model"),
            ModelPropsCheck::Verified
        );
        assert!(verify_model_props(200, br#"{"model_loaded": false}"#).is_err());
        assert!(verify_model_props(200, br#"{"model": null}"#).is_err());
        assert!(verify_model_props(200, br#"{"model": ""}"#).is_err());
    }

    #[test]
    fn model_props_handles_errors_without_string_matching() {
        assert!(
            verify_model_props(200, br#"{"error": null, "nested": {"error": "metadata"}}"#).is_ok()
        );
        assert!(verify_model_props(200, br#"{"error": "load failed"}"#).is_err());
        assert!(verify_model_props(200, b"not-json").is_err());
    }

    #[test]
    fn model_props_tolerates_unsupported_endpoint_statuses() {
        assert_eq!(
            verify_model_props(404, b"not found").expect("404 compatibility"),
            ModelPropsCheck::Unsupported
        );
        assert_eq!(
            verify_model_props(405, b"method not allowed").expect("405 compatibility"),
            ModelPropsCheck::Unsupported
        );
        assert!(verify_model_props(503, b"loading").is_err());
    }
}
