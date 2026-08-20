//! Sandboxed Hugging Face Transformers/PEFT behavioural backend.
//!
//! This adapter never downloads dependencies or model content. It invokes a
//! local Python interpreter inside the same strong Bubblewrap boundary used by
//! the external llama.cpp backend, with network disabled and model/base paths
//! mounted read-only. `trust_remote_code=True` is only enabled by an explicit
//! operator option.

use anyhow::{anyhow, bail, Context, Result};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::mpsc;
use std::time::{Duration, Instant};

const PROTOCOL_PREFIX: &str = "LAYERFAULT_JSON:";
const MAX_RUNNER_LOG_BYTES: usize = 2 * 1024 * 1024;

/// When `recv_protocol` fails, the reader thread's channel disconnecting and
/// a genuine wall-clock timeout look identical from the channel's side alone
/// — both surface as "no line arrived in time". A process that was killed
/// (OOM, a host resource limit, a crash) closes its stdout immediately, so
/// the reader thread's sender drops right away rather than after the full
/// timeout window. Checking whether the child has *already* exited at the
/// moment of failure distinguishes "genuinely still running but slow" from
/// "already dead", which is exactly the ambiguity that previously made a
/// resource-limit kill get reported as an indistinguishable generic
/// timeout with no evidence of what actually happened.
fn describe_if_child_already_exited(child: &mut std::process::Child) -> Option<String> {
    let status = child.try_wait().ok().flatten()?;
    if status.success() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            let hint = if signal == 9 {
                " (SIGKILL — commonly an OOM kill or a host resource limit, not a wall-clock timeout)"
            } else {
                ""
            };
            return Some(format!(
                "sandboxed Transformers runtime process already exited, killed by signal {signal}{hint}, before a response arrived"
            ));
        }
    }
    Some(format!(
        "sandboxed Transformers runtime process already exited ({:?}) before a response arrived",
        status.code()
    ))
}

/// CPU-only Transformers inference (no CUDA/ROCm tooling detected) is
/// meaningfully slower than the profile timeouts were sized for, and that
/// is expected computation, not a hang — a probe genuinely still inside
/// `generate()`'s forward pass, confirmed via `faulthandler` stack dumps,
/// should not be killed as if it were stuck. Scale the wall-clock budget up
/// on CPU-only hosts rather than raising every profile's timeout globally.
/// CPU-only hosts scale from available cores. The environment override takes
/// precedence when hardware-specific tuning is needed.
fn effective_timeout_seconds(base_seconds: u64) -> u64 {
    let multiplier: f64 = std::env::var("LAYERFAULT_BEHAVIOUR_CPU_TIMEOUT_MULTIPLIER")
        .ok()
        .and_then(|value| value.parse().ok())
        .map(|value: f64| value.clamp(1.0, 10.0))
        .unwrap_or_else(|| {
            let has_gpu = crate::sources::find_executable("nvidia-smi").is_some()
                || crate::sources::find_executable("rocm-smi").is_some();
            if has_gpu {
                1.0
            } else {
                let cores = std::thread::available_parallelism()
                    .map(|value| value.get())
                    .unwrap_or(1) as f64;
                // Avoid scaling above 1x on hosts with at least eight cores.
                (8.0 / cores).clamp(1.0, 6.0)
            }
        });
    ((base_seconds as f64) * multiplier).round() as u64
}

pub fn run_transformers(
    model: &Path,
    base: Option<&Path>,
    runtime_path: Option<&Path>,
    suite_path: Option<&Path>,
    seed: u64,
    mut limits: super::BehaviourLimits,
    active: super::ActiveExecutionOptions,
) -> Result<super::BehaviourReport> {
    limits.timeout_seconds = effective_timeout_seconds(limits.timeout_seconds);
    let deadline = super::CommandDeadline::new(limits.timeout_seconds);
    run_transformers_deadline(
        model,
        base,
        runtime_path,
        suite_path,
        seed,
        limits,
        active,
        &deadline,
        "model",
    )
}

#[allow(clippy::too_many_arguments)]
fn run_transformers_deadline(
    model: &Path,
    base: Option<&Path>,
    runtime_path: Option<&Path>,
    suite_path: Option<&Path>,
    seed: u64,
    limits: super::BehaviourLimits,
    active: super::ActiveExecutionOptions,
    deadline: &super::CommandDeadline,
    phase_label: &str,
) -> Result<super::BehaviourReport> {
    let heartbeat = super::ProgressHeartbeat::start(phase_label);
    heartbeat.update(format!("phase={phase_label} static-admission"));
    // Resolved before any sandboxed execution starts: an explicitly
    // requested but unavailable eBPF backend must fail fast. `degraded` is
    // recorded on every execution's telemetry below.
    let telemetry_resolution = super::telemetry_backend::resolve(active.telemetry_backend)?;
    let backend = super::sandbox::get_backend(active.sandbox_kind, active.microvm_config.clone());
    backend.require_execution_stack(active.clone())?;
    super::static_admit(model, active.allow_static_blocked)?;
    if let Some(base) = base {
        super::static_admit(base, active.allow_static_blocked)?;
    }
    if model.is_file() {
        bail!("Transformers behavioural backend requires a local model package directory, not a standalone weight file");
    }

    let model_report = crate::package::inspect(model)?;
    let model_identity = model_report.fingerprint.clone();
    let staged_model = crate::binding::stage_verified_package(model, &model_report)?;
    let staged_base = if let Some(base_path) = base {
        let base_report = crate::package::inspect(base_path)?;
        Some(crate::binding::stage_verified_package(
            base_path,
            &base_report,
        )?)
    } else {
        None
    };

    let suite = super::probes::expand_mutations(
        super::probes::load_suite(suite_path)?,
        limits.max_mutations,
    );
    let executable_candidate = match runtime_path {
        Some(path) => path.to_path_buf(),
        None => crate::sources::find_executable("python3")
            .or_else(|| crate::sources::find_executable("python"))
            .ok_or_else(|| anyhow!("Python runtime was not found on PATH"))?,
    };
    let runtime_support = python_site_packages(&executable_candidate);
    let executable = std::fs::canonicalize(&executable_candidate).with_context(|| {
        format!(
            "unable to canonicalize Python runtime '{}'",
            executable_candidate.display()
        )
    })?;
    let metadata = std::fs::metadata(&executable).with_context(|| {
        format!(
            "unable to inspect Python runtime '{}'",
            executable.display()
        )
    })?;
    if !metadata.is_file() {
        bail!("Python runtime must resolve to a regular file");
    }
    let wrapper = super::sandbox::detect_network_wrapper();
    if wrapper.is_none() {
        bail!(
            "Transformers behaviour requires the strong Bubblewrap sandbox; bwrap is unavailable"
        );
    }

    let canary_a = super::synthetic_canary(&model_identity, seed, "A");
    let canary_b = super::synthetic_canary(&model_identity, seed, "B");
    let workspace = super::sandbox::Workspace::create(&[&canary_a, &canary_b])?;
    let runner_path = workspace
        .root
        .join("workspace")
        .join("layerfault_transformers_runner.py");
    std::fs::write(&runner_path, RUNNER)?;

    let sandboxed = super::sandbox::command_for(
        &executable,
        staged_model.path(),
        staged_base.as_ref().map(|b| b.path()),
        &runtime_support,
        &workspace,
        wrapper.as_ref(),
        limits.timeout_seconds,
    )?;
    let super::sandbox::SandboxedCommand {
        mut command,
        model_argument,
        base_argument,
        runtime_support_arguments,
        trace_enabled,
        pinned_inputs: _pinned_inputs,
    } = sandboxed;
    command
        .env_clear()
        .env("HOME", &workspace.home)
        .env("TMPDIR", &workspace.root)
        .env("HF_HUB_OFFLINE", "1")
        .env("TRANSFORMERS_OFFLINE", "1")
        .env("TOKENIZERS_PARALLELISM", "false")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("PYTHONNOUSERSITE", "1")
        .env("LAYERFAULT_SYNTHETIC_SECRET_A", &canary_a)
        .env("LAYERFAULT_SYNTHETIC_SECRET_B", &canary_b);
    if !runtime_support_arguments.is_empty() {
        let python_path = runtime_support_arguments
            .iter()
            .map(|path| path.to_string_lossy())
            .collect::<Vec<_>>()
            .join(":");
        command.env("PYTHONPATH", python_path);
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .arg("/workspace/workspace/layerfault_transformers_runner.py")
        .arg("--model")
        .arg(&model_argument);
    if let Some(base_argument) = base_argument.as_ref() {
        command.arg("--base").arg(base_argument);
    }
    if active.execute_custom_code {
        command.arg("--trust-remote-code");
    }

    if deadline.expired() {
        bail!("behaviour command hard total timeout expired before Transformers model load");
    }
    let admitted_runtime_sha256 = hash_path(&executable)?;
    let admitted_runtime_version = version_string(&executable);
    // Version discovery is part of admission; byte-bind the executable again
    // because invoking --version is a separate filesystem/open boundary.
    if hash_path(&executable)? != admitted_runtime_sha256 {
        bail!("Python runtime executable changed during version admission");
    }
    heartbeat.update(format!("phase={phase_label} model-loading"));
    let started = Instant::now();
    // Revalidate the exact executable bytes and staged packages immediately before launch.
    if hash_path(&executable)? != admitted_runtime_sha256 {
        bail!("Python runtime executable changed immediately before guarded launch");
    }
    staged_model.revalidate()?;
    if let Some(b) = staged_base.as_ref() {
        b.revalidate()?;
    }
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
            host_fs.clone(),
            &cgroup_caps,
            &limits_cfg,
            "python",
        ) {
            Ok(guard) => Some(guard),
            Err(err) if active.require_cgroup => return Err(err),
            Err(_) => None,
        }
    } else {
        None
    };

    let mut child = command.spawn().with_context(|| {
        format!(
            "unable to start sandboxed Python runtime '{}'",
            executable.display()
        )
    })?;
    if let Some(guard) = cgroup_guard.as_ref() {
        if let Err(err) = guard.attach_process(child.id()) {
            if active.require_cgroup {
                let _ = super::sandbox::terminate_process_tree(&mut child, Duration::from_secs(1));
                return Err(err);
            }
            cgroup_guard = None;
        }
    }
    let mut stdin = match child.stdin.take() {
        Some(value) => value,
        None => {
            let _ = super::sandbox::terminate_process_tree(&mut child, Duration::from_secs(1));
            bail!("Python runtime stdin pipe missing");
        }
    };
    let stdout = match child.stdout.take() {
        Some(value) => value,
        None => {
            let _ = super::sandbox::terminate_process_tree(&mut child, Duration::from_secs(1));
            bail!("Python runtime stdout pipe missing");
        }
    };
    let stderr = match child.stderr.take() {
        Some(value) => value,
        None => {
            let _ = super::sandbox::terminate_process_tree(&mut child, Duration::from_secs(1));
            bail!("Python runtime stderr pipe missing");
        }
    };

    let (line_tx, line_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut total = 0_usize;
        for line in BufReader::new(stdout).lines() {
            let result = line.map_err(anyhow::Error::from).and_then(|line| {
                total = total.saturating_add(line.len());
                if total > MAX_RUNNER_LOG_BYTES {
                    Err(anyhow!("Transformers runner stdout exceeded safety cap"))
                } else {
                    Ok(line)
                }
            });
            let done = result.is_err();
            if line_tx.send(result).is_err() || done {
                break;
            }
        }
    });
    let (stderr_tx, stderr_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = stderr_tx.send(read_capped_drain(stderr, MAX_RUNNER_LOG_BYTES));
    });

    let sandbox_caps = super::sandbox::capabilities(wrapper.as_ref());
    let closure = super::closure::discover_runtime_closure(
        "transformers",
        &executable,
        active.closure_level,
        &sandbox_caps,
        &runtime_support,
        None,
    );

    let runtime = super::RuntimeIdentity {
        backend: if base.is_some() && model.join("adapter_config.json").is_file() {
            "transformers-peft".to_owned()
        } else {
            "transformers-python".to_owned()
        },
        executable: executable.display().to_string(),
        executable_sha256: format!("sha256:{admitted_runtime_sha256}"),
        version: admitted_runtime_version,
        sandbox: sandbox_caps,
        closure: Some(closure),
    };

    let mut executions = Vec::new();
    let mut request_id = 0_u64;
    let mut timed_out = false;
    let mut session_error: Option<String> = None;
    // Model loading gets its own budget, starting now rather than inheriting
    // whatever this run has already spent on admission/staging/spawn. A slow
    // load must not eat into the time probes get, and a probe must not be
    // charged for time the model spent loading.
    let startup_deadline = deadline.phase(limits.timeout_seconds);
    match recv_protocol(&line_rx, startup_deadline.remaining()) {
        Ok(ready) => {
            if !ready
                .get("ready")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
            {
                session_error = Some(
                    ready
                        .get("error")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("Transformers runner failed to initialize")
                        .to_owned(),
                );
            }
        }
        Err(error) => match describe_if_child_already_exited(&mut child) {
            Some(exit_reason) => {
                session_error = Some(exit_reason);
            }
            None => {
                timed_out = true;
                session_error = Some(format!("Transformers loader protocol failed: {error}"));
            }
        },
    }

    // Probe execution gets a fresh budget of its own, starting only once the
    // model actually reported ready — this is what makes model-load time
    // stop counting against probe time. Still bounded by whatever remains of
    // the outer/overall behavioural deadline, so the two phases together
    // can never exceed it.
    let probe_deadline = deadline.phase(limits.timeout_seconds);
    if session_error.is_none() {
        heartbeat.update(format!("phase={phase_label} model-loaded"));
    }
    let planned = suite
        .probes
        .iter()
        .take(limits.max_prompts)
        .map(|probe| probe.repeat.max(1).min(limits.repeat_count.max(1)))
        .sum::<usize>();
    let mut probe_index = 0usize;

    'probes: {
        if session_error.is_none() {
            for probe in suite.probes.iter().take(limits.max_prompts) {
                let repeat = probe.repeat.max(1).min(limits.repeat_count.max(1));
                for repeat_index in 0..repeat {
                    if probe_deadline.expired() {
                        timed_out = true;
                        session_error = Some("behaviour command hard total timeout expired before Transformers probe".to_owned());
                        break 'probes;
                    }
                    probe_index = probe_index.saturating_add(1);
                    heartbeat.update(format!(
                        "phase={phase_label} probe={probe_index}/{planned} id={}",
                        probe.id
                    ));
                    let system = super::probes::render(&probe.system, &canary_a, &canary_b);
                    let prompt = super::probes::render(&probe.prompt, &canary_a, &canary_b);
                    let combined =
                        format!("<system>\n{system}\n</system>\n<user>\n{prompt}\n</user>");
                    request_id = request_id.saturating_add(1);
                    let request = json!({
                        "op":"generate",
                        "id":request_id,
                        "system":system,
                        "prompt":prompt,
                        "combined":combined,
                        "seed":seed.saturating_add(repeat_index as u64),
                        "max_tokens":limits.max_tokens,
                    });
                    let request_line = match serde_json::to_string(&request) {
                        Ok(value) => value,
                        Err(error) => {
                            session_error = Some(format!(
                                "unable to serialize Transformers probe request: {error}"
                            ));
                            break 'probes;
                        }
                    };
                    if let Err(error) =
                        writeln!(stdin, "{request_line}").and_then(|_| stdin.flush())
                    {
                        session_error = Some(format!(
                            "unable to write Transformers probe request: {error}"
                        ));
                        break 'probes;
                    }
                    let request_started = Instant::now();
                    let response = match recv_protocol(&line_rx, probe_deadline.remaining()) {
                        Ok(value) => value,
                        Err(error) => {
                            match describe_if_child_already_exited(&mut child) {
                                Some(exit_reason) => {
                                    session_error =
                                        Some(format!("{exit_reason} (probe '{}')", probe.id));
                                }
                                None => {
                                    timed_out = true;
                                    session_error = Some(format!(
                                        "sandboxed Transformers inference timed out/failed on probe '{}': {error}",
                                        probe.id
                                    ));
                                }
                            }
                            break 'probes;
                        }
                    };
                    if response.get("id").and_then(serde_json::Value::as_u64) != Some(request_id) {
                        session_error = Some(
                            "Transformers runner returned an out-of-order protocol response"
                                .to_owned(),
                        );
                        break 'probes;
                    }
                    if let Some(error) = response.get("error").and_then(serde_json::Value::as_str) {
                        session_error =
                            Some(format!("sandboxed Transformers inference failed: {error}"));
                        break 'probes;
                    }
                    let output = response
                        .get("output")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("");
                    if output.len() > limits.max_output_bytes {
                        session_error = Some(
                            "sandboxed Transformers response exceeded selected output cap"
                                .to_owned(),
                        );
                        break 'probes;
                    }
                    let evaluation =
                        super::evaluate::evaluate(&probe.category, output, &[&canary_a, &canary_b]);
                    executions.push(super::ProbeExecution {
                        probe_id: probe.id.clone(),
                        category: probe.category.clone(),
                        comparison_group: probe.comparison_group.clone(),
                        comparison_role: probe.comparison_role.clone(),
                        expected_boundary: probe.expected_boundary.clone(),
                        prompt_sha256: super::sha256(combined.as_bytes()),
                        response_sha256: super::sha256(output.as_bytes()),
                        response_excerpt: super::bounded_excerpt(output, 4096),
                        duration_ms: u64::try_from(request_started.elapsed().as_millis())
                            .unwrap_or(u64::MAX),
                        exit_code: Some(0),
                        timed_out: false,
                        telemetry: super::sandbox::SandboxTelemetry::default(),
                        evaluation,
                    });
                }
            }
        }
    }

    if session_error.is_none() {
        let _ = writeln!(stdin, "{{\"op\":\"quit\"}}");
        let _ = stdin.flush();
    }
    drop(stdin);
    heartbeat.update(format!("phase={phase_label} teardown"));
    if session_error.is_some() || deadline.expired() {
        let _ = super::sandbox::terminate_process_tree(&mut child, Duration::from_secs(2));
    }
    let wait_started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if wait_started.elapsed() >= Duration::from_secs(2) || deadline.expired() {
            super::sandbox::terminate_process_tree(&mut child, Duration::from_secs(2))?;
            break child.wait()?;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let stderr_text = stderr_rx
        .recv_timeout(Duration::from_secs(2))
        .ok()
        .and_then(|value| value.ok())
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default();
    if !status.success() && session_error.is_none() {
        session_error = Some(format!(
            "sandboxed Transformers runtime exited unsuccessfully ({:?})",
            status.code()
        ));
    }
    let mut telemetry = workspace.collect_telemetry(
        trace_enabled,
        wrapper.as_ref().map(|(path, _)| path.as_path()),
    )?;
    if let Some(mut guard) = cgroup_guard {
        let mut cg_telemetry = guard.collect_telemetry();
        cg_telemetry.cleanup_state = guard.teardown();
        // Kernel-attributed resource-limit evidence is authoritative and
        // strictly more specific than a generic "protocol timed out"
        // guess. When the runner's stdout pipe closes because the kernel
        // killed the process (OOM or pids.max), `recv_protocol` cannot
        // distinguish that from a genuine wall-clock timeout — both
        // surface as the reader thread's channel disconnecting — so a
        // real OOM/pids kill was previously being reported and recorded
        // as `timed_out=true` with no memory-limit evidence at all. Once
        // the cgroup confirms a resource-limit kill, that replaces any
        // earlier generic timeout/exit-failure guess and `timed_out` is
        // corrected: the run did not exceed its time budget, it was
        // killed by a resource limit.
        if cg_telemetry.oom_kill_events > 0 || cg_telemetry.oom_events > 0 {
            session_error = Some(format!(
                "cgroup v2 memory limit exceeded (OOM killed); {} oom_kill event(s), {} oom event(s)",
                cg_telemetry.oom_kill_events, cg_telemetry.oom_events
            ));
            timed_out = false;
        } else if cg_telemetry.pids_events_max > 0 {
            session_error = Some(format!(
                "cgroup v2 process limit exceeded (pids.max); {} event(s)",
                cg_telemetry.pids_events_max
            ));
            timed_out = false;
        }
        telemetry.cgroup = Some(cg_telemetry);
    }
    let mut telemetry_eval = super::evaluate::evaluate_runtime(
        "runtime_side_effects",
        "",
        &stderr_text,
        &[&canary_a, &canary_b],
        &telemetry,
    );
    if let Some(error) = session_error.as_ref() {
        telemetry_eval.risk = telemetry_eval.risk.max(super::evaluate::Risk::Medium);
        telemetry_eval
            .rule_ids
            .push("LF-BEHAV-RUNTIME-FAILURE".to_owned());
        telemetry_eval.indicators.push(format!(
            "sandboxed runtime failed during active analysis: {error}"
        ));
        telemetry_eval.rule_ids.sort();
        telemetry_eval.rule_ids.dedup();
        telemetry_eval.indicators.sort();
        telemetry_eval.indicators.dedup();
    }
    let side_effect_detail = match session_error {
        Some(error) if stderr_text.is_empty() => error,
        Some(error) => format!("{error}\n{stderr_text}"),
        None => stderr_text,
    };
    executions.push(super::ProbeExecution {
        probe_id: "runtime-side-effects".to_owned(),
        category: "runtime_side_effects".to_owned(),
        comparison_group: None,
        comparison_role: None,
        expected_boundary: None,
        prompt_sha256: super::sha256(b"runtime-side-effects"),
        response_sha256: super::sha256(side_effect_detail.as_bytes()),
        response_excerpt: super::bounded_excerpt(&side_effect_detail, 4096),
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        exit_code: status.code(),
        timed_out,
        telemetry,
        evaluation: telemetry_eval,
    });

    for execution in &mut executions {
        execution.telemetry.backend_degraded = telemetry_resolution.degraded.clone();
    }

    super::finalize_report(
        model_identity,
        model.display().to_string(),
        runtime,
        suite,
        seed,
        limits,
        executions,
    )
}

pub fn compare_transformers(
    base: &Path,
    derived: &Path,
    runtime_path: Option<&Path>,
    suite_path: Option<&Path>,
    seed: u64,
    mut limits: super::BehaviourLimits,
    active: super::ActiveExecutionOptions,
) -> Result<super::DifferentialReport> {
    limits.timeout_seconds = effective_timeout_seconds(limits.timeout_seconds);
    let deadline = super::CommandDeadline::new(limits.timeout_seconds);
    let base_report = run_transformers_deadline(
        base,
        None,
        runtime_path,
        suite_path,
        seed,
        limits.clone(),
        active.clone(),
        &deadline,
        "base",
    )?;
    if deadline.expired() {
        bail!("behaviour comparison hard total timeout expired after base Transformers model");
    }
    let derived_base = derived
        .is_dir()
        .then(|| derived.join("adapter_config.json"))
        .filter(|path| path.is_file())
        .map(|_| base);
    let derived_report = run_transformers_deadline(
        derived,
        derived_base,
        runtime_path,
        suite_path,
        seed,
        limits,
        active,
        &deadline,
        "derived",
    )?;
    super::compare_reports(base_report, derived_report)
}

fn python_site_packages(runtime: &Path) -> Vec<PathBuf> {
    let Some(bin_dir) = runtime.parent() else {
        return Vec::new();
    };
    if bin_dir.file_name().and_then(|value| value.to_str()) != Some("bin") {
        return Vec::new();
    }
    let Some(root) = bin_dir.parent() else {
        return Vec::new();
    };
    if !root.join("pyvenv.cfg").is_file() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for library_root in [root.join("lib"), root.join("lib64")] {
        let Ok(entries) = std::fs::read_dir(library_root) else {
            continue;
        };
        for entry in entries.filter_map(|entry| entry.ok()) {
            let name = entry.file_name();
            if !name.to_string_lossy().starts_with("python") {
                continue;
            }
            let site_packages = entry.path().join("site-packages");
            if site_packages.is_dir() {
                out.push(site_packages);
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn recv_protocol(
    rx: &mpsc::Receiver<Result<String>>,
    timeout: Duration,
) -> Result<serde_json::Value> {
    let started = Instant::now();
    loop {
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            bail!("Transformers runner protocol timed out");
        }
        let line = rx
            .recv_timeout(remaining)
            .map_err(|_| anyhow!("Transformers runner protocol timed out"))??;
        let Some(payload) = line.strip_prefix(PROTOCOL_PREFIX) else {
            continue;
        };
        return serde_json::from_str(payload).context("invalid Transformers runner protocol JSON");
    }
}

fn read_capped_drain<R: Read>(mut reader: R, cap: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        if out.len() < cap {
            let retain = (cap - out.len()).min(read);
            out.extend_from_slice(&buf[..retain]);
        }
    }
    Ok(out)
}

fn hash_path(path: &Path) -> Result<String> {
    let mut file = crate::safeio::open_readonly_nofollow(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn version_string(path: &Path) -> Option<String> {
    let output = std::process::Command::new(path)
        .arg("--version")
        .env_clear()
        .output()
        .ok()?;
    let value = if output.stdout.is_empty() {
        output.stderr
    } else {
        output.stdout
    };
    let text = String::from_utf8_lossy(&value).trim().to_owned();
    (!text.is_empty()).then(|| text.chars().take(4096).collect())
}

const RUNNER: &str = r#"
import argparse
import contextlib
import faulthandler
import json
import os
import sys
import traceback

GENERATE_STALL_DUMP_SECONDS = 20

PREFIX = "LAYERFAULT_JSON:"

def emit(value):
    sys.__stdout__.write(PREFIX + json.dumps(value, ensure_ascii=False) + "\n")
    sys.__stdout__.flush()

parser = argparse.ArgumentParser(add_help=False)
parser.add_argument("--model", required=True)
parser.add_argument("--base")
parser.add_argument("--trust-remote-code", action="store_true")
args = parser.parse_args()

os.environ["HF_HUB_OFFLINE"] = "1"
os.environ["TRANSFORMERS_OFFLINE"] = "1"
os.environ["TOKENIZERS_PARALLELISM"] = "false"
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
# Avoid torch.compile JIT warmup cost, which never pays off in this
# short-lived, few-forward-pass probe session.
os.environ["TORCHDYNAMO_DISABLE"] = "1"

try:
    with contextlib.redirect_stdout(sys.stderr):
        import torch
        import transformers
        from transformers import AutoModelForCausalLM, AutoTokenizer
        torch.set_grad_enabled(False)
        try:
            torch._dynamo.config.disable = True
        except Exception:
            pass
        try:
            torch.set_num_threads(max(1, min(8, os.cpu_count() or 1)))
        except Exception:
            pass

        is_adapter = os.path.isdir(args.model) and os.path.isfile(os.path.join(args.model, "adapter_config.json"))
        source = args.base if is_adapter else args.model
        if is_adapter and not args.base:
            raise RuntimeError("PEFT adapter requires a local --base package")
        tokenizer = AutoTokenizer.from_pretrained(
            source,
            local_files_only=True,
            trust_remote_code=args.trust_remote_code,
        )
        # bf16-on-CPU is usually slower than fp32 (software-emulated or
        # upcast anyway on most x86 CPUs), so only use "auto" on GPU.
        dtype_kwarg = "auto"
        if not torch.cuda.is_available():
            dtype_kwarg = torch.float32
        model = AutoModelForCausalLM.from_pretrained(
            source,
            local_files_only=True,
            trust_remote_code=args.trust_remote_code,
            torch_dtype=dtype_kwarg,
        )
        if is_adapter:
            from peft import PeftModel
            model = PeftModel.from_pretrained(model, args.model, local_files_only=True)
        model.eval()
    emit({"ready": True, "transformers": getattr(transformers, "__version__", None), "torch": getattr(torch, "__version__", None), "adapter": is_adapter})
except Exception as exc:
    emit({"ready": False, "error": str(exc), "trace": traceback.format_exc(limit=8)})
    sys.exit(2)

for raw in sys.stdin:
    try:
        req = json.loads(raw)
        if req.get("op") == "quit":
            break
        if req.get("op") != "generate":
            emit({"id": req.get("id"), "error": "unsupported operation"})
            continue
        seed = int(req.get("seed", 0))
        max_tokens = max(1, min(int(req.get("max_tokens", 256)), 4096))
        system = str(req.get("system", ""))
        prompt = str(req.get("prompt", ""))
        combined = str(req.get("combined", prompt))
        rendered = combined
        try:
            if getattr(tokenizer, "chat_template", None):
                rendered = tokenizer.apply_chat_template(
                    [
                        {"role": "system", "content": system},
                        {"role": "user", "content": prompt},
                    ],
                    tokenize=False,
                    add_generation_prompt=True,
                )
        except Exception:
            rendered = combined
        torch.manual_seed(seed)
        encoded = tokenizer(
            rendered,
            return_tensors="pt",
            truncation=True,
            max_length=4096,
        )
        input_len = int(encoded["input_ids"].shape[-1])
        faulthandler.dump_traceback_later(GENERATE_STALL_DUMP_SECONDS, exit=False, file=sys.stderr)
        try:
            with torch.no_grad(), contextlib.redirect_stdout(sys.stderr):
                generated = model.generate(
                    **encoded,
                    max_new_tokens=max_tokens,
                    do_sample=False,
                    pad_token_id=(tokenizer.eos_token_id if tokenizer.eos_token_id is not None else 0),
                )
        finally:
            faulthandler.cancel_dump_traceback_later()
        new_tokens = generated[0][input_len:]
        output = tokenizer.decode(new_tokens, skip_special_tokens=True)
        emit({"id": req.get("id"), "output": output})
    except Exception as exc:
        emit({"id": req.get("id") if isinstance(req, dict) else None, "error": str(exc), "trace": traceback.format_exc(limit=8)})
"#;

#[cfg(test)]
mod protocol_tests {
    use super::*;

    fn spawn_feeder(lines: Vec<String>) -> mpsc::Receiver<Result<String>> {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in lines {
                if tx.send(Ok(line)).is_err() {
                    break;
                }
            }
            // Sender dropped here, matching a runner whose stdout closed
            // (process exited) once every queued line has been delivered.
        });
        rx
    }

    #[test]
    fn recv_protocol_skips_non_protocol_lines_and_returns_the_tagged_payload() {
        // Human-readable Hugging Face progress/log noise on the same
        // stream, ahead of the one machine-readable protocol line, must not
        // be mistaken for the response.
        let rx = spawn_feeder(vec![
            "Downloading shards: 100%|##########| 2/2".to_owned(),
            format!("{PROTOCOL_PREFIX}{{\"ready\":true}}"),
        ]);
        let value = recv_protocol(&rx, Duration::from_secs(2)).expect("parse ready");
        assert_eq!(value.get("ready").and_then(|v| v.as_bool()), Some(true));
    }

    #[test]
    fn recv_protocol_reports_a_response_matching_its_own_request_id() {
        let rx = spawn_feeder(vec![format!(
            "{PROTOCOL_PREFIX}{{\"id\":7,\"output\":\"hello\"}}"
        )]);
        let value = recv_protocol(&rx, Duration::from_secs(2)).expect("parse response");
        assert_eq!(value.get("id").and_then(|v| v.as_u64()), Some(7));
        assert_eq!(value.get("output").and_then(|v| v.as_str()), Some("hello"));
    }

    #[test]
    fn recv_protocol_returns_a_structured_error_on_malformed_json() {
        let rx = spawn_feeder(vec![format!("{PROTOCOL_PREFIX}{{not valid json")]);
        let error = recv_protocol(&rx, Duration::from_secs(2))
            .expect_err("malformed protocol payload must not parse as a response");
        assert!(error
            .to_string()
            .contains("invalid Transformers runner protocol JSON"));
    }

    #[test]
    fn recv_protocol_returns_a_structured_error_when_the_runner_exits_before_responding() {
        // Sender thread finishes (simulating stdout EOF / runner process
        // exit) without ever producing a protocol line.
        let rx = spawn_feeder(vec!["some trailing log output".to_owned()]);
        let error = recv_protocol(&rx, Duration::from_secs(2))
            .expect_err("a runner that exits mid-probe without responding must be a structured error, not a hang or a fabricated success");
        assert!(error.to_string().contains("timed out"));
    }

    #[test]
    fn recv_protocol_times_out_rather_than_blocking_forever_on_a_stalled_runner() {
        let (_tx, rx) = mpsc::channel::<Result<String>>();
        // Nothing is ever sent; the channel just stays open with no data,
        // modelling a runner that hung mid-probe.
        let started = Instant::now();
        let error = recv_protocol(&rx, Duration::from_millis(150))
            .expect_err("a stalled runner must time out, not hang indefinitely");
        assert!(error.to_string().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[cfg(unix)]
    #[test]
    fn describe_if_child_already_exited_returns_none_while_the_process_is_still_running() {
        let mut child = std::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .expect("spawn sleep");
        assert!(
            describe_if_child_already_exited(&mut child).is_none(),
            "a still-running process must not be reported as already exited"
        );
        let _ = child.kill();
        let _ = child.wait();
    }

    #[cfg(unix)]
    #[test]
    fn describe_if_child_already_exited_identifies_a_sigkilled_process_by_signal() {
        // Model the real bug: a process killed out-of-band (OOM, a host
        // resource limit) closes its stdout immediately, well before any
        // timeout elapses. `recv_protocol` alone cannot tell that apart
        // from a slow-but-alive process; checking whether the child has
        // already exited — and by which signal — can.
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        // SIGKILL it directly, bypassing our own graceful-termination path,
        // to model an external kill (e.g. the kernel OOM killer).
        let pid = child.id();
        let _ = std::process::Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .status();
        // Give the kernel a moment to deliver the signal before checking.
        for _ in 0..50 {
            if child.try_wait().ok().flatten().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let description = describe_if_child_already_exited(&mut child)
            .expect("a SIGKILLed process must be reported as already exited");
        assert!(description.contains("signal 9"));
        assert!(description.contains("OOM"));
        let _ = child.wait();
    }

    #[cfg(unix)]
    #[test]
    fn describe_if_child_already_exited_reports_a_clean_exit_without_an_oom_hint() {
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn true");
        for _ in 0..50 {
            if child.try_wait().ok().flatten().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        // `true` exits 0 successfully; that is not evidence of a runner
        // failure, so this must not be reported as an exit reason at all.
        assert!(describe_if_child_already_exited(&mut child).is_none());
        let _ = child.wait();
    }

    const TIMEOUT_MULTIPLIER_ENV: &str = "LAYERFAULT_BEHAVIOUR_CPU_TIMEOUT_MULTIPLIER";

    // Both cases live in one test: the env var is process-global, and Rust
    // runs tests in parallel by default, so two tests mutating it
    // independently would race each other.
    #[test]
    fn timeout_multiplier_override_is_applied_clamped_and_falls_back_on_invalid_input() {
        std::env::set_var(TIMEOUT_MULTIPLIER_ENV, "2");
        assert_eq!(effective_timeout_seconds(100), 200);

        std::env::set_var(TIMEOUT_MULTIPLIER_ENV, "1000");
        assert_eq!(
            effective_timeout_seconds(100),
            1000,
            "multiplier must clamp to 10x, not apply unbounded"
        );

        std::env::set_var(TIMEOUT_MULTIPLIER_ENV, "not-a-number");
        let scaled = effective_timeout_seconds(100);
        // Falls back to the host-detected default without ignoring the base.
        assert!((100..=600).contains(&scaled));

        std::env::remove_var(TIMEOUT_MULTIPLIER_ENV);
    }
}
