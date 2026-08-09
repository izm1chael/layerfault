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

pub fn run_transformers(
    model: &Path,
    base: Option<&Path>,
    runtime_path: Option<&Path>,
    suite_path: Option<&Path>,
    seed: u64,
    limits: super::BehaviourLimits,
    active: super::ActiveExecutionOptions,
) -> Result<super::BehaviourReport> {
    super::sandbox::require_external_execution_stack()?;
    if active.allow_static_blocked || active.execute_custom_code {
        super::sandbox::require_high_risk_observation_stack()?;
    }
    super::static_admit(model, active.allow_static_blocked)?;
    if let Some(base) = base {
        super::static_admit(base, active.allow_static_blocked)?;
    }
    if model.is_file() {
        bail!("Transformers behavioural backend requires a local model package directory, not a standalone weight file");
    }

    let model_identity = if model.is_dir() {
        crate::package::fingerprint(model)?
    } else {
        crate::modelmeta::build_snapshot(model)?.identity.canonical
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
        model,
        base,
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

    let started = Instant::now();
    let mut child = command.spawn().with_context(|| {
        format!(
            "unable to start sandboxed Python runtime '{}'",
            executable.display()
        )
    })?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("Python runtime stdin pipe missing"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("Python runtime stdout pipe missing"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("Python runtime stderr pipe missing"))?;

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
        let _ = stderr_tx.send(read_capped(stderr, MAX_RUNNER_LOG_BYTES));
    });

    let runtime = super::RuntimeIdentity {
        backend: if base.is_some() && model.join("adapter_config.json").is_file() {
            "transformers-peft".to_owned()
        } else {
            "transformers-python".to_owned()
        },
        executable: executable.display().to_string(),
        executable_sha256: format!("sha256:{}", hash_path(&executable)?),
        version: version_string(&executable),
        sandbox: super::sandbox::capabilities(wrapper.as_ref()),
    };

    let mut executions = Vec::new();
    let mut request_id = 0_u64;
    let mut timed_out = false;
    let mut session_error: Option<String> = None;
    match recv_protocol(&line_rx, Duration::from_secs(limits.timeout_seconds.max(1))) {
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
        Err(error) => {
            timed_out = true;
            session_error = Some(format!("Transformers loader protocol failed: {error}"));
        }
    }

    'probes: {
        if session_error.is_none() {
            for probe in suite.probes.iter().take(limits.max_prompts) {
                let repeat = probe.repeat.max(1).min(limits.repeat_count.max(1));
                for repeat_index in 0..repeat {
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
                    if let Err(error) = writeln!(stdin, "{}", serde_json::to_string(&request)?)
                        .and_then(|_| stdin.flush())
                    {
                        session_error = Some(format!(
                            "unable to write Transformers probe request: {error}"
                        ));
                        break 'probes;
                    }
                    let request_started = Instant::now();
                    let response = match recv_protocol(
                        &line_rx,
                        Duration::from_secs(limits.timeout_seconds.max(1)),
                    ) {
                        Ok(value) => value,
                        Err(error) => {
                            timed_out = true;
                            session_error = Some(format!(
                                "sandboxed Transformers inference timed out/failed: {error}"
                            ));
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
        let _ = writeln!(stdin, "{}", serde_json::to_string(&json!({"op":"quit"}))?);
        let _ = stdin.flush();
    }
    drop(stdin);
    if session_error.is_some() {
        let _ = child.kill();
    }
    let deadline = Duration::from_secs(10);
    let wait_started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if wait_started.elapsed() >= deadline {
            let _ = child.kill();
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
    let telemetry = workspace.collect_telemetry(trace_enabled)?;
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
        prompt_sha256: super::sha256(b"runtime-side-effects"),
        response_sha256: super::sha256(side_effect_detail.as_bytes()),
        response_excerpt: super::bounded_excerpt(&side_effect_detail, 4096),
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        exit_code: status.code(),
        timed_out,
        telemetry,
        evaluation: telemetry_eval,
    });

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
    limits: super::BehaviourLimits,
    active: super::ActiveExecutionOptions,
) -> Result<super::DifferentialReport> {
    let base_report = run_transformers(
        base,
        None,
        runtime_path,
        suite_path,
        seed,
        limits.clone(),
        active,
    )?;
    let derived_base = derived
        .is_dir()
        .then(|| derived.join("adapter_config.json"))
        .filter(|path| path.is_file())
        .map(|_| base);
    let derived_report = run_transformers(
        derived,
        derived_base,
        runtime_path,
        suite_path,
        seed,
        limits,
        active,
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

fn read_capped<R: Read>(mut reader: R, cap: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buf)?;
        if read == 0 {
            break;
        }
        if out.len().saturating_add(read) > cap {
            bail!("Transformers runner stderr exceeded safety cap");
        }
        out.extend_from_slice(&buf[..read]);
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
import json
import os
import sys
import traceback

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

try:
    with contextlib.redirect_stdout(sys.stderr):
        import torch
        import transformers
        from transformers import AutoModelForCausalLM, AutoTokenizer
        torch.set_grad_enabled(False)
        try:
            torch.set_num_threads(max(1, min(4, os.cpu_count() or 1)))
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
        model = AutoModelForCausalLM.from_pretrained(
            source,
            local_files_only=True,
            trust_remote_code=args.trust_remote_code,
            torch_dtype="auto",
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
        with torch.no_grad(), contextlib.redirect_stdout(sys.stderr):
            generated = model.generate(
                **encoded,
                max_new_tokens=max_tokens,
                do_sample=False,
                pad_token_id=(tokenizer.eos_token_id if tokenizer.eos_token_id is not None else 0),
            )
        new_tokens = generated[0][input_len:]
        output = tokenizer.decode(new_tokens, skip_special_tokens=True)
        emit({"id": req.get("id"), "output": output})
    except Exception as exc:
        emit({"id": req.get("id") if isinstance(req, dict) else None, "error": str(exc), "trace": traceback.format_exc(limit=8)})
"#;
