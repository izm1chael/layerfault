//! Explicit local quantization reproduction and evidence.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read};
use std::path::Path;
use std::process::Stdio;
use std::sync::mpsc;
use std::time::{Duration, Instant};

const MAX_TOOL_OUTPUT: usize = 1024 * 1024;
const MAX_REPRODUCED_BYTES: u64 = 256 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantizationReproduction {
    pub requested: bool,
    pub supported: bool,
    pub tool_path: String,
    pub tool_sha256: String,
    pub tool_version: Option<String>,
    pub quantization: String,
    pub input_identity: String,
    pub produced_sha256: Option<String>,
    pub target_sha256: String,
    pub exact_match: bool,
    pub semantic_match: bool,
    pub status: String,
    pub reason: Option<String>,
    pub duration_ms: u64,
}

pub fn reproduce(base: &Path, target: &Path, quantizer: &Path, quantization: &str, timeout_seconds: u64) -> Result<QuantizationReproduction> {
    let base_snapshot = crate::modelmeta::build_snapshot(base)?;
    let target_snapshot = crate::modelmeta::build_snapshot(target)?;
    if base_snapshot.format != "gguf" || target_snapshot.format != "gguf" {
        bail!("strong llama-quantize reproduction currently requires GGUF base and GGUF target");
    }
    let qmeta = std::fs::symlink_metadata(quantizer).with_context(|| format!("unable to inspect quantizer '{}'", quantizer.display()))?;
    if qmeta.file_type().is_symlink() || !qmeta.is_file() { bail!("quantizer must be a regular non-symlink executable file"); }
    if quantization.trim().is_empty() || quantization.len() > 128 || !quantization.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c,'_'|'-'|'.')) { bail!("unsafe or invalid quantization identifier"); }
    let tool_sha = hash_path(quantizer)?;
    let version = bounded_version(quantizer);
    let root = std::env::temp_dir().join(format!("layerfault-quant-{}-{}", std::process::id(), crate::paths::now_unix()));
    crate::paths::ensure_private_dir(&root)?;
    let output = root.join("reproduced.gguf");
    let start = Instant::now();
    let result = run_tool(quantizer, base, &output, quantization, timeout_seconds.max(1));
    let elapsed = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let target_sha = target_snapshot.identity.artifact_sha256.clone().ok_or_else(|| anyhow!("target has no artifact SHA-256"))?;
    let mut record = QuantizationReproduction {
        requested:true,supported:true,tool_path:quantizer.display().to_string(),tool_sha256:format!("sha256:{tool_sha}"),tool_version:version,quantization:quantization.to_owned(),input_identity:base_snapshot.identity.canonical,produced_sha256:None,target_sha256:target_sha.clone(),exact_match:false,semantic_match:false,status:"NOT_REPRODUCIBLE".to_owned(),reason:None,duration_ms:elapsed,
    };
    match result {
        Ok(()) => {
            let metadata=std::fs::metadata(&output).context("quantizer did not produce output")?;
            if metadata.len()==0 || metadata.len()>MAX_REPRODUCED_BYTES { record.reason=Some("reproduced artifact size is outside safety bounds".to_owned()); }
            else {
                let produced=format!("sha256:{}",hash_path(&output)?);record.produced_sha256=Some(produced.clone());record.exact_match=produced.eq_ignore_ascii_case(&target_sha);
                let produced_snapshot=crate::modelmeta::build_snapshot(&output)?;
                record.semantic_match=produced_snapshot.tensor_schema_hash==target_snapshot.tensor_schema_hash&&produced_snapshot.architecture==target_snapshot.architecture;
                if record.exact_match {record.status="VERIFIED".to_owned();} else {record.reason=Some("reproduced quantization did not byte-match the supplied target".to_owned());}
            }
        }
        Err(error)=>record.reason=Some(error.to_string()),
    }
    let _=std::fs::remove_dir_all(root);
    Ok(record)
}

fn run_tool(exe:&Path,input:&Path,output:&Path,quantization:&str,timeout:u64)->Result<()> {
    let mut child=std::process::Command::new(exe).env_clear().env("HOME",std::env::temp_dir())
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .arg(input).arg(output).arg(quantization).spawn().with_context(||format!("unable to start quantizer '{}'",exe.display()))?;
    let stdout=child.stdout.take().ok_or_else(||anyhow!("quantizer stdout pipe missing"))?;let stderr=child.stderr.take().ok_or_else(||anyhow!("quantizer stderr pipe missing"))?;
    let (tx,rx)=mpsc::channel();let tx2=tx.clone();std::thread::spawn(move||{let _=tx.send(read_capped(stdout));});std::thread::spawn(move||{let _=tx2.send(read_capped(stderr));});
    let start=Instant::now();let status=loop{if let Some(s)=child.try_wait()?{break s;}
        if start.elapsed()>=Duration::from_secs(timeout){let _=child.kill();let _=child.wait();bail!("quantizer timed out after {timeout} seconds");}std::thread::sleep(Duration::from_millis(25));};
    let _=rx.recv_timeout(Duration::from_secs(2));let _=rx.recv_timeout(Duration::from_secs(2));
    if !status.success(){bail!("quantizer exited with status {}",status.code().map(|v|v.to_string()).unwrap_or_else(||"signal".to_owned()));}Ok(())
}
fn read_capped<R:Read>(mut reader:R)->Result<Vec<u8>>{let mut out=Vec::new();let mut buf=[0u8;8192];loop{let n=reader.read(&mut buf)?;if n==0{break;}
    if out.len().saturating_add(n)>MAX_TOOL_OUTPUT{bail!("tool output exceeded {MAX_TOOL_OUTPUT} byte cap");}out.extend_from_slice(&buf[..n]);}Ok(out)}
fn hash_path(path:&Path)->Result<String>{let mut file=crate::safeio::open_readonly_nofollow(path)?;let mut h=Sha256::new();let mut buf=[0u8;1024*1024];loop{let n=file.read(&mut buf)?;if n==0{break;}h.update(&buf[..n]);}Ok(hex::encode(h.finalize()))}
fn bounded_version(path:&Path)->Option<String>{let mut child=std::process::Command::new(path).arg("--version").env_clear().stdout(Stdio::piped()).stderr(Stdio::null()).spawn().ok()?;let stdout=child.stdout.take()?;let (tx,rx)=mpsc::channel();std::thread::spawn(move||{let _=tx.send(read_capped(stdout));});let start=Instant::now();loop{if child.try_wait().ok().flatten().is_some(){break;}
if start.elapsed()>Duration::from_secs(5){let _=child.kill();let _=child.wait();return None;}std::thread::sleep(Duration::from_millis(20));}let bytes=rx.recv_timeout(Duration::from_secs(1)).ok()?.ok()?;let text=String::from_utf8_lossy(&bytes).trim().to_owned();if text.is_empty(){None}else{Some(text.chars().take(4096).collect())}}
