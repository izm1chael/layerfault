use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct RuntimeResult { pub stdout:String, pub stderr:String, pub exit_code:Option<i32>, pub timed_out:bool, pub duration_ms:u64 }

pub struct RuntimeAdapter { executable:PathBuf, limits:super::BehaviourLimits, wrapper:Option<(PathBuf,String)> }
impl RuntimeAdapter {
    pub fn new(executable:PathBuf, limits:&super::BehaviourLimits)->Result<Self>{
        let metadata=std::fs::symlink_metadata(&executable).with_context(||format!("unable to inspect runtime '{}'",executable.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file(){bail!("runtime must be a regular non-symlink file");}
        let wrapper=super::sandbox::detect_network_wrapper();
        // Standard/deep/research behavioural security requires an enforceable no-network boundary on Linux.
        #[cfg(target_os="linux")]
        if wrapper.is_none() { bail!("no supported network-isolation mechanism (bwrap/unshare) is available; behaviour NOT_RUN rather than silently weakening the sandbox"); }
        Ok(Self{executable,limits:limits.clone(),wrapper})
    }
    pub fn identity(&self)->Result<super::RuntimeIdentity>{
        let sha=hash_path(&self.executable)?;
        let version=version_string(&self.executable);
        Ok(super::RuntimeIdentity{backend:"llama-cpp".to_owned(),executable:self.executable.display().to_string(),executable_sha256:format!("sha256:{sha}"),version,sandbox:super::sandbox::capabilities(self.wrapper.as_ref())})
    }
    pub fn run(&self,model:&Path,prompt:&str,seed:u64,max_tokens:u64)->Result<RuntimeResult>{
        let workspace=super::sandbox::Workspace::create()?;
        let sandboxed=super::sandbox::command_for(&self.executable,model,&workspace,self.wrapper.as_ref())?;
        let model_argument=sandboxed.model_argument;
        let mut command=sandboxed.command;
        command.env_clear().env("HOME",&workspace.home).env("TMPDIR",&workspace.root)
            .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped())
            .arg("-m").arg(model_argument).arg("-p").arg(prompt)
            .arg("--seed").arg(seed.to_string()).arg("--temp").arg("0")
            .arg("-n").arg(max_tokens.to_string()).arg("--no-display-prompt");
        let start=Instant::now();
        let mut child=command.spawn().with_context(||format!("unable to start runtime '{}'",self.executable.display()))?;
        let stdout=child.stdout.take().ok_or_else(||anyhow!("runtime stdout pipe missing"))?;
        let stderr=child.stderr.take().ok_or_else(||anyhow!("runtime stderr pipe missing"))?;
        let (tx,rx)=mpsc::channel(); let tx2=tx.clone(); let cap=self.limits.max_output_bytes;
        std::thread::spawn(move||{let _=tx.send((0,read_capped(stdout,cap)));});
        std::thread::spawn(move||{let _=tx2.send((1,read_capped(stderr,cap)));});
        let deadline=Duration::from_secs(self.limits.timeout_seconds.max(1)); let mut timed_out=false; let status;
        loop { if let Some(s)=child.try_wait()?{status=s;break;}
            if start.elapsed()>=deadline{timed_out=true;let _=child.kill();status=child.wait()?;break;} std::thread::sleep(Duration::from_millis(25)); }
        let mut out=String::new();let mut err=String::new();
        for _ in 0..2 { if let Ok((which,result))=rx.recv_timeout(Duration::from_secs(2)){let bytes=result?;let text=String::from_utf8_lossy(&bytes).into_owned();if which==0{out=text}else{err=text}} }
        Ok(RuntimeResult{stdout:out,stderr:err,exit_code:status.code(),timed_out,duration_ms:u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)})
    }
}
fn read_capped<R:Read>(mut r:R,cap:usize)->Result<Vec<u8>>{let mut out=Vec::new();let mut buf=[0u8;8192];loop{let n=r.read(&mut buf)?;if n==0{break;}
    if out.len().saturating_add(n)>cap{return Err(anyhow!("runtime output exceeded byte cap {cap}"));}out.extend_from_slice(&buf[..n]);}Ok(out)}
fn hash_path(path:&Path)->Result<String>{let mut f=crate::safeio::open_readonly_nofollow(path)?;let mut h=Sha256::new();let mut b=[0u8;1024*1024];loop{let n=f.read(&mut b)?;if n==0{break;}h.update(&b[..n]);}Ok(hex::encode(h.finalize()))}
fn version_string(path:&Path)->Option<String>{
    let mut child=std::process::Command::new(path).arg("--version").env_clear().stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().ok()?;
    let stdout=child.stdout.take()?;
    let (tx,rx)=mpsc::channel();
    std::thread::spawn(move||{let _=tx.send(read_capped(stdout,16*1024));});
    let started=Instant::now();
    loop{
        if child.try_wait().ok().flatten().is_some(){break;}
        if started.elapsed()>Duration::from_secs(5){let _=child.kill();let _=child.wait();break;}
        std::thread::sleep(Duration::from_millis(10));
    }
    let bytes=rx.recv_timeout(Duration::from_secs(1)).ok()?.ok()?;
    let text=String::from_utf8_lossy(&bytes).trim().to_owned();
    if text.is_empty(){None}else{Some(text.chars().take(4096).collect())}
}
