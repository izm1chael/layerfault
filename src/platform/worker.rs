use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

const MAX_FILES_PER_REVIEW: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerOutcome { pub job_id:String,pub kind:String,pub status:String,pub detail:String }

pub fn run_loop(config:&super::PlatformConfig,once:bool)->Result<()> {
    let mut db=super::db::PlatformDb::connect(&config.database)?;db.migrate()?;
    loop{
        match process_one(&mut db,config){Ok(Some(outcome))=>println!("{}",serde_json::to_string(&outcome)?),Ok(None)=>{if once{return Ok(());}std::thread::sleep(Duration::from_secs(2));},Err(error)=>{eprintln!("layerfault worker error: {error:#}");if once{return Err(error);}std::thread::sleep(Duration::from_secs(2));}}
    }
}

pub fn process_one(db:&mut super::db::PlatformDb,config:&super::PlatformConfig)->Result<Option<WorkerOutcome>>{
    let Some(job)=db.claim(&config.worker_id,300)? else{return Ok(None)};
    let result=match job.kind.as_str(){"hub-review"=>process_hub_review(db,config,&job),"weekly"=>{let review=super::weekly::generate(db)?;Ok(format!("generated {}",review.period))},other=>Err(anyhow!("unknown platform job kind '{other}'"))};
    match result{Ok(detail)=>{db.succeed(&job.id)?;Ok(Some(WorkerOutcome{job_id:job.id,kind:job.kind,status:"SUCCEEDED".to_owned(),detail}))},Err(error)=>{let detail=format!("{error:#}");db.fail(&job.id,job.attempts,job.max_attempts,&detail)?;Ok(Some(WorkerOutcome{job_id:job.id,kind:job.kind,status:"FAILED".to_owned(),detail}))}}
}

pub fn crawl_once(db:&mut super::db::PlatformDb,limit:usize,cursor:Option<&str>)->Result<crate::hub::CrawlPage>{
    let client=crate::hub::HubClient::new(crate::hub::token_from_env())?;
    let page=client.list_models(limit,cursor)?;
    for model in &page.models{
        let Some(sha)=model.sha.as_deref() else{continue};
        if sha.len()<40{continue;}
        let payload=serde_json::json!({"repo":model.id,"revision":sha});
        let key=format!("hub-review:{}:{}",model.id,sha);
        let _=db.enqueue("hub-review",&key,&payload,0)?;
    }
    Ok(page)
}

fn process_hub_review(db:&mut super::db::PlatformDb,config:&super::PlatformConfig,job:&super::db::Job)->Result<String>{
    let repo=job.payload.get("repo").and_then(|v|v.as_str()).ok_or_else(||anyhow!("hub-review payload lacks repo"))?;
    let revision=job.payload.get("revision").and_then(|v|v.as_str()).ok_or_else(||anyhow!("hub-review payload lacks revision"))?;
    let client=crate::hub::HubClient::new(crate::hub::token_from_env())?;
    let metadata=client.model(repo,Some(revision))?;
    if metadata.commit_sha!=revision{bail!("Hub resolved revision mismatch: requested {revision}, got {}",metadata.commit_sha);}
    let revision_id=db.upsert_revision(repo,revision,&serde_json::to_value(&metadata)?)?;
    let root=private_job_dir(&job.id)?;
    let selected=select_files(&metadata.files,config.max_hub_download_bytes)?;
    if selected.is_empty(){let body=serde_json::json!({"schema_version":"1.0","repo":repo,"revision":revision,"final_decision":"WARN","primary_concern":"No supported model artifact was selected for bounded review.","source_metadata":metadata,"boundary":"No conclusion about model safety is made."});let review_id=db.insert_review(&revision_id,"WARN",&body)?;let _=std::fs::remove_dir_all(&root);return Ok(format!("stored metadata-only review {review_id}"));}
    let mut downloaded=Vec::new();
    let mut remaining=config.max_hub_download_bytes;
    for file in selected{
        let file_cap=file.size.unwrap_or(remaining).min(remaining);
        if file_cap==0{break;}
        let result=client.download(repo,revision,&file.path,&root,Some(file_cap))?;
        remaining=remaining.saturating_sub(result.bytes);
        downloaded.push(result);
    }
    let package=crate::package::inspect(&root)?;
    let static_block=package.blocking();
    let static_warn=package.findings.iter().any(|finding|finding.status==crate::scanner::ScanStatus::Warn);
    let mut snapshots=Vec::new();
    for download in &downloaded{
        let path=PathBuf::from(&download.path);
        if let Ok(snapshot)=crate::modelmeta::build_snapshot(&path){snapshots.push(snapshot);}
    }
    let decision=if static_block{"BLOCK"}else if static_warn{"WARN"}else{"PASS"};
    let body=serde_json::json!({
        "schema_version":"1.0",
        "repo":repo,
        "revision":revision,
        "observed_unix":crate::paths::now_unix(),
        "downloaded":downloaded,
        "static_package":package,
        "snapshots":snapshots,
        "final_decision":decision,
        "boundary":"This hosted review records the bounded checks performed on the exact immutable revision. PASS does not prove absence of hidden triggers/backdoors."
    });
    let review_id=db.insert_review(&revision_id,decision,&body)?;
    let _=std::fs::remove_dir_all(&root);
    Ok(format!("stored review {review_id} for {repo}@{revision}"))
}

fn select_files(files:&[crate::hub::HubFile],max_total:u64)->Result<Vec<crate::hub::HubFile>>{
    let mut selected=Vec::new();let mut total=0u64;
    for file in files{
        if selected.len()>=MAX_FILES_PER_REVIEW{break;}
        if !review_member(&file.path){continue;}
        let size=file.size.unwrap_or(0);
        if size>max_total||total.saturating_add(size)>max_total{continue;}
        total=total.saturating_add(size);selected.push(file.clone());
    }
    selected.sort_by(|a,b|priority(&a.path).cmp(&priority(&b.path)).then_with(||a.path.cmp(&b.path)));
    Ok(selected)
}

fn review_member(path:&str)->bool{let lower=path.to_ascii_lowercase();[".gguf",".safetensors",".safetensors.index.json",".onnx",".tflite",".keras",".h5",".hdf5","saved_model.pb","config.json","tokenizer.json","tokenizer_config.json","generation_config.json","adapter_config.json","special_tokens_map.json"].iter().any(|suffix|lower.ends_with(suffix))}
fn priority(path:&str)->u8{let lower=path.to_ascii_lowercase();if lower.ends_with("config.json")||lower.ends_with("tokenizer.json")||lower.ends_with("tokenizer_config.json")||lower.ends_with("generation_config.json"){0}else if lower.ends_with(".index.json"){1}else{2}}
fn private_job_dir(id:&str)->Result<PathBuf>{let safe=id.chars().filter(|c|c.is_ascii_alphanumeric()||*c=='-'||*c=='_').take(96).collect::<String>();let root=std::env::temp_dir().join(format!("layerfault-platform-{safe}"));if root.exists(){std::fs::remove_dir_all(&root).with_context(||format!("unable to clean prior job workspace '{}'",root.display()))?;}crate::paths::ensure_private_dir(&root)?;Ok(root)}
