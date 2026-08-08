//! Versioned local model observation/history store.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const MAX_STORE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_RECORDS: usize = 100_000;
const MAX_OBSERVATIONS_PER_RECORD: usize = 10_000;
const MAX_MEMBERS_STORED: usize = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredObservation {
    pub id: String,
    pub observed_unix: u64,
    pub identity: crate::modelmeta::ModelIdentity,
    pub format: String,
    pub architecture: crate::modelmeta::ArchitectureSummary,
    pub tokenizer: Option<crate::modelmeta::TokenizerSummary>,
    pub template: Option<crate::modelmeta::TemplateSummary>,
    pub generation: Option<crate::modelmeta::GenerationConfigSummary>,
    pub tensor_schema_hash: String,
    pub component_hashes: BTreeMap<String, String>,
    pub package_members: Vec<crate::modelmeta::PackageMemberSummary>,
    pub source_target: String,
    pub build: String,
    pub revision: Option<String>,
    pub trust_label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelRecord {
    pub key: String,
    pub name: Option<String>,
    pub publisher: Option<String>,
    pub observations: Vec<StoredObservation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservationStore {
    pub version: u32,
    pub records: Vec<ModelRecord>,
}

impl Default for ObservationStore { fn default()->Self{Self{version:1,records:Vec::new()}} }

impl ObservationStore {
    pub fn path() -> Result<PathBuf> { Ok(crate::paths::config_dir()?.join("models").join("index.json")) }
    pub fn load() -> Result<Self> {
        let path=Self::path()?;
        if !path.exists(){return Ok(Self::default());}
        let file=crate::safeio::open_readonly_nofollow(&path)?;
        let bytes=crate::safeio::read_all_from_file(&file,MAX_STORE_BYTES)?;
        let store:Self=serde_json::from_slice(&bytes).with_context(||format!("invalid model observation store '{}'",path.display()))?;
        if store.version!=1{bail!("unsupported model observation store version {}",store.version);}
        if store.records.len()>MAX_RECORDS{bail!("model observation store contains too many records");}
        for record in &store.records{if record.observations.len()>MAX_OBSERVATIONS_PER_RECORD{bail!("model record '{}' contains too many observations",record.key);}}
        Ok(store)
    }
    pub fn save(&self)->Result<PathBuf>{
        if self.records.len()>MAX_RECORDS{bail!("model observation store exceeds record cap");}
        let bytes=serde_json::to_vec_pretty(self)?;
        if bytes.len() as u64>MAX_STORE_BYTES{bail!("model observation store exceeds byte cap {MAX_STORE_BYTES}");}
        let path=Self::path()?;crate::paths::write_private(&path,&bytes)?;Ok(path)
    }
    pub fn remember(&mut self,snapshot:&crate::modelmeta::ModelSnapshot,name:Option<String>,publisher:Option<String>,revision:Option<String>,trust_label:Option<String>)->Result<(&str,&StoredObservation)> {
        let key=record_key(name.as_deref(),publisher.as_deref(),&snapshot.identity.canonical);
        let mut members=snapshot.package_members.clone();members.truncate(MAX_MEMBERS_STORED);
        let observation=StoredObservation{
            id:observation_id(snapshot)?,observed_unix:crate::paths::now_unix(),identity:snapshot.identity.clone(),format:snapshot.format.clone(),architecture:snapshot.architecture.clone(),tokenizer:snapshot.tokenizer.clone(),template:snapshot.template.clone(),generation:snapshot.generation.clone(),tensor_schema_hash:snapshot.tensor_schema_hash.clone(),component_hashes:snapshot.component_hashes.clone(),package_members:members,source_target:snapshot.target.clone(),build:env!("CARGO_PKG_VERSION").to_owned(),revision,trust_label,
        };
        let index=match self.records.iter().position(|v|v.key==key){Some(index)=>index,None=>{if self.records.len()>=MAX_RECORDS{bail!("model record limit reached");}self.records.push(ModelRecord{key:key.clone(),name:name.clone(),publisher:publisher.clone(),observations:Vec::new()});self.records.len()-1}};
        let record=&mut self.records[index];
        if record.name.is_none(){record.name=name;}
        if record.publisher.is_none(){record.publisher=publisher;}
        if record.observations.last().is_some_and(|v|v.id==observation.id){
            // Same content can be observed repeatedly. Retain the most recent timestamp/revision without duplicating history.
            if let Some(last)=record.observations.last_mut(){*last=observation;}else{return Err(anyhow!("observation replacement invariant failed"));}
        }else{record.observations.push(observation);if record.observations.len()>MAX_OBSERVATIONS_PER_RECORD{record.observations.remove(0);}}
        let obs=record.observations.last().ok_or_else(||anyhow!("observation was not stored"))?;
        Ok((record.key.as_str(),obs))
    }
    pub fn record(&self,selector:&str)->Option<&ModelRecord>{self.records.iter().find(|v|v.key==selector||v.name.as_deref()==Some(selector)||v.observations.iter().any(|o|o.id==selector))}
    pub fn previous_for_snapshot(&self,snapshot:&crate::modelmeta::ModelSnapshot)->Option<&StoredObservation>{
        self.records.iter().flat_map(|r|r.observations.iter()).filter(|o|same_series(o,snapshot)).max_by_key(|o|o.observed_unix)
    }
    pub fn forget(&mut self,selector:&str)->bool{let before=self.records.len();self.records.retain(|r|r.key!=selector&&r.name.as_deref()!=Some(selector)&&!r.observations.iter().any(|o|o.id==selector));before!=self.records.len()}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftChange { pub component:String,pub state:String,pub before:Option<String>,pub after:Option<String>,pub rule_id:Option<String> }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftReport { pub prior_observation_id:String,pub current_identity:String,pub changes:Vec<DriftChange>,pub material:bool }

pub fn drift(prior:&StoredObservation,current:&crate::modelmeta::ModelSnapshot)->DriftReport{
    let mut changes=Vec::new();
    scalar_change(&mut changes,"identity",Some(prior.identity.canonical.clone()),Some(current.identity.canonical.clone()),Some("LF-DRIFT-WEIGHTS-CHANGED"));
    scalar_change(&mut changes,"tensor_schema",Some(prior.tensor_schema_hash.clone()),Some(current.tensor_schema_hash.clone()),Some("LF-DRIFT-WEIGHTS-CHANGED"));
    scalar_change(&mut changes,"tokenizer",hash_json_opt(&prior.tokenizer),hash_json_opt(&current.tokenizer),Some("LF-DRIFT-TOKENIZER-CHANGED"));
    scalar_change(&mut changes,"chat_template",hash_json_opt(&prior.template),hash_json_opt(&current.template),Some("LF-DRIFT-TEMPLATE-CHANGED"));
    scalar_change(&mut changes,"generation_config",hash_json_opt(&prior.generation),hash_json_opt(&current.generation),None);
    let mut names:std::collections::BTreeSet<String>=prior.component_hashes.keys().cloned().collect();names.extend(current.component_hashes.keys().cloned());
    for name in names{let before=prior.component_hashes.get(&name).cloned();let after=current.component_hashes.get(&name).cloned();let rule=if executable_like(&name)&&before!=after{Some("LF-DRIFT-EXECUTABLE-ADDED")}else{None};scalar_change(&mut changes,&format!("component:{name}"),before,after,rule);}
    let material=changes.iter().any(|v|v.state!="UNCHANGED");
    DriftReport{prior_observation_id:prior.id.clone(),current_identity:current.identity.canonical.clone(),changes,material}
}

fn scalar_change(out:&mut Vec<DriftChange>,component:&str,before:Option<String>,after:Option<String>,rule:Option<&str>){let state=match(&before,&after){(None,Some(_))=>"ADDED",(Some(_),None)=>"REMOVED",(Some(a),Some(b)) if a!=b=>"CHANGED",_=>"UNCHANGED"};if state!="UNCHANGED"{out.push(DriftChange{component:component.to_owned(),state:state.to_owned(),before,after,rule_id:rule.map(str::to_owned)});}}
fn executable_like(name:&str)->bool{matches!(Path::new(name).extension().and_then(|v|v.to_str()).unwrap_or("").to_ascii_lowercase().as_str(),"py"|"sh"|"ps1"|"bat"|"cmd"|"so"|"dll"|"dylib"|"exe")}
fn same_series(observation:&StoredObservation,snapshot:&crate::modelmeta::ModelSnapshot)->bool{observation.source_target==snapshot.target}
fn record_key(name:Option<&str>,publisher:Option<&str>,fallback:&str)->String{let raw=match name{Some(name)=>format!("{}\0{}",publisher.unwrap_or(""),name),None=>fallback.to_owned()};format!("lfmodel:sha256:{}",hex::encode(Sha256::digest(raw.as_bytes())))}
fn observation_id(snapshot:&crate::modelmeta::ModelSnapshot)->Result<String>{let bytes=serde_json::to_vec(&(snapshot.identity.clone(),&snapshot.tensor_schema_hash,&snapshot.component_hashes))?;Ok(format!("lfobs:sha256:{}",hex::encode(Sha256::digest(bytes))))}
fn hash_json_opt<T:Serialize>(value:&Option<T>)->Option<String>{value.as_ref().and_then(|v|serde_json::to_vec(v).ok()).map(|b|hex::encode(Sha256::digest(b)))}
