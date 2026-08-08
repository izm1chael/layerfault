use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use rusqlite::OptionalExtension;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub id: String,
    pub kind: String,
    pub payload: serde_json::Value,
    pub attempts: i64,
    pub max_attempts: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelRow {
    pub id: String,
    pub name: String,
    pub latest_revision: Option<String>,
    pub latest_review: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewRow {
    pub id: String,
    pub revision_id: String,
    pub final_decision: String,
    pub created_at: i64,
    pub body: serde_json::Value,
}

pub enum PlatformDb {
    Sqlite(rusqlite::Connection),
    Postgres(postgres::Client),
}

impl PlatformDb {
    pub fn connect(url: &str) -> Result<Self> {
        if let Some(path) = url.strip_prefix("sqlite:") {
            let path = if path.is_empty() { "layerfault-platform.db" } else { path };
            let conn = rusqlite::Connection::open(path)
                .with_context(|| format!("unable to open SQLite database '{path}'"))?;
            conn.busy_timeout(std::time::Duration::from_secs(10))?;
            conn.pragma_update(None, "foreign_keys", "ON")?;
            conn.pragma_update(None, "journal_mode", "WAL")?;
            Ok(Self::Sqlite(conn))
        } else if url.starts_with("postgres://") || url.starts_with("postgresql://") {
            let mut effective=url.to_owned();
            if let Some(password)=crate::paths::secret_from_env("LAYERFAULT_DB_PASSWORD")? {
                let mut parsed=url::Url::parse(url).context("invalid PostgreSQL URL")?;
                if parsed.password().is_none(){parsed.set_password(Some(&password)).map_err(|_|anyhow!("unable to apply PostgreSQL password secret"))?;effective=parsed.to_string();}
            }
            Ok(Self::Postgres(postgres::Client::connect(&effective, postgres::NoTls)
                .context("unable to connect to PostgreSQL")?))
        } else {
            bail!("database must use sqlite:/path or postgres:// URL")
        }
    }

    pub fn migrate(&mut self) -> Result<()> {
        match self {
            Self::Sqlite(conn) => conn.execute_batch(SQLITE_SCHEMA)?,
            Self::Postgres(client) => client.batch_execute(POSTGRES_SCHEMA)?,
        }
        Ok(())
    }

    pub fn enqueue(&mut self, kind: &str, idempotency_key: &str, payload: &serde_json::Value, priority: i64) -> Result<String> {
        if kind.len() > 128 || idempotency_key.len() > 1024 { bail!("job kind/idempotency key too long"); }
        let id = stable_id("lfjob", &[kind.as_bytes(), idempotency_key.as_bytes()]);
        let now = now_i64();
        let payload = serde_json::to_string(payload)?;
        if payload.len() > 4 * 1024 * 1024 { bail!("job payload exceeds 4 MiB cap"); }
        match self {
            Self::Sqlite(conn) => {
                conn.execute("INSERT OR IGNORE INTO jobs(id,kind,idempotency_key,state,priority,attempts,max_attempts,payload_json,created_at) VALUES(?1,?2,?3,'READY',?4,0,5,?5,?6)",rusqlite::params![id,kind,idempotency_key,priority,payload,now])?;
            }
            Self::Postgres(client) => {
                client.execute("INSERT INTO jobs(id,kind,idempotency_key,state,priority,attempts,max_attempts,payload_json,created_at) VALUES($1,$2,$3,'READY',$4,0,5,$5,$6) ON CONFLICT(idempotency_key) DO NOTHING", &[&id,&kind,&idempotency_key,&priority,&payload,&now])?;
            }
        }
        Ok(id)
    }

    pub fn claim(&mut self, worker: &str, lease_seconds: i64) -> Result<Option<Job>> {
        let now = now_i64();
        let lease_until = now.saturating_add(lease_seconds.clamp(10, 86_400));
        match self {
            Self::Sqlite(conn) => {
                let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                let selected: Option<(String,String,String,i64,i64)> = {
                    let mut stmt = tx.prepare("SELECT id,kind,payload_json,attempts,max_attempts FROM jobs WHERE state='READY' OR (state='LEASED' AND lease_until < ?1) ORDER BY priority DESC, created_at ASC LIMIT 1")?;
                    let mut rows = stmt.query(rusqlite::params![now])?;
                    rows.next()?.map(|r| Ok::<_, rusqlite::Error>((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).transpose()?
                };
                let Some((id,kind,payload,attempts,max_attempts))=selected else { tx.commit()?; return Ok(None); };
                let changed=tx.execute("UPDATE jobs SET state='LEASED',lease_owner=?1,lease_until=?2,attempts=attempts+1,started_at=COALESCE(started_at,?3) WHERE id=?4 AND (state='READY' OR lease_until < ?3)",rusqlite::params![worker,lease_until,now,id])?;
                if changed!=1 { tx.rollback()?; return Ok(None); }
                tx.commit()?;
                Ok(Some(Job{id,kind,payload:serde_json::from_str(&payload)?,attempts:attempts+1,max_attempts}))
            }
            Self::Postgres(client) => {
                let row=client.query_opt("UPDATE jobs SET state='LEASED',lease_owner=$1,lease_until=$2,attempts=attempts+1,started_at=COALESCE(started_at,$3) WHERE id=(SELECT id FROM jobs WHERE state='READY' OR (state='LEASED' AND lease_until < $3) ORDER BY priority DESC,created_at ASC LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING id,kind,payload_json,attempts,max_attempts", &[&worker,&lease_until,&now])?;
                match row { Some(row)=>Ok(Some(Job{id:row.get(0),kind:row.get(1),payload:serde_json::from_str::<serde_json::Value>(&row.get::<_,String>(2))?,attempts:row.get(3),max_attempts:row.get(4)})),None=>Ok(None) }
            }
        }
    }

    pub fn succeed(&mut self,id:&str)->Result<()> { self.finish(id,"SUCCEEDED",None) }
    pub fn fail(&mut self,id:&str,attempts:i64,max_attempts:i64,error:&str)->Result<()> { let state=if attempts>=max_attempts{"DEAD"}else{"READY"};self.finish(id,state,Some(error)) }
    fn finish(&mut self,id:&str,state:&str,error:Option<&str>)->Result<()> { let now=now_i64();let error=error.map(|v|truncate(v,8192));match self{Self::Sqlite(c)=>{c.execute("UPDATE jobs SET state=?1,lease_owner=NULL,lease_until=NULL,last_error=?2,finished_at=CASE WHEN ?1='SUCCEEDED' OR ?1='DEAD' THEN ?3 ELSE NULL END WHERE id=?4",rusqlite::params![state,error,now,id])?;},Self::Postgres(c)=>{c.execute("UPDATE jobs SET state=$1,lease_owner=NULL,lease_until=NULL,last_error=$2,finished_at=CASE WHEN $1='SUCCEEDED' OR $1='DEAD' THEN $3 ELSE NULL END WHERE id=$4",&[&state,&error,&now,&id])?;}}Ok(()) }

    pub fn upsert_revision(&mut self, repo:&str, revision:&str, metadata:&serde_json::Value)->Result<String>{
        let model_id=stable_id("lfhubmodel", &[repo.as_bytes()]);let revision_id=stable_id("lfhubrevision", &[repo.as_bytes(),revision.as_bytes()]);let now=now_i64();let metadata=serde_json::to_string(metadata)?;
        match self{
            Self::Sqlite(c)=>{c.execute("INSERT OR IGNORE INTO models(id,canonical_name,created_at) VALUES(?1,?2,?3)",rusqlite::params![model_id,repo,now])?;c.execute("INSERT INTO model_revisions(id,model_id,revision,observed_at,metadata_json) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(model_id,revision) DO UPDATE SET observed_at=excluded.observed_at,metadata_json=excluded.metadata_json",rusqlite::params![revision_id,model_id,revision,now,metadata])?;}
            Self::Postgres(c)=>{c.execute("INSERT INTO models(id,canonical_name,created_at) VALUES($1,$2,$3) ON CONFLICT(id) DO NOTHING",&[&model_id,&repo,&now])?;c.execute("INSERT INTO model_revisions(id,model_id,revision,observed_at,metadata_json) VALUES($1,$2,$3,$4,$5) ON CONFLICT(model_id,revision) DO UPDATE SET observed_at=EXCLUDED.observed_at,metadata_json=EXCLUDED.metadata_json",&[&revision_id,&model_id,&revision,&now,&metadata])?;}
        }Ok(revision_id)
    }

    pub fn insert_review(&mut self,revision_id:&str,decision:&str,body:&serde_json::Value)->Result<String>{
        let body_text=serde_json::to_string(body)?;let body_hash=hex::encode(Sha256::digest(body_text.as_bytes()));let id=stable_id("lfreview", &[revision_id.as_bytes(),body_hash.as_bytes()]);let now=now_i64();
        match self{Self::Sqlite(c)=>{c.execute("INSERT OR IGNORE INTO reviews(id,revision_id,final_decision,created_at,body_json) VALUES(?1,?2,?3,?4,?5)",rusqlite::params![id,revision_id,decision,now,body_text])?;},Self::Postgres(c)=>{c.execute("INSERT INTO reviews(id,revision_id,final_decision,created_at,body_json) VALUES($1,$2,$3,$4,$5) ON CONFLICT(id) DO NOTHING",&[&id,&revision_id,&decision,&now,&body_text])?;}}
        self.index_review_findings(&id,body,now)?;
        Ok(id)
    }

    pub fn list_models(&mut self,limit:usize)->Result<Vec<ModelRow>>{let limit=i64::try_from(limit.clamp(1,200)).unwrap_or(200);match self{Self::Sqlite(c)=>{let mut st=c.prepare("SELECT m.id,m.canonical_name,(SELECT revision FROM model_revisions r WHERE r.model_id=m.id ORDER BY observed_at DESC LIMIT 1),(SELECT rv.id FROM reviews rv JOIN model_revisions rr ON rr.id=rv.revision_id WHERE rr.model_id=m.id ORDER BY rv.created_at DESC LIMIT 1) FROM models m ORDER BY m.created_at DESC LIMIT ?1")?;let rows=st.query_map(rusqlite::params![limit],|r|Ok(ModelRow{id:r.get(0)?,name:r.get(1)?,latest_revision:r.get(2)?,latest_review:r.get(3)?}))?.collect::<std::result::Result<Vec<_>,_>>()?;Ok(rows)},Self::Postgres(c)=>Ok(c.query("SELECT m.id,m.canonical_name,(SELECT revision FROM model_revisions r WHERE r.model_id=m.id ORDER BY observed_at DESC LIMIT 1),(SELECT rv.id FROM reviews rv JOIN model_revisions rr ON rr.id=rv.revision_id WHERE rr.model_id=m.id ORDER BY rv.created_at DESC LIMIT 1) FROM models m ORDER BY m.created_at DESC LIMIT $1",&[&limit])?.into_iter().map(|r|ModelRow{id:r.get(0),name:r.get(1),latest_revision:r.get(2),latest_review:r.get(3)}).collect())}}

    pub fn review(&mut self,id:&str)->Result<Option<ReviewRow>>{match self{Self::Sqlite(c)=>{let mut st=c.prepare("SELECT id,revision_id,final_decision,created_at,body_json FROM reviews WHERE id=?1")?;let mut rows=st.query(rusqlite::params![id])?;match rows.next()?{Some(r)=>Ok(Some(ReviewRow{id:r.get(0)?,revision_id:r.get(1)?,final_decision:r.get(2)?,created_at:r.get(3)?,body:serde_json::from_str::<serde_json::Value>(&r.get::<_,String>(4)?)?})),None=>Ok(None)}},Self::Postgres(c)=>match c.query_opt("SELECT id,revision_id,final_decision,created_at,body_json FROM reviews WHERE id=$1",&[&id])?{Some(r)=>Ok(Some(ReviewRow{id:r.get(0),revision_id:r.get(1),final_decision:r.get(2),created_at:r.get(3),body:serde_json::from_str::<serde_json::Value>(&r.get::<_,String>(4))?})),None=>Ok(None)}}}


    fn index_review_findings(&mut self,review_id:&str,body:&serde_json::Value,created_at:i64)->Result<()> {
        let mut values=Vec::new();
        collect_findings(body,&mut values,0);
        values.truncate(4096);
        for (index,value) in values.into_iter().enumerate(){
            let rule=value.get("rule_id").and_then(|v|v.as_str()).or_else(||value.get("rule").and_then(|v|v.as_str())).unwrap_or("LF-UNCLASSIFIED");
            let domain=value.get("domain").and_then(|v|v.as_str()).unwrap_or("review");
            let status=value.get("status").and_then(|v|v.as_str()).unwrap_or("WARN");
            let confidence=value.get("confidence").and_then(|v|v.as_str()).unwrap_or("MEDIUM");
            let detail=serde_json::to_string(value)?;
            let idx=index.to_string();let finding_id=stable_id("lffinding",&[review_id.as_bytes(),rule.as_bytes(),idx.as_bytes()]);
            match self{Self::Sqlite(c)=>{c.execute("INSERT OR REPLACE INTO findings(id,review_id,rule_id,domain,status,confidence,detail_json,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",rusqlite::params![finding_id,review_id,rule,domain,status,confidence,detail,created_at])?;},Self::Postgres(c)=>{c.execute("INSERT INTO findings(id,review_id,rule_id,domain,status,confidence,detail_json,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(id) DO UPDATE SET detail_json=EXCLUDED.detail_json,status=EXCLUDED.status,confidence=EXCLUDED.confidence",&[&finding_id,&review_id,&rule,&domain,&status,&confidence,&detail,&created_at])?;}}
        }
        if body.get("final_decision").and_then(|v|v.as_str())==Some("BLOCK"){
            let title=format!("Blocking Layerfault review {review_id}");let advisory_body=serde_json::json!({"review_id":review_id,"summary":"A pinned model revision produced blocking Layerfault findings. Review the underlying evidence before deployment."});let text=serde_json::to_string(&advisory_body)?;let advisory_id=stable_id("lfadvisory",&[review_id.as_bytes()]);
            match self{Self::Sqlite(c)=>{c.execute("INSERT OR IGNORE INTO advisories(id,review_id,title,severity,body_json,created_at) VALUES(?1,?2,?3,'HIGH',?4,?5)",rusqlite::params![advisory_id,review_id,title,text,created_at])?;},Self::Postgres(c)=>{c.execute("INSERT INTO advisories(id,review_id,title,severity,body_json,created_at) VALUES($1,$2,$3,'HIGH',$4,$5) ON CONFLICT(id) DO NOTHING",&[&advisory_id,&review_id,&title,&text,&created_at])?;}}
        }
        Ok(())
    }

    pub fn model(&mut self,id:&str)->Result<Option<ModelRow>>{
        match self{
            Self::Sqlite(c)=>{let mut st=c.prepare("SELECT m.id,m.canonical_name,(SELECT revision FROM model_revisions r WHERE r.model_id=m.id ORDER BY observed_at DESC LIMIT 1),(SELECT rv.id FROM reviews rv JOIN model_revisions rr ON rr.id=rv.revision_id WHERE rr.model_id=m.id ORDER BY rv.created_at DESC LIMIT 1) FROM models m WHERE m.id=?1")?;let mut rows=st.query(rusqlite::params![id])?;match rows.next()?{Some(r)=>Ok(Some(ModelRow{id:r.get(0)?,name:r.get(1)?,latest_revision:r.get(2)?,latest_review:r.get(3)?})),None=>Ok(None)}},
            Self::Postgres(c)=>match c.query_opt("SELECT m.id,m.canonical_name,(SELECT revision FROM model_revisions r WHERE r.model_id=m.id ORDER BY observed_at DESC LIMIT 1),(SELECT rv.id FROM reviews rv JOIN model_revisions rr ON rr.id=rv.revision_id WHERE rr.model_id=m.id ORDER BY rv.created_at DESC LIMIT 1) FROM models m WHERE m.id=$1",&[&id])?{Some(r)=>Ok(Some(ModelRow{id:r.get(0),name:r.get(1),latest_revision:r.get(2),latest_review:r.get(3)})),None=>Ok(None)}
        }
    }

    pub fn revisions(&mut self,model_id:&str,limit:usize)->Result<Vec<serde_json::Value>>{
        let limit=i64::try_from(limit.clamp(1,200)).unwrap_or(200);
        match self{
            Self::Sqlite(c)=>{let mut st=c.prepare("SELECT id,revision,observed_at,metadata_json FROM model_revisions WHERE model_id=?1 ORDER BY observed_at DESC LIMIT ?2")?;let rows=st.query_map(rusqlite::params![model_id,limit],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,i64>(2)?,r.get::<_,String>(3)?)))?.collect::<std::result::Result<Vec<_>,_>>()?;rows.into_iter().map(|(id,revision,observed,metadata)|Ok(serde_json::json!({"id":id,"model_id":model_id,"revision":revision,"observed_at":observed,"metadata":serde_json::from_str::<serde_json::Value>(&metadata)?}))).collect()},
            Self::Postgres(c)=>c.query("SELECT id,revision,observed_at,metadata_json FROM model_revisions WHERE model_id=$1 ORDER BY observed_at DESC LIMIT $2",&[&model_id,&limit])?.into_iter().map(|r|{let metadata:String=r.get(3);Ok(serde_json::json!({"id":r.get::<_,String>(0),"model_id":model_id,"revision":r.get::<_,String>(1),"observed_at":r.get::<_,i64>(2),"metadata":serde_json::from_str::<serde_json::Value>(&metadata)?}))}).collect()
        }
    }

    pub fn revision(&mut self,id:&str)->Result<Option<serde_json::Value>>{
        match self{
            Self::Sqlite(c)=>{let mut st=c.prepare("SELECT id,model_id,revision,observed_at,metadata_json FROM model_revisions WHERE id=?1")?;let mut rows=st.query(rusqlite::params![id])?;match rows.next()?{Some(r)=>{let metadata:String=r.get(4)?;Ok(Some(serde_json::json!({"id":r.get::<_,String>(0)?,"model_id":r.get::<_,String>(1)?,"revision":r.get::<_,String>(2)?,"observed_at":r.get::<_,i64>(3)?,"metadata":serde_json::from_str::<serde_json::Value>(&metadata)?})))},None=>Ok(None)}},
            Self::Postgres(c)=>match c.query_opt("SELECT id,model_id,revision,observed_at,metadata_json FROM model_revisions WHERE id=$1",&[&id])?{Some(r)=>{let metadata:String=r.get(4);Ok(Some(serde_json::json!({"id":r.get::<_,String>(0),"model_id":r.get::<_,String>(1),"revision":r.get::<_,String>(2),"observed_at":r.get::<_,i64>(3),"metadata":serde_json::from_str::<serde_json::Value>(&metadata)?})))},None=>Ok(None)}
        }
    }

    pub fn list_findings(&mut self,limit:usize)->Result<Vec<serde_json::Value>>{
        let limit=i64::try_from(limit.clamp(1,500)).unwrap_or(500);
        match self{
            Self::Sqlite(c)=>{let mut st=c.prepare("SELECT id,review_id,rule_id,domain,status,confidence,detail_json,created_at FROM findings ORDER BY created_at DESC LIMIT ?1")?;let rows=st.query_map(rusqlite::params![limit],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,String>(5)?,r.get::<_,String>(6)?,r.get::<_,i64>(7)?)))?.collect::<std::result::Result<Vec<_>,_>>()?;rows.into_iter().map(|(id,review,rule,domain,status,confidence,detail,created)|Ok(serde_json::json!({"id":id,"review_id":review,"rule_id":rule,"domain":domain,"status":status,"confidence":confidence,"detail":serde_json::from_str::<serde_json::Value>(&detail).unwrap_or(serde_json::Value::String(detail)),"created_at":created}))).collect()},
            Self::Postgres(c)=>c.query("SELECT id,review_id,rule_id,domain,status,confidence,detail_json,created_at FROM findings ORDER BY created_at DESC LIMIT $1",&[&limit])?.into_iter().map(|r|{let detail:String=r.get(6);Ok(serde_json::json!({"id":r.get::<_,String>(0),"review_id":r.get::<_,String>(1),"rule_id":r.get::<_,String>(2),"domain":r.get::<_,String>(3),"status":r.get::<_,String>(4),"confidence":r.get::<_,String>(5),"detail":serde_json::from_str::<serde_json::Value>(&detail).unwrap_or(serde_json::Value::String(detail)),"created_at":r.get::<_,i64>(7)}))}).collect()
        }
    }

    pub fn list_advisories(&mut self,limit:usize)->Result<Vec<serde_json::Value>>{
        let limit=i64::try_from(limit.clamp(1,200)).unwrap_or(200);
        match self{
            Self::Sqlite(c)=>{let mut st=c.prepare("SELECT id,review_id,title,severity,body_json,created_at FROM advisories ORDER BY created_at DESC LIMIT ?1")?;let rows=st.query_map(rusqlite::params![limit],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,i64>(5)?)))?.collect::<std::result::Result<Vec<_>,_>>()?;rows.into_iter().map(|(id,review,title,severity,body,created)|Ok(serde_json::json!({"id":id,"review_id":review,"title":title,"severity":severity,"body":serde_json::from_str::<serde_json::Value>(&body)?,"created_at":created}))).collect()},
            Self::Postgres(c)=>c.query("SELECT id,review_id,title,severity,body_json,created_at FROM advisories ORDER BY created_at DESC LIMIT $1",&[&limit])?.into_iter().map(|r|{let body:String=r.get(4);Ok(serde_json::json!({"id":r.get::<_,String>(0),"review_id":r.get::<_,String>(1),"title":r.get::<_,String>(2),"severity":r.get::<_,String>(3),"body":serde_json::from_str::<serde_json::Value>(&body)?,"created_at":r.get::<_,i64>(5)}))}).collect()
        }
    }

    pub fn weekly(&mut self,period:&str)->Result<Option<serde_json::Value>>{
        match self{
            Self::Sqlite(c)=>{let mut st=c.prepare("SELECT id,period,generated_at,body_json FROM weekly_reviews WHERE period=?1")?;let mut rows=st.query(rusqlite::params![period])?;match rows.next()?{Some(r)=>{let body:String=r.get(3)?;Ok(Some(serde_json::json!({"id":r.get::<_,String>(0)?,"period":r.get::<_,String>(1)?,"generated_at":r.get::<_,i64>(2)?,"body":serde_json::from_str::<serde_json::Value>(&body)?})))},None=>Ok(None)}},
            Self::Postgres(c)=>match c.query_opt("SELECT id,period,generated_at,body_json FROM weekly_reviews WHERE period=$1",&[&period])?{Some(r)=>{let body:String=r.get(3);Ok(Some(serde_json::json!({"id":r.get::<_,String>(0),"period":r.get::<_,String>(1),"generated_at":r.get::<_,i64>(2),"body":serde_json::from_str::<serde_json::Value>(&body)?})))},None=>Ok(None)}
        }
    }


    pub fn crawl_cursor(&mut self,key:&str)->Result<Option<String>>{
        match self{Self::Sqlite(c)=>Ok(c.query_row("SELECT cursor FROM crawl_cursors WHERE id=?1",rusqlite::params![key],|r|r.get::<_,String>(0)).optional()?),Self::Postgres(c)=>Ok(c.query_opt("SELECT cursor FROM crawl_cursors WHERE id=$1",&[&key])?.map(|r|r.get(0)))}
    }
    pub fn set_crawl_cursor(&mut self,key:&str,cursor:&str)->Result<()> {if key.len()>256||cursor.len()>16*1024{bail!("crawl cursor exceeds cap");}let now=now_i64();match self{Self::Sqlite(c)=>{c.execute("INSERT INTO crawl_cursors(id,cursor,updated_at) VALUES(?1,?2,?3) ON CONFLICT(id) DO UPDATE SET cursor=excluded.cursor,updated_at=excluded.updated_at",rusqlite::params![key,cursor,now])?;},Self::Postgres(c)=>{c.execute("INSERT INTO crawl_cursors(id,cursor,updated_at) VALUES($1,$2,$3) ON CONFLICT(id) DO UPDATE SET cursor=EXCLUDED.cursor,updated_at=EXCLUDED.updated_at",&[&key,&cursor,&now])?;}}Ok(())}

    pub fn aggregate(&mut self)->Result<serde_json::Value>{
        let (models,revisions,reviews,blocks,warns)=match self{Self::Sqlite(c)=>{let q=|sql:&str|->Result<i64>{Ok(c.query_row(sql,[],|r|r.get(0))?)};(q("SELECT COUNT(*) FROM models")?,q("SELECT COUNT(*) FROM model_revisions")?,q("SELECT COUNT(*) FROM reviews")?,q("SELECT COUNT(*) FROM reviews WHERE final_decision='BLOCK'")?,q("SELECT COUNT(*) FROM reviews WHERE final_decision='WARN'")?)},Self::Postgres(c)=>{let q=|c:&mut postgres::Client,sql:&str|->Result<i64>{Ok(c.query_one(sql,&[])?.get(0))};(q(c,"SELECT COUNT(*) FROM models")?,q(c,"SELECT COUNT(*) FROM model_revisions")?,q(c,"SELECT COUNT(*) FROM reviews")?,q(c,"SELECT COUNT(*) FROM reviews WHERE final_decision='BLOCK'")?,q(c,"SELECT COUNT(*) FROM reviews WHERE final_decision='WARN'")?)}};
        Ok(serde_json::json!({"models":models,"revisions":revisions,"reviews":reviews,"blocking_reviews":blocks,"warning_reviews":warns,"no_block_or_warning_reviews":reviews-blocks-warns}))
    }

    pub fn store_weekly(&mut self,period:&str,body:&serde_json::Value)->Result<String>{let id=stable_id("lfweekly",&[period.as_bytes()]);let now=now_i64();let text=serde_json::to_string(body)?;match self{Self::Sqlite(c)=>{c.execute("INSERT INTO weekly_reviews(id,period,generated_at,body_json) VALUES(?1,?2,?3,?4) ON CONFLICT(period) DO UPDATE SET generated_at=excluded.generated_at,body_json=excluded.body_json",rusqlite::params![id,period,now,text])?;},Self::Postgres(c)=>{c.execute("INSERT INTO weekly_reviews(id,period,generated_at,body_json) VALUES($1,$2,$3,$4) ON CONFLICT(period) DO UPDATE SET generated_at=EXCLUDED.generated_at,body_json=EXCLUDED.body_json",&[&id,&period,&now,&text])?;}}Ok(id)}
    pub fn list_weekly(&mut self,limit:usize)->Result<Vec<serde_json::Value>>{let limit=i64::try_from(limit.clamp(1,100)).unwrap_or(100);match self{Self::Sqlite(c)=>{let mut st=c.prepare("SELECT id,period,generated_at,body_json FROM weekly_reviews ORDER BY generated_at DESC LIMIT ?1")?;let values=st.query_map(rusqlite::params![limit],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,i64>(2)?,r.get::<_,String>(3)?)))?.collect::<std::result::Result<Vec<_>,_>>()?;values.into_iter().map(|(id,period,generated,body)|Ok(serde_json::json!({"id":id,"period":period,"generated_at":generated,"body":serde_json::from_str::<serde_json::Value>(&body)?}))).collect()},Self::Postgres(c)=>c.query("SELECT id,period,generated_at,body_json FROM weekly_reviews ORDER BY generated_at DESC LIMIT $1",&[&limit])?.into_iter().map(|r|{let body:String=r.get(3);Ok(serde_json::json!({"id":r.get::<_,String>(0),"period":r.get::<_,String>(1),"generated_at":r.get::<_,i64>(2),"body":serde_json::from_str::<serde_json::Value>(&body)?}))}).collect()}}
}

fn collect_findings<'a>(value:&'a serde_json::Value,out:&mut Vec<&'a serde_json::Value>,depth:usize){
    if depth>16||out.len()>=4096{return;}
    match value{serde_json::Value::Object(map)=>{if map.contains_key("rule_id")||map.contains_key("rule"){out.push(value);}for child in map.values(){collect_findings(child,out,depth+1);}},serde_json::Value::Array(values)=>for child in values.iter().take(4096){collect_findings(child,out,depth+1);},_=>{}}
}

pub fn stable_id(prefix:&str,parts:&[&[u8]])->String{let mut h=Sha256::new();h.update(prefix.as_bytes());h.update([0]);for p in parts{h.update((p.len()as u64).to_le_bytes());h.update(p);}format!("{prefix}:sha256:{}",hex::encode(h.finalize()))}
fn now_i64()->i64{i64::try_from(crate::paths::now_unix()).unwrap_or(i64::MAX)}
fn truncate(value:&str,cap:usize)->String{if value.len()<=cap{return value.to_owned();}let mut end=cap;while end>0&&!value.is_char_boundary(end){end-=1;}value[..end].to_owned()}

const SQLITE_SCHEMA:&str=r#"
CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY,applied_at BIGINT NOT NULL);
INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(1,strftime('%s','now'));
CREATE TABLE IF NOT EXISTS models(id TEXT PRIMARY KEY,canonical_name TEXT NOT NULL UNIQUE,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS model_revisions(id TEXT PRIMARY KEY,model_id TEXT NOT NULL,revision TEXT NOT NULL,observed_at BIGINT NOT NULL,metadata_json TEXT NOT NULL,UNIQUE(model_id,revision));
CREATE TABLE IF NOT EXISTS reviews(id TEXT PRIMARY KEY,revision_id TEXT NOT NULL,final_decision TEXT NOT NULL,created_at BIGINT NOT NULL,body_json TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS reviews_revision_idx ON reviews(revision_id,created_at);
CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY,review_id TEXT NOT NULL,rule_id TEXT NOT NULL,domain TEXT NOT NULL,status TEXT NOT NULL,confidence TEXT NOT NULL,detail_json TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE INDEX IF NOT EXISTS findings_review_idx ON findings(review_id,created_at);
CREATE TABLE IF NOT EXISTS advisories(id TEXT PRIMARY KEY,review_id TEXT NOT NULL,title TEXT NOT NULL,severity TEXT NOT NULL,body_json TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,kind TEXT NOT NULL,idempotency_key TEXT NOT NULL UNIQUE,state TEXT NOT NULL,priority BIGINT NOT NULL,attempts BIGINT NOT NULL,max_attempts BIGINT NOT NULL,lease_owner TEXT,lease_until BIGINT,payload_json TEXT NOT NULL,last_error TEXT,created_at BIGINT NOT NULL,started_at BIGINT,finished_at BIGINT);
CREATE INDEX IF NOT EXISTS jobs_ready_idx ON jobs(state,priority,created_at);
CREATE TABLE IF NOT EXISTS crawl_cursors(id TEXT PRIMARY KEY,cursor TEXT NOT NULL,updated_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS weekly_reviews(id TEXT PRIMARY KEY,period TEXT NOT NULL UNIQUE,generated_at BIGINT NOT NULL,body_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS newsletter_publications(id TEXT PRIMARY KEY,weekly_review_id TEXT NOT NULL,format TEXT NOT NULL,body_sha256 TEXT NOT NULL,sent_at BIGINT,UNIQUE(weekly_review_id,format));
"#;
const POSTGRES_SCHEMA:&str=r#"
CREATE TABLE IF NOT EXISTS schema_migrations(version BIGINT PRIMARY KEY,applied_at BIGINT NOT NULL);
INSERT INTO schema_migrations(version,applied_at) VALUES(1,EXTRACT(EPOCH FROM NOW())::BIGINT) ON CONFLICT(version) DO NOTHING;
CREATE TABLE IF NOT EXISTS models(id TEXT PRIMARY KEY,canonical_name TEXT NOT NULL UNIQUE,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS model_revisions(id TEXT PRIMARY KEY,model_id TEXT NOT NULL,revision TEXT NOT NULL,observed_at BIGINT NOT NULL,metadata_json TEXT NOT NULL,UNIQUE(model_id,revision));
CREATE TABLE IF NOT EXISTS reviews(id TEXT PRIMARY KEY,revision_id TEXT NOT NULL,final_decision TEXT NOT NULL,created_at BIGINT NOT NULL,body_json TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS reviews_revision_idx ON reviews(revision_id,created_at);
CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY,review_id TEXT NOT NULL,rule_id TEXT NOT NULL,domain TEXT NOT NULL,status TEXT NOT NULL,confidence TEXT NOT NULL,detail_json TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE INDEX IF NOT EXISTS findings_review_idx ON findings(review_id,created_at);
CREATE TABLE IF NOT EXISTS advisories(id TEXT PRIMARY KEY,review_id TEXT NOT NULL,title TEXT NOT NULL,severity TEXT NOT NULL,body_json TEXT NOT NULL,created_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,kind TEXT NOT NULL,idempotency_key TEXT NOT NULL UNIQUE,state TEXT NOT NULL,priority BIGINT NOT NULL,attempts BIGINT NOT NULL,max_attempts BIGINT NOT NULL,lease_owner TEXT,lease_until BIGINT,payload_json TEXT NOT NULL,last_error TEXT,created_at BIGINT NOT NULL,started_at BIGINT,finished_at BIGINT);
CREATE INDEX IF NOT EXISTS jobs_ready_idx ON jobs(state,priority,created_at);
CREATE TABLE IF NOT EXISTS crawl_cursors(id TEXT PRIMARY KEY,cursor TEXT NOT NULL,updated_at BIGINT NOT NULL);
CREATE TABLE IF NOT EXISTS weekly_reviews(id TEXT PRIMARY KEY,period TEXT NOT NULL UNIQUE,generated_at BIGINT NOT NULL,body_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS newsletter_publications(id TEXT PRIMARY KEY,weekly_review_id TEXT NOT NULL,format TEXT NOT NULL,body_sha256 TEXT NOT NULL,sent_at BIGINT,UNIQUE(weekly_review_id,format));
"#;
