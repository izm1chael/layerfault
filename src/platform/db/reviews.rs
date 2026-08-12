use super::connection::PlatformDb;
use super::types::{
    now_i64, stable_id, ModelRow, PreparedAdvisory, PreparedFinding, PreparedReviewIndex, ReviewRow,
};
use anyhow::Result;
use sha2::{Digest, Sha256};

impl PlatformDb {
    pub fn upsert_revision(
        &mut self,
        repo: &str,
        revision: &str,
        metadata: &serde_json::Value,
    ) -> Result<String> {
        let model_id = stable_id("lfhubmodel", &[repo.as_bytes()]);
        let revision_id = stable_id("lfhubrevision", &[repo.as_bytes(), revision.as_bytes()]);
        let now = now_i64();
        let metadata = serde_json::to_string(metadata)?;
        match self {
            Self::Sqlite(c) => {
                let tx = c.transaction()?;
                tx.execute(
                    "INSERT OR IGNORE INTO models(id,canonical_name,created_at) VALUES(?1,?2,?3)",
                    rusqlite::params![model_id, repo, now],
                )?;
                tx.execute("INSERT INTO model_revisions(id,model_id,revision,observed_at,metadata_json) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(model_id,revision) DO UPDATE SET observed_at=excluded.observed_at,metadata_json=excluded.metadata_json",rusqlite::params![revision_id,model_id,revision,now,metadata])?;
                tx.commit()?;
            }
            Self::Postgres(c) => {
                let mut tx = c.transaction()?;
                tx.execute("INSERT INTO models(id,canonical_name,created_at) VALUES($1,$2,$3) ON CONFLICT(id) DO NOTHING",&[&model_id,&repo,&now])?;
                tx.execute("INSERT INTO model_revisions(id,model_id,revision,observed_at,metadata_json) VALUES($1,$2,$3,$4,$5) ON CONFLICT(model_id,revision) DO UPDATE SET observed_at=EXCLUDED.observed_at,metadata_json=EXCLUDED.metadata_json",&[&revision_id,&model_id,&revision,&now,&metadata])?;
                tx.commit()?;
            }
        }
        Ok(revision_id)
    }

    pub fn insert_review(
        &mut self,
        revision_id: &str,
        decision: &str,
        body: &serde_json::Value,
    ) -> Result<String> {
        let body_text = serde_json::to_string(body)?;
        let body_hash = hex::encode(Sha256::digest(body_text.as_bytes()));
        let id = stable_id("lfreview", &[revision_id.as_bytes(), body_hash.as_bytes()]);
        let now = now_i64();
        let index = prepare_review_index(&id, body, now)?;
        match self {
            Self::Sqlite(c) => {
                let tx = c.transaction()?;
                tx.execute("INSERT OR IGNORE INTO reviews(id,revision_id,final_decision,created_at,body_json) VALUES(?1,?2,?3,?4,?5)",rusqlite::params![id,revision_id,decision,now,body_text])?;
                insert_review_index_sqlite(&tx, &index)?;
                tx.commit()?;
            }
            Self::Postgres(c) => {
                let mut tx = c.transaction()?;
                tx.execute("INSERT INTO reviews(id,revision_id,final_decision,created_at,body_json) VALUES($1,$2,$3,$4,$5) ON CONFLICT(id) DO NOTHING",&[&id,&revision_id,&decision,&now,&body_text])?;
                insert_review_index_postgres(&mut tx, &index)?;
                tx.commit()?;
            }
        }
        Ok(id)
    }

    pub fn list_models(&mut self, limit: usize) -> Result<Vec<ModelRow>> {
        let limit = i64::try_from(limit.clamp(1, 200)).unwrap_or(200);
        match self{Self::Sqlite(c)=>{let mut st=c.prepare("SELECT m.id,m.canonical_name,(SELECT revision FROM model_revisions r WHERE r.model_id=m.id ORDER BY observed_at DESC LIMIT 1),(SELECT rv.id FROM reviews rv JOIN model_revisions rr ON rr.id=rv.revision_id WHERE rr.model_id=m.id ORDER BY rv.created_at DESC LIMIT 1) FROM models m ORDER BY m.created_at DESC LIMIT ?1")?;let rows=st.query_map(rusqlite::params![limit],|r|Ok(ModelRow{id:r.get(0)?,name:r.get(1)?,latest_revision:r.get(2)?,latest_review:r.get(3)?}))?.collect::<std::result::Result<Vec<_>,_>>()?;Ok(rows)},Self::Postgres(c)=>Ok(c.query("SELECT m.id,m.canonical_name,(SELECT revision FROM model_revisions r WHERE r.model_id=m.id ORDER BY observed_at DESC LIMIT 1),(SELECT rv.id FROM reviews rv JOIN model_revisions rr ON rr.id=rv.revision_id WHERE rr.model_id=m.id ORDER BY rv.created_at DESC LIMIT 1) FROM models m ORDER BY m.created_at DESC LIMIT $1",&[&limit])?.into_iter().map(|r|ModelRow{id:r.get(0),name:r.get(1),latest_revision:r.get(2),latest_review:r.get(3)}).collect())}
    }

    pub fn review(&mut self, id: &str) -> Result<Option<ReviewRow>> {
        match self{Self::Sqlite(c)=>{let mut st=c.prepare("SELECT id,revision_id,final_decision,created_at,body_json FROM reviews WHERE id=?1")?;let mut rows=st.query(rusqlite::params![id])?;match rows.next()?{Some(r)=>Ok(Some(ReviewRow{id:r.get(0)?,revision_id:r.get(1)?,final_decision:r.get(2)?,created_at:r.get(3)?,body:serde_json::from_str::<serde_json::Value>(&r.get::<_,String>(4)?)?})),None=>Ok(None)}},Self::Postgres(c)=>match c.query_opt("SELECT id,revision_id,final_decision,created_at,body_json FROM reviews WHERE id=$1",&[&id])?{Some(r)=>Ok(Some(ReviewRow{id:r.get(0),revision_id:r.get(1),final_decision:r.get(2),created_at:r.get(3),body:serde_json::from_str::<serde_json::Value>(&r.get::<_,String>(4))?})),None=>Ok(None)}}
    }

    pub fn model(&mut self, id: &str) -> Result<Option<ModelRow>> {
        match self{
            Self::Sqlite(c)=>{let mut st=c.prepare("SELECT m.id,m.canonical_name,(SELECT revision FROM model_revisions r WHERE r.model_id=m.id ORDER BY observed_at DESC LIMIT 1),(SELECT rv.id FROM reviews rv JOIN model_revisions rr ON rr.id=rv.revision_id WHERE rr.model_id=m.id ORDER BY rv.created_at DESC LIMIT 1) FROM models m WHERE m.id=?1")?;let mut rows=st.query(rusqlite::params![id])?;match rows.next()?{Some(r)=>Ok(Some(ModelRow{id:r.get(0)?,name:r.get(1)?,latest_revision:r.get(2)?,latest_review:r.get(3)?})),None=>Ok(None)}},
            Self::Postgres(c)=>match c.query_opt("SELECT m.id,m.canonical_name,(SELECT revision FROM model_revisions r WHERE r.model_id=m.id ORDER BY observed_at DESC LIMIT 1),(SELECT rv.id FROM reviews rv JOIN model_revisions rr ON rr.id=rv.revision_id WHERE rr.model_id=m.id ORDER BY rv.created_at DESC LIMIT 1) FROM models m WHERE m.id=$1",&[&id])?{Some(r)=>Ok(Some(ModelRow{id:r.get(0),name:r.get(1),latest_revision:r.get(2),latest_review:r.get(3)})),None=>Ok(None)}
        }
    }

    pub fn revisions(&mut self, model_id: &str, limit: usize) -> Result<Vec<serde_json::Value>> {
        let limit = i64::try_from(limit.clamp(1, 200)).unwrap_or(200);
        match self{
            Self::Sqlite(c)=>{let mut st=c.prepare("SELECT id,revision,observed_at,metadata_json FROM model_revisions WHERE model_id=?1 ORDER BY observed_at DESC LIMIT ?2")?;let rows=st.query_map(rusqlite::params![model_id,limit],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,i64>(2)?,r.get::<_,String>(3)?)))?.collect::<std::result::Result<Vec<_>,_>>()?;rows.into_iter().map(|(id,revision,observed,metadata)|Ok(serde_json::json!({"id":id,"model_id":model_id,"revision":revision,"observed_at":observed,"metadata":serde_json::from_str::<serde_json::Value>(&metadata)?}))).collect()},
            Self::Postgres(c)=>c.query("SELECT id,revision,observed_at,metadata_json FROM model_revisions WHERE model_id=$1 ORDER BY observed_at DESC LIMIT $2",&[&model_id,&limit])?.into_iter().map(|r|{let metadata:String=r.get(3);Ok(serde_json::json!({"id":r.get::<_,String>(0),"model_id":model_id,"revision":r.get::<_,String>(1),"observed_at":r.get::<_,i64>(2),"metadata":serde_json::from_str::<serde_json::Value>(&metadata)?}))}).collect()
        }
    }

    pub fn revision(&mut self, id: &str) -> Result<Option<serde_json::Value>> {
        match self{
            Self::Sqlite(c)=>{let mut st=c.prepare("SELECT id,model_id,revision,observed_at,metadata_json FROM model_revisions WHERE id=?1")?;let mut rows=st.query(rusqlite::params![id])?;match rows.next()?{Some(r)=>{let metadata:String=r.get(4)?;Ok(Some(serde_json::json!({"id":r.get::<_,String>(0)?,"model_id":r.get::<_,String>(1)?,"revision":r.get::<_,String>(2)?,"observed_at":r.get::<_,i64>(3)?,"metadata":serde_json::from_str::<serde_json::Value>(&metadata)?})))},None=>Ok(None)}},
            Self::Postgres(c)=>match c.query_opt("SELECT id,model_id,revision,observed_at,metadata_json FROM model_revisions WHERE id=$1",&[&id])?{Some(r)=>{let metadata:String=r.get(4);Ok(Some(serde_json::json!({"id":r.get::<_,String>(0),"model_id":r.get::<_,String>(1),"revision":r.get::<_,String>(2),"observed_at":r.get::<_,i64>(3),"metadata":serde_json::from_str::<serde_json::Value>(&metadata)?})))},None=>Ok(None)}
        }
    }

    pub fn list_findings(&mut self, limit: usize) -> Result<Vec<serde_json::Value>> {
        let limit = i64::try_from(limit.clamp(1, 500)).unwrap_or(500);
        match self{
            Self::Sqlite(c)=>{let mut st=c.prepare("SELECT id,review_id,rule_id,domain,status,confidence,detail_json,created_at FROM findings ORDER BY created_at DESC LIMIT ?1")?;let rows=st.query_map(rusqlite::params![limit],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,String>(5)?,r.get::<_,String>(6)?,r.get::<_,i64>(7)?)))?.collect::<std::result::Result<Vec<_>,_>>()?;rows.into_iter().map(|(id,review,rule,domain,status,confidence,detail,created)|Ok(serde_json::json!({"id":id,"review_id":review,"rule_id":rule,"domain":domain,"status":status,"confidence":confidence,"detail":serde_json::from_str::<serde_json::Value>(&detail).unwrap_or(serde_json::Value::String(detail)),"created_at":created}))).collect()},
            Self::Postgres(c)=>c.query("SELECT id,review_id,rule_id,domain,status,confidence,detail_json,created_at FROM findings ORDER BY created_at DESC LIMIT $1",&[&limit])?.into_iter().map(|r|{let detail:String=r.get(6);Ok(serde_json::json!({"id":r.get::<_,String>(0),"review_id":r.get::<_,String>(1),"rule_id":r.get::<_,String>(2),"domain":r.get::<_,String>(3),"status":r.get::<_,String>(4),"confidence":r.get::<_,String>(5),"detail":serde_json::from_str::<serde_json::Value>(&detail).unwrap_or(serde_json::Value::String(detail)),"created_at":r.get::<_,i64>(7)}))}).collect()
        }
    }

    pub fn list_advisories(&mut self, limit: usize) -> Result<Vec<serde_json::Value>> {
        let limit = i64::try_from(limit.clamp(1, 200)).unwrap_or(200);
        match self{
            Self::Sqlite(c)=>{let mut st=c.prepare("SELECT id,review_id,title,severity,body_json,created_at FROM advisories ORDER BY created_at DESC LIMIT ?1")?;let rows=st.query_map(rusqlite::params![limit],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,i64>(5)?)))?.collect::<std::result::Result<Vec<_>,_>>()?;rows.into_iter().map(|(id,review,title,severity,body,created)|Ok(serde_json::json!({"id":id,"review_id":review,"title":title,"severity":severity,"body":serde_json::from_str::<serde_json::Value>(&body)?,"created_at":created}))).collect()},
            Self::Postgres(c)=>c.query("SELECT id,review_id,title,severity,body_json,created_at FROM advisories ORDER BY created_at DESC LIMIT $1",&[&limit])?.into_iter().map(|r|{let body:String=r.get(4);Ok(serde_json::json!({"id":r.get::<_,String>(0),"review_id":r.get::<_,String>(1),"title":r.get::<_,String>(2),"severity":r.get::<_,String>(3),"body":serde_json::from_str::<serde_json::Value>(&body)?,"created_at":r.get::<_,i64>(5)}))}).collect()
        }
    }

    pub fn aggregate(&mut self) -> Result<serde_json::Value> {
        let (models, revisions, reviews, blocks, warns) = match self {
            Self::Sqlite(c) => {
                let q = |sql: &str| -> Result<i64> { Ok(c.query_row(sql, [], |r| r.get(0))?) };
                (
                    q("SELECT COUNT(*) FROM models")?,
                    q("SELECT COUNT(*) FROM model_revisions")?,
                    q("SELECT COUNT(*) FROM reviews")?,
                    q("SELECT COUNT(*) FROM reviews WHERE final_decision='BLOCK'")?,
                    q("SELECT COUNT(*) FROM reviews WHERE final_decision='WARN'")?,
                )
            }
            Self::Postgres(c) => {
                let q = |c: &mut postgres::Client, sql: &str| -> Result<i64> {
                    Ok(c.query_one(sql, &[])?.get(0))
                };
                (
                    q(c, "SELECT COUNT(*) FROM models")?,
                    q(c, "SELECT COUNT(*) FROM model_revisions")?,
                    q(c, "SELECT COUNT(*) FROM reviews")?,
                    q(
                        c,
                        "SELECT COUNT(*) FROM reviews WHERE final_decision='BLOCK'",
                    )?,
                    q(
                        c,
                        "SELECT COUNT(*) FROM reviews WHERE final_decision='WARN'",
                    )?,
                )
            }
        };
        Ok(
            serde_json::json!({"models":models,"revisions":revisions,"reviews":reviews,"blocking_reviews":blocks,"warning_reviews":warns,"no_block_or_warning_reviews":reviews-blocks-warns}),
        )
    }
}

fn prepare_review_index(
    review_id: &str,
    body: &serde_json::Value,
    created_at: i64,
) -> Result<PreparedReviewIndex> {
    let mut values = Vec::new();
    collect_findings(body, &mut values, 0);
    values.truncate(4096);
    let mut findings = Vec::with_capacity(values.len());
    for (index, value) in values.into_iter().enumerate() {
        let rule = value
            .get("rule_id")
            .and_then(|value| value.as_str())
            .or_else(|| value.get("rule").and_then(|value| value.as_str()))
            .unwrap_or("LF-UNCLASSIFIED")
            .to_owned();
        let domain = value
            .get("domain")
            .and_then(|value| value.as_str())
            .unwrap_or("review")
            .to_owned();
        let status = value
            .get("status")
            .and_then(|value| value.as_str())
            .unwrap_or("WARN")
            .to_owned();
        let confidence = value
            .get("confidence")
            .and_then(|value| value.as_str())
            .unwrap_or("MEDIUM")
            .to_owned();
        let detail = serde_json::to_string(value)?;
        let index = index.to_string();
        let id = stable_id(
            "lffinding",
            &[review_id.as_bytes(), rule.as_bytes(), index.as_bytes()],
        );
        findings.push(PreparedFinding {
            id,
            review_id: review_id.to_owned(),
            rule,
            domain,
            status,
            confidence,
            detail,
            created_at,
        });
    }
    let advisory = if body.get("final_decision").and_then(|value| value.as_str()) == Some("BLOCK") {
        let advisory_body = serde_json::json!({
            "review_id": review_id,
            "summary": "A pinned model revision produced blocking Layerfault findings. Review the underlying evidence before deployment."
        });
        Some(PreparedAdvisory {
            id: stable_id("lfadvisory", &[review_id.as_bytes()]),
            review_id: review_id.to_owned(),
            title: format!("Blocking Layerfault review {review_id}"),
            body: serde_json::to_string(&advisory_body)?,
            created_at,
        })
    } else {
        None
    };
    Ok(PreparedReviewIndex { findings, advisory })
}

fn insert_review_index_sqlite(
    connection: &rusqlite::Connection,
    index: &PreparedReviewIndex,
) -> Result<()> {
    for finding in &index.findings {
        connection.execute(
            "INSERT OR REPLACE INTO findings(id,review_id,rule_id,domain,status,confidence,detail_json,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            rusqlite::params![
                finding.id,
                finding.review_id,
                finding.rule,
                finding.domain,
                finding.status,
                finding.confidence,
                finding.detail,
                finding.created_at
            ],
        )?;
    }
    if let Some(advisory) = &index.advisory {
        connection.execute(
            "INSERT OR IGNORE INTO advisories(id,review_id,title,severity,body_json,created_at) VALUES(?1,?2,?3,'HIGH',?4,?5)",
            rusqlite::params![
                advisory.id,
                advisory.review_id,
                advisory.title,
                advisory.body,
                advisory.created_at
            ],
        )?;
    }
    Ok(())
}

fn insert_review_index_postgres(
    connection: &mut impl postgres::GenericClient,
    index: &PreparedReviewIndex,
) -> Result<()> {
    for finding in &index.findings {
        connection.execute(
            "INSERT INTO findings(id,review_id,rule_id,domain,status,confidence,detail_json,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(id) DO UPDATE SET detail_json=EXCLUDED.detail_json,status=EXCLUDED.status,confidence=EXCLUDED.confidence",
            &[
                &finding.id,
                &finding.review_id,
                &finding.rule,
                &finding.domain,
                &finding.status,
                &finding.confidence,
                &finding.detail,
                &finding.created_at,
            ],
        )?;
    }
    if let Some(advisory) = &index.advisory {
        connection.execute(
            "INSERT INTO advisories(id,review_id,title,severity,body_json,created_at) VALUES($1,$2,$3,'HIGH',$4,$5) ON CONFLICT(id) DO NOTHING",
            &[
                &advisory.id,
                &advisory.review_id,
                &advisory.title,
                &advisory.body,
                &advisory.created_at,
            ],
        )?;
    }
    Ok(())
}

fn collect_findings<'a>(
    value: &'a serde_json::Value,
    out: &mut Vec<&'a serde_json::Value>,
    depth: usize,
) {
    if depth > 16 || out.len() >= 4096 {
        return;
    }
    match value {
        serde_json::Value::Object(map) => {
            if map.contains_key("rule_id") || map.contains_key("rule") {
                out.push(value);
            }
            for child in map.values() {
                collect_findings(child, out, depth + 1);
            }
        }
        serde_json::Value::Array(values) => {
            for child in values.iter().take(4096) {
                collect_findings(child, out, depth + 1);
            }
        }
        _ => {}
    }
}
