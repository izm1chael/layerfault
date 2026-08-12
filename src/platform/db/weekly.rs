use super::connection::PlatformDb;
use super::types::{now_i64, stable_id};
use anyhow::Result;

impl PlatformDb {
    pub fn weekly(&mut self, period: &str) -> Result<Option<serde_json::Value>> {
        match self {
            Self::Sqlite(c) => {
                let mut st = c.prepare(
                    "SELECT id,period,generated_at,body_json FROM weekly_reviews WHERE period=?1",
                )?;
                let mut rows = st.query(rusqlite::params![period])?;
                match rows.next()? {
                    Some(r) => {
                        let body: String = r.get(3)?;
                        Ok(Some(
                            serde_json::json!({"id":r.get::<_,String>(0)?,"period":r.get::<_,String>(1)?,"generated_at":r.get::<_,i64>(2)?,"body":serde_json::from_str::<serde_json::Value>(&body)?}),
                        ))
                    }
                    None => Ok(None),
                }
            }
            Self::Postgres(c) => match c.query_opt(
                "SELECT id,period,generated_at,body_json FROM weekly_reviews WHERE period=$1",
                &[&period],
            )? {
                Some(r) => {
                    let body: String = r.get(3);
                    Ok(Some(
                        serde_json::json!({"id":r.get::<_,String>(0),"period":r.get::<_,String>(1),"generated_at":r.get::<_,i64>(2),"body":serde_json::from_str::<serde_json::Value>(&body)?}),
                    ))
                }
                None => Ok(None),
            },
        }
    }

    pub fn store_weekly(&mut self, period: &str, body: &serde_json::Value) -> Result<String> {
        let id = stable_id("lfweekly", &[period.as_bytes()]);
        let now = now_i64();
        let text = serde_json::to_string(body)?;
        match self {
            Self::Sqlite(c) => {
                c.execute("INSERT INTO weekly_reviews(id,period,generated_at,body_json) VALUES(?1,?2,?3,?4) ON CONFLICT(period) DO UPDATE SET generated_at=excluded.generated_at,body_json=excluded.body_json",rusqlite::params![id,period,now,text])?;
            }
            Self::Postgres(c) => {
                c.execute("INSERT INTO weekly_reviews(id,period,generated_at,body_json) VALUES($1,$2,$3,$4) ON CONFLICT(period) DO UPDATE SET generated_at=EXCLUDED.generated_at,body_json=EXCLUDED.body_json",&[&id,&period,&now,&text])?;
            }
        }
        Ok(id)
    }
    pub fn list_weekly(&mut self, limit: usize) -> Result<Vec<serde_json::Value>> {
        let limit = i64::try_from(limit.clamp(1, 100)).unwrap_or(100);
        match self{Self::Sqlite(c)=>{let mut st=c.prepare("SELECT id,period,generated_at,body_json FROM weekly_reviews ORDER BY generated_at DESC LIMIT ?1")?;let values=st.query_map(rusqlite::params![limit],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,i64>(2)?,r.get::<_,String>(3)?)))?.collect::<std::result::Result<Vec<_>,_>>()?;values.into_iter().map(|(id,period,generated,body)|Ok(serde_json::json!({"id":id,"period":period,"generated_at":generated,"body":serde_json::from_str::<serde_json::Value>(&body)?}))).collect()},Self::Postgres(c)=>c.query("SELECT id,period,generated_at,body_json FROM weekly_reviews ORDER BY generated_at DESC LIMIT $1",&[&limit])?.into_iter().map(|r|{let body:String=r.get(3);Ok(serde_json::json!({"id":r.get::<_,String>(0),"period":r.get::<_,String>(1),"generated_at":r.get::<_,i64>(2),"body":serde_json::from_str::<serde_json::Value>(&body)?}))}).collect()}
    }
}
