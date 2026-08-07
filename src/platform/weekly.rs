use anyhow::{bail, Context, Result};
use chrono::{Datelike, Utc};
use lettre::{transport::smtp::authentication::Credentials, Message, SmtpTransport, Transport};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeeklyReview {
    pub version: u32,
    pub period: String,
    pub generated_at: String,
    pub counts: serde_json::Value,
    pub methodology_boundary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewsletterBodies {
    pub subject: String,
    pub text: String,
    pub markdown: String,
    pub html: String,
}

pub fn generate(db:&mut super::db::PlatformDb)->Result<WeeklyReview>{
    let now=Utc::now();
    let week=now.iso_week();
    let period=format!("{}-W{:02}",week.year(),week.week());
    let counts=db.aggregate()?;
    let review=WeeklyReview{version:1,period:period.clone(),generated_at:now.to_rfc3339(),counts,methodology_boundary:"Counts describe Layerfault checks performed on observed revisions. A review without blocking/warning findings is not proof that a model is safe or free of hidden triggers.".to_owned()};
    db.store_weekly(&period,&serde_json::to_value(&review)?)?;
    Ok(review)
}

pub fn render(review:&WeeklyReview,public_base:Option<&str>)->NewsletterBodies{
    let models=n(&review.counts,"models");let revisions=n(&review.counts,"revisions");let reviews=n(&review.counts,"reviews");let blocks=n(&review.counts,"blocking_reviews");let warnings=n(&review.counts,"warning_reviews");let no_findings=n(&review.counts,"no_block_or_warning_reviews");
    let subject=format!("Layerfault Open Model Security Review — {}",review.period);
    let link=public_base.map(|v|format!("{}/weekly/{}",v.trim_end_matches('/'),review.period));
    let text=format!("{subject}\n\nModels observed: {models}\nRevisions observed: {revisions}\nReviews: {reviews}\nBlocking reviews: {blocks}\nWarning reviews: {warnings}\nReviews with no blocking/warning findings under the checks performed: {no_findings}\n{}\n\nBoundary: {}\n",link.as_ref().map(|v|format!("\nFull review: {v}" )).unwrap_or_default(),review.methodology_boundary);
    let markdown=format!("# {subject}\n\n| Metric | Count |\n|---|---:|\n| Models observed | {models} |\n| Revisions observed | {revisions} |\n| Reviews | {reviews} |\n| Blocking reviews | {blocks} |\n| Warning reviews | {warnings} |\n| No blocking/warning findings under checks performed | {no_findings} |\n\n{}\n\n> {}\n",link.as_ref().map(|v|format!("[Full review]({v})" )).unwrap_or_default(),review.methodology_boundary);
    let html=format!("<!doctype html><html><body><h1>{}</h1><table><tr><th>Metric</th><th>Count</th></tr><tr><td>Models observed</td><td>{models}</td></tr><tr><td>Revisions observed</td><td>{revisions}</td></tr><tr><td>Reviews</td><td>{reviews}</td></tr><tr><td>Blocking reviews</td><td>{blocks}</td></tr><tr><td>Warning reviews</td><td>{warnings}</td></tr><tr><td>No blocking/warning findings under checks performed</td><td>{no_findings}</td></tr></table>{}<p><strong>Boundary:</strong> {}</p></body></html>",escape(&subject),link.as_ref().map(|v|format!("<p><a href=\"{}\">Full review</a></p>",escape_attr(v))).unwrap_or_default(),escape(&review.methodology_boundary));
    NewsletterBodies{subject,text,markdown,html}
}

pub fn send_smtp(bodies:&NewsletterBodies,to:&str,from:&str,host:&str,username:Option<&str>,password:Option<&str>,dry_run:bool)->Result<()> {
    if dry_run{return Ok(());}if host.trim().is_empty(){bail!("SMTP host is required");}
    let message=Message::builder().from(from.parse().context("invalid newsletter From address")?).to(to.parse().context("invalid newsletter To address")?).subject(&bodies.subject).header(lettre::message::header::ContentType::TEXT_HTML).body(bodies.html.clone())?;
    let mut builder=SmtpTransport::relay(host).context("unable to configure TLS SMTP relay")?;
    if let (Some(user),Some(pass))=(username,password){builder=builder.credentials(Credentials::new(user.to_owned(),pass.to_owned()));}
    let mailer=builder.build();mailer.send(&message).context("SMTP newsletter send failed")?;Ok(())
}

fn n(value:&serde_json::Value,key:&str)->i64{value.get(key).and_then(|v|v.as_i64()).unwrap_or(0)}
fn escape(value:&str)->String{value.replace('&',"&amp;").replace('<',"&lt;").replace('>',"&gt;").replace('"',"&quot;").replace('\'',"&#39;")}
fn escape_attr(value:&str)->String{escape(value)}
