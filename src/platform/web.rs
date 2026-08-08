use anyhow::{anyhow, Result};
use std::io::Read;
use std::sync::{
    mpsc::{sync_channel, TrySendError},
    Arc, Mutex,
};
use std::time::{SystemTime, UNIX_EPOCH};
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

const MAX_REQUEST_BODY: u64 = 1024 * 1024;
const REQUESTS_PER_MINUTE: u64 = 600;
const MAX_HTTP_WORKERS: usize = 32;
const HTTP_QUEUE_DEPTH: usize = 1024;

struct State {
    db: Mutex<super::db::PlatformDb>,
    config: super::PlatformConfig,
    limiter: Mutex<RateWindow>,
}
struct RateWindow {
    minute: u64,
    count: u64,
}

pub fn serve(config: super::PlatformConfig) -> Result<()> {
    let mut db = super::db::PlatformDb::connect(&config.database)?;
    db.migrate()?;
    let server = Server::http(&config.listen)
        .map_err(|e| anyhow!("unable to listen on {}: {e}", config.listen))?;
    let state = Arc::new(State {
        db: Mutex::new(db),
        config,
        limiter: Mutex::new(RateWindow {
            minute: 0,
            count: 0,
        }),
    });
    let workers = std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(4)
        .clamp(2, MAX_HTTP_WORKERS);
    let (sender, receiver) = sync_channel::<Request>(HTTP_QUEUE_DEPTH);
    let receiver = Arc::new(Mutex::new(receiver));
    for index in 0..workers {
        let receiver = Arc::clone(&receiver);
        let state = Arc::clone(&state);
        std::thread::Builder::new()
            .name(format!("layerfault-http-{index}"))
            .spawn(move || loop {
                let request = {
                    let guard = match receiver.lock() {
                        Ok(guard) => guard,
                        Err(_) => return,
                    };
                    match guard.recv() {
                        Ok(request) => request,
                        Err(_) => return,
                    }
                };
                if let Err(error) = handle(request, &state) {
                    eprintln!("platform request error: {error:#}");
                }
            })?;
    }
    eprintln!(
        "Layerfault platform listening on http://{} with {} bounded worker(s)",
        state.config.listen, workers
    );
    for request in server.incoming_requests() {
        match sender.try_send(request) {
            Ok(()) => {}
            Err(TrySendError::Full(request)) => {
                let _ = respond_json(
                    request,
                    503,
                    &serde_json::json!({"error":"server request queue is full"}),
                );
            }
            Err(TrySendError::Disconnected(_)) => {
                return Err(anyhow!("platform HTTP worker pool stopped unexpectedly"));
            }
        }
    }
    Ok(())
}

fn handle(request: Request, state: &State) -> Result<()> {
    if !allow_request(&state.limiter)? {
        return respond_json(
            request,
            429,
            &serde_json::json!({"error":"rate limit exceeded"}),
        );
    }
    let method = request.method().clone();
    let raw_url = request.url().to_owned();
    let path = raw_url.split('?').next().unwrap_or("/");
    if method == Method::Get && path == "/api/v1/health" {
        return respond_json(
            request,
            200,
            &serde_json::json!({"status":"ok","version":env!("CARGO_PKG_VERSION")}),
        );
    }
    if method == Method::Get && path == "/api/v1/models" {
        let limit = query_limit(&raw_url, 100);
        let mut db = lock_db(state)?;
        return respond_json(request, 200, &serde_json::to_value(db.list_models(limit)?)?);
    }
    if method == Method::Get && path.starts_with("/api/v1/models/") && path.ends_with("/revisions")
    {
        let id = path
            .trim_start_matches("/api/v1/models/")
            .trim_end_matches("/revisions")
            .trim_end_matches('/');
        if !safe_id(id) {
            return respond_json(
                request,
                400,
                &serde_json::json!({"error":"invalid model id"}),
            );
        }
        let mut db = lock_db(state)?;
        return respond_json(
            request,
            200,
            &serde_json::to_value(db.revisions(id, query_limit(&raw_url, 100))?)?,
        );
    }
    if method == Method::Get && path.starts_with("/api/v1/models/") {
        let id = path.trim_start_matches("/api/v1/models/");
        if !safe_id(id) {
            return respond_json(
                request,
                400,
                &serde_json::json!({"error":"invalid model id"}),
            );
        }
        let mut db = lock_db(state)?;
        return match db.model(id)? {
            Some(row) => respond_json(request, 200, &serde_json::to_value(row)?),
            None => respond_json(request, 404, &serde_json::json!({"error":"not found"})),
        };
    }
    if method == Method::Get && path.starts_with("/api/v1/revisions/") {
        let id = path.trim_start_matches("/api/v1/revisions/");
        if !safe_id(id) {
            return respond_json(
                request,
                400,
                &serde_json::json!({"error":"invalid revision id"}),
            );
        }
        let mut db = lock_db(state)?;
        return match db.revision(id)? {
            Some(row) => respond_json(request, 200, &row),
            None => respond_json(request, 404, &serde_json::json!({"error":"not found"})),
        };
    }
    if method == Method::Get && path.starts_with("/api/v1/reviews/") {
        let id = path.trim_start_matches("/api/v1/reviews/");
        if !safe_id(id) {
            return respond_json(
                request,
                400,
                &serde_json::json!({"error":"invalid review id"}),
            );
        }
        let mut db = lock_db(state)?;
        return match db.review(id)? {
            Some(review) => respond_json(request, 200, &serde_json::to_value(review)?),
            None => respond_json(request, 404, &serde_json::json!({"error":"not found"})),
        };
    }
    if method == Method::Get && path == "/api/v1/findings" {
        let mut db = lock_db(state)?;
        return respond_json(
            request,
            200,
            &serde_json::to_value(db.list_findings(query_limit(&raw_url, 100))?)?,
        );
    }
    if method == Method::Get && path == "/api/v1/advisories" {
        let mut db = lock_db(state)?;
        return respond_json(
            request,
            200,
            &serde_json::to_value(db.list_advisories(query_limit(&raw_url, 100))?)?,
        );
    }
    if method == Method::Get && path == "/api/v1/weekly" {
        let mut db = lock_db(state)?;
        return respond_json(
            request,
            200,
            &serde_json::to_value(db.list_weekly(query_limit(&raw_url, 20))?)?,
        );
    }
    if method == Method::Get && path.starts_with("/api/v1/weekly/") {
        let period = path.trim_start_matches("/api/v1/weekly/");
        if !safe_period(period) {
            return respond_json(request, 400, &serde_json::json!({"error":"invalid period"}));
        }
        let mut db = lock_db(state)?;
        return match db.weekly(period)? {
            Some(row) => respond_json(request, 200, &row),
            None => respond_json(request, 404, &serde_json::json!({"error":"not found"})),
        };
    }
    if method == Method::Post && path == "/api/v1/admin/crawl" {
        return admin_crawl(request, state);
    }
    if method == Method::Post && path == "/webhooks/huggingface" {
        return webhook(request, state);
    }
    if method == Method::Get && path == "/metrics" {
        let mut db = lock_db(state)?;
        let aggregate = db.aggregate()?;
        return respond_text(
            request,
            200,
            &metrics(&aggregate),
            "text/plain; version=0.0.4",
        );
    }
    if method == Method::Get && path == "/" {
        return home(request, state);
    }
    if method == Method::Get && path == "/models" {
        return models_page(request, state);
    }
    if method == Method::Get && path.starts_with("/models/") {
        return model_page(request, state, path.trim_start_matches("/models/"));
    }
    if method == Method::Get && path.starts_with("/reviews/") {
        return review_page(request, state, path.trim_start_matches("/reviews/"));
    }
    if method == Method::Get && path == "/weekly" {
        return weekly_page(request, state);
    }
    if method == Method::Get && path.starts_with("/weekly/") {
        return weekly_detail_page(request, state, path.trim_start_matches("/weekly/"));
    }
    if method == Method::Get && path == "/advisories" {
        return advisories_page(request, state);
    }
    if method == Method::Get && path.starts_with("/feeds/") {
        return atom_feed(request, state, path.trim_start_matches("/feeds/"));
    }
    respond_json(request, 404, &serde_json::json!({"error":"not found"}))
}

fn admin_crawl(mut request: Request, state: &State) -> Result<()> {
    if !admin_authorized(&request, state)? {
        return respond_json(
            request,
            401,
            &serde_json::json!({"error":"admin authorization required"}),
        );
    }
    if request
        .body_length()
        .is_some_and(|length| length as u64 > MAX_REQUEST_BODY)
    {
        return respond_json(
            request,
            413,
            &serde_json::json!({"error":"request body too large"}),
        );
    }
    let mut bytes = Vec::new();
    request
        .as_reader()
        .take(MAX_REQUEST_BODY + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_REQUEST_BODY {
        return respond_json(
            request,
            413,
            &serde_json::json!({"error":"request body too large"}),
        );
    }
    let payload: serde_json::Value = if bytes.is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_slice(&bytes)?
    };
    let limit = payload
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(100)
        .clamp(1, 1000) as usize;
    let cursor = payload.get("cursor").and_then(|v| v.as_str());
    let mut db = lock_db(state)?;
    let page = super::worker::crawl_once(&mut db, limit, cursor)?;
    respond_json(
        request,
        202,
        &serde_json::json!({"queued":page.models.len(),"next":page.next}),
    )
}

fn webhook(mut request: Request, state: &State) -> Result<()> {
    let expected = crate::paths::secret_from_env(&state.config.webhook_secret_env)?
        .ok_or_else(|| anyhow!("webhook secret environment/file is not configured"))?;
    let received = header(&request, "X-Webhook-Secret");
    if !crate::hub::verify_webhook_secret(received.as_deref(), &expected) {
        return respond_json(
            request,
            401,
            &serde_json::json!({"error":"invalid webhook secret"}),
        );
    }
    if request
        .body_length()
        .is_some_and(|length| length as u64 > MAX_REQUEST_BODY)
    {
        return respond_json(
            request,
            413,
            &serde_json::json!({"error":"request body too large"}),
        );
    }
    let mut bytes = Vec::new();
    request
        .as_reader()
        .take(MAX_REQUEST_BODY + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_REQUEST_BODY {
        return respond_json(
            request,
            413,
            &serde_json::json!({"error":"request body too large"}),
        );
    }
    let payload: serde_json::Value = serde_json::from_slice(&bytes)?;
    let repo = payload
        .pointer("/repo/name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("webhook payload lacks repo.name"))?;
    let sha = payload
        .pointer("/repo/headSha")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("webhook payload lacks repo.headSha"))?;
    let mut db = lock_db(state)?;
    let id = db.enqueue(
        "hub-review",
        &format!("hub-review:{repo}:{sha}"),
        &serde_json::json!({"repo":repo,"revision":sha,"source":"webhook"}),
        10,
    )?;
    respond_json(request, 202, &serde_json::json!({"queued":id}))
}

fn home(request: Request, state: &State) -> Result<()> {
    let mut db = lock_db(state)?;
    let agg = db.aggregate()?;
    let body=format!("<!doctype html><html><head><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\"><title>Layerfault</title></head><body><h1>Layerfault Open Model Security Review</h1><p>Models: {} · Revisions: {} · Reviews: {}</p><p><a href=\"/models\">Models</a> · <a href=\"/weekly\">Weekly reviews</a></p><p>Layerfault reports evidence from checks performed; it does not prove a model is free of hidden behaviour.</p></body></html>",n(&agg,"models"),n(&agg,"revisions"),n(&agg,"reviews"));
    respond_html(request, 200, &body)
}
fn models_page(request: Request, state: &State) -> Result<()> {
    let mut db = lock_db(state)?;
    let rows = db.list_models(200)?;
    let mut items = String::new();
    for row in rows {
        items.push_str(&format!(
            "<li><a href=\"/models/{}\">{}</a> — revision {} — {}</li>",
            esc_attr(&row.id),
            esc(&row.name),
            esc(row.latest_revision.as_deref().unwrap_or("unknown")),
            row.latest_review
                .as_ref()
                .map(|id| format!("<a href=\"/reviews/{}\">review</a>", esc_attr(id)))
                .unwrap_or_else(|| "no review".to_owned())
        ));
    }
    let body = page("Models", &format!("<h1>Models</h1><ul>{items}</ul>"));
    respond_html(request, 200, &body)
}
fn model_page(request: Request, state: &State, id: &str) -> Result<()> {
    if !safe_id(id) {
        return respond_html(
            request,
            400,
            &page("Invalid model", "<p>Invalid model id.</p>"),
        );
    }
    let mut db = lock_db(state)?;
    let Some(model) = db.model(id)? else {
        return respond_html(request, 404, &page("Not found", "<p>Model not found.</p>"));
    };
    let revisions = db.revisions(id, 100)?;
    let mut items = String::new();
    for revision in revisions {
        let rid = revision.get("id").and_then(|v| v.as_str()).unwrap_or("");
        let sha = revision
            .get("revision")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        items.push_str(&format!(
            "<li>{} <small>{}</small></li>",
            esc(sha),
            esc(rid)
        ));
    }
    let latest = model
        .latest_review
        .as_ref()
        .map(|r| {
            format!(
                "<p>Latest review: <a href=\"/reviews/{}\">{}</a></p>",
                esc_attr(r),
                esc(r)
            )
        })
        .unwrap_or_default();
    respond_html(request,200,&page(&model.name,&format!("<h1>{}</h1>{latest}<h2>Observed immutable revisions</h2><ul>{items}</ul><p>Model-card metadata and base-model claims are evidence, not proof of lineage.</p>",esc(&model.name))))
}

fn review_page(request: Request, state: &State, id: &str) -> Result<()> {
    if !safe_id(id) {
        return respond_html(
            request,
            400,
            &page("Invalid review", "<p>Invalid review id.</p>"),
        );
    }
    let mut db = lock_db(state)?;
    match db.review(id)? {
        Some(review) => {
            let pretty = serde_json::to_string_pretty(&review.body)?;
            let body=page("Security review",&format!("<h1>Security review</h1><p>Decision: <strong>{}</strong></p><p>Exact revision id: {}</p><pre>{}</pre><p>Boundary: this report describes checks performed; it is not proof of absence of hidden triggers/backdoors.</p>",esc(&review.final_decision),esc(&review.revision_id),esc(&pretty)));
            respond_html(request, 200, &body)
        }
        None => respond_html(request, 404, &page("Not found", "<p>Review not found.</p>")),
    }
}
fn weekly_page(request: Request, state: &State) -> Result<()> {
    let mut db = lock_db(state)?;
    let values = db.list_weekly(52)?;
    let mut items = String::new();
    for value in values {
        let period = value
            .get("period")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        items.push_str(&format!("<li>{}</li>", esc(period)));
    }
    respond_html(
        request,
        200,
        &page(
            "Weekly reviews",
            &format!("<h1>Weekly reviews</h1><ul>{items}</ul>"),
        ),
    )
}
fn weekly_detail_page(request: Request, state: &State, period: &str) -> Result<()> {
    if !safe_period(period) {
        return respond_html(
            request,
            400,
            &page("Invalid period", "<p>Invalid weekly period.</p>"),
        );
    }
    let mut db = lock_db(state)?;
    match db.weekly(period)? {
        Some(value) => {
            let pretty = serde_json::to_string_pretty(&value)?;
            respond_html(request,200,&page(period,&format!("<h1>Weekly review {}</h1><pre>{}</pre><p>Counts describe checks performed; they do not prove the reviewed models are free of hidden behaviour.</p>",esc(period),esc(&pretty))))
        }
        None => respond_html(
            request,
            404,
            &page("Not found", "<p>Weekly review not found.</p>"),
        ),
    }
}

fn atom_feed(request: Request, state: &State, kind: &str) -> Result<()> {
    let now = chrono::Utc::now().to_rfc3339();
    let mut db = lock_db(state)?;
    let mut entries = String::new();
    let title = match kind {
        "weekly.atom" => {
            for row in db.list_weekly(50)? {
                let id = row.get("id").and_then(|v| v.as_str()).unwrap_or("weekly");
                let period = row
                    .get("period")
                    .and_then(|v| v.as_str())
                    .unwrap_or("weekly");
                entries.push_str(&atom_entry(
                    id,
                    period,
                    &format!("/weekly/{period}"),
                    "Layerfault weekly aggregate review.",
                ));
            }
            "Layerfault Weekly Reviews"
        }
        "advisories.atom" => {
            for row in db.list_advisories(50)? {
                let id = row.get("id").and_then(|v| v.as_str()).unwrap_or("advisory");
                let title = row
                    .get("title")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Layerfault advisory");
                entries.push_str(&atom_entry(
                    id,
                    title,
                    "/advisories",
                    "Evidence-backed Layerfault advisory.",
                ));
            }
            "Layerfault Advisories"
        }
        "reviews.atom" => {
            for row in db.list_models(50)? {
                if let Some(review) = row.latest_review.as_deref() {
                    entries.push_str(&atom_entry(
                        review,
                        &format!("Review: {}", row.name),
                        &format!("/reviews/{review}"),
                        "Pinned model-revision security review.",
                    ));
                }
            }
            "Layerfault Model Reviews"
        }
        _ => return respond_json(request, 404, &serde_json::json!({"error":"feed not found"})),
    };
    let body=format!("<?xml version=\"1.0\" encoding=\"utf-8\"?><feed xmlns=\"http://www.w3.org/2005/Atom\"><id>urn:layerfault:{}</id><title>{}</title><updated>{}</updated>{}</feed>",esc_xml(kind),esc_xml(title),now,entries);
    respond_text(request, 200, &body, "application/atom+xml; charset=utf-8")
}
fn atom_entry(id: &str, title: &str, href: &str, summary: &str) -> String {
    format!(
        "<entry><id>{}</id><title>{}</title><link href=\"{}\"/><summary>{}</summary></entry>",
        esc_xml(id),
        esc_xml(title),
        esc_xml(href),
        esc_xml(summary)
    )
}
fn esc_xml(value: &str) -> String {
    esc(value)
}

fn advisories_page(request: Request, state: &State) -> Result<()> {
    let mut db = lock_db(state)?;
    let values = db.list_advisories(100)?;
    let mut items = String::new();
    for value in values {
        let title = value
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("Layerfault advisory");
        let severity = value
            .get("severity")
            .and_then(|v| v.as_str())
            .unwrap_or("UNKNOWN");
        items.push_str(&format!(
            "<li><strong>{}</strong> — {}</li>",
            esc(severity),
            esc(title)
        ));
    }
    respond_html(request,200,&page("Advisories",&format!("<h1>Advisories</h1><ul>{items}</ul><p>Advisories summarize evidence from specific pinned reviews and are not universal declarations about a model.</p>")))
}

fn lock_db(state: &State) -> Result<std::sync::MutexGuard<'_, super::db::PlatformDb>> {
    state
        .db
        .lock()
        .map_err(|_| anyhow!("platform database lock is poisoned"))
}
fn allow_request(limiter: &Mutex<RateWindow>) -> Result<bool> {
    let minute = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 60;
    let mut rate = limiter
        .lock()
        .map_err(|_| anyhow!("rate limiter lock is poisoned"))?;
    if rate.minute != minute {
        rate.minute = minute;
        rate.count = 0;
    }
    rate.count = rate.count.saturating_add(1);
    Ok(rate.count <= REQUESTS_PER_MINUTE)
}
fn header(request: &Request, name: &'static str) -> Option<String> {
    request
        .headers()
        .iter()
        .find(|h| h.field.equiv(name))
        .map(|h| h.value.as_str().to_owned())
}
fn query_limit(url: &str, default: usize) -> usize {
    url.split_once('?')
        .map(|(_, q)| {
            q.split('&')
                .find_map(|pair| {
                    pair.split_once('=')
                        .filter(|(k, _)| *k == "limit")
                        .and_then(|(_, v)| v.parse::<usize>().ok())
                })
                .unwrap_or(default)
        })
        .unwrap_or(default)
        .clamp(1, 200)
}
fn admin_authorized(request: &Request, state: &State) -> Result<bool> {
    let expected = crate::paths::secret_from_env(&state.config.admin_token_env)?
        .ok_or_else(|| anyhow!("admin token environment/file is not configured"))?;
    if expected.len() < 24 {
        return Err(anyhow!("configured admin token is too short"));
    }
    let bearer =
        header(request, "Authorization").and_then(|v| v.strip_prefix("Bearer ").map(str::to_owned));
    Ok(crate::hub::verify_webhook_secret(
        bearer.as_deref(),
        &expected,
    ))
}
fn safe_period(value: &str) -> bool {
    value.len() >= 4
        && value.len() <= 32
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}
fn safe_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '-' | '_' | '.'))
}
fn respond_json(request: Request, status: u16, value: &serde_json::Value) -> Result<()> {
    let body = serde_json::to_string(value)?;
    respond(request, status, body, "application/json; charset=utf-8")
}
fn respond_html(request: Request, status: u16, body: &str) -> Result<()> {
    respond(request, status, body.to_owned(), "text/html; charset=utf-8")
}
fn respond_text(request: Request, status: u16, body: &str, content_type: &str) -> Result<()> {
    respond(request, status, body.to_owned(), content_type)
}
fn respond(request: Request, status: u16, body: String, content_type: &str) -> Result<()> {
    let mut response = Response::from_string(body).with_status_code(StatusCode(status));
    for (name, value) in [
        ("Content-Type", content_type),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "no-referrer"),
        (
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
        ),
    ] {
        response = response.with_header(
            Header::from_bytes(name.as_bytes(), value.as_bytes())
                .map_err(|_| anyhow!("invalid static HTTP header"))?,
        );
    }
    request
        .respond(response)
        .map_err(|e| anyhow!("HTTP response failed: {e}"))?;
    Ok(())
}
fn page(title: &str, content: &str) -> String {
    format!("<!doctype html><html><head><meta charset=\"utf-8\"><title>{}</title></head><body>{}</body></html>",esc(title),content)
}
fn esc(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn esc_attr(value: &str) -> String {
    esc(value)
}
fn n(value: &serde_json::Value, key: &str) -> i64 {
    value.get(key).and_then(|v| v.as_i64()).unwrap_or(0)
}
fn metrics(value: &serde_json::Value) -> String {
    format!("layerfault_models {}\nlayerfault_revisions {}\nlayerfault_reviews {}\nlayerfault_blocking_reviews {}\nlayerfault_warning_reviews {}\n",n(value,"models"),n(value,"revisions"),n(value,"reviews"),n(value,"blocking_reviews"),n(value,"warning_reviews"))
}
