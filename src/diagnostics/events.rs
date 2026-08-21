use super::sink::{level_allows, level_from_u8, render_event_with_data, write_line, Level, LEVEL};
use serde_json::json;
use std::sync::atomic::Ordering;
use std::time::Duration;

/// Emit a diagnostic event at `level` with `kind` and `message`.
pub fn emit(level: Level, kind: &str, message: &str) {
    emit_full(level, kind, message, None, None);
}

/// Emit a diagnostic event with structured metadata data payload.
pub fn emit_with_data(level: Level, kind: &str, message: &str, data: serde_json::Value) {
    let configured = level_from_u8(LEVEL.load(Ordering::Relaxed));
    if !level_allows(configured, level) {
        return;
    }
    let line = render_event_with_data(level, kind, message, None, None, Some(&data));
    write_line(&line);
}

/// Emit a diagnostic event with optional `subject` and `hint`.
pub fn emit_full(
    level: Level,
    kind: &str,
    message: &str,
    subject: Option<&str>,
    hint: Option<&str>,
) {
    let configured = level_from_u8(LEVEL.load(Ordering::Relaxed));
    if !level_allows(configured, level) {
        return;
    }
    let line = render_event_with_data(level, kind, message, subject, hint, None);
    write_line(&line);
}

/// Emit a subprocess lifecycle diagnostic event.
pub fn emit_subproc(
    level: Level,
    command: &str,
    exit_code: Option<i32>,
    duration: Duration,
    stderr_tail: Option<&str>,
) {
    let configured = level_from_u8(LEVEL.load(Ordering::Relaxed));
    if !level_allows(configured, level) {
        return;
    }
    let mut data = json!({
        "command": command,
        "duration_ms": duration.as_millis(),
        "exit_code": exit_code,
    });
    if let Some(tail) = stderr_tail {
        if !tail.is_empty() {
            data["stderr_tail"] = json!(tail);
        }
    }
    let msg = match exit_code {
        Some(0) => format!("subprocess '{command}' exited cleanly in {:?}", duration),
        Some(code) => format!(
            "subprocess '{command}' failed with exit code {code} in {:?}",
            duration
        ),
        None => format!("subprocess '{command}' terminated abnormally"),
    };
    let line = render_event_with_data(level, "subprocess", &msg, Some(command), None, Some(&data));
    write_line(&line);
}

/// Emit an HTTP network interaction diagnostic event.
pub fn emit_http(
    level: Level,
    method: &str,
    url: &str,
    status_code: Option<u16>,
    duration: Duration,
    bytes: Option<usize>,
) {
    let configured = level_from_u8(LEVEL.load(Ordering::Relaxed));
    if !level_allows(configured, level) {
        return;
    }
    let mut data = json!({
        "method": method,
        "url": url,
        "duration_ms": duration.as_millis(),
    });
    if let Some(code) = status_code {
        data["status"] = json!(code);
    }
    if let Some(b) = bytes {
        data["bytes"] = json!(b);
    }
    let msg = format!("{method} {url} -> {:?}", status_code);
    let line = render_event_with_data(level, "http", &msg, Some(url), None, Some(&data));
    write_line(&line);
}

/// Emit a garbage collection / staging cleanup diagnostic event.
pub fn emit_gc(level: Level, target: &str, reclaimed_bytes: u64, removed_items: usize) {
    let configured = level_from_u8(LEVEL.load(Ordering::Relaxed));
    if !level_allows(configured, level) {
        return;
    }
    let data = json!({
        "target": target,
        "reclaimed_bytes": reclaimed_bytes,
        "removed_items": removed_items,
    });
    let msg = format!(
        "reclaimed {} bytes across {} items in {}",
        reclaimed_bytes, removed_items, target
    );
    let line = render_event_with_data(level, "gc", &msg, Some(target), None, Some(&data));
    write_line(&line);
}
