use crate::finding_evidence::redact_secrets;
use serde_json::{json, Map, Value};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};

/// Tracing / diagnostic severity floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Level {
    Off = 0,
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
    Trace = 5,
}

impl Level {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }

    /// Parse a level name, case-insensitive. `warning` is accepted as `Warn`.
    pub fn parse(value: &str) -> Option<Self> {
        value.parse().ok()
    }
}

impl std::str::FromStr for Level {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" => Ok(Level::Off),
            "error" => Ok(Level::Error),
            "warn" | "warning" => Ok(Level::Warn),
            "info" => Ok(Level::Info),
            "debug" => Ok(Level::Debug),
            "trace" => Ok(Level::Trace),
            _ => Err(()),
        }
    }
}

pub(crate) const fn level_to_u8(level: Level) -> u8 {
    level as u8
}

pub(crate) fn level_from_u8(value: u8) -> Level {
    match value {
        0 => Level::Off,
        1 => Level::Error,
        2 => Level::Warn,
        3 => Level::Info,
        4 => Level::Debug,
        _ => Level::Trace,
    }
}

pub(crate) static LEVEL: AtomicU8 = AtomicU8::new(level_to_u8(Level::Warn));

pub(crate) enum Sink {
    Stderr,
    File(Mutex<File>),
}

pub(crate) static SINK: OnceLock<Sink> = OnceLock::new();

pub(crate) fn level_allows(current: Level, target: Level) -> bool {
    current != Level::Off && (target as u8) <= (current as u8)
}

/// Configure the channel from the environment. Idempotent; the CLI calls it once
/// at startup from `cli::run`.
///
/// * `LAYERFAULT_LOG` — minimum level (`off`/`error`/`warn`/`info`/`debug`/`trace`).
/// * `LAYERFAULT_LOG_FILE` — append NDJSON to this path instead of stderr.
pub fn init_from_env() {
    if let Ok(raw) = std::env::var("LAYERFAULT_LOG") {
        if let Some(level) = Level::parse(&raw) {
            LEVEL.store(level_to_u8(level), Ordering::Relaxed);
        }
    }
    if let Ok(path) = std::env::var("LAYERFAULT_LOG_FILE") {
        if !path.trim().is_empty() {
            if let Ok(file) = OpenOptions::new().create(true).append(true).open(&path) {
                let _ = SINK.set(Sink::File(Mutex::new(file)));
            }
        }
    }
}

/// Render the NDJSON line for an event with structured JSON data.
pub(crate) fn render_event_with_data(
    level: Level,
    kind: &str,
    message: &str,
    subject: Option<&str>,
    hint: Option<&str>,
    data: Option<&serde_json::Value>,
) -> String {
    let (clean_msg, _) = redact_secrets(message);
    let clean_subj = subject.map(|s| redact_secrets(s).0);
    let clean_hint = hint.map(|h| redact_secrets(h).0);

    let mut obj = json!({
        "level": level.as_str(),
        "kind": kind,
        "message": clean_msg,
    });

    if let Some(s) = clean_subj {
        obj["subject"] = json!(s);
    }
    if let Some(h) = clean_hint {
        obj["hint"] = json!(h);
    }
    if let Some(d) = data {
        obj["data"] = redact_json_value(d);
    }

    serde_json::to_string(&obj).unwrap_or_else(|_| "{}".to_owned())
}

fn redact_json_value(value: &Value) -> Value {
    match value {
        Value::String(text) => Value::String(redact_secrets(text).0),
        Value::Array(values) => Value::Array(values.iter().map(redact_json_value).collect()),
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), redact_json_value(value)))
                .collect::<Map<String, Value>>(),
        ),
        other => other.clone(),
    }
}

#[allow(dead_code)]
pub(crate) fn render_event(
    level: Level,
    kind: &str,
    message: &str,
    subject: Option<&str>,
    hint: Option<&str>,
) -> String {
    render_event_with_data(level, kind, message, subject, hint, None)
}

pub(crate) fn write_line(line: &str) {
    let sink = SINK.get_or_init(|| Sink::Stderr);
    match sink {
        Sink::Stderr => {
            let mut stderr = std::io::stderr().lock();
            let _ = writeln!(stderr, "{line}");
        }
        Sink::File(mutex) => {
            if let Ok(mut file) = mutex.lock() {
                let _ = writeln!(file, "{line}");
            }
        }
    }
}
