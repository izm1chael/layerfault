//! Diagnostic event channel for Layerfault internal tracing and telemetry.
//!
//! Emits single-line NDJSON records to stderr (default) or a configured log file.
//! All messages and fields pass through secret redaction before rendering.

pub mod events;
pub mod sink;
pub mod span;

pub use events::{emit, emit_full, emit_gc, emit_http, emit_subproc, emit_with_data};
pub use sink::{init_from_env, Level};
pub use span::DiagnosticSpan;

#[cfg(test)]
mod tests {
    use super::sink::*;
    use serde_json::json;

    #[test]
    fn level_ordering_and_names() {
        assert!(Level::Error < Level::Warn);
        assert!(Level::Warn < Level::Info);
        assert_eq!(Level::Warn.as_str(), "warn");
    }

    #[test]
    fn level_parse_is_case_insensitive_and_accepts_warning() {
        assert_eq!(Level::parse("INFO"), Some(Level::Info));
        assert_eq!(Level::parse("warning"), Some(Level::Warn));
        assert_eq!(Level::parse("nope"), None);
    }

    #[test]
    fn level_allows_gates_by_configured_floor() {
        assert!(level_allows(Level::Warn, Level::Error));
        assert!(level_allows(Level::Warn, Level::Warn));
        assert!(!level_allows(Level::Warn, Level::Info));
        assert!(!level_allows(Level::Off, Level::Error));
    }

    #[test]
    fn render_event_redacts_secret_shaped_messages() {
        let line = render_event(
            Level::Warn,
            "mcp_transport",
            "bearer hf_0123456789abcdef0123456789abcdef01 failed",
            Some("https://huggingface.co/api"),
            None,
        );
        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed["level"], "warn");
        assert_eq!(parsed["kind"], "mcp_transport");
        let msg = parsed["message"].as_str().unwrap();
        assert!(!msg.contains("hf_0123456789abcdef0123456789abcdef01"));
        assert!(msg.contains("<redacted"));
    }

    #[test]
    fn render_event_omits_optional_fields_when_none() {
        let line = render_event(
            Level::Info,
            "startup",
            "layerfault initializing",
            None,
            None,
        );
        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed["level"], "info");
        assert_eq!(parsed["kind"], "startup");
        assert_eq!(parsed["message"], "layerfault initializing");
        assert!(parsed.get("subject").is_none());
        assert!(parsed.get("hint").is_none());
    }

    #[test]
    fn render_event_includes_optional_fields_when_some() {
        let line = render_event(
            Level::Error,
            "sandbox",
            "bubblewrap not found",
            Some("path=/usr/bin/bwrap"),
            Some("install bubblewrap via package manager"),
        );
        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed["subject"].as_str().unwrap(), "path=/usr/bin/bwrap");
        assert_eq!(
            parsed["hint"].as_str().unwrap(),
            "install bubblewrap via package manager"
        );
    }

    #[test]
    fn render_event_with_data_includes_structured_json() {
        let payload = json!({"pid": 1234, "status": 0});
        let line = render_event_with_data(
            Level::Info,
            "process",
            "process finished",
            Some("bin=llama-server"),
            None,
            Some(&payload),
        );
        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed["data"]["pid"], 1234);
        assert_eq!(parsed["data"]["status"], 0);
    }

    #[test]
    fn render_event_redacts_nested_structured_data() {
        let payload = json!({
            "stderr_tail": "authorization: Bearer hf_0123456789abcdef0123456789abcdef01",
            "nested": ["api_key='sk-abcd1234efgh5678ij'"]
        });
        let line = render_event_with_data(
            Level::Warn,
            "subprocess",
            "process failed",
            None,
            None,
            Some(&payload),
        );
        assert!(!line.contains("hf_0123456789abcdef0123456789abcdef01"));
        assert!(!line.contains("sk-abcd1234efgh5678ij"));
        assert!(line.contains("<redacted"));
    }
}
