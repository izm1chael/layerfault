use super::events::emit_full;
use super::sink::Level;
use std::time::Instant;

/// RAII diagnostic span for tracking execution phase timing and lifecycle.
pub struct DiagnosticSpan {
    name: &'static str,
    subject: Option<String>,
    started: Instant,
    level: Level,
}

impl DiagnosticSpan {
    pub fn new(level: Level, name: &'static str, subject: Option<String>) -> Self {
        emit_full(
            level,
            name,
            &format!("started {name}"),
            subject.as_deref(),
            None,
        );
        Self {
            name,
            subject,
            started: Instant::now(),
            level,
        }
    }

    pub fn trace(name: &'static str, subject: Option<String>) -> Self {
        Self::new(Level::Trace, name, subject)
    }

    pub fn info(name: &'static str, subject: Option<String>) -> Self {
        Self::new(Level::Info, name, subject)
    }
}

impl Drop for DiagnosticSpan {
    fn drop(&mut self) {
        let elapsed_ms = self.started.elapsed().as_millis();
        emit_full(
            self.level,
            self.name,
            &format!("completed {} in {}ms", self.name, elapsed_ms),
            self.subject.as_deref(),
            None,
        );
    }
}
