use serde::{Deserialize, Serialize};
use std::fmt;

/// High-level taxonomy of operational and system errors across Layerfault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    /// Format parse failure, malformed magic, or invalid header.
    ParseFormat,
    /// Format stream or file truncated prematurely.
    FormatTruncated,
    /// Subprocess exited non-zero or failed execution.
    SubprocessExit,
    /// Subprocess crashed unexpectedly or was terminated by signal.
    SubprocessCrash,
    /// Sandboxed execution environment failure or missing capability.
    SandboxEnvironment,
    /// Isolation or sandbox boundary violation.
    SandboxViolation,
    /// Execution binding or stage copy failure.
    ExecutionBinding,
    /// Configured resource budget or deadline exceeded.
    BudgetExceeded,
    /// Target file, directory, or artifact not found.
    NotFound,
    /// Invalid configuration, argument, or input parameter.
    InvalidInput,
    /// Cryptographic hash, signature, or digest mismatch.
    IntegrityMismatch,
    /// Network or HTTP transport communication failure.
    HttpTransport,
    /// Remote service or API protocol error.
    RemoteApi,
    /// Agent or MCP protocol discovery / transport failure.
    AgentProtocol,
    /// General system or OS error.
    System,
    /// Catch-all for uncategorized or unclassified errors.
    Uncategorized,
    Unclassified,
}

impl ErrorKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ParseFormat => "parse_format",
            Self::FormatTruncated => "format_truncated",
            Self::SubprocessExit => "subprocess_exit",
            Self::SubprocessCrash => "subprocess_crash",
            Self::SandboxEnvironment => "sandbox_environment",
            Self::SandboxViolation => "sandbox_violation",
            Self::ExecutionBinding => "execution_binding",
            Self::BudgetExceeded => "budget_exceeded",
            Self::NotFound => "not_found",
            Self::InvalidInput => "invalid_input",
            Self::IntegrityMismatch => "integrity_mismatch",
            Self::HttpTransport => "http_transport",
            Self::RemoteApi => "remote_api",
            Self::AgentProtocol => "agent_protocol",
            Self::System => "system",
            Self::Uncategorized | Self::Unclassified => "uncategorized",
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Operational severity of the failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Warning,
    Error,
    Fatal,
}

impl Severity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Fatal => "fatal",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A classified, structured Layerfault operational error carrying taxonomy,
/// stable error codes, optional remediation hints, and causal context.
#[derive(Debug, Clone)]
pub struct LayerfaultError {
    pub(crate) kind: ErrorKind,
    pub(crate) severity: Severity,
    pub(crate) code: Option<&'static str>,
    pub(crate) message: String,
    pub(crate) subject: Option<String>,
    pub(crate) hint: Option<String>,
    pub(crate) recoverable: bool,
}

impl LayerfaultError {
    pub fn new(kind: ErrorKind, severity: Severity, message: impl Into<String>) -> Self {
        Self {
            kind,
            severity,
            code: None,
            message: message.into(),
            subject: None,
            hint: None,
            recoverable: false,
        }
    }

    pub fn with_code(mut self, code: &'static str) -> Self {
        self.code = Some(code);
        self
    }

    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    pub fn with_recoverable(mut self, recoverable: bool) -> Self {
        self.recoverable = recoverable;
        self
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn severity(&self) -> Severity {
        self.severity
    }

    pub fn code(&self) -> Option<&'static str> {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn subject(&self) -> Option<&str> {
        self.subject.as_deref()
    }

    pub fn hint(&self) -> Option<&str> {
        self.hint.as_deref()
    }

    pub fn recoverable(&self) -> bool {
        self.recoverable
    }

    // Helper constructors for common operational failure modes:
    pub fn parse(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::ParseFormat, Severity::Error, message)
    }

    pub fn format_truncated(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::FormatTruncated, Severity::Error, message)
    }

    pub fn subprocess(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::SubprocessExit, Severity::Error, message).with_recoverable(true)
    }

    pub fn subprocess_crash(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::SubprocessCrash, Severity::Fatal, message)
    }

    pub fn sandbox(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::SandboxEnvironment, Severity::Fatal, message)
    }

    pub fn binding(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::ExecutionBinding, Severity::Error, message)
    }

    pub fn http(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::HttpTransport, Severity::Error, message).with_recoverable(true)
    }

    pub fn api(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::RemoteApi, Severity::Error, message)
    }

    pub fn agent_protocol(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::AgentProtocol, Severity::Error, message)
    }

    pub fn budget(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::BudgetExceeded, Severity::Error, message)
    }

    pub fn integrity(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::IntegrityMismatch, Severity::Error, message)
    }

    pub fn config(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidInput, Severity::Error, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::NotFound, Severity::Error, message)
    }

    pub fn system(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::System, Severity::Error, message)
    }
}

impl fmt::Display for LayerfaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(code) = self.code {
            write!(f, "[{code}] ")?;
        }
        write!(f, "{}: {}", self.kind, self.message)?;
        if let Some(subject) = &self.subject {
            write!(f, " (subject: {subject})")?;
        }
        if let Some(hint) = &self.hint {
            write!(f, " [hint: {hint}]")?;
        }
        Ok(())
    }
}

impl std::error::Error for LayerfaultError {}
