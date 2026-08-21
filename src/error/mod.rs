//! Layerfault error taxonomy, structured failure codes, and contextual error extensions.

pub mod context;
pub mod types;

pub use context::ContextLf;
pub use types::{ErrorKind, LayerfaultError, Severity};

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn kind_strings_are_stable_snake_case() {
        assert_eq!(ErrorKind::ParseFormat.as_str(), "parse_format");
        assert_eq!(ErrorKind::FormatTruncated.as_str(), "format_truncated");
        assert_eq!(ErrorKind::SubprocessExit.as_str(), "subprocess_exit");
        assert_eq!(ErrorKind::SubprocessCrash.as_str(), "subprocess_crash");
        assert_eq!(ErrorKind::HttpTransport.as_str(), "http_transport");
        assert_eq!(ErrorKind::RemoteApi.as_str(), "remote_api");
        assert_eq!(ErrorKind::AgentProtocol.as_str(), "agent_protocol");
    }

    #[test]
    fn severity_is_ordered() {
        assert!(Severity::Warning < Severity::Error);
        assert!(Severity::Error < Severity::Fatal);
    }

    #[test]
    fn error_display_formatting() {
        let err = LayerfaultError::new(ErrorKind::ParseFormat, Severity::Error, "invalid magic")
            .with_code("LF-ERR-FORMAT-MAGIC")
            .with_subject("file=model.bin")
            .with_hint("check file format");
        let rendered = format!("{err}");
        assert!(rendered.contains("[LF-ERR-FORMAT-MAGIC]"));
        assert!(rendered.contains("parse_format: invalid magic"));
        assert!(rendered.contains("(subject: file=model.bin)"));
        assert!(rendered.contains("[hint: check file format]"));
    }

    #[test]
    fn source_chain_is_preserved() {
        let root = io::Error::new(io::ErrorKind::ConnectionReset, "socket closed");
        let err: anyhow::Error = LayerfaultError::http("failed to talk to llama-server")
            .with_code("LF-ERR-HTTP-RESET")
            .into();
        let chained = err.context(root);
        let mut chain_iter = chained.chain();
        assert_eq!(chain_iter.next().unwrap().to_string(), "socket closed");
        assert!(chain_iter
            .next()
            .unwrap()
            .to_string()
            .contains("failed to talk to llama-server"));
    }

    #[test]
    fn converts_into_and_out_of_anyhow() {
        let error: anyhow::Error = LayerfaultError::subprocess("probe exited 139").into();
        let classified = error
            .downcast_ref::<LayerfaultError>()
            .expect("downcasts back out");
        assert_eq!(classified.kind(), ErrorKind::SubprocessExit);
        assert!(classified.recoverable());
    }

    #[test]
    fn error_code_formatting_and_storage() {
        let error = LayerfaultError::http("connection dropped")
            .with_code("LF-ERR-HTTP-CONN-RESET")
            .with_subject("endpoint=https://api.invalid");
        assert_eq!(error.code(), Some("LF-ERR-HTTP-CONN-RESET"));
        assert_eq!(error.subject(), Some("endpoint=https://api.invalid"));
    }

    #[test]
    fn context_lf_extension_trait_works() {
        fn failing_operation() -> io::Result<()> {
            Err(io::Error::new(io::ErrorKind::NotFound, "file not found"))
        }

        let result = failing_operation().context_lf(ErrorKind::NotFound, "model load failed");
        assert!(result.is_err());
        let err = result.unwrap_err();
        let causes: Vec<String> = err.chain().map(|c| c.to_string()).collect();
        assert_eq!(causes.len(), 2);
        assert_eq!(causes[0], "file not found");
        assert!(causes[1].contains("model load failed"));
    }
}
