use super::types::{ErrorKind, LayerfaultError, Severity};

/// Extension trait that attaches Layerfault error classification to arbitrary
/// `Result<T, E>` values while preserving the underlying cause in the error chain.
pub trait ContextLf<T, E> {
    /// Wrap the error with a classified [`LayerfaultError`], preserving the original
    /// error as the source in the chain.
    fn context_lf(self, kind: ErrorKind, message: impl Into<String>) -> anyhow::Result<T>;

    /// Wrap the error with a lazily-evaluated classified [`LayerfaultError`].
    fn with_context_lf<F, M>(self, kind: ErrorKind, f: F) -> anyhow::Result<T>
    where
        F: FnOnce() -> M,
        M: Into<String>;
}

impl<T, E> ContextLf<T, E> for std::result::Result<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn context_lf(self, kind: ErrorKind, message: impl Into<String>) -> anyhow::Result<T> {
        self.map_err(|cause| {
            let classified = LayerfaultError::new(kind, Severity::Error, message);
            anyhow::Error::from(classified).context(cause)
        })
    }

    fn with_context_lf<F, M>(self, kind: ErrorKind, f: F) -> anyhow::Result<T>
    where
        F: FnOnce() -> M,
        M: Into<String>,
    {
        self.map_err(|cause| {
            let classified = LayerfaultError::new(kind, Severity::Error, f());
            anyhow::Error::from(classified).context(cause)
        })
    }
}
