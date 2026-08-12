//! Explicit networked Hugging Face Hub ingestion.
//!
//! No local scan/review command calls this module implicitly.

pub mod cache;
mod client;
mod types;

pub use client::{token_from_env, verify_webhook_secret, HubClient};
pub use types::{
    is_security_relevant_member, CrawlPage, DownloadResult, HubFile, HubLfsMetadata, HubModel,
    HubRevision, IntegrityExpectationSource, IntegrityResult, RemoteObjectExpectation,
};
