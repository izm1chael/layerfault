pub mod db;
pub mod web;
pub mod weekly;
pub mod worker;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformConfig {
    pub database: String,
    pub listen: String,
    pub admin_token_env: String,
    pub webhook_secret_env: String,
    pub worker_id: String,
    pub max_hub_download_bytes: u64,
}

impl PlatformConfig {
    pub fn from_values(database: String, listen: Option<String>) -> Result<Self> {
        if database.trim().is_empty() { bail!("platform database must not be empty"); }
        Ok(Self {
            database,
            listen: listen.unwrap_or_else(|| "127.0.0.1:8787".to_owned()),
            admin_token_env: "LAYERFAULT_ADMIN_TOKEN".to_owned(),
            webhook_secret_env: "LAYERFAULT_HF_WEBHOOK_SECRET".to_owned(),
            worker_id: format!("worker-{}", std::process::id()),
            max_hub_download_bytes: 20 * 1024 * 1024 * 1024,
        })
    }
}
