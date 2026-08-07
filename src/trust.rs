use crate::paths;
use crate::safeio::{open_readonly_nofollow, read_all_from_file};
use anyhow::{anyhow, Context, Result};
use ed25519_dalek::pkcs8::DecodePublicKey;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const MAX_TRUST_STORE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TrustedKey {
    pub name: String,
    pub fingerprint: String,
    pub public_key_pem: String,
    #[serde(default)]
    pub namespaces: Vec<String>,
    #[serde(default)]
    pub revoked: bool,
    #[serde(default)]
    pub added_unix: u64,
    #[serde(default)]
    pub active_from_unix: Option<u64>,
    #[serde(default)]
    pub expires_unix: Option<u64>,
    #[serde(default)]
    pub rotation_group: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TrustStore {
    pub version: u32,
    #[serde(default)]
    pub keys: Vec<TrustedKey>,
}

impl Default for TrustStore {
    fn default() -> Self {
        Self {
            version: 1,
            keys: Vec::new(),
        }
    }
}

impl TrustStore {
    pub fn default_path() -> Result<PathBuf> {
        Ok(paths::config_dir()?.join("trust.json"))
    }

    pub fn load(path: Option<&Path>) -> Result<Self> {
        let path = match path {
            Some(path) => path.to_path_buf(),
            None => Self::default_path()?,
        };
        if !path.exists() {
            return Ok(Self::default());
        }
        let file = open_readonly_nofollow(&path)?;
        let bytes = read_all_from_file(&file, MAX_TRUST_STORE_BYTES)?;
        let store: Self = serde_json::from_slice(&bytes)
            .with_context(|| format!("Trust store '{}' is not valid JSON", path.display()))?;
        if store.version != 1 {
            return Err(anyhow!(
                "Unsupported trust-store version {} in '{}'",
                store.version,
                path.display()
            ));
        }
        for key in &store.keys {
            let parsed = parse_public_key_pem(&key.public_key_pem)
                .with_context(|| format!("Invalid public key for '{}'", key.name))?;
            let expected = fingerprint(&parsed);
            if !expected.eq_ignore_ascii_case(&key.fingerprint) {
                return Err(anyhow!(
                    "Trust-store fingerprint mismatch for '{}': stored {}, computed {}",
                    key.name,
                    key.fingerprint,
                    expected
                ));
            }
        }
        Ok(store)
    }

    pub fn save(&self, path: Option<&Path>) -> Result<PathBuf> {
        let path = match path {
            Some(path) => path.to_path_buf(),
            None => Self::default_path()?,
        };
        let bytes = serde_json::to_vec_pretty(self)?;
        paths::write_private(&path, &bytes)?;
        Ok(path)
    }

    pub fn add_key(
        &mut self,
        name: String,
        pem: String,
        namespaces: Vec<String>,
    ) -> Result<TrustedKey> {
        if name.trim().is_empty() {
            return Err(anyhow!("Trusted key name cannot be empty"));
        }
        let verifying_key = parse_public_key_pem(&pem)?;
        let fingerprint = fingerprint(&verifying_key);
        let namespaces = if namespaces.is_empty() {
            vec!["*".to_owned()]
        } else {
            namespaces
        };
        for namespace in &namespaces {
            validate_pattern(namespace)?;
        }
        let key = TrustedKey {
            name,
            fingerprint: fingerprint.clone(),
            public_key_pem: pem,
            namespaces,
            revoked: false,
            added_unix: paths::now_unix(),
            active_from_unix: None,
            expires_unix: None,
            rotation_group: None,
        };
        self.keys.retain(|existing| {
            !existing.fingerprint.eq_ignore_ascii_case(&fingerprint)
                && !existing.name.eq_ignore_ascii_case(&key.name)
        });
        self.keys.push(key.clone());
        self.keys.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(key)
    }

    pub fn remove_key(&mut self, selector: &str) -> Result<TrustedKey> {
        let index = self
            .keys
            .iter()
            .position(|key| {
                key.fingerprint.eq_ignore_ascii_case(selector)
                    || key.name.eq_ignore_ascii_case(selector)
            })
            .ok_or_else(|| anyhow!("Trusted key '{selector}' was not found"))?;
        Ok(self.keys.remove(index))
    }

    pub fn revoke_key(&mut self, selector: &str, revoked: bool) -> Result<TrustedKey> {
        let key = self
            .keys
            .iter_mut()
            .find(|key| {
                key.fingerprint.eq_ignore_ascii_case(selector)
                    || key.name.eq_ignore_ascii_case(selector)
            })
            .ok_or_else(|| anyhow!("Trusted key '{selector}' was not found"))?;
        key.revoked = revoked;
        Ok(key.clone())
    }

    pub fn find_by_fingerprint(&self, fingerprint: &str) -> Option<&TrustedKey> {
        self.keys
            .iter()
            .find(|key| key.fingerprint.eq_ignore_ascii_case(fingerprint))
    }

    pub fn authorized_for(&self, key: &TrustedKey, model: &str) -> bool {
        self.key_active(key, paths::now_unix())
            && key
                .namespaces
                .iter()
                .any(|pattern| glob_match(pattern, model))
    }

    pub fn key_active(&self, key: &TrustedKey, now: u64) -> bool {
        !key.revoked
            && key.active_from_unix.is_none_or(|value| now >= value)
            && key.expires_unix.is_none_or(|value| now <= value)
    }

    pub fn configure_key_lifetime(
        &mut self,
        selector: &str,
        active_from_unix: Option<u64>,
        expires_unix: Option<u64>,
        rotation_group: Option<String>,
    ) -> Result<TrustedKey> {
        if active_from_unix
            .zip(expires_unix)
            .is_some_and(|(start, end)| start > end)
        {
            return Err(anyhow!("key activation time cannot be after expiry"));
        }
        let key = self
            .keys
            .iter_mut()
            .find(|key| {
                key.fingerprint.eq_ignore_ascii_case(selector)
                    || key.name.eq_ignore_ascii_case(selector)
            })
            .ok_or_else(|| anyhow!("Trusted key '{selector}' was not found"))?;
        key.active_from_unix = active_from_unix;
        key.expires_unix = expires_unix;
        key.rotation_group = rotation_group.filter(|value| !value.trim().is_empty());
        Ok(key.clone())
    }

    pub fn merge(&mut self, other: TrustStore) -> Result<()> {
        if other.version != 1 {
            return Err(anyhow!(
                "Unsupported imported trust-store version {}",
                other.version
            ));
        }
        for key in other.keys {
            let parsed = parse_public_key_pem(&key.public_key_pem)?;
            let expected = fingerprint(&parsed);
            if !expected.eq_ignore_ascii_case(&key.fingerprint) {
                return Err(anyhow!(
                    "Imported trust key '{}' has an invalid fingerprint",
                    key.name
                ));
            }
            self.keys.retain(|existing| {
                !existing.fingerprint.eq_ignore_ascii_case(&key.fingerprint)
                    && !existing.name.eq_ignore_ascii_case(&key.name)
            });
            self.keys.push(key);
        }
        self.keys.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(())
    }
}

pub fn read_public_key_pem(path: &Path) -> Result<String> {
    let file = open_readonly_nofollow(path)?;
    let bytes = read_all_from_file(&file, 64 * 1024)?;
    String::from_utf8(bytes).map_err(|_| anyhow!("Public key PEM must be valid UTF-8"))
}

pub fn parse_public_key_pem(pem: &str) -> Result<VerifyingKey> {
    VerifyingKey::from_public_key_pem(pem).map_err(Into::into)
}

pub fn fingerprint(key: &VerifyingKey) -> String {
    let digest = Sha256::digest(key.to_bytes());
    format!("sha256:{}", hex::encode(digest))
}

fn validate_pattern(pattern: &str) -> Result<()> {
    if pattern.trim().is_empty()
        || pattern.contains('\\')
        || pattern.split('/').any(|part| part == "..")
    {
        return Err(anyhow!("Unsafe namespace pattern '{pattern}'"));
    }
    Ok(())
}

pub fn glob_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let mut regex = String::from("^");
    for ch in pattern.chars() {
        match ch {
            '*' => regex.push_str(".*"),
            '?' => regex.push('.'),
            '.' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|' | '\\' => {
                regex.push('\\');
                regex.push(ch);
            }
            other => regex.push(other),
        }
    }
    regex.push('$');
    regex::Regex::new(&regex)
        .map(|compiled| compiled.is_match(value))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_matching_is_anchored() {
        assert!(glob_match(
            "registry.ollama.ai/library/*",
            "registry.ollama.ai/library/gemma3:latest"
        ));
        assert!(!glob_match(
            "registry.ollama.ai/library/*",
            "evil/registry.ollama.ai/library/gemma3:latest"
        ));
        assert!(glob_match("*/acme/*", "registry.example/acme/model:v1"));
    }
}
