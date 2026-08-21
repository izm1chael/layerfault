use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

pub(super) const MAX_DOWNLOAD_BYTES: u64 = 200 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HubLfsMetadata {
    pub oid: String,
    pub size: u64,
    #[serde(default, rename = "pointerSize")]
    pub pointer_size: Option<u64>,
}

/// Mirrors the real Hub `?blobs=true` sibling shape, which carries the LFS
/// digest under `sha256` (bare hex, no algorithm prefix) rather than `oid`.
#[derive(Debug, Clone, Deserialize)]
struct RawHubLfsMetadata {
    #[serde(default)]
    oid: Option<String>,
    #[serde(default)]
    sha256: Option<String>,
    size: u64,
    #[serde(default, rename = "pointerSize")]
    pointer_size: Option<u64>,
}

impl TryFrom<RawHubLfsMetadata> for HubLfsMetadata {
    type Error = anyhow::Error;

    fn try_from(raw: RawHubLfsMetadata) -> Result<Self> {
        let oid = match (raw.oid, raw.sha256) {
            (Some(oid), Some(sha256)) => {
                let normalized_sha256 = if sha256.contains(':') {
                    sha256
                } else {
                    format!("sha256:{sha256}")
                };
                if oid != normalized_sha256 {
                    bail!("LFS metadata has conflicting 'oid' and 'sha256' values");
                }
                oid
            }
            (Some(oid), None) => oid,
            (None, Some(sha256)) if sha256.contains(':') => sha256,
            (None, Some(sha256)) => format!("sha256:{sha256}"),
            (None, None) => bail!("LFS metadata missing both 'oid' and 'sha256' fields"),
        };
        Ok(HubLfsMetadata {
            oid,
            size: raw.size,
            pointer_size: raw.pointer_size,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IntegrityExpectationSource {
    GitLfs,
    GitBlob,
    None,
    UnsupportedAlgorithm,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoteObjectExpectation {
    pub sha256: Option<String>,
    pub size: Option<u64>,
    pub source: IntegrityExpectationSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IntegrityResult {
    Match,
    Mismatch,
    #[default]
    ExpectationUnavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubFile {
    #[serde(rename = "rfilename")]
    pub path: String,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default, rename = "blobId")]
    pub blob_id: Option<String>,
    #[serde(default)]
    pub lfs: Option<serde_json::Value>,
}

impl HubFile {
    pub fn lfs_metadata(&self) -> Result<Option<HubLfsMetadata>> {
        let Some(val) = &self.lfs else {
            return Ok(None);
        };
        if val.is_null() {
            return Ok(None);
        }
        let raw: RawHubLfsMetadata = serde_json::from_value(val.clone())
            .context("invalid LFS metadata structure in Hub file record")?;
        Ok(Some(HubLfsMetadata::try_from(raw)?))
    }

    pub fn expectation(&self) -> Result<RemoteObjectExpectation> {
        if let Some(lfs) = self.lfs_metadata()? {
            let raw_oid = lfs.oid.trim();
            if raw_oid.is_empty() {
                bail!("LFS metadata carries an empty OID string");
            }
            let (alg, hex_part) = if let Some(stripped) = raw_oid.strip_prefix("sha256:") {
                ("sha256", stripped)
            } else if raw_oid.contains(':') {
                return Ok(RemoteObjectExpectation {
                    sha256: None,
                    size: Some(lfs.size),
                    source: IntegrityExpectationSource::UnsupportedAlgorithm,
                });
            } else {
                ("sha256", raw_oid)
            };

            if alg != "sha256" {
                return Ok(RemoteObjectExpectation {
                    sha256: None,
                    size: Some(lfs.size),
                    source: IntegrityExpectationSource::UnsupportedAlgorithm,
                });
            }

            if hex_part.len() != 64 || !hex_part.bytes().all(|b| b.is_ascii_hexdigit()) {
                bail!("LFS OID '{raw_oid}' is not a valid 64-character hexadecimal SHA-256 digest");
            }

            if lfs.size > MAX_DOWNLOAD_BYTES {
                bail!(
                    "LFS declared size {} exceeds maximum configured download cap {}",
                    lfs.size,
                    MAX_DOWNLOAD_BYTES
                );
            }

            if let Some(file_size) = self.size {
                if file_size != lfs.size {
                    bail!(
                        "API file size ({file_size}) conflicts with LFS declared size ({})",
                        lfs.size
                    );
                }
            }

            if let Some(pointer_size) = lfs.pointer_size {
                if pointer_size == 0 || pointer_size > 4096 {
                    bail!("LFS pointer_size {pointer_size} is outside safe bounds");
                }
            }

            let normalized_sha = format!("sha256:{}", hex_part.to_ascii_lowercase());
            return Ok(RemoteObjectExpectation {
                sha256: Some(normalized_sha),
                size: Some(lfs.size),
                source: IntegrityExpectationSource::GitLfs,
            });
        }

        Ok(RemoteObjectExpectation {
            sha256: None,
            size: self.size,
            source: IntegrityExpectationSource::None,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct HubModel {
    pub id: String,
    #[serde(default)]
    pub sha: Option<String>,
    #[serde(default)]
    pub private: bool,
    #[serde(default)]
    pub gated: serde_json::Value,
    #[serde(default)]
    pub siblings: Vec<HubFile>,
    #[serde(default, rename = "lastModified")]
    pub last_modified: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub pipeline_tag: Option<String>,
    #[serde(default)]
    pub library_name: Option<String>,
    #[serde(default)]
    pub card_data: Option<serde_json::Value>,
}

// A plain `#[serde(alias = "modelId")]` on `id` cannot represent this API's
// real response shape: every live Hub endpoint (the model-list endpoint
// `platform crawl` uses, and the single-model endpoint the webhook path
// uses) sends *both* `id` and `modelId` as separate top-level keys with the
// same value, simultaneously. `#[serde(alias = ...)]` only tells serde which
// *one* spelling to accept — it treats two recognized spellings appearing
// together as a genuine duplicate-field conflict and rejects the whole
// payload, regardless of whether the alias happens to equal the field's own
// canonical name. Deserializing into an intermediate shape with both keys
// optional, then resolving `id.or(model_id)` afterward, is required.
impl<'de> Deserialize<'de> for HubModel {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Raw {
            #[serde(default)]
            id: Option<String>,
            #[serde(default, rename = "modelId")]
            model_id: Option<String>,
            #[serde(default)]
            sha: Option<String>,
            #[serde(default)]
            private: bool,
            #[serde(default)]
            gated: serde_json::Value,
            #[serde(default)]
            siblings: Vec<HubFile>,
            #[serde(default, rename = "lastModified")]
            last_modified: Option<String>,
            #[serde(default)]
            tags: Vec<String>,
            #[serde(default)]
            pipeline_tag: Option<String>,
            #[serde(default)]
            library_name: Option<String>,
            #[serde(default)]
            card_data: Option<serde_json::Value>,
        }

        let raw = Raw::deserialize(deserializer)?;
        let id = raw.id.or(raw.model_id).ok_or_else(|| {
            serde::de::Error::custom("Hub model response is missing both `id` and `modelId`")
        })?;
        Ok(HubModel {
            id,
            sha: raw.sha,
            private: raw.private,
            gated: raw.gated,
            siblings: raw.siblings,
            last_modified: raw.last_modified,
            tags: raw.tags,
            pipeline_tag: raw.pipeline_tag,
            library_name: raw.library_name,
            card_data: raw.card_data,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubRevision {
    pub repo: String,
    pub requested_revision: String,
    pub commit_sha: String,
    pub observed_unix: u64,
    pub files: Vec<HubFile>,
    pub claims: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadResult {
    pub repo: String,
    pub revision: String,
    pub file: String,
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
    pub elapsed_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_bytes: Option<u64>,
    #[serde(default)]
    pub integrity_result: IntegrityResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlPage {
    pub models: Vec<HubModel>,
    pub next: Option<String>,
}

/// True when a Hugging Face repository member can materially affect model
/// loading, execution, structure, tokenizer/template behaviour, or package
/// admission. Hosted/direct reviews must share this selector so a PASS never
/// means "only weight/config suffixes happened to be downloaded".
pub fn is_security_relevant_member(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    [
        ".gguf",
        ".safetensors",
        ".safetensors.index.json",
        ".onnx",
        ".tflite",
        ".keras",
        ".h5",
        ".hdf5",
        ".pb",
        ".pkl",
        ".pickle",
        ".joblib",
        ".pt",
        ".pth",
        ".ckpt",
        ".bin",
        ".py",
        ".pyi",
        ".sh",
        ".ps1",
        ".bat",
        ".cmd",
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".node",
        ".jar",
        ".json",
        ".toml",
        ".yaml",
        ".yml",
        ".jinja",
        ".j2",
    ]
    .iter()
    .any(|suffix| lower.ends_with(suffix))
        || matches!(
            name,
            "setup.py"
                | "pyproject.toml"
                | "requirements.txt"
                | "requirements-dev.txt"
                | "environment.yml"
                | "environment.yaml"
                | "model_index.json"
                | "configuration.json"
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hub_model_accepts_id_and_model_id_present_together() {
        // Every real Hub API response (both the list endpoint `platform
        // crawl` uses and the single-model endpoint the webhook path uses)
        // sends `id` and `modelId` as separate top-level keys simultaneously,
        // with the same value. A plain `#[serde(alias = "modelId")]` on `id`
        // rejects this as a duplicate-field conflict.
        let json = r#"{"id":"Qwen/Qwen3-0.6B","modelId":"Qwen/Qwen3-0.6B","sha":"abc123"}"#;
        let model: HubModel =
            serde_json::from_str(json).expect("must parse a real Hub payload shape");
        assert_eq!(model.id, "Qwen/Qwen3-0.6B");
    }

    #[test]
    fn hub_model_falls_back_to_model_id_when_id_absent() {
        let json = r#"{"modelId":"Qwen/Qwen3-0.6B"}"#;
        let model: HubModel = serde_json::from_str(json).expect("modelId alone must still resolve");
        assert_eq!(model.id, "Qwen/Qwen3-0.6B");
    }

    #[test]
    fn hub_model_accepts_bare_id_alone() {
        let json = r#"{"id":"Qwen/Qwen3-0.6B"}"#;
        let model: HubModel = serde_json::from_str(json).expect("id alone must still resolve");
        assert_eq!(model.id, "Qwen/Qwen3-0.6B");
    }

    #[test]
    fn hub_model_rejects_missing_both_id_and_model_id() {
        let json = r#"{"sha":"abc123"}"#;
        assert!(serde_json::from_str::<HubModel>(json).is_err());
    }

    #[test]
    fn security_member_selector_includes_loader_and_serialization_risk() {
        for path in [
            "pytorch_model.bin",
            "weights/model.pkl",
            "model.safetensors",
            "loader.py",
            "native/extension.so",
            "config.json",
            "chat_template.jinja",
            "requirements.txt",
        ] {
            assert!(
                is_security_relevant_member(path),
                "expected security member: {path}"
            );
        }
        assert!(!is_security_relevant_member("README.md"));
        assert!(!is_security_relevant_member("assets/logo.png"));
    }

    #[test]
    fn lfs_expectation_valid_sha256() {
        let file = HubFile {
            path: "model.safetensors".to_owned(),
            size: Some(1024),
            blob_id: None,
            lfs: Some(serde_json::json!({
                "oid": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "size": 1024,
                "pointerSize": 128
            })),
        };
        let exp = file.expectation().unwrap();
        assert_eq!(
            exp.sha256,
            Some(
                "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    .to_owned()
            )
        );
        assert_eq!(exp.size, Some(1024));
        assert_eq!(exp.source, IntegrityExpectationSource::GitLfs);
    }

    #[test]
    fn lfs_expectation_normalizes_uppercase_hex() {
        let file = HubFile {
            path: "model.safetensors".to_owned(),
            size: Some(1024),
            blob_id: None,
            lfs: Some(serde_json::json!({
                "oid": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
                "size": 1024
            })),
        };
        let exp = file.expectation().unwrap();
        assert_eq!(
            exp.sha256,
            Some(
                "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                    .to_owned()
            )
        );
    }

    #[test]
    fn lfs_expectation_malformed_oid() {
        let file = HubFile {
            path: "model.safetensors".to_owned(),
            size: Some(1024),
            blob_id: None,
            lfs: Some(serde_json::json!({
                "oid": "sha256:invalid_hex_string",
                "size": 1024
            })),
        };
        assert!(file.expectation().is_err());
    }

    #[test]
    fn lfs_expectation_from_real_hub_blobs_true_shape() {
        // The real `?blobs=true` API response carries the digest under
        // `sha256` (bare hex, no algorithm prefix), not `oid`.
        let file = HubFile {
            path: "model.safetensors".to_owned(),
            size: Some(453864),
            blob_id: Some("cdebb9016e0099550c661ad5d7b4b0db174d2da7".to_owned()),
            lfs: Some(serde_json::json!({
                "sha256": "8111d5afb0715dbf5a31396d31432cb56370ba23f6650a035ea0fc8a20b4e500",
                "size": 453864,
                "pointerSize": 131
            })),
        };
        let exp = file.expectation().unwrap();
        assert_eq!(
            exp.sha256,
            Some(
                "sha256:8111d5afb0715dbf5a31396d31432cb56370ba23f6650a035ea0fc8a20b4e500"
                    .to_owned()
            )
        );
        assert_eq!(exp.size, Some(453864));
        assert_eq!(exp.source, IntegrityExpectationSource::GitLfs);
    }

    #[test]
    fn lfs_expectation_oid_and_sha256_agree() {
        let file = HubFile {
            path: "model.safetensors".to_owned(),
            size: Some(453864),
            blob_id: None,
            lfs: Some(serde_json::json!({
                "oid": "sha256:8111d5afb0715dbf5a31396d31432cb56370ba23f6650a035ea0fc8a20b4e500",
                "sha256": "8111d5afb0715dbf5a31396d31432cb56370ba23f6650a035ea0fc8a20b4e500",
                "size": 453864
            })),
        };
        let exp = file.expectation().unwrap();
        assert_eq!(
            exp.sha256,
            Some(
                "sha256:8111d5afb0715dbf5a31396d31432cb56370ba23f6650a035ea0fc8a20b4e500"
                    .to_owned()
            )
        );
    }

    #[test]
    fn lfs_expectation_oid_and_sha256_conflict() {
        let file = HubFile {
            path: "model.safetensors".to_owned(),
            size: Some(453864),
            blob_id: None,
            lfs: Some(serde_json::json!({
                "oid": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "sha256": "8111d5afb0715dbf5a31396d31432cb56370ba23f6650a035ea0fc8a20b4e500",
                "size": 453864
            })),
        };
        let err = file.expectation().unwrap_err();
        assert!(
            err.to_string()
                .contains("conflicting 'oid' and 'sha256' values"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn lfs_expectation_unsupported_algorithm() {
        let file = HubFile {
            path: "model.safetensors".to_owned(),
            size: Some(1024),
            blob_id: None,
            lfs: Some(serde_json::json!({
                "oid": "sha512:abcdef123456",
                "size": 1024
            })),
        };
        let exp = file.expectation().unwrap();
        assert_eq!(exp.sha256, None);
        assert_eq!(exp.source, IntegrityExpectationSource::UnsupportedAlgorithm);
    }

    #[test]
    fn lfs_expectation_size_conflict() {
        let file = HubFile {
            path: "model.safetensors".to_owned(),
            size: Some(2048),
            blob_id: None,
            lfs: Some(serde_json::json!({
                "oid": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "size": 1024
            })),
        };
        assert!(file.expectation().is_err());
    }

    #[test]
    fn lfs_expectation_missing_lfs() {
        let file = HubFile {
            path: "model.safetensors".to_owned(),
            size: Some(1024),
            blob_id: None,
            lfs: None,
        };
        let exp = file.expectation().unwrap();
        assert_eq!(exp.sha256, None);
        assert_eq!(exp.size, Some(1024));
        assert_eq!(exp.source, IntegrityExpectationSource::None);
    }
}
