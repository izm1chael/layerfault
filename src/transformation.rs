//! Transformation claims and cryptographically bound lineage records.

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const MAX_CHAIN_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CHAIN_LINKS: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LineageState {
    Verified,
    Consistent,
    Unverified,
    Contradicted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DerivedIntegrityState {
    Verified,
    Consistent,
    Unverified,
    Anomalous,
    Contradicted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BehaviourState {
    NotRun,
    NoSuspiciousObserved,
    Suspicious,
    HighRisk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DifferentialBehaviourState {
    NotRun,
    Expected,
    NeutralVariation,
    CapabilityChange,
    SecurityRegression,
    SuspiciousTrigger,
    HighRiskBehaviour,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransformationType {
    FineTune,
    LoraAdapter,
    LoraMerge,
    Quantization,
    Conversion,
    TokenizerModification,
    TemplateModification,
    Repackaging,
    Other,
}

impl TransformationType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FineTune => "fine-tune",
            Self::LoraAdapter => "lora-adapter",
            Self::LoraMerge => "lora-merge",
            Self::Quantization => "quantization",
            Self::Conversion => "conversion",
            Self::TokenizerModification => "tokenizer-modification",
            Self::TemplateModification => "template-modification",
            Self::Repackaging => "repackaging",
            Self::Other => "other",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().replace('_', "-").as_str() {
            "fine-tune" | "finetune" => Ok(Self::FineTune),
            "lora" | "lora-adapter" => Ok(Self::LoraAdapter),
            "lora-merge" => Ok(Self::LoraMerge),
            "quantization" | "quantize" => Ok(Self::Quantization),
            "conversion" | "convert" => Ok(Self::Conversion),
            "tokenizer-modification" => Ok(Self::TokenizerModification),
            "template-modification" => Ok(Self::TemplateModification),
            "repackaging" | "repackage" => Ok(Self::Repackaging),
            "other" => Ok(Self::Other),
            other => bail!("unsupported transformation claim '{other}'"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransformationEndpoint {
    pub identity: String,
    #[serde(default)]
    pub artifact_sha256: Option<String>,
    #[serde(default)]
    pub package_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformationDescriptor {
    #[serde(rename = "type")]
    pub kind: TransformationType,
    pub tool: String,
    #[serde(default)]
    pub tool_version: Option<String>,
    #[serde(default)]
    pub parameters: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformationManifest {
    pub version: u32,
    pub parent: TransformationEndpoint,
    pub child: TransformationEndpoint,
    pub transformation: TransformationDescriptor,
    #[serde(default)]
    pub timestamp: Option<String>,
    #[serde(default)]
    pub signer: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTransformationLink {
    pub manifest: TransformationManifest,
    pub key_fingerprint: String,
    pub public_key_hex: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformationChain {
    pub version: u32,
    pub links: Vec<SignedTransformationLink>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChainLinkVerification {
    pub index: usize,
    pub valid_signature: bool,
    pub fingerprint_matches: bool,
    pub trusted_signer: bool,
    pub authorized_for_child: bool,
    pub parent: String,
    pub child: String,
    pub transformation: TransformationType,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChainVerification {
    pub state: LineageState,
    pub root_identity: Option<String>,
    pub endpoint_identity: Option<String>,
    pub links: Vec<ChainLinkVerification>,
    pub findings: Vec<String>,
}

pub fn load_manifest(path: &Path) -> Result<TransformationManifest> {
    let file = crate::safeio::open_readonly_nofollow(path)?;
    let bytes = crate::safeio::read_all_from_file(&file, MAX_CHAIN_BYTES)?;
    let manifest: TransformationManifest = serde_json::from_slice(&bytes)
        .with_context(|| format!("transformation manifest '{}' is invalid JSON", path.display()))?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

pub fn load_chain(path: &Path) -> Result<TransformationChain> {
    let file = crate::safeio::open_readonly_nofollow(path)?;
    let bytes = crate::safeio::read_all_from_file(&file, MAX_CHAIN_BYTES)?;
    let chain: TransformationChain = serde_json::from_slice(&bytes)
        .with_context(|| format!("transformation chain '{}' is invalid JSON", path.display()))?;
    if chain.version != 1 {
        bail!("unsupported transformation chain version {}", chain.version);
    }
    if chain.links.is_empty() || chain.links.len() > MAX_CHAIN_LINKS {
        bail!("transformation chain link count must be in 1..={MAX_CHAIN_LINKS}");
    }
    for link in &chain.links {
        validate_manifest(&link.manifest)?;
    }
    Ok(chain)
}

pub fn canonical_manifest_bytes(manifest: &TransformationManifest) -> Result<Vec<u8>> {
    validate_manifest(manifest)?;
    serde_json::to_vec(manifest).map_err(Into::into)
}

pub fn manifest_digest(manifest: &TransformationManifest) -> Result<String> {
    Ok(format!(
        "sha256:{}",
        hex::encode(Sha256::digest(canonical_manifest_bytes(manifest)?))
    ))
}

pub fn verify_chain(path: &Path, trust_store: &crate::trust::TrustStore) -> Result<ChainVerification> {
    let chain = load_chain(path)?;
    let mut findings = Vec::new();
    let mut verified = Vec::with_capacity(chain.links.len());
    let mut seen_edges = BTreeSet::<(String, String)>::new();
    let mut all_crypto = true;
    let mut all_trusted = true;
    let mut contradicted = false;

    for (index, link) in chain.links.iter().enumerate() {
        let public = parse_public_key_hex(&link.public_key_hex)?;
        let computed_fingerprint = crate::trust::fingerprint(&public);
        let fingerprint_matches = computed_fingerprint.eq_ignore_ascii_case(&link.key_fingerprint);
        let signature = hex::decode(&link.signature_hex)
            .context("transformation signature is not hexadecimal")?;
        let signature = Signature::from_slice(&signature)
            .context("transformation signature is not a valid Ed25519 signature")?;
        let valid_signature = fingerprint_matches
            && public
                .verify(&canonical_manifest_bytes(&link.manifest)?, &signature)
                .is_ok();
        let trusted_key = trust_store.find_by_fingerprint(&computed_fingerprint);
        let trusted_signer = trusted_key.is_some_and(|key| trust_store.key_active(key, crate::paths::now_unix()));
        let authorized_for_child = trusted_key.is_some_and(|key| {
            trust_store.authorized_for(key, &link.manifest.child.identity)
        });
        all_crypto &= valid_signature;
        all_trusted &= trusted_signer && authorized_for_child;

        if index > 0 {
            let prior = &chain.links[index - 1].manifest.child;
            if !endpoint_matches(prior, &link.manifest.parent) {
                contradicted = true;
                findings.push("LF-LINEAGE-CHAIN-BROKEN".to_owned());
            }
        }
        let edge = (
            link.manifest.parent.identity.clone(),
            link.manifest.child.identity.clone(),
        );
        if !seen_edges.insert(edge) || link.manifest.parent.identity == link.manifest.child.identity {
            contradicted = true;
            findings.push("LF-LINEAGE-CHAIN-CYCLE".to_owned());
        }
        if !valid_signature {
            findings.push("LF-LINEAGE-CHAIN-SIGNATURE".to_owned());
        } else if !trusted_signer || !authorized_for_child {
            findings.push("LF-LINEAGE-CHAIN-UNTRUSTED-SIGNER".to_owned());
        }
        verified.push(ChainLinkVerification {
            index,
            valid_signature,
            fingerprint_matches,
            trusted_signer,
            authorized_for_child,
            parent: link.manifest.parent.identity.clone(),
            child: link.manifest.child.identity.clone(),
            transformation: link.manifest.transformation.kind,
            detail: if valid_signature && trusted_signer && authorized_for_child {
                "signature valid; signer trusted and authorized for child identity".to_owned()
            } else if valid_signature {
                "signature valid but configured trust/authorization is incomplete".to_owned()
            } else {
                "signature or embedded key fingerprint is invalid".to_owned()
            },
        });
    }
    findings.sort();
    findings.dedup();
    let state = if contradicted || !all_crypto {
        LineageState::Contradicted
    } else if all_trusted {
        LineageState::Verified
    } else {
        LineageState::Unverified
    };
    Ok(ChainVerification {
        state,
        root_identity: chain.links.first().map(|v| v.manifest.parent.identity.clone()),
        endpoint_identity: chain.links.last().map(|v| v.manifest.child.identity.clone()),
        links: verified,
        findings,
    })
}

pub fn endpoint_matches(left: &TransformationEndpoint, right: &TransformationEndpoint) -> bool {
    left.identity == right.identity
        && optional_eq(&left.artifact_sha256, &right.artifact_sha256)
        && optional_eq(&left.package_fingerprint, &right.package_fingerprint)
}

fn optional_eq(left: &Option<String>, right: &Option<String>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left.eq_ignore_ascii_case(right),
        _ => true,
    }
}

fn validate_manifest(manifest: &TransformationManifest) -> Result<()> {
    if manifest.version != 1 {
        bail!("unsupported transformation manifest version {}", manifest.version);
    }
    for endpoint in [&manifest.parent, &manifest.child] {
        if endpoint.identity.trim().is_empty() || endpoint.identity.len() > 8192 {
            bail!("transformation endpoint identity is empty or too long");
        }
        validate_digest(endpoint.artifact_sha256.as_deref())?;
    }
    if manifest.transformation.tool.trim().is_empty() || manifest.transformation.tool.len() > 4096 {
        bail!("transformation tool identity is empty or too long");
    }
    if manifest.transformation.parameters.len() > 4096 {
        bail!("transformation parameter count exceeds safety limit");
    }
    Ok(())
}

fn validate_digest(value: Option<&str>) -> Result<()> {
    let Some(value) = value else { return Ok(()); };
    let value = value.strip_prefix("sha256:").unwrap_or(value);
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("artifact SHA-256 must contain exactly 64 hexadecimal characters");
    }
    Ok(())
}

fn parse_public_key_hex(value: &str) -> Result<VerifyingKey> {
    let bytes = hex::decode(value).context("transformation public key is not hexadecimal")?;
    let bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("transformation public key must be 32 Ed25519 bytes"))?;
    VerifyingKey::from_bytes(&bytes).context("invalid Ed25519 transformation public key")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_parser_accepts_common_aliases() {
        assert_eq!(TransformationType::parse("lora").unwrap(), TransformationType::LoraAdapter);
        assert_eq!(TransformationType::parse("finetune").unwrap(), TransformationType::FineTune);
    }

    #[test]
    fn endpoint_optional_hashes_do_not_create_false_contradiction() {
        let a = TransformationEndpoint { identity: "x".into(), artifact_sha256: None, package_fingerprint: None };
        let b = TransformationEndpoint { identity: "x".into(), artifact_sha256: Some(format!("sha256:{}", "a".repeat(64))), package_fingerprint: None };
        assert!(endpoint_matches(&a, &b));
    }
}
