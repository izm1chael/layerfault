use super::{passport_sha256, ModelSecurityPassport};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

const MAX_PASSPORT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassportVerification {
    pub valid: bool,
    pub version: u32,
    pub sha256: String,
    #[serde(default)]
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassportDiff {
    pub same_subject: bool,
    pub left_sha256: String,
    pub right_sha256: String,
    #[serde(default)]
    pub changed: Vec<String>,
}

pub fn load(path: &Path) -> Result<ModelSecurityPassport> {
    let file = crate::safeio::open_readonly_nofollow(path)?;
    let bytes = crate::safeio::read_all_from_file(&file, MAX_PASSPORT_BYTES)?;
    let passport: ModelSecurityPassport = serde_json::from_slice(&bytes)
        .with_context(|| format!("security passport '{}' is invalid JSON", path.display()))?;
    validate_passport(&passport)?;
    Ok(passport)
}

pub fn load_portable(path: &Path) -> Result<ModelSecurityPassport> {
    match load(path) {
        Ok(passport) => Ok(passport),
        Err(raw_error) => match super::passport_signing::load_signed_passport(path) {
            Ok(signed) => {
                let verification =
                    super::passport_signing::verify_signed_passport(&signed, None)?;
                if !verification.valid_signature {
                    bail!("signed security passport has an invalid signature");
                }
                Ok(signed.passport)
            }
            Err(signed_error) => bail!(
                "unable to load '{}' as an unsigned or signed security passport; unsigned passport: {}; signed envelope: {}",
                path.display(),
                raw_error,
                signed_error
            ),
        },
    }
}

pub fn verify(passport: &ModelSecurityPassport) -> Result<PassportVerification> {
    validate_passport(passport)?;
    let mut limitations = passport.limitations.clone();
    if passport.version == 1 {
        limitations.push(
            "passport version 1 does not carry composition, agent or domain-completeness extensions"
                .to_owned(),
        );
    }
    limitations.sort();
    limitations.dedup();
    Ok(PassportVerification {
        valid: true,
        version: passport.version,
        sha256: passport_sha256(passport)?,
        limitations,
    })
}

pub fn diff(left: &ModelSecurityPassport, right: &ModelSecurityPassport) -> Result<PassportDiff> {
    validate_passport(left)?;
    validate_passport(right)?;
    let mut changed = Vec::new();
    if left.subject.name != right.subject.name || left.subject.format != right.subject.format {
        changed.push("subject".to_owned());
    }
    if serde_json::to_value(&left.identity)? != serde_json::to_value(&right.identity)? {
        changed.push("identity".to_owned());
    }
    if left.composition.as_ref().map(|v| &v.identity)
        != right.composition.as_ref().map(|v| &v.identity)
    {
        changed.push("composition".to_owned());
    }
    if left
        .agent
        .as_ref()
        .map(|v| (&v.agent_identity, &v.capability_graph_identity))
        != right
            .agent
            .as_ref()
            .map(|v| (&v.agent_identity, &v.capability_graph_identity))
    {
        changed.push("agent".to_owned());
    }
    if serde_json::to_value(&left.provenance)? != serde_json::to_value(&right.provenance)? {
        changed.push("provenance".to_owned());
    }
    if serde_json::to_value(&left.behavioural)? != serde_json::to_value(&right.behavioural)? {
        changed.push("behavioural".to_owned());
    }
    if serde_json::to_value(&left.completeness)? != serde_json::to_value(&right.completeness)? {
        changed.push("completeness".to_owned());
    }
    if serde_json::to_value(&left.runtime)? != serde_json::to_value(&right.runtime)? {
        changed.push("runtime".to_owned());
    }
    if left.ruleset_sha256 != right.ruleset_sha256 {
        changed.push("ruleset".to_owned());
    }
    if left.intelligence_sha256 != right.intelligence_sha256
        || left.intelligence_epoch != right.intelligence_epoch
    {
        changed.push("intelligence".to_owned());
    }
    if serde_json::to_value(&left.findings)? != serde_json::to_value(&right.findings)? {
        changed.push("findings".to_owned());
    }
    if serde_json::to_value(&left.coverage)? != serde_json::to_value(&right.coverage)? {
        changed.push("coverage".to_owned());
    }
    if serde_json::to_value(&left.policy)? != serde_json::to_value(&right.policy)? {
        changed.push("policy".to_owned());
    }
    if left.evidence_digest != right.evidence_digest {
        changed.push("evidence_digest".to_owned());
    }
    changed.sort();
    changed.dedup();
    Ok(PassportDiff {
        same_subject: left.subject.name == right.subject.name
            && left.subject.format == right.subject.format,
        left_sha256: passport_sha256(left)?,
        right_sha256: passport_sha256(right)?,
        changed,
    })
}

pub(crate) fn validate_passport(passport: &ModelSecurityPassport) -> Result<()> {
    if !matches!(passport.version, 1 | 2) {
        bail!("unsupported security passport version {}", passport.version);
    }
    if passport.subject.name.trim().is_empty() || passport.subject.name.len() > 64 * 1024 {
        bail!("security passport has an invalid subject name");
    }
    if passport.subject.format.trim().is_empty() || passport.subject.format.len() > 16 * 1024 {
        bail!("security passport has an invalid subject format");
    }
    if passport.runtime.len() > 4096
        || passport.findings.rule_ids.len() > 100_000
        || passport.findings.finding_ids.len() > 100_000
        || passport.limitations.len() > 100_000
    {
        bail!("security passport exceeds structural safety limits");
    }
    if passport.version == 1
        && (passport.composition.is_some()
            || passport.agent.is_some()
            || passport.provenance.is_some()
            || passport.behavioural.is_some()
            || passport.completeness.is_some()
            || passport.intelligence_epoch.is_some())
    {
        bail!("security passport version 1 contains version 2 fields");
    }
    if let Some(composition) = &passport.composition {
        if !composition.identity.starts_with("lfcomposition:v1:sha256:") {
            bail!("security passport contains a non-canonical composition identity");
        }
    }
    if let Some(agent) = &passport.agent {
        if agent.agent_identity.trim().is_empty()
            || agent.capability_graph_identity.trim().is_empty()
        {
            bail!("security passport contains an incomplete agent identity binding");
        }
        if agent.high_impact_capabilities.len() > 16_384 || agent.dangerous_chains.len() > 16_384 {
            bail!("security passport agent summary exceeds safety limits");
        }
    }
    Ok(())
}
