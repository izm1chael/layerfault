use anyhow::Result;
use serde::Serialize;
use std::path::Path;
#[derive(Debug, Clone, Serialize)]
pub struct ExecutionGateVerification {
    pub allowed: bool,
    pub evidence_valid: bool,
    pub evidence_trusted: bool,
    pub artifact_match: bool,
    pub runtime_match: bool,
    pub ruleset_match: bool,
    pub intelligence_match: Option<bool>,
    pub passport_match: Option<bool>,
    pub reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rule_ids: Vec<String>,
}
pub fn verify_for_execution(
    evidence_path: &Path,
    trust_store: &crate::trust::TrustStore,
    artifact_path: &Path,
    runtime_path: Option<&Path>,
    current_intelligence_sha256: Option<&str>,
    current_passport_sha256: Option<&str>,
) -> Result<ExecutionGateVerification> {
    let verified = crate::evidence::verify(evidence_path, Some(trust_store))?;
    let envelope = crate::evidence::load(evidence_path)?;
    let mut reasons = Vec::new();
    let mut rule_ids = Vec::new();
    let receipt = envelope.payload.admission_receipt.as_ref();
    if !verified.valid_signature {
        reasons.push("signed evidence signature is invalid".into())
    }
    if !verified.trusted || !verified.authorized_for_subject {
        reasons.push("signed evidence key is not trusted/authorized for this subject".into())
    }
    if envelope.payload.decision != "ALLOW" {
        reasons.push(format!(
            "signed evidence decision is {} rather than ALLOW",
            envelope.payload.decision
        ))
    }
    if receipt.is_none() {
        reasons.push("signed evidence does not contain an admission receipt".into())
    }
    let artifact_digest = crate::safeio::sha256_path(artifact_path)?;
    let artifact_match = receipt.is_some_and(|r| {
        canonical_digest(&r.artifact_identity) == canonical_digest(&artifact_digest)
    });
    if !artifact_match {
        reasons.push("current artifact digest does not match admission receipt".into());
        rule_ids.push("LF-ADMISSION-RECEIPT-ARTIFACT-MISMATCH".into())
    }
    let runtime_match = match receipt.and_then(|r| r.runtime.as_ref()) {
        None => true,
        Some(expected) => match runtime_path {
            None => false,
            Some(path) => {
                let digest = crate::safeio::sha256_path(path)?;
                canonical_digest(&digest) == canonical_digest(&expected.executable_sha256)
            }
        },
    };
    if !runtime_match {
        reasons.push("current runtime executable digest does not match admission receipt".into());
        rule_ids.push("LF-ADMISSION-RECEIPT-RUNTIME-MISMATCH".into())
    }
    let ruleset_match =
        receipt.is_some_and(|r| r.ruleset_sha256 == crate::explain::ruleset_sha256());
    if !ruleset_match {
        reasons.push("current ruleset digest differs from admission receipt".into());
        rule_ids.push("LF-ADMISSION-RECEIPT-RULESET-MISMATCH".into())
    }
    let intelligence_match = receipt
        .and_then(|r| r.intelligence_sha256.as_deref())
        .map(|expected| current_intelligence_sha256 == Some(expected));
    if intelligence_match == Some(false) {
        reasons.push("current security intelligence digest differs from admission receipt".into());
        rule_ids.push("LF-ADMISSION-RECEIPT-INTELLIGENCE-MISMATCH".into())
    }
    let passport_match = receipt
        .and_then(|r| r.passport_sha256.as_deref())
        .map(|expected| current_passport_sha256 == Some(expected));
    if passport_match == Some(false) {
        reasons.push("current security passport digest differs from admission receipt".into())
    }
    let allowed = verified.valid_signature
        && verified.trusted
        && verified.authorized_for_subject
        && envelope.payload.decision == "ALLOW"
        && receipt.is_some()
        && artifact_match
        && runtime_match
        && ruleset_match
        && intelligence_match != Some(false)
        && passport_match != Some(false);
    Ok(ExecutionGateVerification {
        allowed,
        evidence_valid: verified.valid_signature,
        evidence_trusted: verified.trusted && verified.authorized_for_subject,
        artifact_match,
        runtime_match,
        ruleset_match,
        intelligence_match,
        passport_match,
        reasons,
        rule_ids,
    })
}
fn canonical_digest(v: &str) -> String {
    if v.starts_with("sha256:") {
        v.to_ascii_lowercase()
    } else {
        format!("sha256:{}", v.to_ascii_lowercase())
    }
}
