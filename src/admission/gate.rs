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
    pub composition_match: Option<bool>,
    pub runtime_configuration_match: Option<bool>,
    pub agent_match: Option<bool>,
    pub capability_graph_match: Option<bool>,
    pub mcp_servers_match: Option<bool>,
    pub reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rule_ids: Vec<String>,
}
#[derive(Debug, Clone, Default)]
pub struct ExecutionContextExpectation<'a> {
    pub composition_identity: Option<&'a str>,
    pub runtime_configuration_identity: Option<&'a str>,
    pub agent_identity: Option<&'a str>,
    pub capability_graph_identity: Option<&'a str>,
    pub mcp_server_identities: Vec<&'a str>,
}

pub fn verify_for_execution(
    evidence_path: &Path,
    trust_store: &crate::trust::TrustStore,
    artifact_path: &Path,
    runtime_path: Option<&Path>,
    current_intelligence_sha256: Option<&str>,
    current_passport_sha256: Option<&str>,
) -> Result<ExecutionGateVerification> {
    verify_for_execution_context(
        evidence_path,
        trust_store,
        artifact_path,
        runtime_path,
        current_intelligence_sha256,
        current_passport_sha256,
        &ExecutionContextExpectation::default(),
    )
}

pub fn verify_for_execution_context(
    evidence_path: &Path,
    trust_store: &crate::trust::TrustStore,
    artifact_path: &Path,
    runtime_path: Option<&Path>,
    current_intelligence_sha256: Option<&str>,
    current_passport_sha256: Option<&str>,
    current: &ExecutionContextExpectation<'_>,
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
    if let Some(receipt) = receipt {
        if !matches!(receipt.version, 1 | 2) {
            reasons.push(format!(
                "unsupported admission receipt version {}",
                receipt.version
            ));
        }
        let has_execution_extensions = receipt.composition_identity.is_some()
            || receipt.runtime_configuration_identity.is_some()
            || receipt.agent_identity.is_some()
            || receipt.capability_graph_identity.is_some()
            || !receipt.mcp_server_identities.is_empty();
        if receipt.version == 1 && has_execution_extensions {
            reasons.push("admission receipt version 1 contains execution-context fields that require version 2".into());
        }
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
    let composition_match = receipt
        .and_then(|r| r.composition_identity.as_deref())
        .map(|expected| current.composition_identity == Some(expected));
    if composition_match == Some(false) {
        reasons.push("current model composition identity differs from admission receipt".into());
        rule_ids.push("LF-ADMISSION-RECEIPT-COMPOSITION-MISMATCH".into());
    }
    let runtime_configuration_match = receipt
        .and_then(|r| r.runtime_configuration_identity.as_deref())
        .map(|expected| current.runtime_configuration_identity == Some(expected));
    if runtime_configuration_match == Some(false) {
        reasons
            .push("current runtime configuration identity differs from admission receipt".into());
        rule_ids.push("LF-ADMISSION-RECEIPT-RUNTIME-CONFIG-MISMATCH".into());
    }
    let agent_match = receipt
        .and_then(|r| r.agent_identity.as_deref())
        .map(|expected| current.agent_identity == Some(expected));
    if agent_match == Some(false) {
        reasons.push("current agent identity differs from admission receipt".into());
        rule_ids.push("LF-ADMISSION-RECEIPT-AGENT-MISMATCH".into());
    }
    let capability_graph_match = receipt
        .and_then(|r| r.capability_graph_identity.as_deref())
        .map(|expected| current.capability_graph_identity == Some(expected));
    if capability_graph_match == Some(false) {
        reasons.push("current capability graph identity differs from admission receipt".into());
        rule_ids.push("LF-ADMISSION-RECEIPT-CAPABILITY-MISMATCH".into());
    }
    let mcp_servers_match = receipt.and_then(|r| {
        if r.mcp_server_identities.is_empty() {
            None
        } else {
            let mut expected = r.mcp_server_identities.clone();
            expected.sort();
            expected.dedup();
            let mut observed = current
                .mcp_server_identities
                .iter()
                .map(|v| (*v).to_owned())
                .collect::<Vec<_>>();
            observed.sort();
            observed.dedup();
            Some(expected == observed)
        }
    });
    if mcp_servers_match == Some(false) {
        reasons.push("current MCP server identities differ from admission receipt".into());
        rule_ids.push("LF-ADMISSION-RECEIPT-MCP-MISMATCH".into());
    }
    let receipt_version_valid = receipt.is_some_and(|receipt| {
        matches!(receipt.version, 1 | 2)
            && !(receipt.version == 1
                && (receipt.composition_identity.is_some()
                    || receipt.runtime_configuration_identity.is_some()
                    || receipt.agent_identity.is_some()
                    || receipt.capability_graph_identity.is_some()
                    || !receipt.mcp_server_identities.is_empty()))
    });
    let allowed = verified.valid_signature
        && verified.trusted
        && verified.authorized_for_subject
        && envelope.payload.decision == "ALLOW"
        && receipt.is_some()
        && receipt_version_valid
        && artifact_match
        && runtime_match
        && ruleset_match
        && intelligence_match != Some(false)
        && passport_match != Some(false)
        && composition_match != Some(false)
        && runtime_configuration_match != Some(false)
        && agent_match != Some(false)
        && capability_graph_match != Some(false)
        && mcp_servers_match != Some(false);
    Ok(ExecutionGateVerification {
        allowed,
        evidence_valid: verified.valid_signature,
        evidence_trusted: verified.trusted && verified.authorized_for_subject,
        artifact_match,
        runtime_match,
        ruleset_match,
        intelligence_match,
        passport_match,
        composition_match,
        runtime_configuration_match,
        agent_match,
        capability_graph_match,
        mcp_servers_match,
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
