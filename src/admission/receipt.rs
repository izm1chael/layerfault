use super::ArtifactAdmission;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissionReceiptContext {
    pub version: u32,
    pub artifact_identity: String,
    #[serde(default)]
    pub package_identity: Option<String>,
    #[serde(default)]
    pub layered_identity: Option<crate::model::identity::LayeredModelIdentity>,
    pub policy_action: String,
    pub scanner_revision: String,
    pub ruleset_sha256: String,
    #[serde(default)]
    pub intelligence_sha256: Option<String>,
    #[serde(default)]
    pub passport_sha256: Option<String>,
    #[serde(default)]
    pub runtime: Option<ReceiptRuntime>,
    #[serde(default)]
    pub compatibility: Option<crate::runtime_security::CompatibilityState>,
    #[serde(default)]
    pub exploitability: Vec<ReceiptExploitability>,
    #[serde(default)]
    pub limitations: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptRuntime {
    pub kind: String,
    pub executable: String,
    pub executable_sha256: String,
    pub parsed_version: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptExploitability {
    pub advisory_id: String,
    pub state: String,
    pub reachability: String,
}
pub fn build_receipt(
    admission: &ArtifactAdmission,
    layered: Option<&crate::model::identity::LayeredModelIdentity>,
    runtime: Option<&crate::runtime_security::RuntimePosture>,
    compatibility: Option<&crate::runtime_security::ModelRuntimeCompatibility>,
    exploitability: &[crate::runtime_security::AdvisoryApplicability],
    intelligence_sha256: Option<&str>,
    passport_sha256: Option<&str>,
) -> Result<AdmissionReceiptContext> {
    if admission.policy.action == crate::policy::PolicyAction::Block {
        bail!("cannot create ALLOW admission receipt from a BLOCK policy decision")
    }
    if compatibility
        .is_some_and(|c| c.state == crate::runtime_security::CompatibilityState::Incompatible)
    {
        bail!("cannot create admission receipt for an incompatible model/runtime pair")
    }
    if exploitability
        .iter()
        .any(|a| a.state == crate::runtime_security::ExploitabilityState::PreconditionsMet)
    {
        bail!("cannot create admission receipt while contextual runtime exploitability preconditions are met")
    }
    let artifact_identity = admission
        .report
        .sha256
        .clone()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| admission.identity.clone());
    if artifact_identity.is_empty() {
        bail!("artifact identity is required for receipt creation")
    }
    let runtime = runtime
        .map(|r| {
            let digest = r
                .installation
                .executable_sha256
                .clone()
                .filter(|v| !v.is_empty())
                .ok_or_else(|| {
                    anyhow::anyhow!("runtime executable SHA-256 is required for receipt creation")
                })?;
            let executable = r.installation.executable.clone().ok_or_else(|| {
                anyhow::anyhow!("runtime executable path is required for receipt creation")
            })?;
            Ok::<ReceiptRuntime, anyhow::Error>(ReceiptRuntime {
                kind: r.installation.runtime.as_str().into(),
                executable,
                executable_sha256: digest,
                parsed_version: r.installation.parsed_version.clone(),
            })
        })
        .transpose()?;
    Ok(AdmissionReceiptContext {
        version: 1,
        artifact_identity,
        package_identity: layered.and_then(|i| i.package.as_ref().map(|v| v.value.clone())),
        layered_identity: layered.cloned(),
        policy_action: format!("{:?}", admission.policy.action).to_ascii_uppercase(),
        scanner_revision: crate::explain::scanner_revision().into(),
        ruleset_sha256: crate::explain::ruleset_sha256().into(),
        intelligence_sha256: intelligence_sha256.map(str::to_owned),
        passport_sha256: passport_sha256.map(str::to_owned),
        runtime,
        compatibility: compatibility.map(|c| c.state),
        exploitability: exploitability
            .iter()
            .map(|a| ReceiptExploitability {
                advisory_id: a.advisory_id.clone(),
                state: format!("{:?}", a.state),
                reachability: format!("{:?}", a.reachability),
            })
            .collect(),
        limitations: Vec::new(),
    })
}
