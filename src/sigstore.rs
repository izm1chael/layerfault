use anyhow::{anyhow, Context, Result};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, serde::Serialize)]
pub struct SigstoreEvaluation {
    pub verified: bool,
    pub identity: String,
    pub issuer: String,
    pub bundle: String,
    pub detail: String,
}

pub fn verify_blob(
    path: &Path,
    bundle: &Path,
    identity: &str,
    issuer: &str,
) -> Result<SigstoreEvaluation> {
    if crate::sources::find_executable("cosign").is_none() {
        return Err(anyhow!("cosign is not installed; Sigstore verification is optional and never downloaded automatically"));
    }
    let output = Command::new("cosign")
        .arg("verify-blob")
        .arg(path)
        .arg("--bundle")
        .arg(bundle)
        .arg("--certificate-identity")
        .arg(identity)
        .arg("--certificate-oidc-issuer")
        .arg(issuer)
        .output()
        .context("Unable to execute cosign verify-blob")?;
    let detail = if output.status.success() {
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    } else {
        String::from_utf8_lossy(&output.stderr).trim().to_owned()
    };
    Ok(SigstoreEvaluation {
        verified: output.status.success(),
        identity: identity.to_owned(),
        issuer: issuer.to_owned(),
        bundle: bundle.display().to_string(),
        detail,
    })
}
