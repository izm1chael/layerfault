use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;
use std::process::Stdio;

#[derive(Debug, Clone, serde::Serialize)]
pub struct SigstoreEvaluation {
    pub verified: bool,
    pub identity: String,
    pub issuer: String,
    pub bundle: String,
    pub detail: String,
    pub verifier_path: String,
    pub verifier_sha256: String,
    pub verifier_version: Option<String>,
}

pub fn verify_blob(
    path: &Path,
    bundle: &Path,
    identity: &str,
    issuer: &str,
) -> Result<SigstoreEvaluation> {
    let candidate = crate::sources::find_executable("cosign").ok_or_else(|| {
        anyhow!("cosign is not installed; Sigstore verification is optional and never downloaded automatically")
    })?;
    let verifier = crate::safeio::canonical_executable(&candidate)?;
    let before_sha256 = executable_sha256(&verifier)?;
    let version = verifier_version(&verifier);

    // Re-bind immediately before the security decision. A user-writable PATH
    // entry replaced after version discovery must not silently become the
    // verifier whose exit status Layerfault trusts.
    let launch_sha256 = executable_sha256(&verifier)?;
    if launch_sha256 != before_sha256 {
        return Err(anyhow!(
            "cosign verifier changed between discovery and verification"
        ));
    }
    let mut command = crate::safeio::command_for_executable(&verifier)?;
    let output = command
        .arg("verify-blob")
        .arg(path)
        .arg("--bundle")
        .arg(bundle)
        .arg("--certificate-identity")
        .arg(identity)
        .arg("--certificate-oidc-issuer")
        .arg(issuer)
        .env_clear()
        .stdin(Stdio::null())
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
        verifier_path: verifier.display().to_string(),
        verifier_sha256: format!("sha256:{launch_sha256}"),
        verifier_version: version,
    })
}

fn executable_sha256(path: &Path) -> Result<String> {
    let mut file = crate::safeio::open_readonly_nofollow(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 1024 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn verifier_version(path: &Path) -> Option<String> {
    let mut command = crate::safeio::command_for_executable(path).ok()?;
    let output = command
        .arg("version")
        .env_clear()
        .stdin(Stdio::null())
        .output()
        .ok()?;
    let bytes = if output.stdout.is_empty() {
        output.stderr
    } else {
        output.stdout
    };
    let value = String::from_utf8_lossy(&bytes).trim().to_owned();
    (!value.is_empty()).then(|| value.chars().take(4096).collect())
}
