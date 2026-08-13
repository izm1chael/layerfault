use anyhow::{anyhow, Result};
use ed25519_dalek::VerifyingKey;
use layerfault::admission::SigstoreRequest;
use layerfault::safeio;
use std::path::Path;

pub(crate) fn load_verifying_key(path: &Path) -> Result<VerifyingKey> {
    use ed25519_dalek::pkcs8::DecodePublicKey;
    let file = safeio::open_readonly_nofollow(path)?;
    let bytes = safeio::read_all_from_file(&file, 64 * 1024)?;
    let pem =
        std::str::from_utf8(&bytes).map_err(|_| anyhow!("Public key PEM must be valid UTF-8"))?;
    Ok(VerifyingKey::from_public_key_pem(pem)?)
}

pub(crate) fn sigstore_request<'a>(
    bundle: Option<&'a Path>,
    identity: Option<&'a str>,
    issuer: Option<&'a str>,
) -> Result<Option<SigstoreRequest<'a>>> {
    match (bundle, identity, issuer) {
        (None, None, None) => Ok(None),
        (Some(bundle), Some(identity), Some(issuer)) => Ok(Some(SigstoreRequest { bundle, identity, issuer })),
        _ => Err(anyhow!("Sigstore verification requires --sigstore-bundle, --certificate-identity and --certificate-issuer together")),
    }
}

pub(crate) fn parse_nonnegative_finite_f64(value: &str) -> std::result::Result<f64, String> {
    let parsed: f64 = value
        .parse()
        .map_err(|_| format!("'{value}' is not a number"))?;
    if !parsed.is_finite() || parsed < 0.0 {
        return Err("value must be finite and >= 0".to_owned());
    }
    Ok(parsed)
}
pub(crate) fn parse_positive_u64(value: &str) -> std::result::Result<u64, String> {
    let parsed: u64 = value
        .parse()
        .map_err(|_| format!("'{value}' is not a positive integer"))?;
    if parsed == 0 {
        return Err("value must be > 0".to_owned());
    }
    Ok(parsed)
}
pub(crate) fn parse_jobs(value: &str) -> std::result::Result<usize, String> {
    let parsed: usize = value
        .parse()
        .map_err(|_| format!("'{value}' is not a positive integer"))?;
    if !(1..=64).contains(&parsed) {
        return Err("jobs must be between 1 and 64".to_owned());
    }
    Ok(parsed)
}
pub(crate) fn parse_scheduler(value: &str) -> std::result::Result<String, String> {
    match layerfault::scheduler::SchedulerMode::parse(value) {
        Ok(mode) => Ok(mode.as_str().to_owned()),
        Err(err) => Err(err.to_string()),
    }
}
pub(crate) fn parse_nonnegative_i64(value: &str) -> std::result::Result<i64, String> {
    let parsed: i64 = value
        .parse()
        .map_err(|_| format!("'{value}' is not an integer"))?;
    if parsed < 0 {
        return Err("value must be >= 0".to_owned());
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_non_finite_cli_thresholds() {
        assert!(parse_nonnegative_finite_f64("NaN").is_err());
        assert!(parse_nonnegative_finite_f64("inf").is_err());
        assert!(parse_nonnegative_finite_f64("-1").is_err());
    }
    #[test]
    fn jobs_are_bounded() {
        assert!(parse_jobs("1").is_ok());
        assert!(parse_jobs("64").is_ok());
        assert!(parse_jobs("0").is_err());
        assert!(parse_jobs("65").is_err());
    }
}
