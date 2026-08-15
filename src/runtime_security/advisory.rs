use crate::safeio::{open_readonly_nofollow, read_all_from_file};
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use crate::sources;
use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::pkcs8::DecodePublicKey;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const BUILTIN: &str = include_str!("../../advisories/runtime-advisories.json");
const MAX_DATABASE_BYTES: u64 = 4 * 1024 * 1024;

use super::types::RuntimeKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Moderate,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvisoryMatcher {
    pub scheme: String,
    pub fixed: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityImpact {
    CodeExecution,
    MemoryCorruption,
    DenialOfService,
    InformationDisclosure,
    AuthenticationBypass,
    IntegrityViolation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AdvisoryPrecondition {
    ArtifactFormat { format: String },
    RulePresent { rule_id: String },
    ConfigFieldPresent { path: String },
    ConfigFieldEquals { path: String, value: String },
    ConfigFieldPrefix { path: String, prefix: String },
    RuntimeFlagPresent { flag: String },
    RuntimeFlagAbsent { flag: String },
    RuntimeExecutableName { names: Vec<String> },
    EnvironmentBoolean { name: String, value: bool },
    NetworkExposed,
    ArchitectureIn { values: Vec<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum VersionMatcher {
    SemverLt {
        fixed: String,
    },
    BuildLt {
        fixed: String,
    },
    BuildRange {
        #[serde(default)]
        min_inclusive: Option<String>,
        #[serde(default)]
        max_inclusive: Option<String>,
    },
    SemverRange {
        #[serde(default)]
        min_inclusive: Option<String>,
        #[serde(default)]
        max_exclusive: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeAdvisory {
    pub id: String,
    pub runtime: String,
    pub severity: Severity,
    pub title: String,
    pub matcher: AdvisoryMatcher,
    pub reference: String,
    #[serde(default)]
    pub cve: Vec<String>,
    #[serde(default)]
    pub cwe: Vec<String>,
    #[serde(default)]
    pub impact: Vec<SecurityImpact>,
    #[serde(default)]
    pub preconditions: Vec<AdvisoryPrecondition>,
    #[serde(default)]
    pub remediation: Option<String>,
    #[serde(default)]
    pub version_matcher: Option<VersionMatcher>,
    #[serde(default)]
    pub upstream_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvisoryDatabase {
    pub version: u32,
    pub generated_unix: u64,
    pub advisories: Vec<RuntimeAdvisory>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeInfo {
    pub runtime: RuntimeKind,
    pub executable: String,
    pub executable_sha256: String,
    pub raw_version: String,
    pub parsed_version: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeEvaluation {
    pub runtime: RuntimeInfo,
    pub database_sha256: String,
    pub findings: Vec<LayerScanResult>,
    pub blocking: bool,
}

pub fn builtin_database() -> Result<AdvisoryDatabase> {
    parse_database(BUILTIN.as_bytes())
}

pub fn load_database(path: Option<&Path>) -> Result<(AdvisoryDatabase, Vec<u8>)> {
    match path {
        Some(path) => {
            let file = open_readonly_nofollow(path)?;
            let bytes = read_all_from_file(&file, MAX_DATABASE_BYTES)?;
            Ok((parse_database(&bytes)?, bytes))
        }
        None => {
            let bytes = BUILTIN.as_bytes().to_vec();
            Ok((parse_database(&bytes)?, bytes))
        }
    }
}

fn parse_database(bytes: &[u8]) -> Result<AdvisoryDatabase> {
    let db: AdvisoryDatabase =
        serde_json::from_slice(bytes).context("Runtime advisory database is not valid JSON")?;
    if db.version != 1 {
        return Err(anyhow!(
            "Unsupported runtime advisory database version {}",
            db.version
        ));
    }
    let mut ids = std::collections::BTreeSet::new();
    for advisory in &db.advisories {
        if advisory.id.trim().is_empty()
            || advisory.runtime.trim().is_empty()
            || (advisory.matcher.fixed.trim().is_empty() && advisory.version_matcher.is_none())
        {
            return Err(anyhow!(
                "Runtime advisory database contains an incomplete advisory"
            ));
        }
        if !ids.insert(advisory.id.to_ascii_uppercase()) {
            return Err(anyhow!(
                "Runtime advisory database contains duplicate advisory id '{}'",
                advisory.id
            ));
        }
        RuntimeKind::parse(&advisory.runtime)
            .with_context(|| format!("Advisory '{}' has an unsupported runtime", advisory.id))?;
        if let Some(version_matcher) = &advisory.version_matcher {
            validate_version_matcher(version_matcher).with_context(|| {
                format!("Advisory '{}' has an invalid version matcher", advisory.id)
            })?;
        } else {
            match advisory.matcher.scheme.as_str() {
                "semver_lt" if parse_semver(&advisory.matcher.fixed).is_none() => {
                    return Err(anyhow!(
                        "Advisory '{}' has invalid semver fixed boundary '{}'",
                        advisory.id,
                        advisory.matcher.fixed
                    ));
                }
                "build_lt" if parse_build_boundary(&advisory.matcher.fixed).is_none() => {
                    return Err(anyhow!(
                        "Advisory '{}' has invalid build fixed boundary '{}'",
                        advisory.id,
                        advisory.matcher.fixed
                    ));
                }
                "semver_lt" | "build_lt" => {}
                other => return Err(anyhow!("Unsupported advisory matcher scheme '{other}'")),
            }
        }
        if !(advisory.reference.starts_with("https://")
            || advisory.reference.starts_with("http://"))
        {
            return Err(anyhow!(
                "Advisory '{}' reference is not an HTTP(S) URL",
                advisory.id
            ));
        }
    }
    Ok(db)
}

pub fn load_verified_external_database(
    database: &Path,
    signature: &Path,
    public_key: &Path,
) -> Result<(AdvisoryDatabase, Vec<u8>, String)> {
    let db_file = open_readonly_nofollow(database)?;
    let bytes = read_all_from_file(&db_file, MAX_DATABASE_BYTES)?;
    let parsed = parse_database(&bytes)?;
    let sig_file = open_readonly_nofollow(signature)?;
    let sig_text = String::from_utf8(read_all_from_file(&sig_file, 4096)?)
        .map_err(|_| anyhow!("Advisory signature must be UTF-8 hexadecimal"))?;
    let sig_bytes =
        hex::decode(sig_text.trim()).context("Advisory signature is not hexadecimal")?;
    let signature =
        Signature::from_slice(&sig_bytes).context("Advisory signature is not Ed25519")?;
    let key_file = open_readonly_nofollow(public_key)?;
    let key_pem = String::from_utf8(read_all_from_file(&key_file, 64 * 1024)?)
        .map_err(|_| anyhow!("Advisory public key must be PEM UTF-8"))?;
    let key = VerifyingKey::from_public_key_pem(&key_pem)
        .context("Unable to parse advisory Ed25519 public key")?;
    key.verify(&bytes, &signature)
        .context("Advisory database signature verification failed")?;
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
    Ok((parsed, bytes, digest))
}

pub fn verify_external_database(
    database: &Path,
    signature: &Path,
    public_key: &Path,
) -> Result<String> {
    let (_, _, digest) = load_verified_external_database(database, signature, public_key)?;
    Ok(digest)
}

fn default_runtime_executable(kind: RuntimeKind) -> Result<PathBuf> {
    let adapter = crate::runtime_security::adapters::adapter_for(kind);
    let path = adapter
        .executable_names()
        .iter()
        .find_map(|name| sources::find_executable(name));
    path.ok_or_else(|| {
        anyhow!(
            "Runtime executable for '{}' was not found in PATH",
            kind.as_str()
        )
    })
}

pub fn detect_runtime(kind: RuntimeKind) -> Result<RuntimeInfo> {
    let path = default_runtime_executable(kind)?;
    detect_runtime_executable(kind, &path)
}

pub fn detect_runtime_named(kind: RuntimeKind, executable_name: &str) -> Result<RuntimeInfo> {
    let path = sources::find_executable(executable_name)
        .ok_or_else(|| anyhow!("Runtime executable '{executable_name}' was not found in PATH"))?;
    detect_runtime_executable(kind, &path)
}

pub fn detect_runtime_executable(kind: RuntimeKind, executable: &Path) -> Result<RuntimeInfo> {
    let path = std::fs::canonicalize(executable).with_context(|| {
        format!(
            "Unable to resolve runtime executable '{}'",
            executable.display()
        )
    })?;
    let executable_sha256 = runtime_executable_sha256(&path)?;
    let output = crate::safeio::command_for_executable(&path)? // nosemgrep: rust.actix.command-injection.rust-actix-command-injection.rust-actix-command-injection -- canonical executable path; std::process::Command does not invoke a shell
        .arg("--version")
        .output()
        .with_context(|| format!("Unable to execute '{} --version'", path.display()))?;
    let combined = if output.stdout.is_empty() {
        String::from_utf8_lossy(&output.stderr).into_owned()
    } else {
        String::from_utf8_lossy(&output.stdout).into_owned()
    };
    if !output.status.success() && combined.trim().is_empty() {
        return Err(anyhow!(
            "Runtime '{}' did not return version information",
            kind.as_str()
        ));
    }
    let parsed = crate::runtime_security::adapters::adapter_for(kind).parse_version(&combined);
    Ok(RuntimeInfo {
        runtime: kind,
        executable: path.display().to_string(),
        executable_sha256,
        raw_version: combined.trim().to_owned(),
        parsed_version: parsed,
    })
}

pub fn revalidate_runtime_identity(info: &RuntimeInfo) -> Result<()> {
    let path = Path::new(&info.executable);
    let current = runtime_executable_sha256(path)?;
    if current != info.executable_sha256 {
        bail!(
            "runtime executable '{}' changed after advisory/version admission (expected {}, got {})",
            info.executable,
            info.executable_sha256,
            current
        );
    }
    Ok(())
}

fn runtime_executable_sha256(path: &Path) -> Result<String> {
    use std::io::Read as _;
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
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

pub fn evaluate(kind: RuntimeKind, database_path: Option<&Path>) -> Result<RuntimeEvaluation> {
    let runtime = detect_runtime(kind)?;
    let (database, bytes) = load_database(database_path)?;
    Ok(evaluate_info(runtime, &database, &bytes))
}

pub fn evaluate_named(
    kind: RuntimeKind,
    executable_name: &str,
    database: &AdvisoryDatabase,
    database_bytes: &[u8],
) -> Result<RuntimeEvaluation> {
    let runtime = detect_runtime_named(kind, executable_name)?;
    Ok(evaluate_info(runtime, database, database_bytes))
}

pub fn evaluate_info(
    runtime: RuntimeInfo,
    database: &AdvisoryDatabase,
    database_bytes: &[u8],
) -> RuntimeEvaluation {
    let mut findings = Vec::new();
    let parsed = runtime.parsed_version.clone();
    for advisory in database
        .advisories
        .iter()
        .filter(|a| a.runtime.eq_ignore_ascii_case(runtime.runtime.as_str()))
    {
        let affected = parsed
            .as_deref()
            .and_then(|version| advisory_affected(version, advisory));
        match affected {
            Some(true) => {
                let status = if advisory.severity >= Severity::High { ScanStatus::Fail } else { ScanStatus::Warn };
                findings.push(finding_with(&runtime, status, advisory.severity, &advisory.id, format!("{} is affected by {} ({:?}): {}. Fixed boundary: {}. {}", runtime.runtime.as_str(), advisory.id, advisory.severity, advisory.title, advisory.matcher.fixed, advisory.reference), Some(advisory)));
            }
            Some(false) => {}
            None => findings.push(finding(&runtime, ScanStatus::Warn, Severity::Moderate, "LF-RUNTIME-VERSION-UNKNOWN", format!("Layerfault could not compare runtime version '{}' against advisory {} fixed boundary {}", parsed.as_deref().unwrap_or("unknown"), advisory.id, advisory.matcher.fixed))),
        }
    }
    if parsed.is_none() {
        findings.push(finding(&runtime, ScanStatus::Warn, Severity::Moderate, "LF-RUNTIME-VERSION-UNKNOWN", format!("Layerfault could not parse a security-comparable version from '{}'; runtime advisory admission is incomplete", runtime.raw_version)));
    }
    let age = crate::paths::now_unix().saturating_sub(database.generated_unix);
    if age > 90 * 24 * 60 * 60 {
        findings.push(finding(&runtime, ScanStatus::Warn, Severity::Moderate, "LF-RUNTIME-ADVISORY-STALE", format!("Runtime advisory catalog is {} days old; refresh it before relying on absence of a match", age / 86400)));
    }
    if findings.is_empty() {
        findings.push(finding(
            &runtime,
            ScanStatus::Pass,
            Severity::Low,
            "LF-RUNTIME-ADVISORY-CLEAR",
            format!(
                "No bundled advisory in this catalog matched {} {}",
                runtime.runtime.as_str(),
                runtime.parsed_version.as_deref().unwrap_or("unknown")
            ),
        ));
    }
    let blocking = findings.iter().any(|f| f.status == ScanStatus::Fail);
    RuntimeEvaluation {
        runtime,
        database_sha256: format!("sha256:{}", hex::encode(Sha256::digest(database_bytes))),
        findings,
        blocking,
    }
}

pub(crate) fn advisory_affected(version: &str, advisory: &RuntimeAdvisory) -> Option<bool> {
    match advisory.version_matcher.as_ref() {
        Some(matcher) => version_matcher_affected(version, matcher),
        None => matcher_affected(version, &advisory.matcher),
    }
}

fn parse_build_boundary(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    let digits = trimmed
        .strip_prefix('b')
        .or_else(|| trimmed.strip_prefix('B'))?;
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

fn validate_version_matcher(matcher: &VersionMatcher) -> Result<()> {
    match matcher {
        VersionMatcher::SemverLt { fixed } => {
            if parse_semver(fixed).is_none() {
                bail!("invalid semver boundary '{fixed}'");
            }
        }
        VersionMatcher::BuildLt { fixed } => {
            if parse_build_boundary(fixed).is_none() {
                bail!("invalid build boundary '{fixed}'");
            }
        }
        VersionMatcher::BuildRange {
            min_inclusive,
            max_inclusive,
        } => {
            if min_inclusive.is_none() && max_inclusive.is_none() {
                bail!("empty build range");
            }
            for boundary in [min_inclusive.as_deref(), max_inclusive.as_deref()]
                .into_iter()
                .flatten()
            {
                if parse_build_boundary(boundary).is_none() {
                    bail!("invalid build boundary '{boundary}'");
                }
            }
        }
        VersionMatcher::SemverRange {
            min_inclusive,
            max_exclusive,
        } => {
            if min_inclusive.is_none() && max_exclusive.is_none() {
                bail!("empty semver range");
            }
            for boundary in [min_inclusive.as_deref(), max_exclusive.as_deref()]
                .into_iter()
                .flatten()
            {
                if parse_semver(boundary).is_none() {
                    bail!("invalid semver boundary '{boundary}'");
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn version_matcher_affected(version: &str, matcher: &VersionMatcher) -> Option<bool> {
    match matcher {
        VersionMatcher::SemverLt { fixed } => Some(compare_semver(version, fixed)? < 0),
        VersionMatcher::BuildLt { fixed } => {
            let current = parse_build_boundary(version)?;
            let fixed = parse_build_boundary(fixed)?;
            Some(current < fixed)
        }
        VersionMatcher::BuildRange {
            min_inclusive,
            max_inclusive,
        } => {
            let current = parse_build_boundary(version)?;
            let lower = min_inclusive
                .as_deref()
                .map(parse_build_boundary)
                .transpose_option()?;
            let upper = max_inclusive
                .as_deref()
                .map(parse_build_boundary)
                .transpose_option()?;
            Some(lower.is_none_or(|v| current >= v) && upper.is_none_or(|v| current <= v))
        }
        VersionMatcher::SemverRange {
            min_inclusive,
            max_exclusive,
        } => {
            let current = parse_semver(version)?;
            let lower = min_inclusive.as_deref().and_then(parse_semver);
            let upper = max_exclusive.as_deref().and_then(parse_semver);
            if min_inclusive.is_some() && lower.is_none()
                || max_exclusive.is_some() && upper.is_none()
            {
                return None;
            }
            Some(lower.is_none_or(|v| current >= v) && upper.is_none_or(|v| current < v))
        }
    }
}

trait TransposeOption<T> {
    fn transpose_option(self) -> Option<Option<T>>;
}
impl<T> TransposeOption<T> for Option<Option<T>> {
    fn transpose_option(self) -> Option<Option<T>> {
        match self {
            Some(Some(v)) => Some(Some(v)),
            Some(None) => None,
            None => Some(None),
        }
    }
}

fn matcher_affected(version: &str, matcher: &AdvisoryMatcher) -> Option<bool> {
    match matcher.scheme.as_str() {
        "semver_lt" => Some(compare_semver(version, &matcher.fixed)? < 0),
        "build_lt" => {
            let current = version.trim_start_matches('b').parse::<u64>().ok()?;
            let fixed = matcher.fixed.trim_start_matches('b').parse::<u64>().ok()?;
            Some(current < fixed)
        }
        _ => None,
    }
}

fn compare_semver(left: &str, right: &str) -> Option<i8> {
    let l = parse_semver(left)?;
    let r = parse_semver(right)?;
    Some(if l < r {
        -1
    } else if l > r {
        1
    } else {
        0
    })
}

fn parse_semver(value: &str) -> Option<(u64, u64, u64)> {
    let re = Regex::new(r"(?i)(?:^|[^0-9])(\d+)\.(\d+)\.(\d+)(?:[^0-9]|$)").ok()?;
    let caps = re.captures(value)?;
    Some((
        caps.get(1)?.as_str().parse().ok()?,
        caps.get(2)?.as_str().parse().ok()?,
        caps.get(3)?.as_str().parse().ok()?,
    ))
}

#[cfg_attr(not(test), allow(dead_code))]
fn parse_build(value: &str) -> Option<u64> {
    let patterns = [
        r"(?i)\bb(\d{3,7})\b",
        r"(?i)version\s*:?\s*(\d{3,7})\b",
        r"(?i)build\s*:?\s*(\d{3,7})\b",
    ];
    for pattern in patterns {
        let re = Regex::new(pattern).ok()?;
        if let Some(caps) = re.captures(value) {
            return caps.get(1)?.as_str().parse().ok();
        }
    }
    None
}

fn finding(
    runtime: &RuntimeInfo,
    status: ScanStatus,
    severity: Severity,
    rule: &str,
    detail: String,
) -> LayerScanResult {
    finding_with(runtime, status, severity, rule, detail, None)
}

/// Build a runtime-advisory finding, optionally with the matched advisory
/// evidence: runtime, detected version, advisory ID, affected range and
/// comparison result.
fn finding_with(
    runtime: &RuntimeInfo,
    status: ScanStatus,
    severity: Severity,
    rule: &str,
    detail: String,
    advisory: Option<&RuntimeAdvisory>,
) -> LayerScanResult {
    let layer_digest = runtime
        .parsed_version
        .clone()
        .unwrap_or_else(|| runtime.raw_version.clone());
    let media_type = format!(
        "application/vnd.layerfault.runtime+{}",
        runtime.runtime.as_str()
    );
    let subject = crate::finding_evidence::EvidenceSubject::identity(&layer_digest, &media_type)
        .with_sha256(Some(runtime.executable_sha256.clone()));
    let mut facts = serde_json::json!({
        "runtime": runtime.runtime.as_str(),
        "executable": runtime.executable,
        "raw_version": runtime.raw_version,
        "parsed_version": runtime.parsed_version,
        "severity": format!("{severity:?}"),
    });
    if let Some(advisory) = advisory {
        facts["advisory_id"] = serde_json::Value::String(advisory.id.clone());
        facts["fixed_boundary"] = serde_json::Value::String(advisory.matcher.fixed.clone());
        facts["matcher_scheme"] = serde_json::Value::String(advisory.matcher.scheme.clone());
        facts["reference"] = serde_json::Value::String(advisory.reference.clone());
    }
    crate::finding_evidence::FindingBuilder::new(rule, CheckType::RuntimeAdvisory, status)
        .class(if status == ScanStatus::Fail {
            FindingClass::Operational
        } else {
            FindingClass::Policy
        })
        .confidence(Confidence::High)
        .digest(&layer_digest)
        .media_type(&media_type)
        .subject(subject.clone())
        .detail(detail)
        .match_note(format!("runtime advisory {severity:?}"))
        .evidence(crate::finding_evidence::advisory_match(subject, facts))
        .finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn semver_boundary() {
        assert_eq!(compare_semver("0.17.0", "0.17.1"), Some(-1));
        assert_eq!(compare_semver("0.17.1", "0.17.1"), Some(0));
    }
    #[test]
    fn build_parser() {
        assert_eq!(parse_build("llama.cpp version: 9637 (abc)"), Some(9637));
        assert_eq!(parse_build("b8492"), Some(8492));
    }
    #[test]
    fn current_llama_build_clears_old_entries() -> Result<()> {
        let db = builtin_database()?;
        let bytes = BUILTIN.as_bytes();
        let info = RuntimeInfo {
            runtime: RuntimeKind::LlamaCpp,
            executable: "test".into(),
            executable_sha256: "sha256:synthetic".into(),
            raw_version: "version: 9637".into(),
            parsed_version: Some("b9637".into()),
        };
        assert!(!evaluate_info(info, &db, bytes).blocking);
        Ok(())
    }
    #[test]
    fn vulnerable_ollama_blocks() -> Result<()> {
        let db = builtin_database()?;
        let bytes = BUILTIN.as_bytes();
        let info = RuntimeInfo {
            runtime: RuntimeKind::Ollama,
            executable: "test".into(),
            executable_sha256: "sha256:synthetic".into(),
            raw_version: "ollama version is 0.17.0".into(),
            parsed_version: Some("0.17.0".into()),
        };
        assert!(evaluate_info(info, &db, bytes).blocking);
        Ok(())
    }
}
