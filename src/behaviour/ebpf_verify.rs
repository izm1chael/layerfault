//! Hash/version-pinned trust for the external eBPF telemetry helper.
//!
//! Closest existing precedent is `crate::sigstore::verify_blob`, which
//! resolves `cosign` and re-hashes it immediately before spawn to close a
//! discovery-to-launch TOCTOU window — but it does not pin against a
//! known-good hash; it only detects "did the binary change under us."
//! This module adds Layerfault's first true pinned-identity check: the
//! helper must match an exact, compile-time-embedded manifest (sha256 +
//! version range + schema version) or the run is a hard failure, never a
//! silent downgrade.
//!
//! The manifest is embedded from a repo-tracked file
//! (`helpers/layerfault-ebpf-telemetry/EXPECTED.toml`) so verification stays
//! fully offline, consistent with Layerfault's offline-by-default local
//! scanning: no runtime fetch of trust material is introduced.

use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Stdio;

const EMBEDDED_MANIFEST: &str =
    include_str!("../../helpers/layerfault-ebpf-telemetry/EXPECTED.toml");

/// Parsed expected-identity manifest for the eBPF helper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelperManifest {
    pub min_version: (u64, u64, u64),
    pub max_version: (u64, u64, u64),
    pub sha256: String,
    pub schema_version: u16,
}

/// Result of a successful verification, carried into `EbpfTelemetryBackend`
/// prepare-time wiring and recorded for audit purposes.
#[derive(Debug, Clone)]
pub struct VerifiedHelper {
    pub path: PathBuf,
    pub sha256: String,
    pub version: String,
}

pub fn embedded_manifest() -> Result<HelperManifest> {
    parse_manifest(EMBEDDED_MANIFEST)
}

/// Resolve the eBPF helper via the same `find_executable` idiom used for
/// `strace`/`bwrap`/`cosign` (env override `LAYERFAULT_EBPF_HELPER`, else
/// PATH), then hash/version-verify it against the embedded manifest. `Err`
/// covers every reason the eBPF backend cannot be trusted right now: helper
/// not found, hash mismatch, version out of range, or a malformed manifest.
pub fn locate_and_verify_helper() -> Result<VerifiedHelper> {
    let manifest = embedded_manifest().context("eBPF helper manifest is invalid")?;
    let candidate = crate::sources::find_executable("layerfault-ebpf-telemetry").ok_or_else(
        || anyhow!("layerfault-ebpf-telemetry helper is not installed (set LAYERFAULT_EBPF_HELPER or place it on PATH)"),
    )?;
    verify_helper(&candidate, &manifest)
}

fn parse_manifest(text: &str) -> Result<HelperManifest> {
    let value: toml::Value =
        toml::from_str(text).context("unable to parse embedded eBPF helper manifest")?;
    let table = value
        .as_table()
        .ok_or_else(|| anyhow!("eBPF helper manifest must be a TOML table"))?;
    let min_version = parse_semver(
        table
            .get("min_version")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| anyhow!("manifest missing string field 'min_version'"))?,
    )?;
    let max_version = parse_semver(
        table
            .get("max_version")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| anyhow!("manifest missing string field 'max_version'"))?,
    )?;
    let sha256 = table
        .get("sha256")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| anyhow!("manifest missing string field 'sha256'"))?
        .to_ascii_lowercase();
    if sha256.len() != 64 || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(anyhow!(
            "manifest 'sha256' must contain exactly 64 hexadecimal characters"
        ));
    }
    let schema_version = table
        .get("schema_version")
        .and_then(toml::Value::as_integer)
        .ok_or_else(|| anyhow!("manifest missing integer field 'schema_version'"))?;
    let schema_version = u16::try_from(schema_version)
        .map_err(|_| anyhow!("manifest 'schema_version' out of range"))?;
    if schema_version != crate::behaviour::ebpf_telemetry::PROTOCOL_SCHEMA_VERSION {
        return Err(anyhow!(
            "manifest schema version {schema_version} does not match supported protocol schema version {}",
            crate::behaviour::ebpf_telemetry::PROTOCOL_SCHEMA_VERSION
        ));
    }
    if min_version >= max_version {
        return Err(anyhow!(
            "manifest version range must have min_version lower than max_version"
        ));
    }
    Ok(HelperManifest {
        min_version,
        max_version,
        sha256,
        schema_version,
    })
}

fn parse_semver(value: &str) -> Result<(u64, u64, u64)> {
    let mut parts = value.trim().split('.');
    let major = parts
        .next()
        .ok_or_else(|| anyhow!("empty version string"))?
        .parse::<u64>()
        .with_context(|| format!("invalid major version in '{value}'"))?;
    let minor = parts
        .next()
        .unwrap_or("0")
        .parse::<u64>()
        .with_context(|| format!("invalid minor version in '{value}'"))?;
    let patch = parts
        .next()
        .unwrap_or("0")
        .parse::<u64>()
        .with_context(|| format!("invalid patch version in '{value}'"))?;
    if parts.next().is_some() {
        return Err(anyhow!("version '{value}' has more than three components"));
    }
    Ok((major, minor, patch))
}

/// Resolve, hash-verify, and version-verify the eBPF helper binary at
/// `candidate`. On any mismatch (hash, version range, symlink, unreadable,
/// unparseable manifest) this returns `Err` — callers must treat that as a
/// hard failure for an explicitly requested `ebpf` backend, and as a
/// visible (never silent) `auto`-mode fallback reason otherwise. Re-hashes
/// immediately before returning to close the same discovery-to-launch
/// TOCTOU window `sigstore::verify_blob` closes for `cosign`.
pub fn verify_helper(candidate: &Path, manifest: &HelperManifest) -> Result<VerifiedHelper> {
    let verifier = crate::safeio::canonical_executable_nosymlink(candidate)
        .context("eBPF helper path failed symlink/exec-bit verification")?;

    let discovered_sha256 = executable_sha256(&verifier)?;
    if discovered_sha256 != manifest.sha256 {
        return Err(anyhow!(
            "eBPF helper hash mismatch: expected sha256:{}, found sha256:{}",
            manifest.sha256,
            discovered_sha256
        ));
    }

    let version_str = helper_version(&verifier)
        .ok_or_else(|| anyhow!("unable to determine eBPF helper version"))?;
    let version = parse_semver(&version_str)
        .with_context(|| format!("eBPF helper reported unparseable version '{version_str}'"))?;
    if version < manifest.min_version || version >= manifest.max_version {
        return Err(anyhow!(
            "eBPF helper version {version_str} outside expected range [{:?}, {:?})",
            manifest.min_version,
            manifest.max_version
        ));
    }

    // Re-bind immediately before the security decision. A user-writable
    // PATH entry replaced after version discovery must not silently become
    // the helper Layerfault trusts to observe a sandbox run.
    let launch_sha256 = executable_sha256(&verifier)?;
    if launch_sha256 != discovered_sha256 {
        return Err(anyhow!(
            "eBPF helper changed between discovery and verification"
        ));
    }

    Ok(VerifiedHelper {
        path: verifier,
        sha256: launch_sha256,
        version: version_str,
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

fn helper_version(path: &Path) -> Option<String> {
    let mut command = crate::safeio::command_for_executable(path).ok()?;
    let output = command
        .arg("--version")
        .env_clear()
        .stdin(Stdio::null())
        .output()
        .ok()?;
    let bytes = if output.stdout.is_empty() {
        output.stderr
    } else {
        output.stdout
    };
    let text = String::from_utf8_lossy(&bytes);
    // clap's `--version` output is "<name> <version>"; take the last
    // whitespace-separated token.
    text.split_whitespace()
        .last()
        .map(|value| value.chars().take(64).collect())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;

    fn write_fixture_binary(dir: &Path, contents: &[u8]) -> PathBuf {
        let path = dir.join("fixture-helper");
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(contents).unwrap();
        drop(file);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    fn sha256_hex(contents: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(contents);
        hex::encode(hasher.finalize())
    }

    #[test]
    fn embedded_manifest_parses() {
        // The manifest ships with a deliberately unsatisfiable sha256
        // placeholder until a real release pipeline populates it (see
        // EXPECTED.toml's comment); this test only asserts the file is
        // well-formed, not that any real binary currently matches it.
        let manifest = embedded_manifest().unwrap();
        assert_eq!(manifest.schema_version, 1);
    }

    #[test]
    fn version_range_parsing_is_half_open() {
        let manifest = parse_manifest(
            "min_version = \"0.1.0\"\nmax_version = \"0.2.0\"\nsha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\nschema_version = 1\n",
        )
        .unwrap();
        assert_eq!(manifest.min_version, (0, 1, 0));
        assert_eq!(manifest.max_version, (0, 2, 0));
    }

    #[test]
    fn malformed_hash_and_version_range_are_rejected() {
        assert!(parse_manifest(
            "min_version = \"0.1.0\"\nmax_version = \"0.2.0\"\nsha256 = \"nope\"\nschema_version = 1\n"
        )
        .is_err());
        assert!(parse_manifest(
            "min_version = \"0.2.0\"\nmax_version = \"0.1.0\"\nsha256 = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\nschema_version = 1\n"
        )
        .is_err());
    }

    #[test]
    fn hash_mismatch_is_hard_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let contents = b"#!/bin/sh\necho fixture\n";
        let path = write_fixture_binary(dir.path(), contents);
        let manifest = HelperManifest {
            min_version: (0, 0, 0),
            max_version: (99, 0, 0),
            sha256: "0".repeat(64),
            schema_version: 1,
        };
        let err = verify_helper(&path, &manifest).unwrap_err();
        assert!(err.to_string().contains("hash mismatch"));
    }

    #[test]
    fn correct_hash_but_unparseable_version_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let contents = b"#!/bin/sh\nexit 1\n";
        let path = write_fixture_binary(dir.path(), contents);
        let manifest = HelperManifest {
            min_version: (0, 0, 0),
            max_version: (99, 0, 0),
            sha256: sha256_hex(contents),
            schema_version: 1,
        };
        // The fixture script has no real --version implementation, so this
        // must fail closed rather than assume a version in range.
        let err = verify_helper(&path, &manifest).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("version"));
    }
}
