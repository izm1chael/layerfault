//! User-facing telemetry backend selection (`--telemetry-backend
//! auto|strace|ebpf`) and the decision layer that turns a selection into a
//! concrete `TelemetryBackendKind`, following the same "string CLI field +
//! custom value_parser + typed enum with parse()/as_str()" idiom as
//! `scheduler::SchedulerMode`.

use crate::behaviour::sandbox::TelemetryBackendKind;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

/// The backend mode a user selects. Distinct from `TelemetryBackendKind`,
/// which records which backend actually produced a given `SandboxTelemetry`
/// — `Auto` is a selection strategy, never an observed outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TelemetryBackendMode {
    #[default]
    Auto,
    Strace,
    Ebpf,
}

impl TelemetryBackendMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Strace => "strace",
            Self::Ebpf => "ebpf",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "strace" => Ok(Self::Strace),
            "ebpf" => Ok(Self::Ebpf),
            other => {
                bail!("Unknown telemetry backend '{other}'; expected 'auto', 'strace', or 'ebpf'")
            }
        }
    }
}

impl std::fmt::Display for TelemetryBackendMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Enables `#[arg(long)] telemetry_backend: TelemetryBackendMode` directly
/// on the CLI struct, matching the existing `SandboxKind` idiom in
/// `sandbox.rs` (clap infers a `value_parser` from `FromStr` automatically).
impl std::str::FromStr for TelemetryBackendMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Outcome of resolving a `TelemetryBackendMode` selection to a concrete
/// backend. `degraded` is set exactly when `auto` fell back from eBPF to
/// strace — never left implicit, per "never silently downgrade requested
/// security controls."
#[derive(Debug, Clone)]
pub struct BackendResolution {
    pub backend: TelemetryBackendKind,
    pub degraded: Option<String>,
}

/// Whether this build can actually *collect* telemetry via a verified eBPF
/// helper, as opposed to merely verifying one's identity. Hash/version
/// verification (`ebpf_verify`) is real and load-bearing today; the live
/// spawn-before-child-launch/ring-buffer-consumption wiring that would let
/// `Workspace::collect_telemetry_with` actually use an `EbpfTelemetryBackend`
/// is a tracked follow-up (see `helpers/layerfault-ebpf-telemetry/src/
/// probes.rs`'s module doc comment). Gating on this constant — rather than
/// letting a future correctly-verified helper silently start being trusted
/// for collection before that wiring exists — prevents `resolve()` from
/// ever claiming an eBPF-sourced run that strace actually produced.
const LIVE_EBPF_COLLECTION_IMPLEMENTED: bool = false;

/// Resolve a backend selection. `Strace` always succeeds (its only
/// dependency, the `strace` binary itself, is checked separately at sandbox
/// launch as it always has been). `Ebpf` requires a verified helper AND
/// live collection support, or fails hard — no fallback, because the user
/// explicitly asked for it. `Auto` prefers a verified eBPF helper and falls
/// back to strace with a recorded, visible reason when one isn't available.
pub fn resolve(mode: TelemetryBackendMode) -> Result<BackendResolution> {
    match mode {
        TelemetryBackendMode::Strace => Ok(BackendResolution {
            backend: TelemetryBackendKind::Strace,
            degraded: None,
        }),
        TelemetryBackendMode::Ebpf => {
            ebpf_availability().map_err(|err| {
                anyhow::anyhow!(
                    "eBPF telemetry backend was explicitly requested but is unavailable: {err}"
                )
            })?;
            Ok(BackendResolution {
                backend: TelemetryBackendKind::Ebpf,
                degraded: None,
            })
        }
        TelemetryBackendMode::Auto => match ebpf_availability() {
            Ok(()) => Ok(BackendResolution {
                backend: TelemetryBackendKind::Ebpf,
                degraded: None,
            }),
            Err(err) => Ok(BackendResolution {
                backend: TelemetryBackendKind::Strace,
                degraded: Some(format!(
                    "eBPF telemetry backend unavailable, falling back to strace: {err}"
                )),
            }),
        },
    }
}

fn ebpf_availability() -> Result<()> {
    crate::behaviour::ebpf_verify::locate_and_verify_helper()?;
    if !LIVE_EBPF_COLLECTION_IMPLEMENTED {
        bail!(
            "eBPF helper identity verified, but live telemetry collection is not yet wired into this build"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_known_modes_case_insensitively() {
        assert_eq!(
            TelemetryBackendMode::parse("AUTO").unwrap(),
            TelemetryBackendMode::Auto
        );
        assert_eq!(
            TelemetryBackendMode::parse("Strace").unwrap(),
            TelemetryBackendMode::Strace
        );
        assert_eq!(
            TelemetryBackendMode::parse("ebpf").unwrap(),
            TelemetryBackendMode::Ebpf
        );
    }

    #[test]
    fn rejects_unknown_mode() {
        assert!(TelemetryBackendMode::parse("bogus").is_err());
    }

    #[test]
    fn strace_mode_always_resolves() {
        let resolution = resolve(TelemetryBackendMode::Strace).unwrap();
        assert_eq!(resolution.backend, TelemetryBackendKind::Strace);
        assert!(resolution.degraded.is_none());
    }

    #[test]
    fn explicit_ebpf_hard_fails_when_helper_unavailable() {
        // No helper is installed in the test environment (and the embedded
        // manifest's placeholder sha256 is unsatisfiable by design until a
        // release pipeline populates it), so this must be a hard error, not
        // a silent fallback.
        let err = resolve(TelemetryBackendMode::Ebpf).unwrap_err();
        assert!(err.to_string().contains("explicitly requested"));
    }

    #[test]
    fn auto_mode_falls_back_visibly_when_helper_unavailable() {
        let resolution = resolve(TelemetryBackendMode::Auto).unwrap();
        assert_eq!(resolution.backend, TelemetryBackendKind::Strace);
        assert!(resolution.degraded.is_some());
    }
}
