//! Static command/package identity for MCP server launch commands.
//!
//! `{"command": "npx", "args": ["-y", "@some/mcp-server"]}` hashes its
//! arguments as part of its identity, but that answers no security question on
//! its own: it says nothing about whether the launch command would fetch
//! unpinned code from a registry at connection time. This module answers
//! that question from the static configuration alone — no package registry
//! is queried and no command is ever run.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageManagerKind {
    Npx,
    Bunx,
    PnpmDlx,
    YarnDlx,
    Uvx,
    PipxRun,
    Other,
}

impl PackageManagerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            PackageManagerKind::Npx => "npx",
            PackageManagerKind::Bunx => "bunx",
            PackageManagerKind::PnpmDlx => "pnpm dlx",
            PackageManagerKind::YarnDlx => "yarn dlx",
            PackageManagerKind::Uvx => "uvx",
            PackageManagerKind::PipxRun => "pipx run",
            PackageManagerKind::Other => "other",
        }
    }
}

/// Static posture of an MCP server's launch command. Present only when the
/// command shape matches a recognised ad-hoc package runner; a plain
/// executable (a locally installed binary, an absolute path) has nothing to
/// report here and this is `None`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyChainPosture {
    pub package_manager: PackageManagerKind,
    /// The launcher fetches the package on demand from a registry rather
    /// than requiring it to be pre-installed (true for every
    /// `PackageManagerKind` this module currently recognises).
    pub auto_downloads: bool,
    /// The package specifier includes an exact, non-range version
    /// (`name@1.2.3`), not `latest`, a range, or no version at all.
    pub version_pinned: bool,
    /// An unqualified flag (`-y`/`--yes`) that causes the package manager to
    /// proceed without an interactive install confirmation.
    pub auto_confirm_flag_present: bool,
    /// SHA-256 identity of the bare package specifier as given in the
    /// launch arguments (e.g. `@some/mcp-server@1.2.3`). Like
    /// `McpServer::argument_sha256`, the raw specifier is deliberately
    /// excluded from serialized output — a launch argument can contain
    /// material as sensitive as a credential, even where it structurally
    /// resembles a package name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_spec_sha256: Option<String>,
}

/// Recognise an ad-hoc package-runner launch command and classify its
/// posture. Returns `None` for anything not matching a known launcher shape
/// — that is not evidence of safety, only that this module has nothing to
/// say about the command.
pub fn analyze(executable: Option<&str>, arguments: &[String]) -> Option<SupplyChainPosture> {
    let executable = executable?;
    let command_name = executable.rsplit(['/', '\\']).next().unwrap_or(executable);

    let (package_manager, spec_args): (PackageManagerKind, &[String]) = match command_name {
        "npx" => (PackageManagerKind::Npx, arguments),
        "bunx" => (PackageManagerKind::Bunx, arguments),
        "uvx" => (PackageManagerKind::Uvx, arguments),
        "pnpm" if arguments.first().map(String::as_str) == Some("dlx") => {
            (PackageManagerKind::PnpmDlx, &arguments[1..])
        }
        "yarn" if arguments.first().map(String::as_str) == Some("dlx") => {
            (PackageManagerKind::YarnDlx, &arguments[1..])
        }
        "pipx" if arguments.first().map(String::as_str) == Some("run") => {
            (PackageManagerKind::PipxRun, &arguments[1..])
        }
        _ => return None,
    };

    let auto_confirm_flag_present = arguments
        .iter()
        .any(|argument| argument == "-y" || argument == "--yes");

    let package_spec = spec_args
        .iter()
        .find(|argument| !argument.starts_with('-'))
        .cloned();

    let version_pinned = package_spec
        .as_deref()
        .is_some_and(|specifier| package_spec_has_exact_version(package_manager, specifier));
    let package_spec_sha256 = package_spec
        .as_deref()
        .map(|spec| format!("sha256:{}", hex::encode(Sha256::digest(spec.as_bytes()))));

    Some(SupplyChainPosture {
        package_manager,
        auto_downloads: true,
        version_pinned,
        auto_confirm_flag_present,
        package_spec_sha256,
    })
}

/// A package specifier pins an exact version when it carries an `@version`
/// suffix that is neither `latest`/`next`/a dist-tag-shaped word nor a
/// semver range. Scoped npm packages (`@scope/name@version`) have their
/// leading `@` skipped when locating the version separator.
fn package_spec_has_exact_version(manager: PackageManagerKind, spec: &str) -> bool {
    if matches!(
        manager,
        PackageManagerKind::Uvx | PackageManagerKind::PipxRun
    ) {
        let Some((name, version)) = spec.split_once("==") else {
            return false;
        };
        return !name.is_empty()
            && !version.is_empty()
            && !version.contains('*')
            && !version
                .chars()
                .any(|character| matches!(character, '<' | '>' | '~' | '^'));
    }
    let (name, rest) = if let Some(stripped) = spec.strip_prefix('@') {
        match stripped.split_once('@') {
            Some((scoped_name, version)) => (format!("@{scoped_name}"), Some(version)),
            None => (spec.to_owned(), None),
        }
    } else {
        match spec.split_once('@') {
            Some((name, version)) => (name.to_owned(), Some(version)),
            None => (spec.to_owned(), None),
        }
    };
    let _ = name;
    let Some(version) = rest else {
        return false;
    };
    if version.is_empty() || matches!(version, "latest" | "next" | "canary" | "beta" | "*") {
        return false;
    }
    let core = version.split(['-', '+']).next().unwrap_or(version);
    core.split('.').count() == 3
        && core
            .split('.')
            .all(|component| !component.is_empty() && component.chars().all(|c| c.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn npx_with_auto_confirm_and_unpinned_package_is_recognised() {
        let posture = analyze(
            Some("npx"),
            &[
                "-y".to_owned(),
                "@modelcontextprotocol/server-fs".to_owned(),
            ],
        )
        .expect("npx is a recognised launcher");
        assert_eq!(posture.package_manager, PackageManagerKind::Npx);
        assert!(posture.auto_downloads);
        assert!(posture.auto_confirm_flag_present);
        assert!(!posture.version_pinned);
        assert!(posture.package_spec_sha256.is_some());
    }

    #[test]
    fn npx_with_exact_pinned_version_is_not_flagged_unpinned() {
        let posture = analyze(
            Some("npx"),
            &[
                "-y".to_owned(),
                "@modelcontextprotocol/server-fs@1.4.2".to_owned(),
            ],
        )
        .unwrap();
        assert!(posture.version_pinned);
    }

    #[test]
    fn npx_at_latest_is_not_pinned() {
        let posture = analyze(Some("npx"), &["package@latest".to_owned()]).unwrap();
        assert!(!posture.version_pinned);
    }

    #[test]
    fn npx_with_semver_range_is_not_pinned() {
        let posture = analyze(Some("npx"), &["package@^1.2.0".to_owned()]).unwrap();
        assert!(!posture.version_pinned);
    }

    #[test]
    fn npm_dist_tag_is_not_mistaken_for_an_exact_version() {
        let posture = analyze(Some("npx"), &["package@beta".to_owned()]).unwrap();
        assert!(!posture.version_pinned);
    }

    #[test]
    fn python_runner_uses_pep_440_exact_pin_syntax() {
        assert!(
            analyze(Some("uvx"), &["package==1.2.3".to_owned()])
                .unwrap()
                .version_pinned
        );
        assert!(
            !analyze(
                Some("pipx"),
                &["run".to_owned(), "package@1.2.3".to_owned()]
            )
            .unwrap()
            .version_pinned
        );
    }

    #[test]
    fn pnpm_dlx_and_yarn_dlx_and_pipx_run_are_recognised() {
        assert_eq!(
            analyze(Some("pnpm"), &["dlx".to_owned(), "server".to_owned()])
                .unwrap()
                .package_manager,
            PackageManagerKind::PnpmDlx
        );
        assert_eq!(
            analyze(Some("yarn"), &["dlx".to_owned(), "server".to_owned()])
                .unwrap()
                .package_manager,
            PackageManagerKind::YarnDlx
        );
        assert_eq!(
            analyze(Some("pipx"), &["run".to_owned(), "server".to_owned()])
                .unwrap()
                .package_manager,
            PackageManagerKind::PipxRun
        );
    }

    #[test]
    fn plain_locally_installed_executable_is_not_a_supply_chain_launcher() {
        assert!(analyze(Some("/usr/local/bin/my-mcp-server"), &[]).is_none());
        assert!(analyze(Some("node"), &["server.js".to_owned()]).is_none());
    }

    #[test]
    fn absolute_path_to_npx_is_still_recognised_by_basename() {
        let posture = analyze(Some("/usr/bin/npx"), &["server".to_owned()]).unwrap();
        assert_eq!(posture.package_manager, PackageManagerKind::Npx);
    }
}
