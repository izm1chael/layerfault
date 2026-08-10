//! Normalized dependency record shape shared by every manifest/lockfile parser.
//!
//! Parsing is deliberately separate from risk classification: this module only
//! describes what a manifest declares. [`super::risk`] decides what, if
//! anything, is worth a finding.

use crate::finding_evidence::EvidenceLocation;

/// The packaging ecosystem a dependency declaration was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DependencyEcosystem {
    Pip,
    Poetry,
    Pdm,
    Uv,
    Conda,
    WheelMetadata,
}

/// Where a declared dependency's content would actually come from.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum DependencySource {
    /// A package index (PyPI or an alternate/extra index).
    Registry {
        index_url: Option<String>,
        extra_index: bool,
    },
    /// A direct URL to a wheel/sdist, optionally hash-verified.
    DirectUrl { url: String, has_hash: bool },
    /// A version-control-system dependency.
    Vcs {
        vcs: String,
        url: String,
        reference: Option<String>,
        is_full_commit_sha: bool,
    },
    /// A local filesystem path, editable or not.
    LocalPath {
        path: String,
        editable: bool,
        escapes_root: bool,
    },
    /// Present but not classifiable into one of the above without inventing
    /// structure the manifest did not declare.
    Unresolved { raw: String },
}

/// One normalized dependency declaration.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize)]
pub struct DependencyRecord {
    pub name: Option<String>,
    pub raw_requirement: String,
    pub ecosystem: Option<DependencyEcosystem>,
    pub source: Option<DependencySource>,
    pub version_constraint: Option<String>,
    pub is_floating: bool,
    pub has_hash_pin: bool,
    pub extras: Vec<String>,
    pub markers: Option<String>,
    pub location: Option<EvidenceLocation>,
    pub declared_in: String,
}

impl DependencyRecord {
    pub fn new(declared_in: &str, raw_requirement: &str) -> Self {
        Self {
            declared_in: declared_in.to_owned(),
            // Any URL embedded in the raw text is credential-redacted up
            // front, since this string is retained verbatim as finding
            // evidence (see `super::risk::classify`).
            raw_requirement: super::risk::redact_userinfo(raw_requirement),
            ..Self::default()
        }
    }
}
