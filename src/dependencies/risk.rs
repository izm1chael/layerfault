//! Shared classification helpers used by every dependency-manifest parser.
//!
//! Layerfault never contacts a registry, VCS host or index: everything here is
//! a syntactic judgement about what a manifest *declares*, not what currently
//! resolves.

use super::types::{DependencyRecord, DependencySource};
use crate::finding_evidence::{config_value, source_excerpt, EvidenceLocation, FindingEvidence};
use crate::scanner::{Confidence, ScanStatus};

/// A URL reduced to the parts safe to retain as evidence: scheme, host, path.
/// Userinfo and query parameters likely to carry tokens are stripped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedUrl {
    pub normalized: String,
    pub scheme: String,
    pub host: Option<String>,
    pub is_plaintext_http: bool,
    pub is_localhost_or_file: bool,
}

/// Normalize a URL for evidence: strip userinfo/query, classify transport.
///
/// This never resolves DNS or performs a request; it is pure string parsing.
pub fn redact_url(raw: &str) -> RedactedUrl {
    let raw = raw.trim();
    let (scheme, rest) = match raw.split_once("://") {
        Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
        None => {
            return RedactedUrl {
                normalized: sanitize_component(raw),
                scheme: String::new(),
                host: None,
                is_plaintext_http: false,
                is_localhost_or_file: raw.starts_with('/') || raw.starts_with("file:"),
            };
        }
    };

    // Strip fragment and query (queries commonly carry tokens/signatures).
    let rest = rest.split('#').next().unwrap_or(rest);
    let path_start = rest.find('/').unwrap_or(rest.len());
    let (authority, path) = rest.split_at(path_start);
    let path = path.split('?').next().unwrap_or(path);

    // Strip userinfo (`user:pass@host`).
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = host_port.split(':').next().unwrap_or(host_port);
    let host_lower = host.to_ascii_lowercase();

    let is_localhost = matches!(host_lower.as_str(), "localhost" | "127.0.0.1" | "::1")
        || host_lower.is_empty()
        || scheme == "file";
    let is_plaintext_http = scheme == "http";

    let normalized = if host_lower.is_empty() {
        format!("{scheme}://{}", sanitize_component(path))
    } else {
        format!("{scheme}://{}{}", host_lower, sanitize_component(path))
    };

    RedactedUrl {
        normalized,
        scheme,
        host: if host_lower.is_empty() {
            None
        } else {
            Some(host_lower)
        },
        is_plaintext_http,
        is_localhost_or_file: is_localhost,
    }
}

fn sanitize_component(value: &str) -> String {
    crate::finding_evidence::sanitize_text(value)
}

/// Strip `user:pass@`/`user@` userinfo out of any URL embedded in free-form
/// manifest text, so raw requirement/lockfile text retained as evidence never
/// carries credentials even when the URL sits inside a larger line.
pub fn redact_userinfo(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(scheme_idx) = rest.find("://") {
        let (before, after_scheme) = rest.split_at(scheme_idx + 3);
        out.push_str(before);
        let authority_end = after_scheme
            .find(|c: char| c == '/' || c.is_whitespace())
            .unwrap_or(after_scheme.len());
        let (authority, remainder) = after_scheme.split_at(authority_end);
        if let Some(at_idx) = authority.rfind('@') {
            out.push_str("<redacted>@");
            out.push_str(&authority[at_idx + 1..]);
        } else {
            out.push_str(authority);
        }
        rest = remainder;
    }
    out.push_str(rest);
    out
}

/// True when `value` is a 40-character hexadecimal string, i.e. a full Git
/// commit SHA rather than a branch/tag name that can be retargeted.
pub fn is_full_commit_sha(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Classify a local/editable dependency path. `escapes_root` is true when the
/// path is absolute, a `file://` URL, or contains a `..` traversal segment,
/// matching [`crate::safeio::validated_relative_path`]'s package-relative
/// containment rules.
pub fn classify_local_path(path: &str, editable: bool) -> DependencySource {
    let stripped = path.strip_prefix("file://").unwrap_or(path);
    let escapes_root = crate::safeio::validated_relative_path(stripped, true).is_err();
    DependencySource::LocalPath {
        path: sanitize_component(path),
        editable,
        escapes_root,
    }
}

/// True when a version constraint pins an exact version (`==`) rather than a
/// range/floating bound (`>=`, `~=`, absent, etc).
pub fn is_exact_pin(constraint: Option<&str>) -> bool {
    match constraint {
        Some(spec) => spec
            .split(',')
            .map(str::trim)
            .any(|clause| clause.starts_with("==") && !clause.contains('*')),
        None => false,
    }
}

/// A pending finding that [`super::mod@super`]'s orchestration turns into a
/// [`crate::scanner::LayerScanResult`] once it knows the finding's digest and
/// package-relative subject. Keeping this shape separate from `LayerScanResult`
/// lets classification stay pure and independently testable.
#[derive(Debug, Clone)]
pub struct RiskFinding {
    pub rule_id: &'static str,
    pub status: ScanStatus,
    pub confidence: Confidence,
    pub detail: String,
    pub evidence: Vec<FindingEvidence>,
}

/// Classify one dependency record into zero or more risk findings.
///
/// `subject` evidence carries the record's own location so every finding
/// points at the exact requirement/table entry that triggered it.
pub fn classify(
    record: &DependencyRecord,
    subject: &crate::finding_evidence::EvidenceSubject,
) -> Vec<RiskFinding> {
    let mut out = Vec::new();
    let evidence_at = |description: &str| -> FindingEvidence {
        let base = FindingEvidence::new(
            crate::finding_evidence::EvidenceKind::ConfigValue,
            subject.clone(),
            description,
        )
        .matched(&record.raw_requirement);
        match &record.location {
            Some(location) => base.at(location.clone()),
            None => base,
        }
    };

    if record.is_floating {
        out.push(RiskFinding {
            rule_id: "LF-DEP-FLOATING",
            status: ScanStatus::Warn,
            confidence: Confidence::Medium,
            detail: format!(
                "Dependency '{}' in '{}' has no exact version pin, hash or full VCS commit",
                record.name.as_deref().unwrap_or("<unnamed>"),
                record.declared_in
            ),
            evidence: vec![evidence_at("Unpinned dependency declaration")],
        });
    }

    match &record.source {
        Some(DependencySource::DirectUrl { url, has_hash }) => {
            let redacted = redact_url(url);
            out.push(RiskFinding {
                rule_id: "LF-DEP-DIRECT-URL",
                status: ScanStatus::Warn,
                confidence: Confidence::Medium,
                detail: format!(
                    "Dependency '{}' in '{}' is fetched from a direct URL rather than the configured index",
                    record.name.as_deref().unwrap_or("<unnamed>"),
                    record.declared_in
                ),
                evidence: vec![evidence_at("Direct URL dependency source").structured(
                    serde_json::json!({ "url": redacted.normalized, "has_hash": has_hash }),
                )],
            });
            if redacted.is_plaintext_http || redacted.is_localhost_or_file {
                out.push(RiskFinding {
                    rule_id: "LF-DEP-INSECURE-TRANSPORT",
                    status: ScanStatus::Warn,
                    confidence: Confidence::High,
                    detail: format!(
                        "Dependency '{}' in '{}' is fetched over a non-HTTPS or local transport",
                        record.name.as_deref().unwrap_or("<unnamed>"),
                        record.declared_in
                    ),
                    evidence: vec![evidence_at("Insecure transport for dependency source")
                        .structured(serde_json::json!({ "url": redacted.normalized }))],
                });
            }
        }
        Some(DependencySource::Vcs {
            vcs,
            url,
            reference,
            is_full_commit_sha,
        }) => {
            let rule_id = if *is_full_commit_sha {
                "LF-DEP-VCS"
            } else {
                "LF-DEP-VCS-MUTABLE-REF"
            };
            let redacted = redact_url(url);
            out.push(RiskFinding {
                rule_id,
                status: ScanStatus::Warn,
                confidence: Confidence::Medium,
                detail: format!(
                    "Dependency '{}' in '{}' is a {vcs} dependency{}",
                    record.name.as_deref().unwrap_or("<unnamed>"),
                    record.declared_in,
                    if *is_full_commit_sha {
                        " pinned to a full commit".to_owned()
                    } else {
                        format!(
                            " pinned to a mutable reference ('{}')",
                            reference.as_deref().unwrap_or("<none>")
                        )
                    }
                ),
                evidence: vec![evidence_at("VCS dependency source").structured(
                    serde_json::json!({
                        "vcs": vcs,
                        "url": redacted.normalized,
                        "reference": reference,
                        "is_full_commit_sha": is_full_commit_sha,
                    }),
                )],
            });
        }
        Some(DependencySource::LocalPath {
            path,
            editable,
            escapes_root,
        }) => {
            if *escapes_root {
                out.push(RiskFinding {
                    rule_id: "LF-DEP-PATH-ESCAPE",
                    status: ScanStatus::Fail,
                    confidence: Confidence::High,
                    detail: format!(
                        "Local/editable dependency '{}' in '{}' resolves outside the declaring manifest's directory tree",
                        path, record.declared_in
                    ),
                    evidence: vec![evidence_at("Local dependency path escapes containment root")
                        .structured(serde_json::json!({ "path": path, "editable": editable }))],
                });
            } else {
                out.push(RiskFinding {
                    rule_id: "LF-DEP-LOCAL-PATH",
                    status: ScanStatus::Warn,
                    confidence: Confidence::Low,
                    detail: format!(
                        "Dependency '{}' in '{}' is a local/editable path dependency",
                        path, record.declared_in
                    ),
                    evidence: vec![evidence_at("Local/editable dependency source")
                        .structured(serde_json::json!({ "path": path, "editable": editable }))],
                });
            }
        }
        _ => {}
    }

    out
}

/// A risk finding for an alternate/insecure package index or channel.
pub fn index_finding(
    declared_in: &str,
    subject: &crate::finding_evidence::EvidenceSubject,
    location: Option<EvidenceLocation>,
    raw_url: &str,
    label: &str,
) -> Vec<RiskFinding> {
    let redacted = redact_url(raw_url);
    let mut out = vec![RiskFinding {
        rule_id: "LF-DEP-ALT-INDEX",
        status: ScanStatus::Warn,
        confidence: Confidence::Medium,
        detail: format!("'{declared_in}' declares a {label} pointing away from the default index"),
        evidence: vec![config_value(
            subject.clone(),
            label,
            serde_json::Value::String(redacted.normalized.clone()),
            "Alternate package index/channel declared",
        )
        .at(location.clone().unwrap_or(EvidenceLocation::Metadata {
            key: label.to_owned(),
        }))],
    }];
    if redacted.is_plaintext_http || redacted.is_localhost_or_file {
        out.push(RiskFinding {
            rule_id: "LF-DEP-INSECURE-TRANSPORT",
            status: ScanStatus::Warn,
            confidence: Confidence::High,
            detail: format!(
                "'{declared_in}' declares a {label} over a non-HTTPS or local transport"
            ),
            evidence: vec![config_value(
                subject.clone(),
                label,
                serde_json::Value::String(redacted.normalized),
                "Insecure transport for package index/channel",
            )
            .at(location.unwrap_or(EvidenceLocation::Metadata {
                key: label.to_owned(),
            }))],
        });
    }
    out
}

/// A `--trusted-host`/explicit-HTTPS-bypass finding.
pub fn trusted_host_finding(
    declared_in: &str,
    subject: &crate::finding_evidence::EvidenceSubject,
    location: Option<EvidenceLocation>,
    host: &str,
) -> RiskFinding {
    RiskFinding {
        rule_id: "LF-DEP-INSECURE-TRANSPORT",
        status: ScanStatus::Warn,
        confidence: Confidence::High,
        detail: format!("'{declared_in}' declares --trusted-host for '{host}', bypassing certificate verification"),
        evidence: vec![source_excerpt(
            subject.clone(),
            location_line(&location),
            location_line(&location),
            host,
            &format!("--trusted-host {host}"),
        )],
    }
}

fn location_line(location: &Option<EvidenceLocation>) -> u64 {
    match location {
        Some(EvidenceLocation::Text { line_start, .. }) => *line_start,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_userinfo_and_query() {
        let redacted = redact_url("https://user:token123@example.com/pkg.whl?sig=abc");
        assert_eq!(redacted.normalized, "https://example.com/pkg.whl");
        assert!(!redacted.normalized.contains("token123"));
        assert!(!redacted.is_plaintext_http);
    }

    #[test]
    fn flags_plaintext_http() {
        let redacted = redact_url("http://example.com/index");
        assert!(redacted.is_plaintext_http);
    }

    #[test]
    fn flags_localhost() {
        let redacted = redact_url("http://localhost:8080/simple");
        assert!(redacted.is_localhost_or_file);
    }

    #[test]
    fn full_sha_is_recognized() {
        assert!(is_full_commit_sha(&"a".repeat(40)));
        assert!(!is_full_commit_sha("main"));
        assert!(!is_full_commit_sha(&"a".repeat(7)));
    }

    #[test]
    fn path_escape_is_detected() {
        let source = classify_local_path("../sibling", true);
        assert!(matches!(
            source,
            DependencySource::LocalPath {
                escapes_root: true,
                ..
            }
        ));
        let source = classify_local_path("vendor/pkg", false);
        assert!(matches!(
            source,
            DependencySource::LocalPath {
                escapes_root: false,
                ..
            }
        ));
    }

    #[test]
    fn exact_pin_detection() {
        assert!(is_exact_pin(Some("==1.2.3")));
        assert!(!is_exact_pin(Some(">=1.2")));
        assert!(!is_exact_pin(None));
    }
}
