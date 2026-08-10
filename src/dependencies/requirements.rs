//! Pip requirements-file syntax (`requirements.txt`, `requirements-*.txt`,
//! `requirements.lock`) parsed without shell execution or network access.
//!
//! Supports the pip syntax subset named in the spec: version specifiers,
//! extras, PEP 508 direct references, `git+`/`hg+`/`svn+`/`bzr+` VCS
//! references, `-e`/`--editable`, `-r`/`--requirement` and `-c`/`--constraint`
//! includes (bounded, cycle-safe, package-relative only), `--index-url`,
//! `--extra-index-url`, `--find-links`, `--trusted-host`, `--require-hashes`
//! and `--hash=`.

use super::limits::DependencyBudgetTracker;
use super::risk::{self, RiskFinding};
use super::types::{DependencyRecord, DependencySource};
use crate::coverage::Coverage;
use crate::finding_evidence::{EvidenceLocation, EvidenceSubject};
use std::path::Path;

pub struct RequirementsOutcome {
    pub records: Vec<DependencyRecord>,
    pub issues: Vec<RiskFinding>,
}

/// Parse one requirements-syntax file, following `-r`/`-c` includes.
pub fn parse_requirements_file(
    package_root: Option<&Path>,
    relative_path: &str,
    source: &str,
    tracker: &mut DependencyBudgetTracker,
    coverage: &mut Coverage,
) -> RequirementsOutcome {
    let mut outcome = RequirementsOutcome {
        records: Vec::new(),
        issues: Vec::new(),
    };
    parse_into(
        package_root,
        relative_path,
        source,
        tracker,
        coverage,
        &mut outcome,
    );
    outcome
}

fn parse_into(
    package_root: Option<&Path>,
    relative_path: &str,
    source: &str,
    tracker: &mut DependencyBudgetTracker,
    coverage: &mut Coverage,
    outcome: &mut RequirementsOutcome,
) {
    let subject = EvidenceSubject::member(relative_path);
    let mut last_record_index: Option<usize> = None;

    for (line_no, raw_line) in join_continuations(source) {
        if tracker.add_line().is_err() {
            coverage.parser_failure(&format!(
                "'{relative_path}' exceeded the bounded requirement-line count"
            ));
            break;
        }
        let line = strip_comment(&raw_line);
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let location = EvidenceLocation::Text {
            line_start: line_no,
            line_end: line_no,
            column_start: None,
            column_end: None,
        };

        if trimmed == "--require-hashes" {
            continue;
        }
        if let Some(value) = flag_value(trimmed, &["--hash"]) {
            if let Some(idx) = last_record_index {
                outcome.records[idx].has_hash_pin = true;
                outcome.records[idx].is_floating = false;
            }
            let _ = value;
            continue;
        }
        if let Some(value) = flag_value(trimmed, &["--index-url", "-i"]) {
            outcome.issues.extend(risk::index_finding(
                relative_path,
                &subject,
                Some(location.clone()),
                value,
                "--index-url",
            ));
            continue;
        }
        if let Some(value) = flag_value(trimmed, &["--extra-index-url"]) {
            outcome.issues.extend(risk::index_finding(
                relative_path,
                &subject,
                Some(location.clone()),
                value,
                "--extra-index-url",
            ));
            continue;
        }
        if let Some(value) = flag_value(trimmed, &["--find-links", "-f"]) {
            outcome.issues.extend(risk::index_finding(
                relative_path,
                &subject,
                Some(location.clone()),
                value,
                "--find-links",
            ));
            continue;
        }
        if let Some(value) = flag_value(trimmed, &["--trusted-host"]) {
            outcome.issues.push(risk::trusted_host_finding(
                relative_path,
                &subject,
                Some(location.clone()),
                value,
            ));
            continue;
        }
        if let Some(value) = flag_value(trimmed, &["-r", "--requirement"]) {
            resolve_include(
                package_root,
                relative_path,
                value,
                &location,
                &subject,
                tracker,
                coverage,
                outcome,
            );
            continue;
        }
        if let Some(value) = flag_value(trimmed, &["-c", "--constraint"]) {
            resolve_include(
                package_root,
                relative_path,
                value,
                &location,
                &subject,
                tracker,
                coverage,
                outcome,
            );
            continue;
        }
        if let Some(value) = flag_value(trimmed, &["-e", "--editable"]) {
            let mut record = DependencyRecord::new(relative_path, trimmed);
            record.location = Some(location);
            record.source = Some(classify_editable(value));
            apply_pin_state(&mut record, None);
            outcome.records.push(record);
            last_record_index = Some(outcome.records.len() - 1);
            continue;
        }
        if trimmed.starts_with('-') {
            // Unrecognized option; conservatively ignored rather than
            // misparsed as a requirement name.
            continue;
        }

        let (spec_text, inline_hash) = extract_inline_hashes(trimmed);
        let mut record = parse_requirement_line(&spec_text, relative_path);
        record.location = Some(location);
        if inline_hash {
            record.has_hash_pin = true;
            record.is_floating = false;
        }
        outcome.records.push(record);
        last_record_index = Some(outcome.records.len() - 1);
    }
}

/// Line continuations join a requirement and its `--hash=` options onto one
/// logical line (`package==1.0 --hash=sha256:...`). Strip any such inline
/// hash tokens before tokenizing the requirement spec itself.
fn extract_inline_hashes(line: &str) -> (String, bool) {
    let mut has_hash = false;
    let mut kept: Vec<&str> = Vec::new();
    for token in line.split_whitespace() {
        if token.starts_with("--hash=") {
            has_hash = true;
        } else {
            kept.push(token);
        }
    }
    (kept.join(" "), has_hash)
}

#[allow(clippy::too_many_arguments)]
fn resolve_include(
    package_root: Option<&Path>,
    including_file: &str,
    target: &str,
    location: &EvidenceLocation,
    subject: &EvidenceSubject,
    tracker: &mut DependencyBudgetTracker,
    coverage: &mut Coverage,
    outcome: &mut RequirementsOutcome,
) {
    let Some(joined) = join_relative(including_file, target) else {
        outcome.issues.push(RiskFinding {
            rule_id: "LF-DEP-PATH-ESCAPE",
            status: crate::scanner::ScanStatus::Fail,
            confidence: crate::scanner::Confidence::High,
            detail: format!(
                "'{including_file}' includes '{target}', which escapes the package directory tree"
            ),
            evidence: vec![crate::finding_evidence::source_excerpt(
                subject.clone(),
                location_line(location),
                location_line(location),
                target,
                target,
            )],
        });
        coverage.omit(
            1,
            &format!("include reference escapes the package root: '{target}'"),
            &[target.to_owned()],
        );
        return;
    };

    if let Err(reason) = tracker.enter_include(&joined) {
        outcome.issues.push(RiskFinding {
            rule_id: "LF-DEP-ANALYSIS-INCOMPLETE",
            status: crate::scanner::ScanStatus::Warn,
            confidence: crate::scanner::Confidence::Medium,
            detail: format!("'{including_file}' include chain was bounded: {reason}"),
            evidence: vec![crate::finding_evidence::coverage_gap(
                subject.clone(),
                &reason,
            )],
        });
        coverage.omit(1, &reason, &[joined]);
        return;
    }

    let Some(root) = package_root else {
        let reason = format!(
            "no package root available to resolve include '{joined}' declared in '{including_file}'"
        );
        outcome.issues.push(missing_include_finding(
            including_file,
            &joined,
            location,
            subject,
            &reason,
        ));
        coverage.omit(1, &reason, &[joined]);
        tracker.leave_include();
        return;
    };

    match crate::safeio::optional_regular_file_within(root, &joined, false) {
        Ok(Some(path)) => {
            let limits = tracker.limits.clone();
            match std::fs::File::open(&path).and_then(|file| {
                crate::safeio::read_all_from_file(&file, limits.max_manifest_bytes)
                    .map_err(std::io::Error::other)
            }) {
                Ok(bytes) => match std::str::from_utf8(&bytes) {
                    Ok(text) => {
                        parse_into(Some(root), &joined, text, tracker, coverage, outcome);
                    }
                    Err(_) => {
                        let reason = format!("include '{joined}' is not valid UTF-8 text");
                        coverage.parser_failure(&reason);
                        outcome.issues.push(RiskFinding {
                            rule_id: "LF-DEP-ANALYSIS-INCOMPLETE",
                            status: crate::scanner::ScanStatus::Warn,
                            confidence: crate::scanner::Confidence::Medium,
                            detail: reason.clone(),
                            evidence: vec![crate::finding_evidence::coverage_gap(
                                subject.clone(),
                                &reason,
                            )],
                        });
                    }
                },
                Err(_) => {
                    let reason = format!("include '{joined}' could not be safely read");
                    coverage.parser_failure(&reason);
                    outcome.issues.push(RiskFinding {
                        rule_id: "LF-DEP-ANALYSIS-INCOMPLETE",
                        status: crate::scanner::ScanStatus::Warn,
                        confidence: crate::scanner::Confidence::Medium,
                        detail: reason.clone(),
                        evidence: vec![crate::finding_evidence::coverage_gap(
                            subject.clone(),
                            &reason,
                        )],
                    });
                }
            }
        }
        Ok(None) => {
            let reason = format!("declared include not found: '{joined}'");
            outcome.issues.push(missing_include_finding(
                including_file,
                &joined,
                location,
                subject,
                &reason,
            ));
            coverage.omit(1, &reason, &[joined]);
        }
        Err(_) => {
            let reason = format!("include '{joined}' could not be safely opened");
            outcome.issues.push(missing_include_finding(
                including_file,
                &joined,
                location,
                subject,
                &reason,
            ));
            coverage.omit(1, &reason, &[joined]);
        }
    }
    tracker.leave_include();
}

fn missing_include_finding(
    including_file: &str,
    target: &str,
    location: &EvidenceLocation,
    subject: &EvidenceSubject,
    reason: &str,
) -> RiskFinding {
    RiskFinding {
        rule_id: "LF-DEP-INCLUDE-MISSING",
        status: crate::scanner::ScanStatus::Warn,
        confidence: crate::scanner::Confidence::Medium,
        detail: format!(
            "'{including_file}' references an include that Layerfault could not resolve: {reason}"
        ),
        evidence: vec![
            crate::finding_evidence::coverage_gap(subject.clone(), reason)
                .at(location.clone())
                .matched(target),
        ],
    }
}

fn location_line(location: &EvidenceLocation) -> u64 {
    match location {
        EvidenceLocation::Text { line_start, .. } => *line_start,
        _ => 0,
    }
}

/// Resolve `target` relative to the directory containing `including_file`,
/// collapsing `.`/`..` segments manually so escapes are caught before any
/// filesystem call. Returns `None` when the resolved path would leave the
/// package root.
fn join_relative(including_file: &str, target: &str) -> Option<String> {
    if target.starts_with('/') || target.contains("://") || target.contains('\\') {
        return None;
    }
    let mut components: Vec<&str> = including_file
        .rsplit_once('/')
        .map(|(dir, _)| dir.split('/').filter(|s| !s.is_empty()).collect())
        .unwrap_or_default();
    for segment in target.split('/') {
        match segment {
            "" | "." => continue,
            ".." => {
                components.pop()?;
            }
            other => components.push(other),
        }
    }
    if components.is_empty() {
        return None;
    }
    Some(components.join("/"))
}

/// Join backslash-continued physical lines, returning each logical line paired
/// with the 1-based line number it started on.
fn join_continuations(source: &str) -> Vec<(u64, String)> {
    let mut out = Vec::new();
    let mut buffer = String::new();
    let mut start_line: Option<u64> = None;
    for (index, raw) in source.lines().enumerate() {
        let line_no = index as u64 + 1;
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if start_line.is_none() {
            start_line = Some(line_no);
        }
        if let Some(stripped) = line.strip_suffix('\\') {
            buffer.push_str(stripped);
            continue;
        }
        buffer.push_str(line);
        out.push((start_line.unwrap_or(line_no), std::mem::take(&mut buffer)));
        start_line = None;
    }
    if !buffer.is_empty() {
        out.push((start_line.unwrap_or(1), buffer));
    }
    out
}

/// Strip a trailing comment. Only `#` preceded by whitespace (or at the very
/// start of the line) is treated as a comment start, so `#egg=name` URL
/// fragments are preserved.
fn strip_comment(line: &str) -> &str {
    if line.starts_with('#') {
        return "";
    }
    if let Some(idx) = line.find('#') {
        let prev = line.as_bytes().get(idx.wrapping_sub(1)).copied();
        if matches!(prev, Some(b' ') | Some(b'\t')) {
            return line[..idx].trim_end();
        }
    }
    line
}

/// Match a long or short flag written as `--flag=value`, `--flag value`, or
/// `--flag` (empty value).
fn flag_value<'a>(trimmed: &'a str, flags: &[&str]) -> Option<&'a str> {
    for flag in flags {
        if let Some(rest) = trimmed.strip_prefix(flag) {
            if let Some(value) = rest.strip_prefix('=') {
                return Some(value.trim());
            }
            if let Some(value) = rest.strip_prefix(' ') {
                return Some(value.trim());
            }
            if rest.is_empty() {
                return Some("");
            }
        }
    }
    None
}

fn classify_editable(target: &str) -> DependencySource {
    let (vcs_prefix, _) = detect_vcs_prefix(target);
    if vcs_prefix.is_some() {
        classify_url_source(target)
    } else {
        risk::classify_local_path(target, true)
    }
}

/// Parse one PEP 508-shaped requirement spec (used both for requirements-file
/// lines and for `pyproject.toml` dependency array entries).
pub(crate) fn parse_requirement_line(text: &str, declared_in: &str) -> DependencyRecord {
    let mut record = DependencyRecord::new(declared_in, text);

    let (main, markers) = match text.split_once(';') {
        Some((a, b)) => (a.trim(), Some(b.trim().to_owned())),
        None => (text.trim(), None),
    };
    record.markers = markers;

    if let Some((name_part, url_part)) = main.split_once('@') {
        let name_part = name_part.trim();
        let url_part = url_part.trim();
        if !name_part.is_empty() && !url_part.is_empty() && looks_like_reference(url_part) {
            let (name, extras) = parse_name_extras(name_part);
            record.name = Some(name);
            record.extras = extras;
            record.source = Some(classify_url_source(url_part));
            apply_pin_state(&mut record, None);
            return record;
        }
    }

    if looks_like_reference(main) {
        record.source = Some(classify_url_source(main));
        apply_pin_state(&mut record, None);
        return record;
    }

    if looks_like_local_path(main) {
        record.source = Some(risk::classify_local_path(main, false));
        apply_pin_state(&mut record, None);
        return record;
    }

    let (name_extras, constraint) = split_name_and_constraint(main);
    let (name, extras) = parse_name_extras(name_extras);
    record.name = Some(name);
    record.extras = extras;
    record.version_constraint = constraint.clone();
    record.source = Some(DependencySource::Registry {
        index_url: None,
        extra_index: false,
    });
    apply_pin_state(&mut record, constraint.as_deref());
    record
}

pub(crate) fn apply_pin_state(record: &mut DependencyRecord, constraint: Option<&str>) {
    let pinned = match &record.source {
        Some(DependencySource::Vcs {
            is_full_commit_sha, ..
        }) => *is_full_commit_sha,
        Some(DependencySource::DirectUrl { .. }) => true,
        Some(DependencySource::LocalPath { .. }) => true,
        _ => risk::is_exact_pin(constraint),
    };
    record.is_floating = !(pinned || record.has_hash_pin);
}

fn looks_like_reference(value: &str) -> bool {
    detect_vcs_prefix(value).0.is_some()
        || value.starts_with("https://")
        || value.starts_with("http://")
}

fn looks_like_local_path(value: &str) -> bool {
    value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with('/')
        || value.starts_with("file://")
}

fn detect_vcs_prefix(value: &str) -> (Option<&'static str>, &str) {
    for (prefix, vcs) in [
        ("git+", "git"),
        ("hg+", "hg"),
        ("svn+", "svn"),
        ("bzr+", "bzr"),
    ] {
        if let Some(rest) = value.strip_prefix(prefix) {
            return (Some(vcs), rest);
        }
    }
    (None, value)
}

fn classify_url_source(raw: &str) -> DependencySource {
    let (vcs, rest) = detect_vcs_prefix(raw);
    if let Some(vcs) = vcs {
        let without_fragment = rest.split('#').next().unwrap_or(rest);
        let (url, reference) = match without_fragment.rsplit_once('@') {
            Some((u, r)) if !u.is_empty() && !r.is_empty() && !u.ends_with('/') => {
                (u.to_owned(), Some(r.to_owned()))
            }
            _ => (without_fragment.to_owned(), None),
        };
        let is_full_commit_sha = reference
            .as_deref()
            .map(risk::is_full_commit_sha)
            .unwrap_or(false);
        return DependencySource::Vcs {
            vcs: vcs.to_owned(),
            url: risk::redact_url(&url).normalized,
            reference,
            is_full_commit_sha,
        };
    }
    let without_fragment = raw.split('#').next().unwrap_or(raw);
    let has_hash = raw.contains("#sha256=") || raw.contains("#md5=");
    DependencySource::DirectUrl {
        url: risk::redact_url(without_fragment).normalized,
        has_hash,
    }
}

fn split_name_and_constraint(main: &str) -> (&str, Option<String>) {
    const OPERATORS: [&str; 7] = ["===", "==", ">=", "<=", "~=", "!=", ">"];
    let mut best: Option<usize> = None;
    for op in OPERATORS {
        if let Some(idx) = main.find(op) {
            best = Some(best.map_or(idx, |current| current.min(idx)));
        }
    }
    // `<` alone must be checked last so it does not shadow `<=`.
    if let Some(idx) = main.find('<') {
        if !main[idx..].starts_with("<=") {
            best = Some(best.map_or(idx, |current| current.min(idx)));
        }
    }
    match best {
        Some(idx) => (main[..idx].trim(), Some(main[idx..].trim().to_owned())),
        None => (main.trim(), None),
    }
}

fn parse_name_extras(text: &str) -> (String, Vec<String>) {
    if let Some(open) = text.find('[') {
        if let Some(close) = text.find(']') {
            if close > open {
                let name = text[..open].trim().to_owned();
                let extras = text[open + 1..close]
                    .split(',')
                    .map(|s| s.trim().to_owned())
                    .filter(|s| !s.is_empty())
                    .collect();
                return (name, extras);
            }
        }
    }
    (text.trim().to_owned(), Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dependencies::limits::DependencyParseLimits;

    fn parse(source: &str) -> RequirementsOutcome {
        let mut tracker = DependencyBudgetTracker::new(DependencyParseLimits::default());
        let mut coverage = Coverage::complete(1, source.len() as u64);
        parse_requirements_file(
            None,
            "requirements.txt",
            source,
            &mut tracker,
            &mut coverage,
        )
    }

    #[test]
    fn exact_pin_is_not_floating() {
        let outcome = parse("package==1.2.3\n");
        assert_eq!(outcome.records.len(), 1);
        assert!(!outcome.records[0].is_floating);
    }

    #[test]
    fn bare_name_is_floating() {
        let outcome = parse("transformers\n");
        assert!(outcome.records[0].is_floating);
    }

    #[test]
    fn hash_pin_clears_floating() {
        let outcome = parse("package==1.2.3 \\\n    --hash=sha256:abc\n");
        assert!(outcome.records[0].has_hash_pin);
        assert!(!outcome.records[0].is_floating);
    }

    #[test]
    fn direct_url_with_hash_is_recorded() {
        let outcome = parse("name @ https://example.com/pkg.whl#sha256=deadbeef\n");
        assert!(matches!(
            &outcome.records[0].source,
            Some(DependencySource::DirectUrl { has_hash: true, .. })
        ));
    }

    #[test]
    fn git_full_commit_is_pinned() {
        let sha = "a".repeat(40);
        let outcome = parse(&format!("git+https://github.com/x/y.git@{sha}#egg=y\n"));
        assert!(matches!(
            &outcome.records[0].source,
            Some(DependencySource::Vcs {
                is_full_commit_sha: true,
                ..
            })
        ));
        assert!(!outcome.records[0].is_floating);
    }

    #[test]
    fn git_branch_is_mutable() {
        let outcome = parse("git+https://github.com/x/y.git@main#egg=y\n");
        assert!(matches!(
            &outcome.records[0].source,
            Some(DependencySource::Vcs {
                is_full_commit_sha: false,
                ..
            })
        ));
    }

    #[test]
    fn editable_local_escape_is_flagged() {
        let outcome = parse("-e ../sibling\n");
        assert!(matches!(
            &outcome.records[0].source,
            Some(DependencySource::LocalPath {
                escapes_root: true,
                ..
            })
        ));
    }

    #[test]
    fn index_url_is_recorded() {
        let outcome = parse("--index-url https://mirror.example.com/simple\n");
        assert!(outcome
            .issues
            .iter()
            .any(|issue| issue.rule_id == "LF-DEP-ALT-INDEX"));
    }

    #[test]
    fn plaintext_index_flags_insecure_transport() {
        let outcome = parse("--index-url http://mirror.example.com/simple\n");
        assert!(outcome
            .issues
            .iter()
            .any(|issue| issue.rule_id == "LF-DEP-INSECURE-TRANSPORT"));
    }

    #[test]
    fn missing_include_is_flagged() {
        let outcome = parse("-r missing.txt\n");
        assert!(outcome
            .issues
            .iter()
            .any(|issue| issue.rule_id == "LF-DEP-INCLUDE-MISSING"));
    }

    #[test]
    fn comment_lines_are_ignored() {
        let outcome = parse("# a comment\npackage==1.0\n");
        assert_eq!(outcome.records.len(), 1);
    }

    #[test]
    fn egg_fragment_is_not_treated_as_comment() {
        let outcome = parse("git+https://github.com/x/y.git#egg=y\n");
        assert_eq!(outcome.records.len(), 1);
    }
}
