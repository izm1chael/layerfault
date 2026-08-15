//! Evidence quality gate.
//!
//! This is the mechanism described in the evidence-upgrade brief: an
//! automated check that fails the build if a detector rule is introduced
//! without a declared evidence strategy or explanation. It has two halves:
//!
//! 1. Every rule declared in `layerfault::rules::RULES` (plus the data-driven
//!    heuristic signature family) must have a complete `explain::lookup`
//!    entry with non-empty `why_it_matters` and `limitations` — the two
//!    fields that keep a detected capability from being overstated into
//!    proven malicious behaviour.
//! 2. Every rule-id string literal actually emitted by a detector in `src/`
//!    must be a member of the registry, so a new detector cannot ship an
//!    unregistered, undeclared rule. This is a source-level scan run at test
//!    time (not a proc-macro or build-time lint), which is the practical way
//!    to keep a "did every new detector register itself" check honest without
//!    hand-maintaining a duplicate list.

use std::collections::BTreeSet;
use std::path::Path;

/// Files that define or explain rule identities rather than emit findings.
/// Rule-id literals inside these are the registry/explanation tables
/// themselves, not detector emission sites, and would otherwise self-flag.
const NON_EMITTING_FILES: &[&str] = &["src/rules.rs", "src/explain.rs"];

/// Sentinel/example rule-id strings that appear only in tests or docs and are
/// intentionally not registered.
const KNOWN_NON_RULE_SENTINELS: &[&str] = &[
    "LF-TEST",
    "LF-UNRECOGNIZED",
    "LF-NOT-A-REAL-RULE",
    "LF-UNCLASSIFIED",
    // Data-quality diagnostics and mapping identities, not emitted findings.
    "LF-BAD-CVE",
    "LF-DUPLICATE",
    "LF-EXACT",
    "LF-NO-MAPPING",
];

fn collect_rule_literals(root: &Path) -> BTreeSet<String> {
    let pattern = regex::Regex::new(r#""((?:LF|T\d+)-[A-Z0-9-]+)""#).expect("valid regex");
    let mut found = BTreeSet::new();
    for entry in walk_rust_files(root) {
        let relative = entry
            .strip_prefix(root)
            .unwrap_or(&entry)
            .to_string_lossy()
            .replace('\\', "/");
        if NON_EMITTING_FILES.iter().any(|skip| relative == *skip) {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&entry) else {
            continue;
        };
        for capture in pattern.captures_iter(&content) {
            found.insert(capture[1].to_owned());
        }
    }
    found
}

fn walk_rust_files(root: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }
    out
}

/// Every rule declared in the registry has a complete explanation, including
/// `why_it_matters` and `limitations` so a detected capability is never
/// silently overstated into proven behaviour.
#[test]
fn every_registered_rule_has_a_complete_explanation() {
    let mut missing = Vec::new();
    for rule_id in layerfault::rules::all_rule_ids() {
        match layerfault::explain::lookup(&rule_id) {
            None => missing.push(format!("{rule_id}: no explain::lookup entry")),
            Some(explanation) => {
                if explanation.rule_version == 0 {
                    missing.push(format!("{rule_id}: rule_version must be >= 1"));
                }
                if explanation.detector_family.trim().is_empty() {
                    missing.push(format!("{rule_id}: empty detector_family"));
                }
                if explanation.why_it_matters.trim().is_empty() {
                    missing.push(format!("{rule_id}: empty why_it_matters"));
                }
                if explanation.limitations.trim().is_empty() {
                    missing.push(format!("{rule_id}: empty limitations"));
                }
            }
        }
    }
    assert!(
        missing.is_empty(),
        "every registered rule must have a complete explanation:\n{}",
        missing.join("\n")
    );
}

/// Every rule-id string literal that appears in a detector source file must
/// be declared in the registry (or be a heuristic signature, which resolves
/// through the signature table instead). This is what stops a new detector
/// from shipping without an evidence strategy.
#[test]
fn every_emitted_rule_is_registered() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src = root.join("src");
    let literals = collect_rule_literals(&src);

    let mut unregistered = Vec::new();
    for literal in &literals {
        // A literal ending in `-` is a `starts_with("LF-FOO-")`-style prefix
        // guard (used throughout explain.rs's why_it_matters/limitations
        // fallbacks), not an emitted rule id.
        if literal.ends_with('-') {
            continue;
        }
        // Correlation identities (src/correlate.rs) are a distinct namespace
        // from finding rule ids — see FindingCorrelation::id — and are
        // exercised by correlate.rs's own tests instead.
        if literal.starts_with("LF-CORR-") {
            continue;
        }
        if KNOWN_NON_RULE_SENTINELS.contains(&literal.as_str()) {
            continue;
        }
        if layerfault::rules::spec(literal).is_some() {
            continue;
        }
        unregistered.push(literal.clone());
    }
    assert!(
        unregistered.is_empty(),
        "rule id(s) emitted in src/ but not declared in layerfault::rules::RULES \
         (add them with an explicit evidence requirement in src/rules.rs, or add \
         a sentinel to KNOWN_NON_RULE_SENTINELS in this test if it is not a rule id):\n{}",
        unregistered.join("\n")
    );
}
