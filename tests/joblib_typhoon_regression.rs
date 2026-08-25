//! Regression test for a real-world Joblib member that used to be reported
//! opaque/incomplete: `euler314/typhoon-predict`'s pinned revision
//! `6a45b1665c6ebefa9b87e06043624ba8f7bfbe37`,
//! `models/trackformer_1_2/trackformer_1_2_ocean_structure.joblib`.
//!
//! This file is a pickled `sklearn.linear_model.Ridge` ensemble whose
//! coefficient/intercept arrays are Joblib `NumpyArrayWrapper`s written with
//! `allow_mmap=True`: raw contiguous array bytes (padding-marker byte, then
//! alignment padding, then the payload) directly in the stream, not a
//! `.npy`-formatted region. The fixture is committed verbatim (47416 bytes)
//! so this regression is pinned to the exact real bytes that surfaced the
//! gap, not a synthetic approximation of them.

use serde_json::Value;
use std::path::Path;
use std::process::Command;

#[test]
fn typhoon_ocean_structure_joblib_has_no_opaque_array_coverage_gap() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/corpus/pickle/typhoon_trackformer_1_2_ocean_structure.joblib");
    assert!(fixture.exists(), "fixture missing: {}", fixture.display());

    let output = Command::new(env!("CARGO_BIN_EXE_layerfault"))
        .args(["inspect", fixture.to_str().unwrap(), "--json"])
        .output()
        .expect("run layerfault inspect");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|err| panic!("invalid JSON output: {err}\nstdout: {stdout}"));
    let results = report["results"].as_array().expect("results array");

    let rule_ids: Vec<&str> = results
        .iter()
        .map(|r| r["rule_id"].as_str().unwrap_or_default())
        .collect();

    assert!(
        !rule_ids.contains(&"LF-PICKLE-OPAQUE-COMPRESSED"),
        "raw NumPy array regions should be structurally resolved, not left opaque: {rule_ids:?}"
    );
    assert!(
        !rule_ids.contains(&"LF-PICKLE-MALFORMED"),
        "a genuinely valid Joblib stream must not be reported malformed: {rule_ids:?}"
    );

    // The one expected finding: an unrecognized (but non-dangerous) sklearn
    // constructor. This is a real, correct WARN unrelated to array-region
    // coverage and must remain visible.
    assert!(
        rule_ids.contains(&"LF-PICKLE-UNKNOWN-GLOBAL"),
        "expected the known sklearn.linear_model._ridge.Ridge unknown-global finding: {rule_ids:?}"
    );

    let unknown_global = results
        .iter()
        .find(|r| r["rule_id"] == "LF-PICKLE-UNKNOWN-GLOBAL")
        .expect("the sklearn unknown-global finding");
    assert_eq!(
        unknown_global["status"], "Warn",
        "unknown-global finding should be a WARN, not escalated: {unknown_global:?}"
    );

    assert_eq!(
        output.status.code(),
        Some(1),
        "expected WARN-only exit code 1 (unknown-global), got {:?}\nstdout: {stdout}",
        output.status.code()
    );
}
