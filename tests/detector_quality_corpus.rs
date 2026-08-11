use std::process::Command;

#[test]
fn test_detector_quality_corpus_manifest_validity() {
    let manifest_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("detector_quality")
        .join("manifest.json");

    assert!(
        manifest_path.exists(),
        "tests/detector_quality/manifest.json must exist"
    );

    let content = std::fs::read_to_string(&manifest_path).expect("Failed to read manifest.json");
    let json: serde_json::Value =
        serde_json::from_str(&content).expect("manifest.json must be valid JSON");

    assert_eq!(json["version"], 1);
    let fixtures = json["fixtures"]
        .as_array()
        .expect("fixtures must be an array");
    assert!(
        fixtures.len() >= 8,
        "Manifest must contain fixtures for all required categories"
    );

    let required_categories = [
        "positive_block",
        "positive_warn",
        "negative_benign",
        "ambiguous_expected_warn",
        "correlation_positive",
        "evasion_variant",
        "redaction",
        "coverage_incomplete",
    ];

    for cat in required_categories {
        assert!(
            fixtures.iter().any(|f| f["category"] == cat),
            "Manifest must contain at least one fixture for category '{cat}'"
        );
    }
}

#[test]
fn test_detector_quality_runner_execution() {
    let manifest_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("detector_quality")
        .join("manifest.json");
    let script_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join("corpus")
        .join("detector-quality-gate.py");
    let binary_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("debug")
        .join("layerfault");

    if !binary_path.exists() {
        eprintln!("SKIP: target/debug/layerfault binary not built yet");
        return;
    }

    let output = Command::new("python3")
        .arg(&script_path)
        .arg("--binary")
        .arg(&binary_path)
        .arg("--manifest")
        .arg(&manifest_path)
        .arg("--json")
        .output()
        .expect("Failed to execute detector-quality-gate.py");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "detector-quality-gate.py failed.\nStdout: {stdout}\nStderr: {stderr}"
    );

    let report: serde_json::Value =
        serde_json::from_str(&stdout).expect("Runner stdout must be valid JSON");
    assert_eq!(
        report["failed"], 0,
        "Detector quality gate reported failed test cases"
    );
}
