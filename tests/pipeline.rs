use serde_json::Value;
use std::fs;
use std::process::Command;

fn write_safetensors(path: &std::path::Path) {
    let header = br#"{"weight":{"dtype":"U8","shape":[4],"data_offsets":[0,4]}}"#;
    let mut bytes = (header.len() as u64).to_le_bytes().to_vec();
    bytes.extend_from_slice(header);
    bytes.extend_from_slice(&[0, 0, 0, 0]);
    fs::write(path, bytes).unwrap();
}

#[test]
fn pipeline_json_reports_clean_artifact_and_risk_shape() {
    let path = std::env::temp_dir().join(format!(
        "layerfault-pipeline-clean-{}.safetensors",
        std::process::id()
    ));
    write_safetensors(&path);
    let output = Command::new(env!("CARGO_BIN_EXE_layerfault"))
        .args(["pipeline", path.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["decision"], "PASS");
    assert_eq!(value["coverage"]["complete"], true);
    assert_eq!(value["coverage"]["files_discovered"], 1);
    assert_eq!(value["coverage"]["files_scanned"], 1);
    assert!(value.get("merkle_identity").is_none());
    assert!(value["findings"]
        .as_array()
        .unwrap()
        .iter()
        .all(|finding| finding["risk"].is_object()));
    assert!(value["findings"]
        .as_array()
        .unwrap()
        .iter()
        .all(|finding| finding["severity"].is_string()));
    let _ = fs::remove_file(path);
}

#[test]
fn pipeline_unknown_artifact_reports_incomplete_coverage() {
    let path = std::env::temp_dir().join(format!(
        "layerfault-pipeline-unknown-{}.blob",
        std::process::id()
    ));
    fs::write(&path, b"opaque artifact bytes").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_layerfault"))
        .args(["pipeline", path.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["coverage"]["complete"], false);
    assert_eq!(value["coverage"]["files_discovered"], 1);
    assert_eq!(value["coverage"]["files_scanned"], 0);
    assert_eq!(value["coverage"]["omitted"], 1);
    assert!(value["coverage"]["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason.as_str().unwrap().contains("no structural parser")));
    let _ = fs::remove_file(path);
}

#[test]
fn pipeline_preserves_blocking_exit_for_unsafe_serialization() {
    let root =
        std::env::temp_dir().join(format!("layerfault-pipeline-unsafe-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("model.pkl"), [0x80_u8, 4, 1, 2]).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_layerfault"))
        .args(["pipeline", root.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["decision"], "BLOCK");
    assert_eq!(value["coverage"]["complete"], true);
    assert!(value["coverage"]["files_scanned"].as_u64().unwrap() >= 1);
    assert!(value["merkle_identity"]
        .as_str()
        .is_some_and(|identity| identity.starts_with("lfpkg:v2:sha256:")));
    assert!(value["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|finding| finding["rule_id"] == "LF-PICKLE-MALFORMED"));
    assert!(value["findings"]
        .as_array()
        .unwrap()
        .iter()
        .all(|finding| finding["severity"].is_string()));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn finding_json_omits_severity_deserializes_to_unspecified() {
    // Legacy pipeline JSON captured before severity existed must still load,
    // and must never have a severity inferred from status.
    let legacy = serde_json::json!({
        "layer_digest": "sha256:deadbeef",
        "media_type": "application/octet-stream",
        "check_type": "ScanError",
        "status": "Fail",
        "finding_class": "Informational",
        "confidence": "Medium",
        "detail": null,
        "matches": [],
        "duration_ms": 0
    });
    let finding: layerfault::scanner::LayerScanResult = serde_json::from_value(legacy).unwrap();
    assert_eq!(finding.severity, layerfault::scanner::Severity::Unspecified);
}

#[test]
fn finding_severity_round_trips_through_json() {
    let finding = layerfault::scanner::LayerScanResult {
        severity: layerfault::scanner::Severity::Critical,
        ..Default::default()
    };
    let value = serde_json::to_value(&finding).unwrap();
    assert_eq!(value["severity"], "CRITICAL");
    let back: layerfault::scanner::LayerScanResult = serde_json::from_value(value).unwrap();
    assert_eq!(back.severity, layerfault::scanner::Severity::Critical);
}
