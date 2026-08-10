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
    assert!(value["findings"]
        .as_array()
        .unwrap()
        .iter()
        .all(|finding| finding["risk"].is_object()));
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
    assert!(value["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|finding| finding["rule_id"] == "LF-PICKLE-MALFORMED"));
    let _ = fs::remove_dir_all(root);
}
