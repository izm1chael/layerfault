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
fn pipeline_jsonl_round_trips_and_matches_json_finding_count() {
    let path = std::env::temp_dir().join(format!(
        "layerfault-jsonl-clean-{}.safetensors",
        std::process::id()
    ));
    write_safetensors(&path);

    let jsonl_output = Command::new(env!("CARGO_BIN_EXE_layerfault"))
        .args(["pipeline", path.to_str().unwrap(), "--jsonl"])
        .output()
        .unwrap();
    assert!(
        jsonl_output.status.success(),
        "{}",
        String::from_utf8_lossy(&jsonl_output.stderr)
    );
    let stdout = String::from_utf8(jsonl_output.stdout).unwrap();

    let lines: Vec<Value> = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("every line must parse as JSON"))
        .collect();
    assert!(!lines.is_empty(), "expected at least a header/footer");

    let kinds: Vec<&str> = lines
        .iter()
        .map(|line| line["kind"].as_str().expect("every record has a kind"))
        .collect();
    assert_eq!(kinds.first(), Some(&"scan_header"));
    assert_eq!(kinds.last(), Some(&"scan_footer"));
    let known = [
        "scan_header",
        "subject",
        "finding",
        "correlation",
        "coverage",
        "scan_footer",
    ];
    for kind in &kinds {
        assert!(known.contains(kind), "unrecognized record kind '{kind}'");
    }

    let jsonl_finding_count = kinds.iter().filter(|kind| **kind == "finding").count();

    let json_output = Command::new(env!("CARGO_BIN_EXE_layerfault"))
        .args(["pipeline", path.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(json_output.status.success());
    let json_doc: Value = serde_json::from_slice(&json_output.stdout).unwrap();
    let json_finding_count = json_doc["findings"].as_array().unwrap().len();

    assert_eq!(
        jsonl_finding_count, json_finding_count,
        "jsonl and json emission must agree on finding count for the same scan"
    );

    let _ = fs::remove_file(path);
}

#[test]
fn pipeline_jsonl_preserves_blocking_exit_code() {
    let root = std::env::temp_dir().join(format!("layerfault-jsonl-unsafe-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("model.pkl"), [0x80_u8, 4, 1, 2]).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_layerfault"))
        .args(["pipeline", root.to_str().unwrap(), "--jsonl"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<Value> = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let footer = lines.last().expect("expected a scan_footer line");
    assert_eq!(footer["kind"], "scan_footer");
    assert_eq!(footer["exit_code"], 3);
    assert!(lines
        .iter()
        .any(|line| line["kind"] == "finding" && line["rule_id"] == "LF-PICKLE-MALFORMED"));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn json_and_jsonl_flags_conflict() {
    let path = std::env::temp_dir().join(format!(
        "layerfault-jsonl-conflict-{}.safetensors",
        std::process::id()
    ));
    write_safetensors(&path);
    let output = Command::new(env!("CARGO_BIN_EXE_layerfault"))
        .args(["pipeline", path.to_str().unwrap(), "--json", "--jsonl"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let _ = fs::remove_file(path);
}
