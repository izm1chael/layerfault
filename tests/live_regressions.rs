use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn temp_dir(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "layerfault-live-regression-{label}-{}",
        std::process::id()
    ))
}

fn write_safetensors(path: &Path) {
    let header = br#"{"weight":{"dtype":"U8","shape":[4],"data_offsets":[0,4]}}"#;
    let mut bytes = (header.len() as u64).to_le_bytes().to_vec();
    bytes.extend_from_slice(header);
    bytes.extend_from_slice(&[0, 0, 0, 0]);
    fs::write(path, bytes).expect("write Safetensors fixture");
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_layerfault"))
        .args(args)
        .output()
        .expect("run Layerfault")
}

#[test]
fn review_quick_exit_matches_clean_final_decision() {
    let root = temp_dir("review-clean");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("create package");
    write_safetensors(&root.join("model.safetensors"));

    let output = run(&[
        "review",
        root.to_str().unwrap(),
        "--profile",
        "quick",
        "--json",
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("review JSON");
    assert_eq!(value["final_decision"], "PASS");

    let _ = fs::remove_dir_all(root);
}

#[test]
fn review_quick_preserves_static_block_exit() {
    let root = temp_dir("review-block");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("create package");
    fs::write(root.join("model.pkl"), [0x80_u8, 4, 1, 2, 3])
        .expect("write unsafe serialization fixture");

    let output = run(&[
        "review",
        root.to_str().unwrap(),
        "--profile",
        "quick",
        "--json",
    ]);
    assert_eq!(
        output.status.code(),
        Some(3),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("review JSON");
    assert_eq!(value["final_decision"], "BLOCK");
    assert!(value["domains"]["behavioural_security"]["report"].is_null());
    assert!(value["domains"]["behavioural_security"]["not_run_reason"]
        .as_str()
        .is_some_and(|reason| reason.contains("static admission blocked")));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn dataset_poisoning_evidence_returns_warning_exit() {
    let root = temp_dir("dataset-review");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("create dataset");
    fs::write(
        root.join("train.jsonl"),
        "{\"text\":\"normal\",\"label\":\"ok\"}\n{\"text\":\"hidden\\u200btrigger\",\"label\":\"target\"}\n",
    )
    .expect("write dataset");

    let output = run(&[
        "dataset",
        "poisoning-review",
        root.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("dataset JSON");
    assert_eq!(value["state"], "REVIEW");
    assert!(value["indicators"].as_array().is_some_and(|items| items
        .iter()
        .any(|item| item["rule_id"] == "LF-DATASET-ZERO-WIDTH")));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn nested_compressed_joblib_blocks_at_cli_package_boundary() {
    let root = temp_dir("joblib-double-compression");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("create package");
    fs::write(
        root.join("exploit_double_compression.joblib.gz.bz2"),
        b"BZh91AY&SYbounded-fixture",
    )
    .expect("write compressed fixture");

    let output = run(&["inspect", root.to_str().unwrap(), "--json"]);
    assert_eq!(output.status.code(), Some(3));
    let value: Value = serde_json::from_slice(&output.stdout).expect("inspect JSON");
    assert!(value["findings"]
        .as_array()
        .is_some_and(|items| items
            .iter()
            .any(|item| item["matches"]
                .as_array()
                .is_some_and(|matches| matches.iter().any(|m| {
                    m.as_str()
                        .is_some_and(|text| text.contains("LF-SERIALIZATION-UNSAFE"))
                })))));

    let _ = fs::remove_dir_all(root);
}
