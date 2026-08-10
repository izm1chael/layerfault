use layerfault::scanner::{HeuristicsScanner, ScanStatus};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

struct TempStore {
    root: PathBuf,
}

impl TempStore {
    fn new(name: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "layerfault_adversarial_{}_{}_{}",
            name,
            std::process::id(),
            nonce
        ));
        fs::create_dir_all(root.join("blobs")).expect("create blobs");
        fs::create_dir_all(root.join("manifests")).expect("create manifests");
        Self { root }
    }

    fn add_blob(&self, bytes: &[u8]) -> (String, u64) {
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(bytes)));
        let path = self.root.join("blobs").join(digest.replace(':', "-"));
        fs::write(path, bytes).expect("write blob");
        (digest, bytes.len() as u64)
    }

    fn write_manifest(&self, model: &str, tag: &str, body: &str) {
        let path = self
            .root
            .join("manifests/registry.ollama.ai/library")
            .join(model)
            .join(tag);
        fs::create_dir_all(path.parent().expect("manifest parent")).expect("create manifest path");
        fs::write(path, body).expect("write manifest");
    }

    fn run(&self, extra: &[&str]) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_layerfault"));
        command
            .arg("--ollama-dir")
            .arg(&self.root)
            .arg("--jobs")
            .arg("1");
        command.args(extra);
        command.output().expect("run layerfault")
    }
}

impl Drop for TempStore {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn layer_manifest(media_type: &str, digest: &str, size: u64) -> String {
    format!(
        r#"{{"schemaVersion":2,"layers":[{{"mediaType":"{media_type}","digest":"{digest}","size":{size}}}]}}"#
    )
}

fn minimal_gguf() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"GGUF");
    bytes.extend_from_slice(&3_u32.to_le_bytes());
    bytes.extend_from_slice(&1_u64.to_le_bytes()); // tensor count
    bytes.extend_from_slice(&1_u64.to_le_bytes()); // metadata count

    write_string(&mut bytes, "general.name");
    bytes.extend_from_slice(&8_u32.to_le_bytes()); // string
    write_string(&mut bytes, "benign fixture");

    write_string(&mut bytes, "weight");
    bytes.extend_from_slice(&1_u32.to_le_bytes()); // dimensions
    bytes.extend_from_slice(&32_u64.to_le_bytes());
    bytes.extend_from_slice(&2_u32.to_le_bytes()); // Q4_0
    bytes.extend_from_slice(&0_u64.to_le_bytes());
    while bytes.len() % 32 != 0 {
        bytes.push(0);
    }
    bytes.extend_from_slice(&[0_u8; 18]);
    bytes
}

fn write_string(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

fn stdout_json(output: &Output) -> serde_json::Value {
    assert!(
        !output.stdout.is_empty(),
        "no stdout; stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("valid JSON output")
}

#[test]
fn current_parameterized_tensor_layer_is_accepted_and_integrity_checked() {
    let store = TempStore::new("current_tensor");
    let (digest, size) = store.add_blob(&[0_u8; 64]);
    store.write_manifest(
        "current",
        "latest",
        &layer_manifest(
            "application/vnd.ollama.image.tensor; name=weight; dtype=F32; shape=16",
            &digest,
            size,
        ),
    );

    let output = store.run(&["--model", "current", "--json"]);
    assert_eq!(output.status.code(), Some(1)); // missing optional attestation warns
    let json = stdout_json(&output);
    let results = json[0]["scan_results"].as_array().expect("scan results");
    assert!(results
        .iter()
        .any(|r| { r["check_type"] == "IntegrityHash" && r["status"] == "Pass" }));
}

#[test]
fn sarif_output_is_machine_readable_and_keeps_artifact_identity() {
    let store = TempStore::new("sarif");
    let (digest, size) = store.add_blob(b"developer mode");
    store.write_manifest(
        "sarifmodel",
        "latest",
        &layer_manifest("application/vnd.ollama.image.template", &digest, size),
    );

    let output = store.run(&["--model", "sarifmodel", "--sarif"]);
    assert_eq!(output.status.code(), Some(1));
    let json = stdout_json(&output);
    assert_eq!(json["version"], "2.1.0");
    let results = json["runs"][0]["results"]
        .as_array()
        .expect("sarif results");
    assert!(results.iter().any(|result| {
        result["properties"]["model"]
            .as_str()
            .is_some_and(|model| model.contains("sarifmodel"))
    }));
}

#[test]
fn bad_blob_digest_is_exit_code_two() {
    let store = TempStore::new("bad_digest");
    let expected = format!("sha256:{}", "0".repeat(64));
    let path = store.root.join("blobs").join(expected.replace(':', "-"));
    fs::write(path, b"tampered").expect("write tampered blob");
    store.write_manifest(
        "tampered",
        "latest",
        &layer_manifest("application/vnd.ollama.image.template", &expected, 8),
    );

    let output = store.run(&["--model", "tampered", "--json"]);
    assert_eq!(output.status.code(), Some(2));
    let json = stdout_json(&output);
    assert_eq!(json[0]["overall_status"], "Fail");
}

#[test]
fn malformed_gguf_is_a_structural_failure() {
    let store = TempStore::new("bad_gguf");
    let (digest, size) = store.add_blob(b"GGUF\x03\x00\x00\x00truncated");
    store.write_manifest(
        "badgguf",
        "latest",
        &layer_manifest("application/vnd.ollama.image.model", &digest, size),
    );

    let output = store.run(&["--model", "badgguf", "--json"]);
    assert_eq!(output.status.code(), Some(3));
    let json = stdout_json(&output);
    let results = json[0]["scan_results"].as_array().expect("scan results");
    assert!(results
        .iter()
        .any(|r| { r["check_type"] == "GGUFMetadata" && r["status"] == "Fail" }));
}

#[test]
fn one_malformed_model_does_not_abort_other_models() {
    let store = TempStore::new("isolation");
    store.write_manifest("broken", "latest", "{not-json");
    let gguf = minimal_gguf();
    let (digest, size) = store.add_blob(&gguf);
    store.write_manifest(
        "safe",
        "latest",
        &layer_manifest("application/vnd.ollama.image.model", &digest, size),
    );

    let output = store.run(&["--json"]);
    assert_eq!(output.status.code(), Some(3));
    let json = stdout_json(&output);
    let reports = json.as_array().expect("reports");
    assert_eq!(reports.len(), 2);
    assert!(reports
        .iter()
        .any(|r| r["model"].as_str().is_some_and(|v| v.contains("broken"))));
    assert!(reports
        .iter()
        .any(|r| r["model"].as_str().is_some_and(|v| v.contains("safe"))));
}

#[test]
fn sensitive_match_output_is_redacted() {
    let secret = ["AKIA", "ABCDEFGHIJKLMNOP"].concat();
    let finding =
        HeuristicsScanner::scan_content(&format!("credential={secret}"), "sha256:test", 0)
            .expect("heuristic scan");
    assert_eq!(finding.status, ScanStatus::Fail);
    let rendered = finding.matches.join("\n");
    assert!(!rendered.contains(&secret));
    assert!(rendered.contains("<redacted sha256:"));
}

#[test]
fn valid_legacy_gguf_reaches_structure_pass() {
    let store = TempStore::new("valid_gguf");
    let gguf = minimal_gguf();
    let (digest, size) = store.add_blob(&gguf);
    store.write_manifest(
        "validgguf",
        "latest",
        &layer_manifest("application/vnd.ollama.image.model", &digest, size),
    );
    let output = store.run(&["--model", "validgguf", "--json"]);
    assert_eq!(output.status.code(), Some(1));
    let json = stdout_json(&output);
    let results = json[0]["scan_results"].as_array().expect("scan results");
    assert!(results
        .iter()
        .any(|r| { r["check_type"] == "GGUFMetadata" && r["status"] == "Pass" }));
}

#[test]
fn pickle_verdict_tiers_survive_cli_artifact_inspection() {
    let root = std::env::temp_dir().join(format!(
        "layerfault-adversarial-pickle-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("create pickle fixture directory");

    let cases: &[(&str, &[u8], i32, &str, &str)] = &[
        (
            "safe",
            b"ccollections\nOrderedDict\n.",
            0,
            "Pass",
            "LF-PICKLE-SAFE-GLOBALS",
        ),
        (
            "dangerous",
            b"cos\nsystem\n)R.",
            3,
            "Fail",
            "LF-PICKLE-DANGEROUS-GLOBAL",
        ),
        (
            "unknown",
            b"cacme.model\nCustomTensor\n.",
            1,
            "Warn",
            "LF-PICKLE-UNKNOWN-GLOBAL",
        ),
        (
            "malformed",
            b"\x80\x04cfoo\nbar",
            3,
            "Fail",
            "LF-PICKLE-MALFORMED",
        ),
    ];

    for (name, bytes, expected_exit, expected_status, rule) in cases {
        let path = root.join(format!("{name}.pkl"));
        fs::write(&path, bytes).expect("write pickle fixture");
        let output = Command::new(env!("CARGO_BIN_EXE_layerfault"))
            .args(["inspect", path.to_str().expect("UTF-8 path"), "--json"])
            .output()
            .expect("inspect pickle fixture");
        assert_eq!(
            output.status.code(),
            Some(*expected_exit),
            "unexpected exit for {name}; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        let json = stdout_json(&output);
        assert_eq!(json["format"], "pickle");
        let results = json["results"].as_array().expect("artifact results");
        assert!(
            results.iter().any(|result| {
                result["check_type"] == "PickleStructure"
                    && result["status"] == *expected_status
                    && result["matches"].as_array().is_some_and(|matches| {
                        matches
                            .iter()
                            .any(|item| item.as_str().is_some_and(|text| text.contains(rule)))
                    })
            }),
            "missing {rule} for {name}: {json}"
        );
    }

    let _ = fs::remove_dir_all(root);
}
