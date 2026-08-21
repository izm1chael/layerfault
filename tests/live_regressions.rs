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

fn write_overlapping_safetensors(path: &Path) {
    let header = br#"{"a":{"dtype":"U8","shape":[4],"data_offsets":[0,4]},"b":{"dtype":"U8","shape":[4],"data_offsets":[2,6]}}"#;
    let mut bytes = (header.len() as u64).to_le_bytes().to_vec();
    bytes.extend_from_slice(header);
    bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    fs::write(path, bytes).expect("write malformed Safetensors fixture");
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_layerfault"))
        .args(args)
        .output()
        .expect("run Layerfault")
}

fn run_in(cwd: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_layerfault"))
        .current_dir(cwd)
        .args(args)
        .output()
        .expect("run Layerfault")
}

fn varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            out.push(byte | 0x80);
        } else {
            out.push(byte);
            return out;
        }
    }
}

fn field_varint(no: u64, value: u64) -> Vec<u8> {
    let mut out = varint(no << 3);
    out.extend(varint(value));
    out
}

fn field_bytes(no: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = varint((no << 3) | 2);
    out.extend(varint(payload.len() as u64));
    out.extend_from_slice(payload);
    out
}

fn kv(key: &str, value: &str) -> Vec<u8> {
    let mut out = field_bytes(1, key.as_bytes());
    out.extend(field_bytes(2, value.as_bytes()));
    out
}

/// Builds a minimal ONNX ModelProto with a single external-data initializer
/// whose declared offset (999999) is far past the four-byte sidecar's EOF.
/// Mirrors scripts/lab-dev/setup-layerfault-lab-deep.sh case
/// 71-generated-onnx-external-offset, which surfaced a divergence where
/// `pipeline`/`inspect`/`scan-dir`/`verify-package`/`verify-file` returned
/// exit 2 (INTEGRITY_OR_ERROR) while `review --profile quick` correctly
/// returned exit 3 (BLOCK) for the identical LF-ONNX-EXTERNAL-RANGE finding.
fn write_onnx_external_offset_overflow(dir: &Path) {
    let mut external = field_bytes(13, &kv("location", "weights.bin"));
    external.extend(field_bytes(13, &kv("offset", "999999")));
    external.extend(field_bytes(13, &kv("length", "8")));
    external.extend(field_varint(14, 1));

    let mut graph = field_bytes(2, b"layerfault-fixture");
    graph.extend(field_bytes(5, &external));

    let mut model = field_varint(1, 8);
    model.extend(field_bytes(7, &graph));

    fs::write(dir.join("model.onnx"), model).expect("write ONNX fixture");
    fs::write(dir.join("weights.bin"), b"LF00").expect("write external sidecar fixture");
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
    assert_eq!(output.status.code(), Some(1));
    let value: Value = serde_json::from_slice(&output.stdout).expect("inspect JSON");
    assert!(value["findings"]
        .as_array()
        .is_some_and(|items| items
            .iter()
            .any(|item| item["matches"]
                .as_array()
                .is_some_and(|matches| matches.iter().any(|m| {
                    m.as_str()
                        .is_some_and(|text| text.contains("LF-PICKLE-OPAQUE-COMPRESSED"))
                }))
                && item["status"] == "Warn")));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn review_quick_keeps_block_when_snapshot_analysis_fails() {
    let root = temp_dir("review-malformed-weight");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("create package");
    write_overlapping_safetensors(&root.join("model.safetensors"));

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
    assert_eq!(value["domains"]["static_admission"]["state"], "AVAILABLE");
    assert!(matches!(
        value["domains"]["metadata_snapshot"]["state"].as_str(),
        Some("FAILED") | Some("UNAVAILABLE")
    ));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn compare_block_decision_has_block_exit_code() {
    let base = temp_dir("compare-base");
    let derived = temp_dir("compare-derived");
    let _ = fs::remove_dir_all(&base);
    let _ = fs::remove_dir_all(&derived);
    fs::create_dir_all(&base).expect("create base");
    fs::create_dir_all(&derived).expect("create derived");
    write_safetensors(&base.join("model.safetensors"));
    write_safetensors(&derived.join("model.safetensors"));
    fs::write(
        base.join("config.json"),
        br#"{"model_type":"llama","num_hidden_layers":2,"hidden_size":8,"num_attention_heads":2}"#,
    )
    .expect("write base config");
    fs::write(
        derived.join("config.json"),
        br#"{"model_type":"mistral","num_hidden_layers":2,"hidden_size":8,"num_attention_heads":2}"#,
    )
    .expect("write derived config");

    let output = run(&[
        "compare",
        base.to_str().unwrap(),
        derived.to_str().unwrap(),
        "--claim",
        "quantization",
        "--json",
    ]);
    assert_eq!(
        output.status.code(),
        Some(3),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("compare JSON");
    assert_eq!(value["final_decision"], "BLOCK");
    let _ = fs::remove_dir_all(base);
    let _ = fs::remove_dir_all(derived);
}

#[test]
fn onnx_external_range_blocks_consistently_across_every_cli_surface() {
    let root = temp_dir("onnx-external-range");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("create package");
    write_onnx_external_offset_overflow(&root);
    let model_path = root.join("model.onnx");

    let assert_block = |label: &str, output: &Output| {
        assert_eq!(
            output.status.code(),
            Some(3),
            "{label} expected BLOCK (exit 3); stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    };

    assert_block(
        "inspect (package dir)",
        &run(&["inspect", root.to_str().unwrap(), "--json"]),
    );
    assert_block(
        "scan-dir",
        &run(&["scan-dir", root.to_str().unwrap(), "--json"]),
    );
    assert_block(
        "verify-package",
        &run(&[
            "verify-package",
            root.to_str().unwrap(),
            "--policy",
            "workstation",
            "--json",
        ]),
    );
    assert_block(
        "pipeline",
        &run(&[
            "pipeline",
            root.to_str().unwrap(),
            "--policy",
            "workstation",
            "--json",
        ]),
    );
    assert_block(
        "review --profile quick",
        &run(&[
            "review",
            root.to_str().unwrap(),
            "--profile",
            "quick",
            "--json",
        ]),
    );
    assert_block(
        "inspect (single artifact)",
        &run(&["inspect", model_path.to_str().unwrap(), "--json"]),
    );
    assert_block(
        "verify-file",
        &run(&[
            "verify-file",
            model_path.to_str().unwrap(),
            "--policy",
            "workstation",
            "--json",
        ]),
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn onnx_external_range_finding_survives_a_bare_relative_filename() {
    // `path.parent()` on a bare relative filename like "model.onnx" (no
    // directory component) returns `Some("")`, not `None`. A prior bug
    // canonicalized that empty path directly, which fails and replaces the
    // specific, actionable LF-ONNX-EXTERNAL-RANGE finding with an opaque
    // "unable to canonicalize ONNX parent ''" error -- exactly the kind of
    // internal-detail message a human running the CLI from inside the
    // model's own directory (`cd model_dir && layerfault verify-file
    // model.onnx`) should never see in place of the real finding.
    let root = temp_dir("onnx-bare-filename");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("create package");
    write_onnx_external_offset_overflow(&root);

    let output = run_in(&root, &["inspect", "model.onnx", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(3),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("inspect JSON");
    let matches: Vec<&str> = value["results"]
        .as_array()
        .expect("results array")
        .iter()
        .flat_map(|result| result["matches"].as_array().into_iter().flatten())
        .filter_map(Value::as_str)
        .collect();
    assert!(
        matches
            .iter()
            .any(|m| m.contains("LF-ONNX-EXTERNAL-RANGE") && m.contains("exceeds file length")),
        "expected the specific external-range finding, got matches={matches:?}"
    );
    assert!(
        !matches.iter().any(|m| m.contains("canonicalize")),
        "the empty-parent canonicalization error leaked into the findings: {matches:?}"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn dataset_poisoning_review_accepts_a_bare_relative_filename() {
    // Same `Path::parent()` footgun as the ONNX case above, in the dataset
    // single-file path: it used to hard-fail with a bare OS error instead of
    // running the review, for the most natural invocation of the command.
    let root = temp_dir("dataset-bare-filename");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("create dataset dir");
    fs::write(
        root.join("train.jsonl"),
        "{\"text\":\"normal\",\"label\":\"ok\"}\n",
    )
    .expect("write dataset");

    let output = run_in(
        &root,
        &["dataset", "poisoning-review", "train.jsonl", "--json"],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("dataset JSON");
    assert_eq!(value["state"], "NO_SUSPICIOUS_INDICATORS_OBSERVED");

    let _ = fs::remove_dir_all(root);
}

#[test]
fn pipeline_single_artifact_honours_policy_block_over_scanner_warn() {
    // `pipeline` on a single artifact used to compute its exit code as
    // `if scanner_exit != 0 { scanner_exit } else { policy-based }` instead
    // of going through the shared combine helper. A raw HDF5/Keras artifact
    // always scores a scanner-level WARN (LF-KERAS-HDF5-LIMIT), so a policy
    // that independently BLOCKs on size (`max_model_bytes`) was silently
    // downgraded to exit 1 (WARN) instead of exit 4 (BLOCK) -- a human
    // reading the exit code would believe the artifact merely warranted
    // review when the operator's policy actually rejected it outright.
    let root = temp_dir("pipeline-policy-vs-warn");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("create dir");
    let artifact_path = root.join("model.h5");
    fs::write(&artifact_path, b"not a real hdf5 but nonzero length").expect("write HDF5 fixture");
    let policy_path = root.join("tiny-policy.json");
    fs::write(
        &policy_path,
        br#"{"version":1,"profile":"workstation","max_model_bytes":1}"#,
    )
    .expect("write policy file");

    let output = run(&[
        "pipeline",
        artifact_path.to_str().unwrap(),
        "--policy-file",
        policy_path.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(
        output.status.code(),
        Some(4),
        "expected policy BLOCK (exit 4) to win over the scanner WARN; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("pipeline JSON");
    assert_eq!(value["decision"], "BLOCK");

    let _ = fs::remove_dir_all(root);
}

#[test]
fn trust_export_accepts_a_bare_relative_output_filename() {
    // `paths::write_private` (the shared primitive behind --output/--evidence-out
    // across many subcommands) used to canonicalize `path.parent()` directly.
    // For a bare relative filename like "out.json", `parent()` returns
    // `Some("")` (not `None`), so directory-creation/permission calls on the
    // empty path failed with an opaque "Unable to secure ''" that never named
    // the file the user actually asked to write.
    let root = temp_dir("trust-export-bare-filename");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("create dir");

    let output = run_in(&root, &["trust", "export", "--output", "bare-trust.json"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(root.join("bare-trust.json").is_file());

    let _ = fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn safetensors_index_symlink_escape_is_caught_via_bare_relative_filename() {
    // Security-relevant, not just cosmetic: `validate_index` canonicalizes
    // `path.parent()` and falls back to the *unresolved* parent on failure,
    // then checks `canonical_shard.starts_with(&canonical_parent)` to block
    // shard symlinks that escape the index directory. `Path::parent()` on a
    // bare relative index filename returns `Some("")`, canonicalizing ""
    // fails, and `Path::starts_with("")` is trivially true for every path --
    // so the escape check was silently disabled for the most natural
    // invocation (`cd model_dir && layerfault inspect model.safetensors.index.json`).
    let root = temp_dir("safetensors-symlink-escape");
    let outside = temp_dir("safetensors-symlink-escape-outside");
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&outside);
    fs::create_dir_all(&root).expect("create model dir");
    fs::create_dir_all(&outside).expect("create outside dir");

    write_safetensors(&outside.join("secret.safetensors"));
    std::os::unix::fs::symlink(
        outside.join("secret.safetensors"),
        root.join("shard.safetensors"),
    )
    .expect("create escaping symlink");
    fs::write(
        root.join("model.safetensors.index.json"),
        br#"{"weight_map":{"w":"shard.safetensors"}}"#,
    )
    .expect("write index");

    let output = run_in(
        &root,
        &["inspect", "model.safetensors.index.json", "--json"],
    );
    assert_eq!(
        output.status.code(),
        Some(3),
        "expected the escape to BLOCK; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("inspect JSON");
    let detail = value["results"][0]["detail"].as_str().unwrap_or_default();
    assert!(
        detail.contains("resolves outside the index directory"),
        "expected the escape finding, got detail={detail:?}"
    );

    let _ = fs::remove_dir_all(root);
    let _ = fs::remove_dir_all(outside);
}

#[test]
fn tensorflow_checkpoint_shards_are_found_via_bare_relative_filename() {
    // Same `Path::parent()` footgun in checkpoint sibling-shard discovery:
    // reading "" as a directory fails outright, so a bare relative ".index"
    // filename used to error instead of finding its sibling data shard.
    let root = temp_dir("tf-checkpoint-bare-filename");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("create dir");
    fs::write(
        root.join("model.ckpt.index"),
        b"not a real TF index, contents unused",
    )
    .expect("write checkpoint index");
    fs::write(
        root.join("model.ckpt.data-00000-of-00001"),
        b"not real shard data either",
    )
    .expect("write checkpoint shard");

    let output = run_in(&root, &["inspect", "model.ckpt.index", "--json"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("inspect JSON");
    let detail = value["results"][0]["detail"].as_str().unwrap_or_default();
    assert!(
        detail.contains("1 data shard"),
        "expected the sibling shard to be found, got detail={detail:?}"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn artifact_json_exposes_cache_diagnostics() {
    let path = temp_dir("cache-diagnostics").with_extension("safetensors");
    let _ = fs::remove_file(&path);
    write_safetensors(&path);
    let output = run(&["inspect", path.to_str().unwrap(), "--json"]);
    assert_eq!(output.status.code(), Some(0));
    let value: Value = serde_json::from_slice(&output.stdout).expect("inspect JSON");
    assert!(value["cache"]["digest"].is_string());
    assert!(value["cache"]["evidence"].is_string());
    assert!(value["cache"]["digest_min_bytes"].is_number());
    assert!(value["cache"]["evidence_min_bytes"].is_number());
    let _ = fs::remove_file(path);
}

#[test]
fn top_level_error_payload_written_to_stdout_when_json_requested() {
    let output = run(&[
        "verify-package",
        "/nonexistent/path/that/does/not/exist",
        "--policy",
        "workstation",
        "--json",
    ]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout)
        .expect("top-level error payload must be valid JSON on stdout");
    assert!(value["error"]["message"].is_string());
    assert!(value["error"]["causes"].is_array());
}
