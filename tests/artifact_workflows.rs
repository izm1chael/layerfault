use layerfault::admission;
use layerfault::formats::artifact::{self, ArtifactScanMode};
use layerfault::formats::ArtifactFormat;
use layerfault::policy::{PolicyDocument, PolicyProfile};
use layerfault::sources::SourceKind;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

struct TempDir {
    root: PathBuf,
}

impl TempDir {
    fn new(name: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "layerfault_artifact_{name}_{}_{}",
            std::process::id(),
            nonce
        ));
        fs::create_dir_all(&root).expect("create temp dir");
        Self { root }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn write_safetensors(path: &Path, header: &str, data: &[u8]) {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(header.len() as u64).to_le_bytes());
    bytes.extend_from_slice(header.as_bytes());
    bytes.extend_from_slice(data);
    fs::write(path, bytes).expect("write Safetensors fixture");
}

#[test]
fn direct_artifact_scan_accepts_valid_safetensors() {
    let temp = TempDir::new("valid_safe");
    let path = temp.root.join("model.safetensors");
    write_safetensors(
        &path,
        r#"{"weight":{"dtype":"F32","shape":[2],"data_offsets":[0,8]}}"#,
        &[0; 8],
    );

    let report = artifact::inspect(&path, ArtifactScanMode::Full).expect("inspect");
    assert_eq!(report.format, ArtifactFormat::Safetensors);
    assert!(!report.blocking());
    assert!(report.sha256.is_some());
}

#[test]
fn direct_artifact_scan_blocks_safetensors_holes() {
    let temp = TempDir::new("safe_hole");
    let path = temp.root.join("model.safetensors");
    write_safetensors(
        &path,
        r#"{"weight":{"dtype":"F32","shape":[1],"data_offsets":[4,8]}}"#,
        &[0; 8],
    );

    let report = artifact::inspect(&path, ArtifactScanMode::Full).expect("inspect");
    assert!(report.blocking());
}

#[test]
fn sharded_safetensors_index_validates_every_referenced_shard() {
    let temp = TempDir::new("safe_index");
    let shard = temp.root.join("model-00001-of-00001.safetensors");
    write_safetensors(
        &shard,
        r#"{"weight":{"dtype":"U8","shape":[4],"data_offsets":[0,4]}}"#,
        &[0; 4],
    );
    let index = temp.root.join("model.safetensors.index.json");
    fs::write(
        &index,
        r#"{"metadata":{"total_size":4},"weight_map":{"weight":"model-00001-of-00001.safetensors"}}"#,
    )
    .expect("write index");

    let report = artifact::inspect(&index, ArtifactScanMode::Full).expect("inspect index");
    assert_eq!(report.format, ArtifactFormat::SafetensorsIndex);
    assert!(!report.blocking());

    fs::remove_file(&shard).expect("remove shard");
    let report = artifact::inspect(&index, ArtifactScanMode::Full).expect("inspect missing shard");
    assert!(report.blocking());
}

#[test]
fn source_restrictions_are_evaluated_independently_from_structure() {
    let temp = TempDir::new("source_policy");
    let path = temp.root.join("model.safetensors");
    write_safetensors(
        &path,
        r#"{"weight":{"dtype":"U8","shape":[4],"data_offsets":[0,4]}}"#,
        &[0; 4],
    );

    let mut document = PolicyDocument::builtin(PolicyProfile::Workstation);
    document.allowed_sources = vec!["lmstudio".to_owned()];
    document.validate().expect("valid policy");
    let effective = document.effective();

    let blocked = admission::inspect_and_evaluate(
        &path,
        "fixture",
        SourceKind::File,
        &effective,
        None,
        None,
        None,
    )
    .expect("evaluate file source");
    assert_eq!(
        blocked.policy.action,
        layerfault::policy::PolicyAction::Block
    );

    let allowed = admission::inspect_and_evaluate(
        &path,
        "fixture",
        SourceKind::LmStudio,
        &effective,
        None,
        None,
        None,
    )
    .expect("evaluate lmstudio source");
    assert_ne!(
        allowed.policy.action,
        layerfault::policy::PolicyAction::Block
    );
}

#[test]
fn format_detection_recognizes_sharded_index_suffix() {
    assert_eq!(
        ArtifactFormat::detect(Path::new("model.safetensors.index.json"), &[]),
        ArtifactFormat::SafetensorsIndex
    );
}
