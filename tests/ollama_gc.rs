//! Regression coverage for Ollama blob garbage collection: dry-run must
//! only ever report candidates and never touch the filesystem, apply must
//! delete exactly the orphaned set and nothing referenced, and a manifest
//! that cannot be parsed must never cause its (unknowable) referenced blobs
//! to be misidentified as orphaned and deleted.

use layerfault::gc;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
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
            "layerfault_gc_{name}_{}_{}",
            std::process::id(),
            nonce
        ));
        fs::create_dir_all(root.join("blobs")).expect("create blobs dir");
        fs::create_dir_all(root.join("manifests")).expect("create manifests dir");
        Self { root }
    }

    fn add_blob(&self, bytes: &[u8]) -> (String, u64) {
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(bytes)));
        fs::write(
            self.root.join("blobs").join(digest.replace(':', "-")),
            bytes,
        )
        .expect("write blob");
        (digest, bytes.len() as u64)
    }

    fn blob_path(&self, digest: &str) -> PathBuf {
        self.root.join("blobs").join(digest.replace(':', "-"))
    }

    fn write_manifest(&self, model: &str, tag: &str, layers: &[(&str, &str, u64)]) {
        let descriptors = layers
            .iter()
            .map(|(media, digest, size)| {
                serde_json::json!({"mediaType": media, "digest": digest, "size": size})
            })
            .collect::<Vec<_>>();
        let body = serde_json::json!({"schemaVersion": 2, "layers": descriptors});
        let path = self
            .root
            .join("manifests/registry.ollama.ai/library")
            .join(model)
            .join(tag);
        fs::create_dir_all(path.parent().expect("manifest parent")).expect("mkdir manifest");
        fs::write(path, serde_json::to_vec(&body).expect("json")).expect("write manifest");
    }

    fn write_malformed_manifest(&self, model: &str, tag: &str) {
        let path = self
            .root
            .join("manifests/registry.ollama.ai/library")
            .join(model)
            .join(tag);
        fs::create_dir_all(path.parent().expect("manifest parent")).expect("mkdir manifest");
        fs::write(path, b"{ this is not valid json").expect("write malformed manifest");
    }
}

impl Drop for TempStore {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn dry_run_reports_orphan_but_deletes_nothing() {
    let store = TempStore::new("dry_run");
    let (config, config_size) = store.add_blob(b"config bytes");
    let (layer, layer_size) = store.add_blob(b"layer bytes");
    let (orphan, _) = store.add_blob(b"nobody references this");
    store.write_manifest(
        "demo",
        "latest",
        &[
            ("application/vnd.ollama.image.config", &config, config_size),
            ("application/vnd.ollama.image.model", &layer, layer_size),
        ],
    );

    let plan = gc::plan(&store.root).expect("plan");
    assert_eq!(plan.candidates.len(), 1);
    assert_eq!(plan.candidates[0].digest, orphan);

    assert!(
        store.blob_path(&config).is_file(),
        "config must survive dry-run"
    );
    assert!(
        store.blob_path(&layer).is_file(),
        "layer must survive dry-run"
    );
    assert!(
        store.blob_path(&orphan).is_file(),
        "dry-run must not delete anything"
    );
}

#[test]
fn apply_removes_only_the_orphan() {
    let store = TempStore::new("apply");
    let (config, config_size) = store.add_blob(b"config bytes");
    let (layer, layer_size) = store.add_blob(b"layer bytes");
    let (orphan, _) = store.add_blob(b"nobody references this");
    store.write_manifest(
        "demo",
        "latest",
        &[
            ("application/vnd.ollama.image.config", &config, config_size),
            ("application/vnd.ollama.image.model", &layer, layer_size),
        ],
    );

    let plan = gc::plan(&store.root).expect("plan");
    let deleted = gc::execute(&store.root, &plan).expect("execute");
    assert!(deleted > 0);

    assert!(
        store.blob_path(&config).is_file(),
        "referenced config must be retained"
    );
    assert!(
        store.blob_path(&layer).is_file(),
        "referenced layer must be retained"
    );
    assert!(
        !store.blob_path(&orphan).is_file(),
        "orphan must be removed by apply"
    );
}

#[test]
fn shared_layer_across_two_models_is_retained() {
    let store = TempStore::new("shared");
    let (shared, shared_size) = store.add_blob(b"shared layer bytes");
    store.write_manifest(
        "one",
        "latest",
        &[("application/vnd.ollama.image.model", &shared, shared_size)],
    );
    store.write_manifest(
        "two",
        "latest",
        &[("application/vnd.ollama.image.model", &shared, shared_size)],
    );

    let plan = gc::plan(&store.root).expect("plan");
    assert!(
        plan.candidates.is_empty(),
        "a blob referenced by two manifests must not be an orphan candidate"
    );

    let deleted = gc::execute(&store.root, &plan).expect("execute");
    assert_eq!(deleted, 0);
    assert!(
        store.blob_path(&shared).is_file(),
        "shared blob must survive GC"
    );
}

#[test]
fn malformed_manifest_refuses_to_plan_rather_than_risk_unsafe_deletion() {
    let store = TempStore::new("malformed");
    let (referenced, _) = store.add_blob(b"referenced by the broken manifest, presumably");
    // A manifest layerfault cannot parse might still reference `referenced`;
    // there is no way to know, so GC must not guess that it is orphaned.
    store.write_malformed_manifest("broken", "latest");

    let result = gc::plan(&store.root);
    assert!(
        result.is_err(),
        "GC must refuse to plan while any manifest cannot be parsed"
    );
    assert!(store.blob_path(&referenced).is_file());
}

#[test]
fn unknown_unrelated_file_in_blobs_dir_is_not_a_gc_candidate() {
    let store = TempStore::new("unrelated");
    let (config, config_size) = store.add_blob(b"config bytes");
    store.write_manifest(
        "demo",
        "latest",
        &[("application/vnd.ollama.image.config", &config, config_size)],
    );
    // A file that does not match the sha256-<hex> blob naming convention at
    // all (e.g. an in-progress download or stray file) is not itself a
    // recognized content-addressed blob, so it must not be treated as a
    // deletable orphan by this digest-based mark-and-sweep.
    fs::write(
        store.root.join("blobs").join("not-a-digest-name.tmp"),
        b"junk",
    )
    .expect("write unrelated file");

    let plan = gc::plan(&store.root).expect("plan");
    assert!(
        plan.candidates.is_empty(),
        "a non-digest-named file must not be swept as an orphaned blob: {:?}",
        plan.candidates
    );

    let deleted = gc::execute(&store.root, &plan).expect("execute");
    assert_eq!(deleted, 0);
    assert!(store
        .root
        .join("blobs")
        .join("not-a-digest-name.tmp")
        .is_file());
}

#[test]
fn digest_normalization_matches_colon_and_dash_forms() {
    let store = TempStore::new("digest_norm");
    let (config, config_size) = store.add_blob(b"config bytes");
    store.write_manifest(
        "demo",
        "latest",
        &[("application/vnd.ollama.image.config", &config, config_size)],
    );

    // The blob on disk is named with a dash (sha256-<hex>) but manifests
    // reference it with a colon (sha256:<hex>); confirm these are treated
    // as the same digest rather than the on-disk blob looking unreferenced.
    let on_disk_name = config.replace(':', "-");
    assert!(store.root.join("blobs").join(&on_disk_name).is_file());

    let plan = gc::plan(&store.root).expect("plan");
    assert!(
        plan.candidates.is_empty(),
        "colon/dash digest forms must normalize to the same referenced blob"
    );
}

#[test]
fn re_planning_after_a_concurrent_change_is_required_before_apply() {
    let store = TempStore::new("race");
    let (config, config_size) = store.add_blob(b"config bytes");
    let (orphan, _) = store.add_blob(b"orphan bytes");
    store.write_manifest(
        "demo",
        "latest",
        &[("application/vnd.ollama.image.config", &config, config_size)],
    );

    let stale_plan = gc::plan(&store.root).expect("plan");
    assert_eq!(stale_plan.candidates.len(), 1);

    // Simulate the store changing between planning and applying: the
    // orphan gets referenced by a new manifest before the delete runs.
    store.write_manifest(
        "newly-adopted",
        "latest",
        &[("application/vnd.ollama.image.config", &orphan, 1)],
    );

    let result = gc::execute(&store.root, &stale_plan);
    assert!(
        result.is_err(),
        "apply must re-verify the plan and refuse to delete a blob that became referenced"
    );
    assert!(store.blob_path(&orphan).is_file());
}
