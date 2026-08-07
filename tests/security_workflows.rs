use layerfault::{audit, baseline::Baseline, quarantine};
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
            "layerfault_security_{name}_{}_{}",
            std::process::id(),
            nonce
        ));
        fs::create_dir_all(root.join("blobs")).expect("create blobs");
        fs::create_dir_all(root.join("manifests")).expect("create manifests");
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
}

impl Drop for TempStore {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn baseline_detects_manifest_and_descriptor_drift() {
    let store = TempStore::new("baseline");
    let (first, first_size) = store.add_blob(b"first");
    store.write_manifest(
        "demo",
        "latest",
        &[("application/vnd.ollama.image.template", &first, first_size)],
    );
    let baseline = Baseline::capture(&store.root).expect("capture baseline");

    let (second, second_size) = store.add_blob(b"second");
    store.write_manifest(
        "demo",
        "latest",
        &[(
            "application/vnd.ollama.image.template",
            &second,
            second_size,
        )],
    );
    let fake_path = store.root.join("baseline.json");
    let result = baseline
        .verify(&store.root, &fake_path)
        .expect("verify baseline");
    assert!(!result.matches);
    assert_eq!(result.changed_models.len(), 1);
    assert!(result.changed_models[0].added_descriptors.contains(&second));
    assert!(result.changed_models[0]
        .removed_descriptors
        .contains(&first));
}

#[test]
fn store_audit_reports_shared_missing_and_orphaned_blobs() {
    let store = TempStore::new("audit");
    let (shared, shared_size) = store.add_blob(b"shared");
    store.write_manifest(
        "one",
        "latest",
        &[(
            "application/vnd.ollama.image.template",
            &shared,
            shared_size,
        )],
    );
    store.write_manifest(
        "two",
        "latest",
        &[(
            "application/vnd.ollama.image.template",
            &shared,
            shared_size,
        )],
    );

    let orphan_bytes = b"orphan";
    let orphan = format!("sha256:{}", hex::encode(Sha256::digest(orphan_bytes)));
    fs::write(
        store.root.join("blobs").join(orphan.replace(':', "-")),
        orphan_bytes,
    )
    .expect("orphan blob");

    let missing = format!("sha256:{}", "f".repeat(64));
    store.write_manifest(
        "three",
        "latest",
        &[("application/vnd.ollama.image.template", &missing, 123)],
    );

    let result = audit::audit_store(&store.root).expect("audit store");
    assert!(result.orphaned_blobs.contains(&orphan));
    assert!(result
        .missing_blobs
        .iter()
        .any(|entry| entry.digest == missing));
    assert!(result
        .shared_blobs
        .iter()
        .any(|entry| { entry.digest == shared && entry.referenced_by.len() == 2 }));
}

#[test]
fn quarantine_preserves_shared_blobs_and_restores_exclusive_artifacts() {
    let store = TempStore::new("quarantine");
    let (shared, shared_size) = store.add_blob(b"shared");
    let (exclusive, exclusive_size) = store.add_blob(b"exclusive");
    store.write_manifest(
        "target",
        "latest",
        &[
            (
                "application/vnd.ollama.image.template",
                &shared,
                shared_size,
            ),
            (
                "application/vnd.ollama.image.params",
                &exclusive,
                exclusive_size,
            ),
        ],
    );
    store.write_manifest(
        "other",
        "latest",
        &[(
            "application/vnd.ollama.image.template",
            &shared,
            shared_size,
        )],
    );

    let record = quarantine::quarantine_model(&store.root, "target").expect("quarantine");
    assert!(record.shared_blob_digests.contains(&shared));
    assert!(record.moved_blob_digests.contains(&exclusive));
    assert!(store
        .root
        .join("blobs")
        .join(shared.replace(':', "-"))
        .exists());
    assert!(!store
        .root
        .join("blobs")
        .join(exclusive.replace(':', "-"))
        .exists());
    assert!(layerfault::manifest::find_model(&store.root, "target").is_err());

    quarantine::restore(&store.root, &record.id, false).expect("restore");
    assert!(layerfault::manifest::find_model(&store.root, "target").is_ok());
    assert!(store
        .root
        .join("blobs")
        .join(exclusive.replace(':', "-"))
        .exists());
}

#[test]
fn baseline_detects_attestation_signer_set_drift() {
    let store = TempStore::new("baseline_signers");
    let (blob, size) = store.add_blob(b"fixture");
    store.write_manifest(
        "demo",
        "latest",
        &[("application/vnd.ollama.image.template", &blob, size)],
    );
    let model = layerfault::manifest::find_model(&store.root, "demo").expect("model ref");
    let loaded = layerfault::manifest::load_model(&model).expect("load model");
    let envelope = layerfault::provenance::AttestationEnvelope {
        version: 1,
        model: loaded.name.clone(),
        manifest_digest: loaded.digest.clone(),
        key_fingerprint: format!("sha256:{}", "a".repeat(64)),
        signature_hex: "00".repeat(64),
        created_unix: 1,
    };
    let path = layerfault::provenance::envelope_path(&store.root, &loaded.digest);
    fs::write(
        &path,
        serde_json::to_vec(&envelope).expect("serialize envelope"),
    )
    .expect("write envelope");
    let baseline = Baseline::capture(&store.root).expect("capture baseline");

    fs::remove_file(path).expect("remove envelope");
    let result = baseline
        .verify(&store.root, &store.root.join("baseline.json"))
        .expect("verify baseline");
    assert!(!result.matches);
    assert_eq!(result.changed_models.len(), 1);
    assert_eq!(
        result.changed_models[0]
            .removed_attestation_fingerprints
            .len(),
        1
    );
}
