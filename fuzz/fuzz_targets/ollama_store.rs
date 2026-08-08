#![no_main]
mod support;

use libfuzzer_sys::fuzz_target;
use std::fs;

const VALID_MANIFEST: &[u8] = br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","layers":[{"mediaType":"application/vnd.ollama.image.model","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":4}]}"#;

fuzz_target!(|data: &[u8]| {
    let Ok(root) = tempfile::tempdir() else {
        return;
    };
    let parts = support::split_sections(data, 3);
    let manifest_bytes = if support::part(&parts, 0).is_empty() {
        VALID_MANIFEST
    } else {
        support::part(&parts, 0)
    };
    let blob_bytes = support::part(&parts, 1);
    let selector = String::from_utf8_lossy(support::part(&parts, 2));

    let manifest_path = root
        .path()
        .join("manifests/registry.ollama.ai/library/fuzz/latest");
    if let Some(parent) = manifest_path.parent() {
        if fs::create_dir_all(parent).is_err() {
            return;
        }
    }
    if fs::create_dir_all(root.path().join("blobs")).is_err()
        || fs::write(&manifest_path, manifest_bytes).is_err()
        || fs::write(
            root.path().join(
                "blobs/sha256-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            blob_bytes,
        )
        .is_err()
    {
        return;
    }

    if let Ok(models) = layerfault::manifest::discover_all_models(root.path()) {
        for model in models.iter().take(8) {
            let _ = layerfault::manifest::load_model(model);
        }
    }
    if !selector.is_empty() && selector.len() <= 1024 {
        let _ = layerfault::manifest::find_model(root.path(), &selector);
    }
    let _ = layerfault::manifest::find_model(root.path(), "fuzz:latest");
    let _ = layerfault::manifest::find_model(root.path(), "registry.ollama.ai/library/fuzz:latest");
});
