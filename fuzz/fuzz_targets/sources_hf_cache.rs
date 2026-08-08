#![no_main]
mod support;

use libfuzzer_sys::fuzz_target;
use std::fs;

const VALID_REF: &[u8] = b"rev-a";
const VALID_INDEX: &[u8] = br#"{"weight_map":{"w":"model-00001-of-00001.safetensors"}}"#;
const VALID_CONFIG: &[u8] = br#"{"model_type":"fuzz"}"#;

fn valid_shard() -> Vec<u8> {
    let header = br#"{"w":{"dtype":"U8","shape":[1],"data_offsets":[0,1]}}"#;
    let mut bytes = Vec::with_capacity(8 + header.len() + 1);
    bytes.extend_from_slice(&(header.len() as u64).to_le_bytes());
    bytes.extend_from_slice(header);
    bytes.push(b'x');
    bytes
}

fuzz_target!(|data: &[u8]| {
    let Ok(cache) = tempfile::tempdir() else {
        return;
    };
    let parts = support::split_sections(data, 6);
    let repo = cache.path().join("models--org--fuzz");
    let blobs = repo.join("blobs");
    let snapshot = repo.join("snapshots/rev-a");
    if fs::create_dir_all(&blobs).is_err()
        || fs::create_dir_all(&snapshot).is_err()
        || fs::create_dir_all(repo.join("refs")).is_err()
    {
        return;
    }

    let ref_bytes = if support::part(&parts, 0).is_empty() {
        VALID_REF
    } else {
        support::part(&parts, 0)
    };
    if fs::write(repo.join("refs/main"), ref_bytes).is_err() {
        return;
    }

    let index = if support::part(&parts, 1).is_empty() {
        VALID_INDEX
    } else {
        support::part(&parts, 1)
    };
    let fallback_shard = valid_shard();
    let shard = if support::part(&parts, 2).is_empty() {
        fallback_shard.as_slice()
    } else {
        support::part(&parts, 2)
    };
    let config = if support::part(&parts, 3).is_empty() {
        VALID_CONFIG
    } else {
        support::part(&parts, 3)
    };
    let python = support::part(&parts, 4);
    let mode = support::part(&parts, 5).first().copied().unwrap_or(0) % 6;

    let index_blob = blobs.join("index-blob");
    let shard_blob = blobs.join("shard-blob");
    let config_blob = blobs.join("config-blob");
    let python_blob = blobs.join("python-blob");
    if fs::write(&index_blob, index).is_err()
        || fs::write(&shard_blob, shard).is_err()
        || fs::write(&config_blob, config).is_err()
        || fs::write(&python_blob, python).is_err()
        || fs::write(blobs.join("orphan-blob"), b"orphan").is_err()
    {
        return;
    }

    let index_link = snapshot.join("model.safetensors.index.json");
    let shard_link = snapshot.join("model-00001-of-00001.safetensors");
    let config_link = snapshot.join("config.json");
    let python_link = snapshot.join("modeling_fuzz.py");

    if mode != 4
        && support::symlink_file(
            &std::path::PathBuf::from("../../blobs/index-blob"),
            &index_link,
        )
        .is_err()
    {
        return;
    }

    match mode {
        1 => {}
        2 => {
            let outside = cache.path().join("outside-shard.safetensors");
            if fs::write(&outside, shard).is_err()
                || support::symlink_file(&outside, &shard_link).is_err()
            {
                return;
            }
        }
        3 => {
            if fs::write(&shard_link, shard).is_err() {
                return;
            }
        }
        _ => {
            if support::symlink_file(
                &std::path::PathBuf::from("../../blobs/shard-blob"),
                &shard_link,
            )
            .is_err()
            {
                return;
            }
        }
    }

    for (blob_name, link) in [("config-blob", config_link), ("python-blob", python_link)] {
        let relative = std::path::PathBuf::from("../../blobs").join(blob_name);
        if support::symlink_file(&relative, &link).is_err() {
            return;
        }
    }

    let _ = layerfault::sources::audit_hf_cache(Some(cache.path()));
});
