#![no_main]
mod support;

use libfuzzer_sys::fuzz_target;
use std::fs;
use std::fs::File;

fn valid_shard() -> Vec<u8> {
    let header = br#"{"w":{"dtype":"U8","shape":[1],"data_offsets":[0,1]}}"#;
    let mut bytes = Vec::with_capacity(8 + header.len() + 1);
    bytes.extend_from_slice(&(header.len() as u64).to_le_bytes());
    bytes.extend_from_slice(header);
    bytes.push(b'x');
    bytes
}

fuzz_target!(|data: &[u8]| {
    let Ok(root) = tempfile::tempdir() else {
        return;
    };
    let parts = support::split_sections(data, 5);
    let index_bytes = support::part(&parts, 0);
    let fallback_a = valid_shard();
    let fallback_b = valid_shard();
    let fallback_nested = valid_shard();
    let shard_a = if support::part(&parts, 1).is_empty() {
        fallback_a.as_slice()
    } else {
        support::part(&parts, 1)
    };
    let shard_b = if support::part(&parts, 2).is_empty() {
        fallback_b.as_slice()
    } else {
        support::part(&parts, 2)
    };
    let shard_nested = if support::part(&parts, 3).is_empty() {
        fallback_nested.as_slice()
    } else {
        support::part(&parts, 3)
    };
    let mode = support::part(&parts, 4).first().copied().unwrap_or(0) % 4;

    let Ok(index_path) =
        support::write_file(root.path(), "model.safetensors.index.json", index_bytes)
    else {
        return;
    };

    let outside = tempfile::tempdir().ok();
    match mode {
        1 => {}
        2 => {
            let Some(outside) = outside.as_ref() else {
                return;
            };
            let external = outside.path().join("escape.safetensors");
            if fs::write(&external, shard_a).is_err()
                || support::symlink_file(&external, &root.path().join("shard-a.safetensors"))
                    .is_err()
            {
                return;
            }
        }
        3 => {
            if fs::create_dir_all(root.path().join("shard-a.safetensors")).is_err() {
                return;
            }
        }
        _ => {
            if support::write_file(root.path(), "shard-a.safetensors", shard_a).is_err() {
                return;
            }
        }
    }

    if support::write_file(root.path(), "shard-b.safetensors", shard_b).is_err()
        || support::write_file(root.path(), "nested/shard-c.safetensors", shard_nested).is_err()
    {
        return;
    }
    let Ok(file) = File::open(&index_path) else {
        return;
    };
    let Ok(len) = file.metadata().map(|metadata| metadata.len()) else {
        return;
    };
    let _ = layerfault::formats::safetensors::validate_index(&index_path, &file, len);
    let _ = layerfault::formats::safetensors::scan_index(
        &index_path,
        &file,
        len,
        "sha256:fuzz",
        "application/x-safetensors-index",
    );
});
