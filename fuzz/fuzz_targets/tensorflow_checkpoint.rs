#![no_main]
mod support;

use libfuzzer_sys::fuzz_target;
use std::fs::File;

fuzz_target!(|data: &[u8]| {
    let Ok(root) = tempfile::tempdir() else {
        return;
    };
    let parts = support::split_sections(data, 4);
    let Ok(index_path) =
        support::write_file(root.path(), "model.ckpt.index", support::part(&parts, 0))
    else {
        return;
    };
    if !support::part(&parts, 1).is_empty() {
        let _ = support::write_file(
            root.path(),
            "model.ckpt.data-00000-of-00002",
            support::part(&parts, 1),
        );
    }
    if !support::part(&parts, 2).is_empty() {
        let _ = support::write_file(
            root.path(),
            "model.ckpt.data-00001-of-00002",
            support::part(&parts, 2),
        );
    }
    if !support::part(&parts, 3).is_empty() {
        let _ = support::write_file(
            root.path(),
            "other.data-00000-of-00001",
            support::part(&parts, 3),
        );
    }
    let Ok(file) = File::open(&index_path) else {
        return;
    };
    let Ok(len) = file.metadata().map(|metadata| metadata.len()) else {
        return;
    };
    let _ = layerfault::formats::tensorflow::inspect_checkpoint(&index_path, &file, len);
    let _ = layerfault::formats::tensorflow::scan_checkpoint(
        &index_path,
        &file,
        len,
        "sha256:fuzz",
        "application/x-tensorflow-checkpoint",
    );
});
