#![no_main]
mod support;

use libfuzzer_sys::fuzz_target;
use std::fs;

fn fuzz_name(bytes: &[u8]) -> String {
    let mut name = String::with_capacity(bytes.len().min(96));
    for byte in bytes.iter().copied().take(96) {
        let ch = byte as char;
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
            name.push(ch);
        } else {
            name.push('_');
        }
    }
    if name.is_empty() {
        "model-Q4_K.gguf".to_owned()
    } else {
        name
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(root) = tempfile::tempdir() else {
        return;
    };
    let parts = support::split_sections(data, 5);
    let dynamic_name = fuzz_name(support::part(&parts, 0));

    let _ = support::write_file(root.path(), &dynamic_name, support::part(&parts, 1));
    let _ = support::write_file(
        root.path(),
        "nested/model-F16.safetensors",
        support::part(&parts, 2),
    );
    let _ = support::write_file(
        root.path(),
        "nested/model.safetensors.index.json",
        support::part(&parts, 3),
    );
    let _ = support::write_file(root.path(), "ignored/model.onnx", b"ignored");

    if support::part(&parts, 4).first().copied().unwrap_or(0) & 1 == 1 {
        let target = root.path().join("outside.gguf");
        if fs::write(&target, b"GGUF").is_ok() {
            let _ = support::symlink_file(&target, &root.path().join("nested/link-Q8_0.gguf"));
        }
    }

    let _ = layerfault::sources::format_from_path(&root.path().join(&dynamic_name));
    let _ = layerfault::sources::discover_directory(
        root.path(),
        layerfault::sources::SourceKind::Directory,
    );
});
