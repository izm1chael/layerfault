#![no_main]
mod support;

use libfuzzer_sys::fuzz_target;
use std::fs;

fuzz_target!(|data: &[u8]| {
    let Ok(root) = tempfile::tempdir() else {
        return;
    };
    let model = root.path().join("fuzz-model.gguf");
    if fs::write(&model, b"GGUF\x03\0\0\0").is_err() {
        return;
    }
    let path = model.to_string_lossy();
    let json = support::replace_token(data, b"$MODEL", path.as_bytes());
    let _ = layerfault::sources::parse_lmstudio_inventory_bytes(&json);
});
