#![no_main]
mod support;

use libfuzzer_sys::fuzz_target;
use std::fs;

fuzz_target!(|data: &[u8]| {
    let Ok(root) = tempfile::tempdir() else {
        return;
    };
    let parts = support::split_sections(data, 7);
    let files = [
        ("config.json", support::part(&parts, 0)),
        ("modeling_fuzz.py", support::part(&parts, 1)),
        ("tokenizer_config.json", support::part(&parts, 2)),
        ("README.md", support::part(&parts, 3)),
        ("requirements.txt", support::part(&parts, 4)),
        ("custom_module.py", support::part(&parts, 5)),
    ];
    for (name, bytes) in files {
        if fs::write(root.path().join(name), bytes).is_err() {
            return;
        }
    }
    if support::part(&parts, 6)
        .first()
        .is_some_and(|byte| byte & 1 == 1)
        && support::symlink_file(
            std::path::Path::new("custom_module.py"),
            &root.path().join("linked_module.py"),
        )
        .is_err()
    {
        return;
    }
    let _ = layerfault::package::inspect(root.path());
});
