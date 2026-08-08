#![no_main]
use libfuzzer_sys::fuzz_target;
use std::fs;

fuzz_target!(|data: &[u8]| {
    let Ok(root) = tempfile::tempdir() else { return; };
    let split = data.len() / 2;
    if fs::write(root.path().join("config.json"), &data[..split]).is_err() { return; }
    if fs::write(root.path().join("modeling_fuzz.py"), &data[split..]).is_err() { return; }
    let _ = layerfault::package::inspect(root.path());
});
