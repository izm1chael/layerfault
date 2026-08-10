#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Write;

fuzz_target!(|data: &[u8]| {
    let Ok(mut file) = tempfile::NamedTempFile::new() else { return; };
    if file.write_all(data).is_err() { return; }
    let path = file.path().to_path_buf();
    let Ok(opened) = std::fs::File::open(&path) else { return; };
    let _ = layerfault::formats::pickle::scan(
        &path,
        &opened,
        data.len() as u64,
        "sha256:fuzz",
        "application/x-python-pickle",
    );
});
