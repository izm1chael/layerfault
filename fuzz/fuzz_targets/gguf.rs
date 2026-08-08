#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Write;

fuzz_target!(|data: &[u8]| {
    let _ = layerfault::scanner::metadata::validate_gguf_bytes(data);

    let Ok(mut temp) = tempfile::NamedTempFile::new() else {
        return;
    };
    if temp.write_all(data).is_err() {
        return;
    }
    let Ok(file) = temp.reopen() else {
        return;
    };
    let _ = layerfault::scanner::MetadataScanner::scan_file_results(
        &file,
        data.len() as u64,
        "sha256:fuzz",
        "application/x-gguf",
    );
});
