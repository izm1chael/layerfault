#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Write;

fuzz_target!(|data: &[u8]| {
    let Ok(mut temp) = tempfile::NamedTempFile::new() else {
        return;
    };
    if temp.write_all(data).is_err() {
        return;
    }
    let Ok(file) = temp.reopen() else {
        return;
    };
    let _ = layerfault::scanner::BinaryScanner::scan_file(
        &file,
        data.len() as u64,
        "sha256:fuzz",
        "application/vnd.layerfault.fuzz",
    );
    let _ = layerfault::scanner::BinaryScanner::parse_metadata(&file, data.len() as u64);
    let _ = layerfault::scanner::BinaryScanner::inspect_file_capabilities(
        &file,
        data.len() as u64,
        "sha256:fuzz",
        "fuzz_binary",
    );
});
