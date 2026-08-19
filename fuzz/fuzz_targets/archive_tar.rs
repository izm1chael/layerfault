#![no_main]

use layerfault::archive::ArchiveLimits;
use libfuzzer_sys::fuzz_target;
use std::io::Write;

fuzz_target!(|data: &[u8]| {
    let Ok(dir) = tempfile::tempdir() else {
        return;
    };
    let path = dir.path().join("fuzz.tar");
    let Ok(mut file) = std::fs::File::create(&path) else {
        return;
    };
    if file.write_all(data).is_err() {
        return;
    }
    let _ = layerfault::archive::inspect(&path, &ArchiveLimits::default());
});
