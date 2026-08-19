#![no_main]

use layerfault::archive::ArchiveLimits;
use libfuzzer_sys::fuzz_target;
use std::io::Write;

fuzz_target!(|data: &[u8]| {
    if data.len() < 262 || &data[257..262] != b"ustar" {
        return;
    }
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
    let mut limits = ArchiveLimits::default();
    limits.max_members_per_archive = 256;
    limits.max_members_total = 256;
    limits.max_uncompressed_member_bytes = 4 * 1024 * 1024;
    limits.max_uncompressed_total_bytes = 16 * 1024 * 1024;
    limits.max_retained_findings = 256;
    let _ = layerfault::archive::inspect(&path, &limits);
});
