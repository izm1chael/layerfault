#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = layerfault::scanner::metadata::validate_gguf_bytes(data);
});
