#![no_main]
use layerfault::budget::{ScanBudget, ScanBudgetProfile};
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
    if let Ok(inventory) =
        layerfault::formats::safetensors::inventory_file(&file, data.len() as u64)
    {
        for tensor in inventory.tensors.iter().take(16) {
            let _ = layerfault::formats::safetensors::read_tensor_bytes(
                &file,
                &inventory,
                tensor,
                1024 * 1024,
            );
        }
    }
    let Ok(budget) = ScanBudget::new(ScanBudgetProfile::Default.limits()) else {
        return;
    };
    let _ = layerfault::formats::safetensors::scan_file(
        &file,
        data.len() as u64,
        "sha256:fuzz",
        "application/x-safetensors",
        &budget,
    );
});
