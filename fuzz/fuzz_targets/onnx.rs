#![no_main]
use libfuzzer_sys::fuzz_target;
use std::fs;
use std::fs::File;

fuzz_target!(|data: &[u8]| {
    let Ok(root) = tempfile::tempdir() else {
        return;
    };
    let model_path = root.path().join("model.onnx");
    if fs::write(&model_path, data).is_err()
        || fs::create_dir_all(root.path().join("data")).is_err()
        || fs::write(root.path().join("weights.bin"), data).is_err()
        || fs::write(root.path().join("data/weights.bin"), data).is_err()
    {
        return;
    }
    let Ok(file) = File::open(&model_path) else {
        return;
    };
    let _ = layerfault::formats::onnx::inspect(&file, data.len() as u64);
    let _ = layerfault::formats::onnx::scan(
        &model_path,
        &file,
        data.len() as u64,
        "sha256:fuzz",
        "application/x-onnx",
    );
});
