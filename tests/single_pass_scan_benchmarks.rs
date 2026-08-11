use layerfault::safeio::open_readonly_nofollow;
use layerfault::scanner::{BinaryStreamObserver, ScanSession, TextStreamObserver};
use std::io::Write;
use std::time::Instant;
use tempfile::tempdir;

#[test]
fn benchmark_single_pass_vs_multi_pass_synthetic() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("synthetic_100mb.bin");

    // Create 100 MiB synthetic file with embedded signatures
    let chunk = vec![b'a'; 1024 * 1024];
    let mut f = std::fs::File::create(&file_path).unwrap();
    for i in 0..100 {
        if i == 50 {
            f.write_all(b"os.system('id')\n").unwrap();
        } else if i == 75 {
            f.write_all(b"\x7fELF\x02\x01\x01\x00").unwrap();
        } else {
            f.write_all(&chunk).unwrap();
        }
    }
    f.sync_all().unwrap();

    let file = open_readonly_nofollow(&file_path).unwrap();

    // Measure Single Pass (fused SHA-256 + Binary + Text)
    let start_single = Instant::now();
    let session = ScanSession::new(&file_path, &file).unwrap();
    let text_obs = Box::new(TextStreamObserver::new("synthetic_100mb.bin"));
    let bin_obs = Box::new(BinaryStreamObserver::new());
    let (digest, findings) = session
        .run("application/octet-stream", vec![text_obs, bin_obs])
        .unwrap();
    let duration_single = start_single.elapsed();

    assert!(!digest.is_empty());
    assert!(!findings.is_empty());
    let metrics = session.metrics.into_inner();
    assert_eq!(
        metrics.full_passes, 1,
        "Single-pass run must use exactly 1 full pass"
    );

    println!("\n--- Single-Pass Benchmark (100 MiB) ---");
    println!("Duration: {:?}", duration_single);
    println!("Sequential Bytes Read: {}", metrics.bytes_read_sequential);
    println!("Full Passes: {}", metrics.full_passes);
}
