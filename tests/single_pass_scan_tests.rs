use layerfault::safeio::open_readonly_nofollow;
use layerfault::scanner::{BinaryStreamObserver, ScanSession, TextStreamObserver};
use std::io::Write;
use tempfile::tempdir;

#[test]
fn single_pass_digest_matches_standard_hasher() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test_blob.bin");
    let content = vec![0xAB_u8; 2 * 1024 * 1024];
    std::fs::write(&file_path, &content).unwrap();

    let file = open_readonly_nofollow(&file_path).unwrap();
    let session = ScanSession::new(&file_path, &file).unwrap();

    let (digest, _) = session.run("application/octet-stream", vec![]).unwrap();

    let std_digest = layerfault::hashcache::sha256_uncached_prefixed(&file).unwrap();
    assert_eq!(digest, std_digest);
    assert_eq!(session.metrics.borrow().full_passes, 1);
    assert_eq!(
        session.metrics.borrow().bytes_read_sequential,
        content.len() as u64
    );
}

#[test]
fn cross_chunk_boundary_text_signature_detected() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("boundary_script.py");

    // Fill exactly 1 MiB chunk minus 4 bytes, then write "os.system('id')" across boundary
    let chunk_size = 1024 * 1024;
    let mut content = vec![b' '; chunk_size - 4];
    content.extend_from_slice(b"os.system('id')\n");
    content.extend_from_slice(&vec![b' '; chunk_size]);

    std::fs::write(&file_path, &content).unwrap();

    let file = open_readonly_nofollow(&file_path).unwrap();
    let session = ScanSession::new(&file_path, &file).unwrap();

    let text_obs = Box::new(TextStreamObserver::new("boundary_script.py"));
    let (_digest, findings) = session
        .run("application/vnd.layerfault.package-member", vec![text_obs])
        .unwrap();

    assert!(
        findings
            .iter()
            .any(|f| f.rule_id.as_deref() == Some("LF-CODE-OS-SYSTEM")),
        "Cross-chunk boundary os.system signature must be detected"
    );
}

#[test]
fn embedded_binary_offset_is_accurate() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("embedded_elf.bin");

    let target_offset = 0x4000_u64; // 16 KiB
    let mut content = vec![0_u8; target_offset as usize];
    // ELF magic header: 0x7f, 'E', 'L', 'F'
    content.extend_from_slice(b"\x7fELF\x02\x01\x01\x00");
    content.extend_from_slice(&vec![0_u8; 1024]);

    std::fs::write(&file_path, &content).unwrap();

    let file = open_readonly_nofollow(&file_path).unwrap();
    let session = ScanSession::new(&file_path, &file).unwrap();

    let bin_obs = Box::new(BinaryStreamObserver::new());
    let (_digest, findings) = session
        .run("application/octet-stream", vec![bin_obs])
        .unwrap();

    assert!(
        !findings.is_empty(),
        "Embedded ELF binary observer should produce a finding"
    );
    let f = &findings[0];
    assert_eq!(f.status, layerfault::scanner::ScanStatus::Fail);
    assert!(f.matches.iter().any(|m| m.contains("0x4000")));
}

#[test]
fn package_inspection_fuses_reads_and_tracks_metrics() {
    let dir = tempdir().unwrap();
    let pkg_dir = dir.path().join("my_model_package");
    std::fs::create_dir_all(&pkg_dir).unwrap();

    let script_path = pkg_dir.join("main.py");
    std::fs::write(
        &script_path,
        b"import os\ndef run():\n    os.system('echo dangerous')\n",
    )
    .unwrap();

    let report = layerfault::package::inspect(&pkg_dir).unwrap();
    assert!(report.metrics.is_some());
    let metrics = report.metrics.unwrap();
    assert!(metrics.bytes_read_sequential > 0);

    // Verify findings include LF-CODE-OS-SYSTEM
    assert!(report
        .findings
        .iter()
        .any(|f| f.rule_id.as_deref() == Some("LF-CODE-OS-SYSTEM")));
}

#[test]
fn toctou_mutation_during_scan_is_rejected() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("mutating_file.bin");
    std::fs::write(&file_path, vec![0xAA_u8; 1024 * 1024]).unwrap();

    let file = open_readonly_nofollow(&file_path).unwrap();
    let session = ScanSession::new(&file_path, &file).unwrap();

    // Truncate/modify file on disk before session.run finishes identity revalidation
    let mut writer = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&file_path)
        .unwrap();
    writer.write_all(b"MODIFIED AND TRUNCATED CONTENT").unwrap();
    writer.sync_all().unwrap();

    let res = session.run("application/octet-stream", vec![]);
    assert!(
        res.is_err(),
        "Modification during scan session must trigger TOCTOU error"
    );
}
