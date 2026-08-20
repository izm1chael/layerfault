use layerfault::archive::{self, ArchiveFormat, ArchiveLimits, CoverageState};
use layerfault::scanner::ScanStatus;
use std::fs::{self, File};
use std::io::Write;
use tempfile::tempdir;

fn create_zip_archive<F>(path: &std::path::Path, build_fn: F) -> anyhow::Result<()>
where
    F: FnOnce(&mut zip::ZipWriter<File>) -> anyhow::Result<()>,
{
    let file = File::create(path)?; // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path -- tempdir-scoped test fixture
    let mut zip = zip::ZipWriter::new(file);
    build_fn(&mut zip)?;
    zip.finish()?;
    Ok(())
}

fn create_tar_archive<F>(path: &std::path::Path, build_fn: F) -> anyhow::Result<()>
where
    F: FnOnce(&mut tar::Builder<File>) -> anyhow::Result<()>,
{
    let file = File::create(path)?; // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path -- tempdir-scoped test fixture
    let mut builder = tar::Builder::new(file);
    build_fn(&mut builder)?;
    builder.finish()?;
    Ok(())
}

fn create_tar_gz_archive<F>(path: &std::path::Path, build_fn: F) -> anyhow::Result<()>
where
    F: FnOnce(&mut tar::Builder<flate2::write::GzEncoder<File>>) -> anyhow::Result<()>,
{
    let file = File::create(path)?; // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path -- tempdir-scoped test fixture
    let gz = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut builder = tar::Builder::new(gz);
    build_fn(&mut builder)?;
    builder.finish()?;
    Ok(())
}

#[test]
fn test_safe_zip_containing_config() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let zip_path = dir.path().join("safe.zip");

    create_zip_archive(&zip_path, |zip| {
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("config.json", options)?;
        zip.write_all(br#"{"architectures":["TestModel"]}"#)?;
        Ok(())
    })?;

    let limits = ArchiveLimits::default();
    let report = archive::inspect(&zip_path, &limits)?;

    assert_eq!(report.format, ArchiveFormat::Zip);
    assert_eq!(report.members.len(), 1);
    assert_eq!(
        report.members[0].virtual_path,
        format!("file:{}!/config.json", zip_path.display())
    );
    assert_eq!(report.coverage.state, CoverageState::Complete);
    assert!(!report.findings.iter().any(|f| f.status == ScanStatus::Fail));
    Ok(())
}

#[test]
fn test_zip_containing_python_process_call() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let zip_path = dir.path().join("code_exec.zip");

    create_zip_archive(&zip_path, |zip| {
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("payload.py", options)?;
        zip.write_all(b"import os\nos.system('echo malicious')\n")?;
        Ok(())
    })?;

    let limits = ArchiveLimits::default();
    let report = archive::inspect(&zip_path, &limits)?;

    assert!(report
        .findings
        .iter()
        .any(|f| f.matches.iter().any(|m| m.contains("LF-CODE-OS-SYSTEM"))));
    Ok(())
}

#[test]
fn test_zip_containing_pickle_dangerous_global() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let zip_path = dir.path().join("pickle.zip");

    create_zip_archive(&zip_path, |zip| {
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("model.pkl", options)?;
        // Protocol 2 pickle calling os.system
        let pickle_bytes =
            b"\x80\x02cposix\nsystem\nq\x00X\x04\x00\x00\x00evalq\x01\x85q\x02Rq\x03.";
        zip.write_all(pickle_bytes)?;
        Ok(())
    })?;

    let limits = ArchiveLimits::default();
    let report = archive::inspect(&zip_path, &limits)?;

    assert!(report.findings.iter().any(|f| f
        .matches
        .iter()
        .any(|m| m.contains("LF-PICKLE-DANGEROUS-GLOBAL"))
        && f.status == ScanStatus::Fail));
    Ok(())
}

#[test]
fn test_nested_zip_tar_python() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let inner_tar_path = dir.path().join("inner.tar");
    let outer_zip_path = dir.path().join("outer.zip");

    create_tar_archive(&inner_tar_path, |builder| {
        let mut header = tar::Header::new_gnu();
        let content = b"import subprocess\nsubprocess.run(['cat', '/etc/passwd'])\n";
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, "script.py", &content[..])?;
        Ok(())
    })?;

    let tar_bytes = fs::read(&inner_tar_path)?;

    create_zip_archive(&outer_zip_path, |zip| {
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("inner.tar", options)?;
        zip.write_all(&tar_bytes)?;
        Ok(())
    })?;

    let limits = ArchiveLimits::default();
    let report = archive::inspect(&outer_zip_path, &limits)?;

    assert!(report
        .findings
        .iter()
        .any(|f| f.matches.iter().any(|m| m.contains("LF-CODE-SUBPROCESS"))));
    Ok(())
}

#[test]
fn test_path_traversal_variants() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let zip_path = dir.path().join("traversal.zip");

    create_zip_archive(&zip_path, |zip| {
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("../../evil.py", options)?;
        zip.write_all(b"print(1)")?;
        zip.start_file("/abs/path.py", options)?;
        zip.write_all(b"print(2)")?;
        Ok(())
    })?;

    let limits = ArchiveLimits::default();
    let report = archive::inspect(&zip_path, &limits)?;

    assert!(report.findings.iter().any(|f| f
        .matches
        .iter()
        .any(|m| m.contains("LF-ARCHIVE-TRAVERSAL"))
        && f.status == ScanStatus::Fail));
    assert_eq!(report.coverage.state, CoverageState::Incomplete);
    Ok(())
}

#[test]
fn test_symlink_and_hardlink_members() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let tar_path = dir.path().join("links.tar");

    create_tar_archive(&tar_path, |builder| {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_cksum();
        builder.append_link(&mut header, "symlink.txt", "../target.txt")?;

        let mut hard_header = tar::Header::new_gnu();
        hard_header.set_entry_type(tar::EntryType::Link);
        hard_header.set_size(0);
        hard_header.set_cksum();
        builder.append_link(&mut hard_header, "hardlink.txt", "target.txt")?;
        Ok(())
    })?;

    let limits = ArchiveLimits::default();
    let report = archive::inspect(&tar_path, &limits)?;

    assert!(report
        .findings
        .iter()
        .any(|f| f.matches.iter().any(|m| m.contains("LF-ARCHIVE-LINK"))));
    assert_eq!(report.members.len(), 2);
    assert!(report.members.iter().any(|m| m.is_symlink));
    assert!(report.members.iter().any(|m| m.is_hardlink));
    Ok(())
}

#[test]
fn test_duplicate_names_and_case_collisions() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let zip_path = dir.path().join("duplicates.zip");

    let mut raw = Vec::new();
    let entries = [
        ("model.py", b"# v1".as_slice()),
        ("model.py", b"# v2".as_slice()),
        ("Model.py", b"# v3".as_slice()),
    ];
    let mut cd_offsets = Vec::new();

    for (name, content) in &entries {
        let offset = raw.len() as u32;
        cd_offsets.push((offset, *name, content.len() as u32));

        raw.extend_from_slice(b"PK\x03\x04");
        raw.extend_from_slice(&[0x14, 0x00]); // version needed
        raw.extend_from_slice(&[0x00, 0x00]); // flags
        raw.extend_from_slice(&[0x00, 0x00]); // compression = stored
        raw.extend_from_slice(&[0x00, 0x00]); // time
        raw.extend_from_slice(&[0x00, 0x00]); // date
        raw.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // crc32
        let size = content.len() as u32;
        raw.extend_from_slice(&size.to_le_bytes());
        raw.extend_from_slice(&size.to_le_bytes());
        let name_len = name.len() as u16;
        raw.extend_from_slice(&name_len.to_le_bytes());
        raw.extend_from_slice(&[0x00, 0x00]); // extra len
        raw.extend_from_slice(name.as_bytes());
        raw.extend_from_slice(content);
    }

    let cd_start = raw.len() as u32;
    for (offset, name, size) in cd_offsets {
        raw.extend_from_slice(b"PK\x01\x02");
        raw.extend_from_slice(&[0x14, 0x00]); // version made
        raw.extend_from_slice(&[0x14, 0x00]); // version needed
        raw.extend_from_slice(&[0x00, 0x00]); // flags
        raw.extend_from_slice(&[0x00, 0x00]); // stored
        raw.extend_from_slice(&[0x00, 0x00]); // time
        raw.extend_from_slice(&[0x00, 0x00]); // date
        raw.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // crc32
        raw.extend_from_slice(&size.to_le_bytes());
        raw.extend_from_slice(&size.to_le_bytes());
        let name_len = name.len() as u16;
        raw.extend_from_slice(&name_len.to_le_bytes());
        raw.extend_from_slice(&[0x00, 0x00]); // extra
        raw.extend_from_slice(&[0x00, 0x00]); // comment
        raw.extend_from_slice(&[0x00, 0x00]); // disk
        raw.extend_from_slice(&[0x00, 0x00]); // int attr
        raw.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ext attr
        raw.extend_from_slice(&offset.to_le_bytes());
        raw.extend_from_slice(name.as_bytes());
    }

    let cd_end = raw.len() as u32;
    let cd_size = cd_end - cd_start;

    raw.extend_from_slice(b"PK\x05\x06");
    raw.extend_from_slice(&[0x00, 0x00]);
    raw.extend_from_slice(&[0x00, 0x00]);
    raw.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    raw.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    raw.extend_from_slice(&cd_size.to_le_bytes());
    raw.extend_from_slice(&cd_start.to_le_bytes());
    raw.extend_from_slice(&[0x00, 0x00]);

    fs::write(&zip_path, raw)?;

    let limits = ArchiveLimits::default();
    let report = archive::inspect(&zip_path, &limits)?;

    assert!(report
        .findings
        .iter()
        .any(|f| f.matches.iter().any(|m| m.contains("LF-ARCHIVE-DUPLICATE"))));
    Ok(())
}

#[test]
fn test_actual_decompression_exceeds_cap_bomb() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let zip_path = dir.path().join("bomb.zip");

    create_zip_archive(&zip_path, |zip| {
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        zip.start_file("bomb.txt", options)?;
        // Write 2 MiB of zeros which compresses extremely well
        let zeros = vec![0_u8; 2 * 1024 * 1024];
        zip.write_all(&zeros)?;
        Ok(())
    })?;

    // Set uncompressed member limit to 1 MiB
    let limits = ArchiveLimits {
        max_uncompressed_member_bytes: 1024 * 1024,
        max_uncompressed_total_bytes: 2 * 1024 * 1024 * 1024,
        ..ArchiveLimits::default()
    };

    let report = archive::inspect(&zip_path, &limits)?;

    assert!(report.findings.iter().any(|f| f
        .matches
        .iter()
        .any(|m| m.contains("LF-ARCHIVE-BOMB"))
        && f.status == ScanStatus::Fail));
    assert_eq!(report.coverage.state, CoverageState::Incomplete);
    Ok(())
}

#[test]
fn test_encrypted_zip_member() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let zip_path = dir.path().join("encrypted.zip");

    let mut raw_zip = Vec::new();
    // Local header: PK\x03\x04
    raw_zip.extend_from_slice(b"PK\x03\x04");
    raw_zip.extend_from_slice(&[0x14, 0x00]); // version
    raw_zip.extend_from_slice(&[0x01, 0x00]); // general bit flag = 1 (encrypted)
    raw_zip.extend_from_slice(&[0x00, 0x00]); // compression = 0
    raw_zip.extend_from_slice(&[0x00, 0x00]); // time
    raw_zip.extend_from_slice(&[0x00, 0x00]); // date
    raw_zip.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // crc32
    raw_zip.extend_from_slice(&[0x06, 0x00, 0x00, 0x00]); // compressed size = 6
    raw_zip.extend_from_slice(&[0x06, 0x00, 0x00, 0x00]); // uncompressed size = 6
    raw_zip.extend_from_slice(&[0x09, 0x00]); // filename len = 9
    raw_zip.extend_from_slice(&[0x00, 0x00]); // extra len = 0
    raw_zip.extend_from_slice(b"secret.py"); // filename
    raw_zip.extend_from_slice(b"secret"); // body data

    let cd_offset = raw_zip.len() as u32;

    // Central directory header: PK\x01\x02
    raw_zip.extend_from_slice(b"PK\x01\x02");
    raw_zip.extend_from_slice(&[0x14, 0x00]); // version made
    raw_zip.extend_from_slice(&[0x14, 0x00]); // version needed
    raw_zip.extend_from_slice(&[0x01, 0x00]); // general bit flag = 1 (encrypted)
    raw_zip.extend_from_slice(&[0x00, 0x00]); // compression = 0
    raw_zip.extend_from_slice(&[0x00, 0x00]); // time
    raw_zip.extend_from_slice(&[0x00, 0x00]); // date
    raw_zip.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // crc32
    raw_zip.extend_from_slice(&[0x06, 0x00, 0x00, 0x00]); // compressed size
    raw_zip.extend_from_slice(&[0x06, 0x00, 0x00, 0x00]); // uncompressed size
    raw_zip.extend_from_slice(&[0x09, 0x00]); // filename len
    raw_zip.extend_from_slice(&[0x00, 0x00]); // extra len
    raw_zip.extend_from_slice(&[0x00, 0x00]); // comment len
    raw_zip.extend_from_slice(&[0x00, 0x00]); // disk start
    raw_zip.extend_from_slice(&[0x00, 0x00]); // int attr
    raw_zip.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ext attr
    raw_zip.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // offset of local header = 0
    raw_zip.extend_from_slice(b"secret.py");

    let cd_size = (raw_zip.len() as u32) - cd_offset;

    // End of central directory record: PK\x05\x06
    raw_zip.extend_from_slice(b"PK\x05\x06");
    raw_zip.extend_from_slice(&[0x00, 0x00]); // disk num
    raw_zip.extend_from_slice(&[0x00, 0x00]); // cd disk
    raw_zip.extend_from_slice(&[0x01, 0x00]); // entries on disk = 1
    raw_zip.extend_from_slice(&[0x01, 0x00]); // total entries = 1
    raw_zip.extend_from_slice(&cd_size.to_le_bytes());
    raw_zip.extend_from_slice(&cd_offset.to_le_bytes());
    raw_zip.extend_from_slice(&[0x00, 0x00]); // comment len

    fs::write(&zip_path, raw_zip)?;

    let limits = ArchiveLimits::default();
    let report = archive::inspect(&zip_path, &limits)?;

    assert!(report
        .findings
        .iter()
        .any(|f| f.matches.iter().any(|m| m.contains("LF-ARCHIVE-ENCRYPTED"))));
    assert_eq!(report.coverage.state, CoverageState::Incomplete);
    assert!(report.members[0].is_encrypted);

    Ok(())
}

#[test]
fn test_cumulative_nested_budgets() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let inner_zip = dir.path().join("inner.zip");
    let outer_zip = dir.path().join("outer.zip");

    create_zip_archive(&inner_zip, |zip| {
        let options = zip::write::SimpleFileOptions::default();
        for i in 0..10 {
            zip.start_file(format!("file_{}.txt", i), options)?;
            zip.write_all(b"data")?;
        }
        Ok(())
    })?;

    let inner_bytes = fs::read(&inner_zip)?;

    create_zip_archive(&outer_zip, |zip| {
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("inner.zip", options)?;
        zip.write_all(&inner_bytes)?;
        Ok(())
    })?;

    // Set max_members_total to 5
    let limits = ArchiveLimits {
        max_members_total: 5,
        ..ArchiveLimits::default()
    };

    let report = archive::inspect(&outer_zip, &limits)?;

    assert!(report
        .findings
        .iter()
        .any(|f| f.matches.iter().any(|m| m.contains("LF-ARCHIVE-LIMIT"))));
    assert_eq!(report.coverage.state, CoverageState::Incomplete);
    Ok(())
}

#[test]
fn test_format_smuggling_mismatch() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let fake_zip_path = dir.path().join("payload.tar.gz");

    // Write a ZIP file content but with extension .tar.gz
    create_zip_archive(&fake_zip_path, |zip| {
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("data.json", options)?;
        zip.write_all(b"{}")?;
        Ok(())
    })?;

    let limits = ArchiveLimits::default();
    let report = archive::inspect(&fake_zip_path, &limits)?;

    assert!(report.findings.iter().any(|f| f
        .matches
        .iter()
        .any(|m| m.contains("LF-ARCHIVE-FORMAT-MISMATCH"))
        && f.status == ScanStatus::Fail));
    Ok(())
}

#[test]
fn test_wheel_metadata_and_record_verification() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let whl_path = dir.path().join("pkg-1.0.0-py3-none-any.whl");

    create_zip_archive(&whl_path, |zip| {
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("pkg/__init__.py", options)?;
        zip.write_all(b"# init")?;

        zip.start_file("pkg-1.0.0.dist-info/METADATA", options)?;
        zip.write_all(b"Metadata-Version: 2.1\nName: pkg\nVersion: 1.0.0\nRequires-Dist: requests (>=2.0.0)\n")?;

        zip.start_file("pkg-1.0.0.dist-info/RECORD", options)?;
        // Write mismatched hash/size for pkg/__init__.py
        zip.write_all(b"pkg/__init__.py,sha256=invalidhash,999\npkg-1.0.0.dist-info/RECORD,,\n")?;
        Ok(())
    })?;

    let limits = ArchiveLimits::default();
    let report = archive::inspect(&whl_path, &limits)?;

    assert_eq!(report.format, ArchiveFormat::Wheel);
    assert!(report.findings.iter().any(|f| f
        .matches
        .iter()
        .any(|m| m.contains("LF-WHEEL-RECORD-MISMATCH"))
        && f.status == ScanStatus::Fail));
    assert!(report.findings.iter().any(|f| f
        .matches
        .iter()
        .any(|m| m.contains("LF-ARCHIVE-SECURITY-MEMBER"))));
    Ok(())
}

#[test]
fn test_tar_gz_archive() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let tar_gz_path = dir.path().join("archive.tar.gz");

    create_tar_gz_archive(&tar_gz_path, |builder| {
        let mut header = tar::Header::new_gnu();
        let content = b"print('hello tar gz')\n";
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, "app.py", &content[..])?;
        Ok(())
    })?;

    let limits = ArchiveLimits::default();
    let report = archive::inspect(&tar_gz_path, &limits)?;

    assert_eq!(report.format, ArchiveFormat::TarGz);
    assert_eq!(report.members.len(), 1);
    assert_eq!(
        report.members[0].virtual_path,
        format!("file:{}!/app.py", tar_gz_path.display())
    );
    assert_eq!(report.coverage.state, CoverageState::Complete);

    Ok(())
}

#[test]
fn test_standalone_wheel_and_zip_artifact_inspection() -> anyhow::Result<()> {
    let dir = tempdir()?;
    let wheel_path = dir.path().join("tampered_package-1.0.0-py3-none-any.whl");

    create_zip_archive(&wheel_path, |zip| {
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("tampered_package/__init__.py", options)?;
        zip.write_all(b"# tampered code\n")?;

        zip.start_file("tampered_package-1.0.0.dist-info/METADATA", options)?;
        zip.write_all(b"Metadata-Version: 2.1\nName: tampered_package\nVersion: 1.0.0\n")?;

        zip.start_file("tampered_package-1.0.0.dist-info/RECORD", options)?;
        // Bad hash in RECORD
        zip.write_all(b"tampered_package/__init__.py,sha256=invalid_hash,16\n")?;
        Ok(())
    })?;

    let report = layerfault::formats::artifact::inspect(
        &wheel_path,
        layerfault::formats::artifact::ArtifactScanMode::Full,
    )?;
    assert!(
        report.results.iter().any(|f| f.matches.iter().any(|m| m.contains("LF-WHEEL-RECORD-MISMATCH"))),
        "standalone wheel scan must route to archive inspection and emit LF-WHEEL-RECORD-MISMATCH: {:?}",
        report.results
    );
    assert!(
        !report.results.iter().any(|f| f
            .matches
            .iter()
            .any(|m| m.contains("LF-PYTORCH-ZIP-STRUCTURAL"))),
        "standalone wheel must not be misclassified as PyTorch zip"
    );

    Ok(())
}
