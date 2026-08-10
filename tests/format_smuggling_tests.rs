use anyhow::Result;
use layerfault::formats::artifact::{inspect, ArtifactScanMode};
use std::fs;
use std::io::Write;
use tempfile::tempdir;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

fn safetensors_fixture(header_json: &str, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(header_json.len() as u64).to_le_bytes());
    out.extend_from_slice(header_json.as_bytes());
    out.extend_from_slice(data);
    out
}

fn minimal_pe64() -> Vec<u8> {
    let mut bytes = vec![0_u8; 272];
    bytes[0..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&64_u32.to_le_bytes());
    let pe = 64_usize;
    bytes[pe..pe + 4].copy_from_slice(b"PE\0\0");
    bytes[pe + 4..pe + 6].copy_from_slice(&0x8664_u16.to_le_bytes());
    bytes[pe + 6..pe + 8].copy_from_slice(&1_u16.to_le_bytes());
    bytes[pe + 20..pe + 22].copy_from_slice(&112_u16.to_le_bytes());
    bytes[pe + 24..pe + 26].copy_from_slice(&0x020b_u16.to_le_bytes());
    let section = pe + 24 + 112;
    bytes[section + 16..section + 20].copy_from_slice(&16_u32.to_le_bytes());
    bytes[section + 20..section + 24].copy_from_slice(&256_u32.to_le_bytes());
    bytes
}

fn minimal_zip() -> Vec<u8> {
    let mut buf = Vec::new();
    let mut writer = ZipWriter::new(std::io::Cursor::new(&mut buf));
    writer
        .start_file("member.txt", SimpleFileOptions::default())
        .unwrap();
    writer.write_all(b"hello").unwrap();
    writer.finish().unwrap();
    buf
}

#[test]
fn safetensors_containing_pickle_triggers_claim_mismatch() -> Result<()> {
    let dir = tempdir()?;
    let path = dir.path().join("model.safetensors");
    // Pickle protocol 2 stream
    let pickle_bytes = [
        0x80, 0x02, b'c', b'o', b's', b'\n', b's', b'y', b's', b't', b'e', b'm', b'\n', b'q', 0x00,
        b'.',
    ];
    fs::write(&path, pickle_bytes)?;

    let report = inspect(&path, ArtifactScanMode::Full)?;
    assert!(report.blocking());
    assert!(report.results.iter().any(|f| f.rule_id.as_deref()
        == Some("LF-FORMAT-CONTENT-SMUGGLING")
        || f.rule_id.as_deref() == Some("LF-FORMAT-CLAIM-MISMATCH")));
    Ok(())
}

#[test]
fn gguf_containing_zip_triggers_container_smuggling() -> Result<()> {
    let dir = tempdir()?;
    let path = dir.path().join("weights.gguf");
    let zip_bytes = minimal_zip();
    fs::write(&path, zip_bytes)?;

    let report = inspect(&path, ArtifactScanMode::Full)?;
    assert!(report.blocking());
    assert!(report
        .results
        .iter()
        .any(|f| f.rule_id.as_deref() == Some("LF-FORMAT-CONTENT-SMUGGLING")));
    Ok(())
}

#[test]
fn unknown_extension_with_valid_safetensors_is_scanned_clean() -> Result<()> {
    let dir = tempdir()?;
    let path = dir.path().join("weights.custom");
    let bytes = safetensors_fixture(
        r#"{"w":{"dtype":"F32","shape":[2],"data_offsets":[0,8]}}"#,
        &[0; 8],
    );
    fs::write(&path, bytes)?;

    let report = inspect(&path, ArtifactScanMode::Full)?;
    assert_eq!(
        report.format,
        layerfault::formats::ArtifactFormat::Safetensors
    );
    assert!(!report.blocking());
    Ok(())
}

#[test]
fn bin_extension_with_pickle_is_identified_and_scanned_without_mismatch() -> Result<()> {
    let dir = tempdir()?;
    let path = dir.path().join("weights.bin");
    // Safe pickle globals
    let pickle_bytes = [
        0x80, 0x04, 0x95, 0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8c, 0x08, b't', b'o',
        b'r', b'c', b'h', b'.', b'_', b'n', 0x8c, 0x06, b'T', b'e', b'n', b's', b'o', b'r', 0x93,
        0x2e,
    ];
    fs::write(&path, pickle_bytes)?;

    let report = inspect(&path, ArtifactScanMode::Full)?;
    assert_eq!(report.format, layerfault::formats::ArtifactFormat::Pickle);
    assert!(
        !report
            .results
            .iter()
            .any(|f| f.rule_id.as_deref() == Some("LF-FORMAT-CLAIM-MISMATCH")),
        "bin extension must not generate false mismatch findings"
    );
    Ok(())
}

#[test]
fn valid_safetensors_with_appended_pickle_triggers_appended_serialization() -> Result<()> {
    let dir = tempdir()?;
    let path = dir.path().join("weights.safetensors");
    let mut bytes = safetensors_fixture(
        r#"{"w":{"dtype":"F32","shape":[2],"data_offsets":[0,8]}}"#,
        &[0; 8],
    );
    let pickle_bytes = [
        0x80, 0x02, b'c', b'o', b's', b'\n', b's', b'y', b's', b't', b'e', b'm', b'\n', b'q', 0x00,
        b'.',
    ];
    bytes.extend_from_slice(&pickle_bytes);
    fs::write(&path, bytes)?;

    let report = inspect(&path, ArtifactScanMode::Full)?;
    assert!(report.blocking());
    assert!(report
        .results
        .iter()
        .any(|f| f.rule_id.as_deref() == Some("LF-FORMAT-APPENDED-SERIALIZATION")));
    Ok(())
}

#[test]
fn valid_safetensors_with_appended_zip_triggers_appended_archive() -> Result<()> {
    let dir = tempdir()?;
    let path = dir.path().join("weights.safetensors");
    let mut bytes = safetensors_fixture(
        r#"{"w":{"dtype":"F32","shape":[2],"data_offsets":[0,8]}}"#,
        &[0; 8],
    );
    bytes.extend_from_slice(&minimal_zip());
    fs::write(&path, bytes)?;

    let report = inspect(&path, ArtifactScanMode::Full)?;
    assert!(report.blocking());
    assert!(report
        .results
        .iter()
        .any(|f| f.rule_id.as_deref() == Some("LF-FORMAT-APPENDED-ARCHIVE")));
    Ok(())
}

#[test]
fn trailing_zero_padding_only_is_accepted_as_clean() -> Result<()> {
    let dir = tempdir()?;
    let path = dir.path().join("padded.safetensors");
    let mut bytes = safetensors_fixture(
        r#"{"w":{"dtype":"F32","shape":[2],"data_offsets":[0,8]}}"#,
        &[0; 8],
    );
    bytes.extend_from_slice(&[0_u8; 32]); // Alignment zeros
    fs::write(&path, bytes)?;

    let report = inspect(&path, ArtifactScanMode::Full)?;
    assert!(!report.blocking());
    assert!(
        !report
            .results
            .iter()
            .any(|f| f.rule_id.as_deref() == Some("LF-FORMAT-TRAILING-DATA")),
        "trailing zeros must not trigger trailing data warning"
    );
    Ok(())
}

#[test]
fn random_mz_coincidence_in_tensor_data_does_not_become_pe_polyglot() -> Result<()> {
    let dir = tempdir()?;
    let path = dir.path().join("coincidence.safetensors");
    let mut tensor_data = vec![0_u8; 128];
    tensor_data[10..12].copy_from_slice(b"MZ");
    tensor_data[12..20].copy_from_slice(b"NOT_A_PE");
    let bytes = safetensors_fixture(
        r#"{"w":{"dtype":"U8","shape":[128],"data_offsets":[0,128]}}"#,
        &tensor_data,
    );
    fs::write(&path, bytes)?;

    let report = inspect(&path, ArtifactScanMode::Full)?;
    assert!(
        !report
            .results
            .iter()
            .any(|f| f.rule_id.as_deref() == Some("LF-FORMAT-POLYGLOT")
                || f.rule_id.as_deref() == Some("T12-002")),
        "random MZ bytes in tensor data must not trigger false PE/polyglot finding"
    );
    Ok(())
}

#[test]
fn structurally_valid_appended_pe_triggers_polyglot() -> Result<()> {
    let dir = tempdir()?;
    let path = dir.path().join("polyglot.safetensors");
    let mut bytes = safetensors_fixture(
        r#"{"w":{"dtype":"F32","shape":[2],"data_offsets":[0,8]}}"#,
        &[0; 8],
    );
    bytes.extend_from_slice(&minimal_pe64());
    fs::write(&path, bytes)?;

    let report = inspect(&path, ArtifactScanMode::Full)?;
    assert!(report.blocking());
    assert!(report.results.iter().any(|f| {
        let rule = f.rule_id.as_deref();
        rule == Some("LF-FORMAT-POLYGLOT") || rule == Some("T12-002")
    }));
    Ok(())
}
