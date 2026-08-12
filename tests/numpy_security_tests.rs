use layerfault::budget::{ScanBudget, ScanBudgetProfile};
use layerfault::formats::artifact::{inspect_opened_file_with_sha256_budget, ArtifactScanMode};
use layerfault::formats::ArtifactFormat;
use layerfault::scanner::ScanStatus;
use std::io::Write;
use tempfile::NamedTempFile;

fn default_budget() -> ScanBudget {
    ScanBudget::new(ScanBudgetProfile::Default.limits()).unwrap()
}

fn create_npy_v1(descr: &str, fortran: bool, shape: &[u64], payload: &[u8]) -> NamedTempFile {
    let mut file = NamedTempFile::new().unwrap();
    let shape_str = if shape.len() == 1 {
        format!("({},)", shape[0])
    } else {
        format!(
            "({})",
            shape
                .iter()
                .map(|d| d.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let descr_val = if descr.starts_with('[') {
        descr.to_string()
    } else {
        format!("'{descr}'")
    };
    let header_dict = format!(
        "{{'descr': {descr_val}, 'fortran_order': {}, 'shape': {shape_str}, }}",
        if fortran { "True" } else { "False" }
    );

    // Header padding to 16-byte alignment ending in \n
    let prefix_len = 10;
    let total_unpadded = prefix_len + header_dict.len();
    let pad_len = (16 - (total_unpadded % 16)) % 16;
    let mut header_padded = header_dict.into_bytes();
    header_padded.extend(std::iter::repeat_n(b' ', pad_len));
    if header_padded.ends_with(b" ") {
        let last = header_padded.len() - 1;
        header_padded[last] = b'\n';
    } else {
        header_padded.push(b'\n');
    }

    let hlen = header_padded.len() as u16;
    file.write_all(b"\x93NUMPY\x01\x00").unwrap();
    file.write_all(&hlen.to_le_bytes()).unwrap();
    file.write_all(&header_padded).unwrap();
    file.write_all(payload).unwrap();
    file.flush().unwrap();
    file
}

fn create_npy_v2(descr: &str, fortran: bool, shape: &[u64], payload: &[u8]) -> NamedTempFile {
    let mut file = NamedTempFile::new().unwrap();
    let shape_str = if shape.len() == 1 {
        format!("({},)", shape[0])
    } else {
        format!(
            "({})",
            shape
                .iter()
                .map(|d| d.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let descr_val = if descr.starts_with('[') {
        descr.to_string()
    } else {
        format!("'{descr}'")
    };
    let header_dict = format!(
        "{{'descr': {descr_val}, 'fortran_order': {}, 'shape': {shape_str}, }}",
        if fortran { "True" } else { "False" }
    );

    let prefix_len = 12;
    let total_unpadded = prefix_len + header_dict.len();
    let pad_len = (16 - (total_unpadded % 16)) % 16;
    let mut header_padded = header_dict.into_bytes();
    header_padded.extend(std::iter::repeat_n(b' ', pad_len));
    if header_padded.ends_with(b" ") {
        let last = header_padded.len() - 1;
        header_padded[last] = b'\n';
    } else {
        header_padded.push(b'\n');
    }

    let hlen = header_padded.len() as u32;
    file.write_all(b"\x93NUMPY\x02\x00").unwrap();
    file.write_all(&hlen.to_le_bytes()).unwrap();
    file.write_all(&header_padded).unwrap();
    file.write_all(payload).unwrap();
    file.flush().unwrap();
    file
}

#[test]
fn test_valid_npy_v1_numeric() {
    let payload = vec![0u8; 80]; // 10 * 8 bytes
    let file = create_npy_v1("<f8", false, &[10], &payload);
    let budget = default_budget();
    let file_obj = std::fs::File::open(file.path()).unwrap();

    let report = inspect_opened_file_with_sha256_budget(
        file.path(),
        &file_obj,
        ArtifactFormat::Npy,
        ArtifactScanMode::Full,
        "dummy_digest",
        &budget,
    )
    .unwrap();

    assert_eq!(report.format, ArtifactFormat::Npy);
    assert!(report.results.iter().any(|r| r.status == ScanStatus::Pass));
}

#[test]
fn test_valid_npy_v2_big_endian_numeric() {
    let payload = vec![0u8; 40]; // 10 * 4 bytes
    let file = create_npy_v2(">i4", true, &[5, 2], &payload);
    let budget = default_budget();
    let file_obj = std::fs::File::open(file.path()).unwrap();

    let report = inspect_opened_file_with_sha256_budget(
        file.path(),
        &file_obj,
        ArtifactFormat::Npy,
        ArtifactScanMode::Full,
        "dummy_digest",
        &budget,
    )
    .unwrap();

    assert_eq!(report.format, ArtifactFormat::Npy);
    assert!(report.results.iter().any(|r| r.status == ScanStatus::Pass));
}

#[test]
fn test_truncated_npy_data() {
    let payload = vec![0u8; 10]; // Requires 80 bytes for 10 * float64
    let file = create_npy_v1("<f8", false, &[10], &payload);
    let budget = default_budget();
    let file_obj = std::fs::File::open(file.path()).unwrap();

    let report = inspect_opened_file_with_sha256_budget(
        file.path(),
        &file_obj,
        ArtifactFormat::Npy,
        ArtifactScanMode::Full,
        "dummy_digest",
        &budget,
    )
    .unwrap();

    assert!(report
        .results
        .iter()
        .any(|r| r.status == ScanStatus::Fail
            && r.matches.iter().any(|m| m.contains("LF-NPY-STRUCT"))));
}

#[test]
fn test_object_dtype_array_with_dangerous_pickle() {
    // Dangerous pickle payload (os.system)
    let pickle_payload = b"cos\nsystem\n)R.";
    let file = create_npy_v1("O", false, &[1], pickle_payload);
    let budget = default_budget();
    let file_obj = std::fs::File::open(file.path()).unwrap();

    let report = inspect_opened_file_with_sha256_budget(
        file.path(),
        &file_obj,
        ArtifactFormat::Npy,
        ArtifactScanMode::Full,
        "dummy_digest",
        &budget,
    )
    .unwrap();

    assert!(report
        .results
        .iter()
        .any(|r| r.matches.iter().any(|m| m.contains("LF-NPY-OBJECT-DTYPE"))));
    assert!(report
        .results
        .iter()
        .any(|r| r.status == ScanStatus::Fail
            && r.matches.iter().any(|m| m.contains("LF-NPY-PICKLE"))));
}

#[test]
fn test_numeric_npy_rejects_trailing_payload() {
    let payload = vec![0u8; 81];
    let file = create_npy_v1("<f8", false, &[10], &payload);
    let budget = default_budget();
    let file_obj = std::fs::File::open(file.path()).unwrap();

    let report = inspect_opened_file_with_sha256_budget(
        file.path(),
        &file_obj,
        ArtifactFormat::Npy,
        ArtifactScanMode::Full,
        "dummy_digest",
        &budget,
    )
    .unwrap();

    assert!(report.results.iter().any(|result| {
        result.status == ScanStatus::Fail
            && result
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("trailing payload"))
    }));
}

#[test]
fn test_structured_dtype_supported_and_unsupported() {
    let payload = vec![0u8; 120]; // 10 * (8 + 4)
    let file = create_npy_v1("[('a', '<f8'), ('b', '<i4')]", false, &[10], &payload);
    let budget = default_budget();
    let file_obj = std::fs::File::open(file.path()).unwrap();

    let report = inspect_opened_file_with_sha256_budget(
        file.path(),
        &file_obj,
        ArtifactFormat::Npy,
        ArtifactScanMode::Full,
        "dummy_digest",
        &budget,
    )
    .unwrap();

    assert!(report.results.iter().any(|r| r.status == ScanStatus::Pass));
}

#[test]
fn test_extension_mismatch_contradiction() {
    // Safe numeric npy file named model.safetensors
    let payload = vec![0u8; 80];
    let _file = create_npy_v1("<f8", false, &[10], &payload);
    let prefix = b"\x93NUMPY\x01\x00";

    let ident = layerfault::formats::ArtifactIdentification::identify(
        std::path::Path::new("model.safetensors"),
        prefix,
    );
    assert_eq!(ident.extension_claim, Some(ArtifactFormat::Safetensors));
    assert_eq!(ident.selected, ArtifactFormat::Npy);
    assert_eq!(ident.contradictions.len(), 1);
    assert_eq!(
        ident.contradictions[0].kind,
        layerfault::formats::ContradictionKind::ExtensionMismatch
    );
}

#[test]
fn test_numpy_allow_pickle_call_correlates_with_object_array() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("loader.py"),
        b"import numpy as np\nnp.load('weights.npy', allow_pickle=True)\n",
    )
    .unwrap();
    let object_array = create_npy_v1("O", false, &[1], b"N.");
    std::fs::copy(object_array.path(), dir.path().join("weights.npy")).unwrap();

    let report = layerfault::package::inspect(dir.path()).unwrap();
    assert!(report
        .findings
        .iter()
        .any(|finding| { layerfault::policy::rule_id(finding) == "LF-PY-NUMPY-ALLOW-PICKLE" }));
    assert!(report
        .correlations
        .iter()
        .any(|correlation| correlation.id == "LF-CORR-NUMPY-ALLOW-PICKLE"));
}
