use crate::formats::artifact::{self, ArtifactScanMode};
use crate::formats::safetensors;
use crate::scanner::metadata::validate_gguf_bytes;
use anyhow::Result;
use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;

#[derive(Debug, Clone, serde::Serialize)]
pub struct CertificationCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CertificationReport {
    pub tool_version: String,
    pub passed: bool,
    pub checks: Vec<CertificationCheck>,
}

pub fn selftest() -> CertificationReport {
    let checks = vec![
        check(
            "gguf-truncated",
            validate_gguf_bytes(b"GGUF\x03\x00\x00\x00").is_err(),
            "truncated GGUF rejected",
        ),
        check(
            "gguf-invalid-version",
            validate_gguf_bytes(b"GGUF\xff\xff\xff\xff\0\0\0\0").is_err(),
            "invalid GGUF version rejected",
        ),
        check(
            "policy-unsafe-pattern",
            crate::policy::PolicyDocument {
                allowed_model_patterns: vec!["../escape".to_owned()],
                ..crate::policy::PolicyDocument::default()
            }
            .validate()
            .is_err(),
            "unsafe policy pattern rejected",
        ),
    ];
    let passed = checks.iter().all(|item| item.passed);
    CertificationReport {
        tool_version: env!("CARGO_PKG_VERSION").to_owned(),
        passed,
        checks,
    }
}

pub fn certify(include_sparse: bool) -> Result<CertificationReport> {
    let mut report = selftest();
    let root = temp_root();
    fs::create_dir_all(&root)?;

    let safe_path = root.join("valid.safetensors");
    let header = r#"{"w":{"dtype":"F32","shape":[2],"data_offsets":[0,8]}}"#;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(header.len() as u64).to_le_bytes());
    bytes.extend_from_slice(header.as_bytes());
    bytes.extend_from_slice(&[0_u8; 8]);
    fs::write(&safe_path, bytes)?;
    let opened = crate::safeio::open_readonly_nofollow(&safe_path)?;
    let valid = safetensors::validate_file(&opened, opened.metadata()?.len()).is_ok();
    report.checks.push(check(
        "safetensors-valid",
        valid,
        "valid Safetensors fixture accepted",
    ));

    let bad_path = root.join("hole.safetensors");
    let header = r#"{"w":{"dtype":"F32","shape":[1],"data_offsets":[4,8]}}"#;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(header.len() as u64).to_le_bytes());
    bytes.extend_from_slice(header.as_bytes());
    bytes.extend_from_slice(&[0_u8; 8]);
    fs::write(&bad_path, bytes)?;
    let opened = crate::safeio::open_readonly_nofollow(&bad_path)?;
    let invalid = safetensors::validate_file(&opened, opened.metadata()?.len()).is_err();
    report.checks.push(check(
        "safetensors-hole",
        invalid,
        "unindexed Safetensors hole rejected",
    ));

    let package_a = root.join("package-a");
    let package_b = root.join("package-b");
    fs::create_dir_all(&package_a)?;
    fs::create_dir_all(&package_b)?;
    fs::write(
        package_a.join("config.json"),
        br#"{"architectures":["Fixture"]}"#,
    )?;
    fs::write(
        package_b.join("config.json"),
        br#"{"architectures":["Fixture"]}"#,
    )?;
    let fp_a = crate::package::fingerprint(&package_a)?;
    let fp_b = crate::package::fingerprint(&package_b)?;
    report.checks.push(check(
        "package-location-independent",
        fp_a == fp_b && fp_a.starts_with("lfpkg:sha256:"),
        "identical packages at different roots receive the same canonical package identity",
    ));
    fs::write(package_b.join("model.pkl"), [0x80_u8, 4, 1, 2, 3])?;
    let package_report = crate::package::inspect(&package_b)?;
    report.checks.push(check(
        "package-unsafe-serialization",
        package_report.blocking(),
        "code-capable serialization blocks package admission without deserialization",
    ));

    let advisory_db = crate::advisory::builtin_database()?;
    let advisory_bytes = serde_json::to_vec(&advisory_db)?;
    let runtime = crate::advisory::RuntimeInfo {
        runtime: crate::advisory::RuntimeKind::Ollama,
        executable: "synthetic".to_owned(),
        executable_sha256: "sha256:synthetic".into(),
        raw_version: "ollama version is 0.17.0".to_owned(),
        parsed_version: Some("0.17.0".to_owned()),
    };
    let advisory_result = crate::advisory::evaluate_info(runtime, &advisory_db, &advisory_bytes);
    report.checks.push(check(
        "runtime-advisory-block",
        advisory_result.blocking,
        "known-vulnerable synthetic runtime version is blocked by the offline advisory catalog",
    ));

    if include_sparse {
        const GIB: u64 = 1024 * 1024 * 1024;
        for gib in [1_u64, 4, 8, 20] {
            let data_bytes = gib * GIB;
            let sparse = root.join(format!("sparse-{gib}g.safetensors"));
            let header = format!(
                r#"{{"w":{{"dtype":"U8","shape":[{data_bytes}],"data_offsets":[0,{data_bytes}]}}}}"#
            );
            let mut file = fs::File::create(&sparse)?;
            file.write_all(&(header.len() as u64).to_le_bytes())?;
            file.write_all(header.as_bytes())?;
            let data_start = 8 + header.len() as u64;
            file.seek(SeekFrom::Start(data_start + data_bytes - 1))?;
            file.write_all(&[0])?;
            let result = artifact::inspect(&sparse, ArtifactScanMode::StructureOnly);
            report.checks.push(check(
                &format!("sparse-{gib}g-structure"),
                result.is_ok(),
                &format!("{gib} GiB sparse artifact structurally inspected without reading the data buffer"),
            ));
            let _ = fs::remove_file(sparse);
        }
    }

    report.passed = report.checks.iter().all(|item| item.passed);
    let _ = fs::remove_dir_all(root);
    Ok(report)
}

fn check(name: &str, passed: bool, detail: &str) -> CertificationCheck {
    CertificationCheck {
        name: name.to_owned(),
        passed,
        detail: detail.to_owned(),
    }
}

fn temp_root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "layerfault-certify-{}-{}",
        std::process::id(),
        crate::paths::now_unix()
    ))
}
