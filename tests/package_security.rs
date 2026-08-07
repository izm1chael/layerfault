use anyhow::Result;
use layerfault::advisory::{self, RuntimeInfo, RuntimeKind};
use layerfault::package;
use layerfault::scanner::ScanStatus;
use std::fs;

#[test]
fn package_identity_ignores_absolute_root_but_tracks_content() -> Result<()> {
    let a = std::env::temp_dir().join(format!("layerfault-package-it-a-{}", std::process::id()));
    let b = std::env::temp_dir().join(format!("layerfault-package-it-b-{}", std::process::id()));
    let _ = fs::remove_dir_all(&a);
    let _ = fs::remove_dir_all(&b);
    fs::create_dir_all(&a)?;
    fs::create_dir_all(&b)?;
    fs::write(a.join("config.json"), br#"{"architectures":["Fixture"]}"#)?;
    fs::write(b.join("config.json"), br#"{"architectures":["Fixture"]}"#)?;
    assert_eq!(package::fingerprint(&a)?, package::fingerprint(&b)?);
    fs::write(b.join("config.json"), br#"{"architectures":["Changed"]}"#)?;
    assert_ne!(package::fingerprint(&a)?, package::fingerprint(&b)?);
    let _ = fs::remove_dir_all(a);
    let _ = fs::remove_dir_all(b);
    Ok(())
}

#[test]
fn package_blocks_pickle_and_warns_custom_code() -> Result<()> {
    let root =
        std::env::temp_dir().join(format!("layerfault-package-it-risk-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root)?;
    fs::write(
        root.join("config.json"),
        br#"{"auto_map":{"AutoModel":"modeling_fixture.Fixture"}}"#,
    )?;
    fs::write(
        root.join("modeling_fixture.py"),
        b"import subprocess\nsubprocess.run(['echo','fixture'])\n",
    )?;
    fs::write(root.join("model.pkl"), [0x80_u8, 4, 1, 2, 3])?;
    let report = package::inspect(&root)?;
    assert!(report.findings.iter().any(|f| f
        .matches
        .iter()
        .any(|m| m.contains("LF-CODE-AUTO-MAP"))
        && f.status == ScanStatus::Warn));
    assert!(report.findings.iter().any(|f| f
        .matches
        .iter()
        .any(|m| m.contains("LF-SERIALIZATION-UNSAFE"))
        && f.status == ScanStatus::Fail));
    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn bundled_advisory_catalog_blocks_known_vulnerable_runtime() -> Result<()> {
    let db = advisory::builtin_database()?;
    let bytes = serde_json::to_vec(&db)?;
    let info = RuntimeInfo {
        runtime: RuntimeKind::Ollama,
        executable: "fixture".into(),
        raw_version: "ollama version is 0.17.0".into(),
        parsed_version: Some("0.17.0".into()),
    };
    let result = advisory::evaluate_info(info, &db, &bytes);
    assert!(result.blocking);
    assert!(result
        .findings
        .iter()
        .any(|f| f.matches.iter().any(|m| m.contains("CVE-2026-7482"))));
    Ok(())
}
