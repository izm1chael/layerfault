use anyhow::Result;
use layerfault::binding::{self, BindingKind};
use sha2::{Digest, Sha256};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[test]
fn unchanged_package_stages_and_fingerprints_match() -> Result<()> {
    let base = std::env::temp_dir().join(format!(
        "layerfault-pkg-binding-test-1-{}-{}",
        std::process::id(),
        layerfault::paths::now_unix()
    ));
    let pkg_dir = base.join("model_pkg");
    fs::create_dir_all(&pkg_dir)?;
    fs::write(pkg_dir.join("config.json"), b"{\"model_type\": \"llama\"}")?;
    fs::write(pkg_dir.join("tokenizer.json"), b"{\"tokens\": []}")?;
    fs::write(pkg_dir.join("modeling_custom.py"), b"# custom loader")?;
    fs::write(pkg_dir.join("model.safetensors"), b"weight_bytes_12345")?;

    let report = layerfault::package::inspect(&pkg_dir)?;
    let parent = base.join("staging_root");
    let staged = binding::stage_verified_package_under(&pkg_dir, &report, &parent)?;

    assert_eq!(staged.source_fingerprint, report.fingerprint);
    assert_eq!(staged.staged_fingerprint, report.fingerprint);
    assert_eq!(staged.record.kind, BindingKind::PackageStagedRehashed);
    assert_eq!(staged.members.len(), 4);

    let manifest = staged.record.manifest.as_ref().unwrap();
    assert_eq!(manifest.binding, BindingKind::PackageStagedRehashed);
    assert_eq!(manifest.components.len(), 1);
    assert_eq!(manifest.components[0].role, "model");

    staged.revalidate()?;
    staged.cleanup()?;
    let _ = fs::remove_dir_all(base);
    Ok(())
}

#[test]
fn mutate_source_member_during_staging_fails() -> Result<()> {
    let base = std::env::temp_dir().join(format!(
        "layerfault-pkg-binding-test-2-{}-{}",
        std::process::id(),
        layerfault::paths::now_unix()
    ));
    let pkg_dir = base.join("model_pkg");
    fs::create_dir_all(&pkg_dir)?;
    fs::write(pkg_dir.join("config.json"), b"{\"model_type\": \"test\"}")?;
    fs::write(pkg_dir.join("model.safetensors"), b"original_bytes")?;

    let mut report = layerfault::package::inspect(&pkg_dir)?;
    // Alter expected hash in report to simulate source changing before copy
    report.files[1].sha256 =
        Some("sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned());

    let parent = base.join("staging_root");
    let result = binding::stage_verified_package_under(&pkg_dir, &report, &parent);
    assert!(result.is_err());
    let err_msg = result.err().unwrap().to_string();
    assert!(err_msg.contains("hash changed during staging"));

    let _ = fs::remove_dir_all(base);
    Ok(())
}

#[test]
fn mutate_source_after_staging_leaves_staged_copy_bound() -> Result<()> {
    let base = std::env::temp_dir().join(format!(
        "layerfault-pkg-binding-test-3-{}-{}",
        std::process::id(),
        layerfault::paths::now_unix()
    ));
    let pkg_dir = base.join("model_pkg");
    fs::create_dir_all(&pkg_dir)?;
    fs::write(pkg_dir.join("config.json"), b"{\"v\": 1}")?;
    fs::write(pkg_dir.join("model.safetensors"), b"original_weights")?;

    let report = layerfault::package::inspect(&pkg_dir)?;
    let parent = base.join("staging_root");
    let staged = binding::stage_verified_package_under(&pkg_dir, &report, &parent)?;

    // Mutate source package on host
    fs::write(pkg_dir.join("config.json"), b"{\"v\": 2, \"hacked\": true}")?;
    fs::write(pkg_dir.join("malicious.py"), b"import os; os.system('pwn')")?;

    // Staged package remains intact, un-tampered, and valid
    staged.revalidate()?;
    assert_eq!(fs::read(staged.path().join("config.json"))?, b"{\"v\": 1}");
    assert!(!staged.path().join("malicious.py").exists());

    staged.cleanup()?;
    let _ = fs::remove_dir_all(base);
    Ok(())
}

#[test]
#[cfg(unix)]
fn mutate_staged_member_before_launch_fails_revalidation() -> Result<()> {
    let base = std::env::temp_dir().join(format!(
        "layerfault-pkg-binding-test-4-{}-{}",
        std::process::id(),
        layerfault::paths::now_unix()
    ));
    let pkg_dir = base.join("model_pkg");
    fs::create_dir_all(&pkg_dir)?;
    fs::write(pkg_dir.join("config.json"), b"{\"v\": 1}")?;

    let report = layerfault::package::inspect(&pkg_dir)?;
    let parent = base.join("staging_root");
    let staged = binding::stage_verified_package_under(&pkg_dir, &report, &parent)?;

    // Make staged file writable briefly to simulate pre-launch tampering inside staging dir
    let staged_config = staged.path().join("config.json");
    fs::set_permissions(&staged_config, fs::Permissions::from_mode(0o600))?;
    fs::write(&staged_config, b"{\"v\": 99}")?;

    // Revalidation immediately before launch catches the modification
    let result = staged.revalidate();
    assert!(result.is_err());
    let err = result.err().unwrap().to_string();
    assert!(err.contains("Staged package fingerprint changed before launch"));

    staged.cleanup()?;
    let _ = fs::remove_dir_all(base);
    Ok(())
}

#[test]
fn path_traversal_member_impossible() -> Result<()> {
    let base = std::env::temp_dir().join(format!(
        "layerfault-pkg-binding-test-5-{}-{}",
        std::process::id(),
        layerfault::paths::now_unix()
    ));
    let pkg_dir = base.join("model_pkg");
    fs::create_dir_all(&pkg_dir)?;
    fs::write(pkg_dir.join("config.json"), b"{}")?;

    let mut report = layerfault::package::inspect(&pkg_dir)?;
    report.files.push(layerfault::package::PackageEntry {
        relative_path: "../escaped.txt".to_owned(),
        kind: "file".to_owned(),
        size: 10,
        sha256: Some(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
        ),
        digest_cache: None,
    });

    let parent = base.join("staging_root");
    let result = binding::stage_verified_package_under(&pkg_dir, &report, &parent);
    assert!(result.is_err());
    let err = result.err().unwrap().to_string();
    assert!(err.contains("unsafe relative member path component"));

    let _ = fs::remove_dir_all(base);
    Ok(())
}

#[test]
fn symlink_member_refused() -> Result<()> {
    let base = std::env::temp_dir().join(format!(
        "layerfault-pkg-binding-test-6-{}-{}",
        std::process::id(),
        layerfault::paths::now_unix()
    ));
    let pkg_dir = base.join("model_pkg");
    fs::create_dir_all(&pkg_dir)?;
    fs::write(pkg_dir.join("config.json"), b"{}")?;

    let mut report = layerfault::package::inspect(&pkg_dir)?;
    report.files.push(layerfault::package::PackageEntry {
        relative_path: "symlink.py".to_owned(),
        kind: "symlink".to_owned(),
        size: 0,
        sha256: Some(
            "sha256:2222222222222222222222222222222222222222222222222222222222222222".to_owned(),
        ),
        digest_cache: None,
    });

    let parent = base.join("staging_root");
    let result = binding::stage_verified_package_under(&pkg_dir, &report, &parent);
    assert!(result.is_err());
    let err = result.err().unwrap().to_string();
    assert!(err.contains("refuses symlink package members"));

    let _ = fs::remove_dir_all(base);
    Ok(())
}

#[test]
#[cfg(unix)]
fn readonly_staging_permissions_enforced() -> Result<()> {
    let base = std::env::temp_dir().join(format!(
        "layerfault-pkg-binding-test-7-{}-{}",
        std::process::id(),
        layerfault::paths::now_unix()
    ));
    let pkg_dir = base.join("model_pkg");
    let sub_dir = pkg_dir.join("sub");
    fs::create_dir_all(&sub_dir)?;
    fs::write(pkg_dir.join("config.json"), b"{}")?;
    fs::write(sub_dir.join("weights.bin"), b"bytes")?;

    let report = layerfault::package::inspect(&pkg_dir)?;
    let parent = base.join("staging_root");
    let staged = binding::stage_verified_package_under(&pkg_dir, &report, &parent)?;

    let config_perm = fs::metadata(staged.path().join("config.json"))?.permissions();
    let weights_perm = fs::metadata(staged.path().join("sub").join("weights.bin"))?.permissions();
    let sub_dir_perm = fs::metadata(staged.path().join("sub"))?.permissions();

    assert_eq!(config_perm.mode() & 0o777, 0o400);
    assert_eq!(weights_perm.mode() & 0o777, 0o400);
    assert_eq!(sub_dir_perm.mode() & 0o777, 0o700);

    staged.cleanup()?;
    let _ = fs::remove_dir_all(base);
    Ok(())
}

#[test]
fn compound_base_plus_adapter_manifest() -> Result<()> {
    let base = std::env::temp_dir().join(format!(
        "layerfault-pkg-binding-test-8-{}-{}",
        std::process::id(),
        layerfault::paths::now_unix()
    ));
    let base_pkg = base.join("base_model");
    let adapter_pkg = base.join("adapter_model");
    fs::create_dir_all(&base_pkg)?;
    fs::create_dir_all(&adapter_pkg)?;

    fs::write(base_pkg.join("config.json"), b"{\"model_type\": \"base\"}")?;
    fs::write(
        adapter_pkg.join("adapter_config.json"),
        b"{\"peft_type\": \"LORA\"}",
    )?;

    let base_report = layerfault::package::inspect(&base_pkg)?;
    let adapter_report = layerfault::package::inspect(&adapter_pkg)?;

    let parent = base.join("staging_root");
    let staged_base = binding::stage_verified_package_under(&base_pkg, &base_report, &parent)?;
    let staged_adapter =
        binding::stage_verified_package_under(&adapter_pkg, &adapter_report, &parent)?;

    let components = vec![
        binding::ComponentBinding {
            role: "model".to_owned(),
            original_path: adapter_pkg.display().to_string(),
            fingerprint: adapter_report.fingerprint.clone(),
            staged_root_identity: staged_adapter.staged_fingerprint.clone(),
            member_count: staged_adapter.members.len(),
            total_bytes: staged_adapter.members.iter().map(|m| m.bytes).sum(),
        },
        binding::ComponentBinding {
            role: "base".to_owned(),
            original_path: base_pkg.display().to_string(),
            fingerprint: base_report.fingerprint.clone(),
            staged_root_identity: staged_base.staged_fingerprint.clone(),
            member_count: staged_base.members.len(),
            total_bytes: staged_base.members.iter().map(|m| m.bytes).sum(),
        },
    ];

    let manifest =
        binding::build_compound_manifest(components, Some("sha256:python_exe".to_owned()));
    assert_eq!(manifest.binding, BindingKind::PackageStagedRehashed);
    assert_eq!(manifest.components.len(), 2);
    assert_eq!(manifest.components[0].role, "model");
    assert_eq!(manifest.components[1].role, "base");

    staged_adapter.cleanup()?;
    staged_base.cleanup()?;
    let _ = fs::remove_dir_all(base);
    Ok(())
}

#[test]
fn mutate_gguf_source_after_staging_leaves_staged_copy_bound() -> Result<()> {
    let base = std::env::temp_dir().join(format!(
        "layerfault-gguf-binding-test-1-{}-{}",
        std::process::id(),
        layerfault::paths::now_unix()
    ));
    fs::create_dir_all(&base)?;
    let model_path = base.join("model.gguf");
    let original_bytes = b"GGUF_TEST_WEIGHT_BYTES_12345";
    fs::write(&model_path, original_bytes)?;

    let digest = format!("sha256:{}", hex::encode(Sha256::digest(original_bytes)));
    let parent = base.join("staging_root");
    let staged = binding::stage_verified_under(&model_path, &digest, &parent, false)?;

    // Mutate original source file on host
    fs::write(&model_path, b"CORRUPTED_MUTATED_WEIGHT_BYTES")?;

    // Staged artifact remains intact and revalidation succeeds
    staged.revalidate()?;
    assert_eq!(fs::read(staged.path())?, original_bytes);

    staged.cleanup()?;
    let _ = fs::remove_dir_all(base);
    Ok(())
}

#[test]
#[cfg(unix)]
fn mutate_staged_gguf_artifact_before_launch_fails_revalidation() -> Result<()> {
    let base = std::env::temp_dir().join(format!(
        "layerfault-gguf-binding-test-2-{}-{}",
        std::process::id(),
        layerfault::paths::now_unix()
    ));
    fs::create_dir_all(&base)?;
    let model_path = base.join("model.gguf");
    let original_bytes = b"GGUF_TEST_WEIGHT_BYTES_67890";
    fs::write(&model_path, original_bytes)?;

    let digest = format!("sha256:{}", hex::encode(Sha256::digest(original_bytes)));
    let parent = base.join("staging_root");
    let staged = binding::stage_verified_under(&model_path, &digest, &parent, false)?;

    // Mutate staged copy directly (simulating pre-launch tampering inside staging dir)
    let staged_file = staged.path();
    fs::set_permissions(staged_file, fs::Permissions::from_mode(0o600))?;
    fs::write(staged_file, b"HACKED_STAGED_BYTES")?;

    // Pre-launch revalidation catches tampering
    let result = staged.revalidate();
    assert!(result.is_err());
    let err = result.err().unwrap().to_string();
    assert!(err.contains("Staged artifact digest changed before launch"));

    staged.cleanup()?;
    let _ = fs::remove_dir_all(base);
    Ok(())
}

#[test]
fn mutate_gguf_source_during_staging_fails() -> Result<()> {
    let base = std::env::temp_dir().join(format!(
        "layerfault-gguf-binding-test-3-{}-{}",
        std::process::id(),
        layerfault::paths::now_unix()
    ));
    fs::create_dir_all(&base)?;
    let model_path = base.join("model.gguf");
    fs::write(&model_path, b"ORIGINAL_GGUF_BYTES")?;

    let wrong_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let parent = base.join("staging_root");
    let result = binding::stage_verified_under(&model_path, wrong_digest, &parent, false);

    assert!(result.is_err());
    let err = result.err().unwrap().to_string();
    assert!(err.contains("hash changed during staging"));

    let _ = fs::remove_dir_all(base);
    Ok(())
}
