use anyhow::Result;
use layerfault::package::{compute_merkle_leaf, compute_merkle_tree, fingerprint_report};
use std::fs;
use std::path::PathBuf;

fn create_temp_pkg(prefix: &str) -> Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!("{prefix}-{}", layerfault::paths::now_unix()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

#[test]
fn test_merkle_identity_namespace_and_leaf() -> Result<()> {
    let root = create_temp_pkg("layerfault-merkle-namespace")?;
    fs::write(root.join("config.json"), b"{\"model\":\"test\"}")?;
    fs::write(root.join("modeling.py"), b"print('hello')")?;

    let report = fingerprint_report(&root)?;
    assert!(
        report.fingerprint.starts_with("lfpkg:sha256:"),
        "legacy fingerprint prefix must remain lfpkg:sha256:"
    );
    assert!(
        report.merkle_identity.starts_with("lfpkg:v2:sha256:"),
        "versioned Merkle identity must start with lfpkg:v2:sha256:"
    );
    assert_eq!(report.merkle_manifest.len(), 2);

    let leaf_config = report
        .merkle_manifest
        .iter()
        .find(|l| l.path == "config.json")
        .expect("config.json leaf");
    let expected_leaf = compute_merkle_leaf(
        "config.json",
        &leaf_config.sha256,
        leaf_config.size,
        "config",
    );
    assert_eq!(leaf_config.leaf_hash, expected_leaf);

    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn test_enumeration_order_independence() -> Result<()> {
    let root1 = create_temp_pkg("layerfault-merkle-order1")?;
    let root2 = create_temp_pkg("layerfault-merkle-order2")?;

    fs::create_dir_all(root1.join("sub"))?;
    fs::create_dir_all(root2.join("sub"))?;

    fs::write(root1.join("a.txt"), b"content-a")?;
    fs::write(root1.join("b.txt"), b"content-b")?;
    fs::write(root1.join("sub/c.txt"), b"content-c")?;

    fs::write(root2.join("sub/c.txt"), b"content-c")?;
    fs::write(root2.join("b.txt"), b"content-b")?;
    fs::write(root2.join("a.txt"), b"content-a")?;

    let report1 = fingerprint_report(&root1)?;
    let report2 = fingerprint_report(&root2)?;

    assert_eq!(report1.fingerprint, report2.fingerprint);
    assert_eq!(report1.merkle_identity, report2.merkle_identity);

    // Order of input entries to compute_merkle_tree should not alter the resulting root identity
    let entries1 = report1.files.clone();
    let mut entries2 = report1.files.clone();
    entries2.reverse();

    let (id1, manifest1) = compute_merkle_tree(&entries1, None);
    let (id2, manifest2) = compute_merkle_tree(&entries2, None);

    assert_eq!(id1, id2);
    assert_eq!(manifest1, manifest2);

    let _ = fs::remove_dir_all(root1);
    let _ = fs::remove_dir_all(root2);
    Ok(())
}

#[test]
fn test_one_member_change_changes_only_expected_branch() -> Result<()> {
    let root = create_temp_pkg("layerfault-merkle-branch")?;

    fs::create_dir_all(root.join("sub1"))?;
    fs::create_dir_all(root.join("sub2"))?;

    fs::write(root.join("sub1/file1.bin"), b"data1")?;
    fs::write(root.join("sub2/file2.bin"), b"data2")?;

    let report_before = fingerprint_report(&root)?;

    // Modify file inside sub1 only
    fs::write(root.join("sub1/file1.bin"), b"data1-modified")?;

    let report_after = fingerprint_report(&root)?;

    assert_ne!(
        report_before.merkle_identity, report_after.merkle_identity,
        "root identity must change when a member changes"
    );

    let leaf1_before = report_before
        .merkle_manifest
        .iter()
        .find(|l| l.path == "sub1/file1.bin")
        .unwrap();
    let leaf1_after = report_after
        .merkle_manifest
        .iter()
        .find(|l| l.path == "sub1/file1.bin")
        .unwrap();
    assert_ne!(leaf1_before.leaf_hash, leaf1_after.leaf_hash);

    let leaf2_before = report_before
        .merkle_manifest
        .iter()
        .find(|l| l.path == "sub2/file2.bin")
        .unwrap();
    let leaf2_after = report_after
        .merkle_manifest
        .iter()
        .find(|l| l.path == "sub2/file2.bin")
        .unwrap();
    assert_eq!(
        leaf2_before.leaf_hash, leaf2_after.leaf_hash,
        "unmodified sibling branch leaf hash must remain identical"
    );

    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn test_add_remove_rename_changes_root() -> Result<()> {
    let root = create_temp_pkg("layerfault-merkle-mutations")?;

    fs::write(root.join("file1.txt"), b"hello")?;
    fs::write(root.join("file2.txt"), b"world")?;

    let base_rep = fingerprint_report(&root)?;

    // Rename
    fs::rename(root.join("file2.txt"), root.join("renamed.txt"))?;
    let rename_rep = fingerprint_report(&root)?;
    assert_ne!(base_rep.merkle_identity, rename_rep.merkle_identity);

    // Add
    fs::write(root.join("added.txt"), b"new file")?;
    let add_rep = fingerprint_report(&root)?;
    assert_ne!(rename_rep.merkle_identity, add_rep.merkle_identity);

    // Remove
    fs::remove_file(root.join("added.txt"))?;
    let remove_rep = fingerprint_report(&root)?;
    assert_eq!(rename_rep.merkle_identity, remove_rep.merkle_identity);

    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn test_mtime_only_change_does_not_change_identity() -> Result<()> {
    let root = create_temp_pkg("layerfault-merkle-mtime")?;

    let file_path = root.join("model.bin");
    fs::write(&file_path, b"constant weights data")?;

    let rep1 = fingerprint_report(&root)?;

    // Touch mtime without altering content or size
    let now = std::time::SystemTime::now();
    let file = fs::File::open(&file_path)?;
    file.set_modified(now)?;
    drop(file);

    let rep2 = fingerprint_report(&root)?;

    assert_eq!(
        rep1.merkle_identity, rep2.merkle_identity,
        "mtime-only change must not alter Merkle package identity"
    );
    assert_eq!(rep1.merkle_manifest, rep2.merkle_manifest);

    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn test_legacy_fingerprint_unchanged() -> Result<()> {
    let root = create_temp_pkg("layerfault-merkle-legacy")?;

    fs::write(root.join("config.json"), b"{\"vocab_size\": 32000}")?;
    fs::write(root.join("model.bin"), b"binary bytes")?;

    let rep = fingerprint_report(&root)?;
    assert!(rep.fingerprint.starts_with("lfpkg:sha256:"));
    assert!(rep.merkle_identity.starts_with("lfpkg:v2:sha256:"));

    let legacy_fp = layerfault::package::fingerprint(&root)?;
    assert_eq!(rep.fingerprint, legacy_fp);

    let _ = fs::remove_dir_all(root);
    Ok(())
}

#[test]
fn test_unsafe_symlink_handling_consistent() -> Result<()> {
    let root = create_temp_pkg("layerfault-merkle-symlink")?;

    fs::write(root.join("config.json"), b"{}")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        symlink(root.join("config.json"), root.join("symlink_config.json"))?;
        let res = fingerprint_report(&root);
        assert!(
            res.is_err(),
            "fingerprint_report must refuse packages with symlinks"
        );
    }

    let _ = fs::remove_dir_all(root);
    Ok(())
}
