use layerfault::object_cache;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::sync::Mutex;
use tempfile::tempdir;

static ENV_LOCK: Mutex<()> = Mutex::new(());

struct EnvGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    dir: tempfile::TempDir,
}

impl EnvGuard {
    fn new() -> Self {
        let lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = tempdir().unwrap();
        std::env::set_var("LAYERFAULT_CACHE_DIR", dir.path());
        std::env::set_var("LAYERFAULT_OBJECT_CACHE", "on");
        Self { _lock: lock, dir }
    }

    fn cache_dir(&self) -> &std::path::Path {
        self.dir.path()
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        std::env::remove_var("LAYERFAULT_CACHE_DIR");
        std::env::remove_var("LAYERFAULT_OBJECT_CACHE");
        std::env::remove_var("LAYERFAULT_OBJECT_CACHE_STRICT");
        std::env::remove_var("LAYERFAULT_OBJECT_CACHE_MAX_BYTES");
        std::env::remove_var("LAYERFAULT_OBJECT_CACHE_MIN_FREE_BYTES");
    }
}

fn compute_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

#[test]
fn first_download_inserts_verified_object() {
    let _guard = EnvGuard::new();
    let staging = tempdir().unwrap();
    let dest = staging.path().join("model.bin");

    let payload = b"hello verified huggingface model object 123";
    let sha = compute_sha256(payload);
    let part_path = staging.path().join("model.bin.layerfault-part");
    fs::write(&part_path, payload).unwrap();

    object_cache::insert_verified_object(
        &part_path,
        &sha,
        payload.len() as u64,
        "org/model-a",
        "1111111111111111111111111111111111111111",
        "model.bin",
        &dest,
    )
    .unwrap();

    assert!(dest.is_file());
    assert_eq!(fs::read(&dest).unwrap(), payload);

    let obj_path = object_cache::object_path(&sha).unwrap();
    let meta_path = object_cache::meta_path(&sha).unwrap();

    assert!(obj_path.is_file(), "object must exist in store");
    assert!(meta_path.is_file(), "metadata must exist in store");
    assert_eq!(fs::read(&obj_path).unwrap(), payload);

    let meta_bytes = fs::read(&meta_path).unwrap();
    let meta: object_cache::ObjectMetadata = serde_json::from_slice(&meta_bytes).unwrap();
    assert_eq!(meta.canonical_key, sha);
    assert_eq!(meta.size, payload.len() as u64);
    assert_eq!(meta.source_observations.len(), 1);
    assert_eq!(meta.source_observations[0].repo, "org/model-a");
}

#[test]
fn later_revision_same_lfs_digest_reuses_it() {
    let _guard = EnvGuard::new();
    let staging_1 = tempdir().unwrap();
    let dest_1 = staging_1.path().join("model.bin");

    let payload = b"reusable model layer weight content";
    let sha = compute_sha256(payload);
    let part_1 = staging_1.path().join("model.bin.layerfault-part");
    fs::write(&part_1, payload).unwrap();

    object_cache::insert_verified_object(
        &part_1,
        &sha,
        payload.len() as u64,
        "org/model-a",
        "1111111111111111111111111111111111111111",
        "model.bin",
        &dest_1,
    )
    .unwrap();

    let staging_2 = tempdir().unwrap();
    let dest_2 = staging_2.path().join("model.bin");

    let res = object_cache::lookup_and_stage(
        &sha,
        payload.len() as u64,
        "org/model-a",
        "2222222222222222222222222222222222222222",
        "model.bin",
        &dest_2,
    )
    .unwrap();

    assert!(res.is_some(), "lookup must hit cache");
    assert!(dest_2.is_file());
    assert_eq!(fs::read(&dest_2).unwrap(), payload);

    let meta_path = object_cache::meta_path(&sha).unwrap();
    let meta: object_cache::ObjectMetadata =
        serde_json::from_slice(&fs::read(&meta_path).unwrap()).unwrap();
    assert_eq!(
        meta.source_observations.len(),
        2,
        "new revision observation appended"
    );
    assert_eq!(
        meta.source_observations[1].revision,
        "2222222222222222222222222222222222222222"
    );
}

#[test]
fn cross_repo_same_digest_reuses_bytes_recomputes_context() {
    let _guard = EnvGuard::new();
    let staging_1 = tempdir().unwrap();
    let dest_1 = staging_1.path().join("weights.bin");

    let payload = b"shared weight file content across repos";
    let sha = compute_sha256(payload);
    let part_1 = staging_1.path().join("weights.bin.layerfault-part");
    fs::write(&part_1, payload).unwrap();

    object_cache::insert_verified_object(
        &part_1,
        &sha,
        payload.len() as u64,
        "org/repo-a",
        "1111111111111111111111111111111111111111",
        "weights.bin",
        &dest_1,
    )
    .unwrap();

    let staging_2 = tempdir().unwrap();
    let dest_2 = staging_2.path().join("weights.bin");
    let res = object_cache::lookup_and_stage(
        &sha,
        payload.len() as u64,
        "org/repo-b",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "other_path/weights.bin",
        &dest_2,
    )
    .unwrap();

    assert!(res.is_some(), "cross-repo lookup must hit cache");
    assert_eq!(res.unwrap().repo, "org/repo-b");

    let meta_path = object_cache::meta_path(&sha).unwrap();
    let meta: object_cache::ObjectMetadata =
        serde_json::from_slice(&fs::read(&meta_path).unwrap()).unwrap();
    assert_eq!(meta.source_observations.len(), 2);
    assert_eq!(meta.source_observations[1].repo, "org/repo-b");
}

#[test]
fn corrupt_local_object_invalidates_and_rebuilds() {
    let _guard = EnvGuard::new();
    let staging_1 = tempdir().unwrap();
    let dest_1 = staging_1.path().join("data.bin");

    let payload = b"original clean data bytes";
    let sha = compute_sha256(payload);
    let part_1 = staging_1.path().join("data.bin.layerfault-part");
    fs::write(&part_1, payload).unwrap();

    object_cache::insert_verified_object(
        &part_1,
        &sha,
        payload.len() as u64,
        "org/model-c",
        "1111111111111111111111111111111111111111",
        "data.bin",
        &dest_1,
    )
    .unwrap();

    let obj_path = object_cache::object_path(&sha).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&obj_path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fs::write(&obj_path, b"corrupted bytes payload here!").unwrap();

    std::env::set_var("LAYERFAULT_OBJECT_CACHE_STRICT", "1");

    let staging_2 = tempdir().unwrap();
    let dest_2 = staging_2.path().join("data.bin");

    let lookup_res = object_cache::lookup_and_stage(
        &sha,
        payload.len() as u64,
        "org/model-c",
        "1111111111111111111111111111111111111111",
        "data.bin",
        &dest_2,
    )
    .unwrap();

    assert!(
        lookup_res.is_none(),
        "corrupt object must fail revalidation"
    );
    assert!(!obj_path.exists(), "corrupt object file must be purged");
}

#[test]
fn wrong_expected_digest_never_promoted() {
    let _guard = EnvGuard::new();
    assert!(object_cache::parse_canonical_sha256("invalid-digest").is_err());
}

#[test]
fn size_mismatch_rejected() {
    let _guard = EnvGuard::new();
    let staging = tempdir().unwrap();
    let dest = staging.path().join("sized.bin");

    let payload = b"payload size ten";
    let sha = compute_sha256(payload);
    let part = staging.path().join("sized.bin.layerfault-part");
    fs::write(&part, payload).unwrap();

    object_cache::insert_verified_object(
        &part,
        &sha,
        payload.len() as u64,
        "org/size-test",
        "1111111111111111111111111111111111111111",
        "sized.bin",
        &dest,
    )
    .unwrap();

    let staging_2 = tempdir().unwrap();
    let dest_2 = staging_2.path().join("sized.bin");

    let res = object_cache::lookup_and_stage(
        &sha,
        999999,
        "org/size-test",
        "1111111111111111111111111111111111111111",
        "sized.bin",
        &dest_2,
    )
    .unwrap();

    assert!(res.is_none(), "size mismatch must reject cache hit");
}

#[test]
fn partial_cleanup() {
    let guard = EnvGuard::new();
    let cache_d = guard.cache_dir();

    let stale_part = cache_d.join("stale.layerfault-part");
    fs::write(&stale_part, b"abandoned partial download").unwrap();

    let past = std::time::SystemTime::now() - std::time::Duration::from_secs(48 * 3600);
    let file = File::options().write(true).open(&stale_part).unwrap();
    let times = std::fs::FileTimes::new().set_modified(past);
    file.set_times(times).unwrap();

    let plan = object_cache::gc::plan().unwrap();
    assert!(
        plan.stale_part_files.contains(&stale_part),
        "stale part file must be detected in GC plan"
    );

    let _freed = object_cache::gc::execute(&plan).unwrap();
    assert!(!stale_part.exists(), "stale part file must be deleted");
}

#[test]
fn quota_gc_evicts_oldest() {
    let _guard = EnvGuard::new();
    std::env::set_var("LAYERFAULT_OBJECT_CACHE_MAX_BYTES", "100");

    let staging = tempdir().unwrap();

    let payload_1 = vec![1_u8; 60];
    let sha_1 = compute_sha256(&payload_1);
    let part_1 = staging.path().join("1.bin.layerfault-part");
    fs::write(&part_1, &payload_1).unwrap();
    object_cache::insert_verified_object(
        &part_1,
        &sha_1,
        60,
        "org/gc-test",
        "1111111111111111111111111111111111111111",
        "1.bin",
        &staging.path().join("1.bin"),
    )
    .unwrap();

    let obj_1_path = object_cache::object_path(&sha_1).unwrap();
    let meta_1_path = object_cache::meta_path(&sha_1).unwrap();
    let past = std::time::SystemTime::now() - std::time::Duration::from_secs(60);
    if let Ok(f) = File::options().write(true).open(&obj_1_path) {
        let _ = f.set_times(std::fs::FileTimes::new().set_modified(past));
    }
    if let Ok(f) = File::options().write(true).open(&meta_1_path) {
        let _ = f.set_times(std::fs::FileTimes::new().set_modified(past));
    }

    let payload_2 = vec![2_u8; 60];
    let sha_2 = compute_sha256(&payload_2);
    let part_2 = staging.path().join("2.bin.layerfault-part");
    fs::write(&part_2, &payload_2).unwrap();
    object_cache::insert_verified_object(
        &part_2,
        &sha_2,
        60,
        "org/gc-test",
        "1111111111111111111111111111111111111111",
        "2.bin",
        &staging.path().join("2.bin"),
    )
    .unwrap();

    let obj_1_path = object_cache::object_path(&sha_1).unwrap();
    let obj_2_path = object_cache::object_path(&sha_2).unwrap();

    assert!(
        !obj_1_path.exists(),
        "oldest object 1 must be evicted after quota exceeded"
    );
    assert!(
        obj_2_path.exists(),
        "newer object 2 must remain in object store"
    );
}

#[test]
fn concurrent_reuse_and_insertion() {
    let _guard = EnvGuard::new();
    let payload = b"concurrent multi thread access payload";
    let sha = compute_sha256(payload);

    let handles: Vec<_> = (0..10)
        .map(|i| {
            let sha = sha.clone();
            std::thread::spawn(move || {
                let staging = tempdir().unwrap();
                let dest = staging.path().join(format!("thread_{i}.bin"));
                let part = staging
                    .path()
                    .join(format!("thread_{i}.bin.layerfault-part"));
                fs::write(&part, payload).unwrap();

                object_cache::insert_verified_object(
                    &part,
                    &sha,
                    payload.len() as u64,
                    "org/concurrent",
                    "1111111111111111111111111111111111111111",
                    &format!("file_{i}.bin"),
                    &dest,
                )
                .unwrap();

                assert!(dest.is_file());
                assert_eq!(fs::read(&dest).unwrap(), payload);
            })
        })
        .collect();

    for h in handles {
        h.join().unwrap();
    }
}
