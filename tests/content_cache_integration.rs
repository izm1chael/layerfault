use layerfault::formats::artifact::{inspect_with_format, ArtifactScanMode};
use layerfault::formats::ArtifactFormat;
use layerfault::package;
use std::sync::Mutex;
use tempfile::tempdir;

// `LAYERFAULT_CACHE_DIR`/`LAYERFAULT_CONTENT_CACHE` are process-global; serialize
// tests that touch them so parallel test execution doesn't race.
static ENV_LOCK: Mutex<()> = Mutex::new(());

struct EnvGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    _dir: tempfile::TempDir,
}

impl EnvGuard {
    fn new() -> Self {
        let lock = ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        let dir = tempdir().unwrap();
        std::env::set_var("LAYERFAULT_CACHE_DIR", dir.path());
        std::env::set_var("LAYERFAULT_CONTENT_CACHE", "on");
        // These fixtures are a handful of bytes; opt back into caching them
        // within this isolated temp directory (production defaults to a
        // nonzero floor so real cache dirs aren't polluted by tiny files).
        std::env::set_var("LAYERFAULT_CONTENT_CACHE_MIN_BYTES", "0");
        std::env::set_var("LAYERFAULT_HASH_CACHE", "off");
        Self {
            _lock: lock,
            _dir: dir,
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        std::env::remove_var("LAYERFAULT_CACHE_DIR");
        std::env::remove_var("LAYERFAULT_CONTENT_CACHE");
        std::env::remove_var("LAYERFAULT_CONTENT_CACHE_MIN_BYTES");
        std::env::remove_var("LAYERFAULT_HASH_CACHE");
    }
}

/// A minimal pickle stream containing a dangerous `os.system` GLOBAL/REDUCE
/// pair, deterministically producing a structural finding via
/// `formats::pickle::scan` without ever deserializing/executing it.
const DANGEROUS_PICKLE: &[u8] = b"cos\nsystem\n)R.";

#[test]
fn identical_bytes_different_path_produce_equivalent_findings_and_content_cache_hit() {
    let _guard = EnvGuard::new();
    let scan_dir = tempdir().unwrap();

    let path_a = scan_dir.path().join("model-a.pkl");
    let path_b = scan_dir.path().join("model-b.pkl");
    std::fs::write(&path_a, DANGEROUS_PICKLE).unwrap();
    std::fs::write(&path_b, DANGEROUS_PICKLE).unwrap();

    let report_a =
        inspect_with_format(&path_a, ArtifactFormat::Pickle, ArtifactScanMode::Full).unwrap();
    assert_eq!(
        report_a.cache.as_ref().and_then(|c| c.content.as_deref()),
        Some("MISS"),
        "first scan of these bytes must be a content-cache miss"
    );

    let report_b =
        inspect_with_format(&path_b, ArtifactFormat::Pickle, ArtifactScanMode::Full).unwrap();
    assert_eq!(
        report_b.cache.as_ref().and_then(|c| c.content.as_deref()),
        Some("HIT"),
        "identical bytes at a different path must hit the content cache"
    );

    assert_eq!(
        report_a.results.len(),
        report_b.results.len(),
        "cached and fresh scans must produce the same number of findings"
    );
    for (fresh, cached) in report_a.results.iter().zip(report_b.results.iter()) {
        assert_eq!(fresh.status, cached.status);
        assert_eq!(fresh.check_type, cached.check_type);
        assert_eq!(fresh.rule_id, cached.rule_id);
        assert_eq!(fresh.matches, cached.matches);
    }

    // The rehydrated subject must reflect path B, not the path bytes were
    // first observed at (path A) — proving the cache never leaks path
    // identity across a hit.
    let subject_paths: Vec<&str> = report_b
        .results
        .iter()
        .filter_map(|result| result.subject.as_ref())
        .filter_map(|subject| subject.path.as_deref())
        .collect();
    for observed in subject_paths {
        assert!(
            observed.ends_with("model-b.pkl"),
            "expected rehydrated subject path to reference path B, got '{observed}'"
        );
        assert!(
            !observed.ends_with("model-a.pkl"),
            "cached finding leaked the original scan path"
        );
    }
}

#[test]
fn scan_mode_change_is_a_separate_content_cache_record() {
    let _guard = EnvGuard::new();
    let scan_dir = tempdir().unwrap();
    let path = scan_dir.path().join("model.pkl");
    std::fs::write(&path, DANGEROUS_PICKLE).unwrap();

    let full = inspect_with_format(&path, ArtifactFormat::Pickle, ArtifactScanMode::Full).unwrap();
    assert_eq!(
        full.cache.as_ref().and_then(|c| c.content.as_deref()),
        Some("MISS")
    );

    // StructureOnly never computes a content sha256 today, so the content
    // cache is simply not consulted (`NOT_USED`) rather than colliding with
    // the Full-mode record.
    let structure_only = inspect_with_format(
        &path,
        ArtifactFormat::Pickle,
        ArtifactScanMode::StructureOnly,
    )
    .unwrap();
    assert_eq!(
        structure_only
            .cache
            .as_ref()
            .and_then(|c| c.content.as_deref()),
        Some("NOT_USED")
    );

    let full_again =
        inspect_with_format(&path, ArtifactFormat::Pickle, ArtifactScanMode::Full).unwrap();
    assert_eq!(
        full_again.cache.as_ref().and_then(|c| c.content.as_deref()),
        Some("HIT"),
        "Full mode must still hit its own record after a StructureOnly scan"
    );
}

#[test]
fn different_package_role_reuses_intrinsic_evidence_but_recomputes_fingerprint() {
    let _guard = EnvGuard::new();

    // Same bytes placed at two different package-relative roles ("main
    // artifact" vs "vendored dependency include") in two otherwise-distinct
    // packages.
    let package_a = tempdir().unwrap();
    let package_b = tempdir().unwrap();
    std::fs::write(package_a.path().join("model.pkl"), DANGEROUS_PICKLE).unwrap();
    std::fs::create_dir_all(package_b.path().join("vendor/deps")).unwrap();
    std::fs::write(
        package_b.path().join("vendor/deps/model.pkl"),
        DANGEROUS_PICKLE,
    )
    .unwrap();

    let findings_a = package::inspect_member(
        std::path::Path::new("model.pkl"),
        &package_a.path().join("model.pkl"),
    )
    .unwrap();
    let findings_b = package::inspect_member(
        std::path::Path::new("vendor/deps/model.pkl"),
        &package_b.path().join("vendor/deps/model.pkl"),
    )
    .unwrap();

    // Content-intrinsic conclusions (the dangerous pickle GLOBAL/REDUCE
    // finding) must be identical regardless of package role.
    let rule_ids_a: Vec<_> = findings_a
        .iter()
        .filter_map(|f| f.rule_id.clone())
        .collect();
    let rule_ids_b: Vec<_> = findings_b
        .iter()
        .filter_map(|f| f.rule_id.clone())
        .collect();
    assert_eq!(rule_ids_a, rule_ids_b);
    assert!(!rule_ids_a.is_empty());

    // But package-level context (fingerprint, derived from relative_path)
    // must always be recomputed fresh and differs between the two roles.
    let fingerprint_a = package::fingerprint(package_a.path()).unwrap();
    let fingerprint_b = package::fingerprint(package_b.path()).unwrap();
    assert_ne!(
        fingerprint_a, fingerprint_b,
        "package fingerprint must never be reused across different package roles"
    );
}

#[test]
fn cache_disabled_env_var_forces_fresh_analysis_every_time() {
    let _guard = EnvGuard::new();
    std::env::set_var("LAYERFAULT_CONTENT_CACHE", "off");
    let scan_dir = tempdir().unwrap();
    let path_a = scan_dir.path().join("model-a.pkl");
    let path_b = scan_dir.path().join("model-b.pkl");
    std::fs::write(&path_a, DANGEROUS_PICKLE).unwrap();
    std::fs::write(&path_b, DANGEROUS_PICKLE).unwrap();

    let _ = inspect_with_format(&path_a, ArtifactFormat::Pickle, ArtifactScanMode::Full).unwrap();
    let report_b =
        inspect_with_format(&path_b, ArtifactFormat::Pickle, ArtifactScanMode::Full).unwrap();
    assert_eq!(
        report_b.cache.as_ref().and_then(|c| c.content.as_deref()),
        Some("MISS"),
        "disabled content cache must never report a hit"
    );
}
