use layerfault::formats::extract_normalized;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct FixtureExpected {
    tensor_count: Option<usize>,
    metadata_count: Option<usize>,
    global_refs: Option<Vec<String>>,
    schema_version: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct FixtureEntry {
    id: String,
    path: String,
    sha256: String,
    expected: FixtureExpected,
}

#[derive(Debug, Deserialize)]
struct CorpusManifest {
    version: u32,
    fixtures: Vec<FixtureEntry>,
}

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("corpus")
}

#[test]
fn test_corpus_manifest_compatibility() {
    let manifest_path = corpus_dir().join("manifest.json");
    assert!(
        manifest_path.exists(),
        "tests/corpus/manifest.json must exist"
    );

    let content = std::fs::read_to_string(&manifest_path).unwrap();
    let manifest: CorpusManifest = serde_json::from_str(&content).unwrap();

    assert_eq!(manifest.version, 1);
    assert!(!manifest.fixtures.is_empty());

    for fixture in &manifest.fixtures {
        let full_path = corpus_dir().join(&fixture.path);
        assert!(
            full_path.exists(),
            "Fixture {} at {} does not exist",
            fixture.id,
            full_path.display()
        );

        // Verify SHA256 integrity
        let bytes = std::fs::read(&full_path).unwrap();
        let digest_bytes = Sha256::digest(&bytes);
        let hash = digest_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        assert_eq!(
            hash, fixture.sha256,
            "SHA256 mismatch for fixture {}",
            fixture.id
        );

        // Extract normalized model facts
        let norm = extract_normalized(&full_path).unwrap_or_else(|e| {
            panic!(
                "extract_normalized failed on benign fixture {}: {}",
                fixture.id, e
            )
        });

        // Verify expected properties
        if let Some(exp_tensors) = fixture.expected.tensor_count {
            assert_eq!(
                norm.tensors.len(),
                exp_tensors,
                "Tensor count mismatch for {}",
                fixture.id
            );
        }

        if let Some(exp_meta) = fixture.expected.metadata_count {
            assert_eq!(
                norm.metadata.len(),
                exp_meta,
                "Metadata count mismatch for {}",
                fixture.id
            );
        }

        if let Some(ref exp_globals) = fixture.expected.global_refs {
            assert_eq!(
                &norm.global_refs, exp_globals,
                "Global refs mismatch for {}",
                fixture.id
            );
        }

        if let Some(exp_version) = fixture.expected.schema_version {
            assert_eq!(
                norm.version,
                Some(exp_version),
                "Schema version mismatch for {}",
                fixture.id
            );
        }
    }
}

#[test]
fn test_bounded_mutation_differential() {
    let manifest_path = corpus_dir().join("manifest.json");
    if !manifest_path.exists() {
        return;
    }
    let content = std::fs::read_to_string(&manifest_path).unwrap();
    let manifest: CorpusManifest = serde_json::from_str(&content).unwrap();

    let temp_dir = tempfile::tempdir().unwrap();

    for fixture in &manifest.fixtures {
        let full_path = corpus_dir().join(&fixture.path);
        let orig_bytes = std::fs::read(&full_path).unwrap();
        if orig_bytes.is_empty() {
            continue;
        }

        // Bounded Mutations
        let mutations: Vec<(&str, Vec<u8>)> = vec![
            // 1. Truncated byte stream
            ("truncated", orig_bytes[..orig_bytes.len() / 2].to_vec()),
            // 2. Altered Magic (first 4 bytes overwritten)
            ("altered_magic", {
                let mut b = orig_bytes.clone();
                if b.len() >= 4 {
                    b[0..4].copy_from_slice(b"XXXX");
                }
                b
            }),
            // 3. Corrupt offset/count (overwrite header ints if long enough)
            ("corrupt_offset", {
                let mut b = orig_bytes.clone();
                if b.len() >= 16 {
                    b[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
                }
                b
            }),
            // 4. Duplicate keys / corrupted tail
            ("corrupt_tail", {
                let mut b = orig_bytes.clone();
                b.extend_from_slice(b"\xff\xff\xff\xff\xff\xff\xff\xff");
                b
            }),
        ];

        for (mut_name, mut_bytes) in mutations {
            let mut_path = temp_dir
                .path()
                .join(format!("{}_{}.bin", fixture.id, mut_name));
            std::fs::write(&mut_path, &mut_bytes).unwrap();

            // Layerfault MUST NOT panic when inspecting or extracting normalized facts from mutated inputs
            let norm_res = extract_normalized(&mut_path);

            // If norm_res succeeded, verify it did not crash or panic
            if let Ok(norm) = norm_res {
                // Ensure bounded work
                assert!(norm.tensors.len() <= 1_000_000);
            }

            // Also inspect with artifact inspector to ensure security warnings or errors are returned
            let _ = layerfault::formats::artifact::inspect(
                &mut_path,
                layerfault::formats::artifact::ArtifactScanMode::StructureOnly,
            );
        }
    }
}
