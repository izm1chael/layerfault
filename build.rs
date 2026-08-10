use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let mut build_files = Vec::new();
    for root in ["src", "schemas", "advisories", "policies", "vendor"] {
        collect(Path::new(root), &mut build_files);
    }
    for file in ["Cargo.toml", "Cargo.lock", "THREATS.md", "build.rs"] {
        let path = PathBuf::from(file);
        if path.is_file() {
            build_files.push(path);
        }
    }
    build_files.sort();
    build_files.dedup();
    for path in &build_files {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    println!(
        "cargo:rustc-env=LAYERFAULT_BUILD_ID={}",
        digest_files(b"layerfault-build-identity\0", &build_files)
    );

    // Persistent scan evidence is intentionally invalidated by detector/parser
    // semantics, not by unrelated CLI, platform, documentation or policy edits.
    // The full build identity is still embedded separately for evidence/audit.
    let mut scanner_files = Vec::new();
    for root in [
        "src/scanner",
        "src/formats",
        "src/python_static",
        "src/dependencies",
    ] {
        collect(Path::new(root), &mut scanner_files);
    }
    for file in [
        "src/package.rs",
        "src/safeio.rs",
        "src/hashcache.rs",
        "Cargo.toml",
        "Cargo.lock",
        "build.rs",
    ] {
        let path = PathBuf::from(file);
        if path.is_file() {
            scanner_files.push(path);
        }
    }
    scanner_files.sort();
    scanner_files.dedup();
    println!(
        "cargo:rustc-env=LAYERFAULT_SCANNER_REVISION={}",
        digest_files(b"layerfault-scanner-contract\0", &scanner_files)
    );
}

fn digest_files(domain: &[u8], files: &[PathBuf]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for path in files {
        let rel = path.to_string_lossy().replace('\\', "/");
        hasher.update(rel.as_bytes());
        hasher.update([0]);
        match fs::read(path) {
            Ok(bytes) => hasher.update(bytes),
            Err(error) => panic!(
                "failed to read build-identity input {}: {error}",
                path.display()
            ),
        }
        hasher.update([0xff]);
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        let _ = write!(&mut hex, "{byte:02x}");
    }
    format!("sha256:{hex}")
}

fn collect(path: &Path, files: &mut Vec<PathBuf>) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if metadata.file_type().is_symlink() {
        return;
    }
    if metadata.is_file() {
        files.push(path.to_path_buf());
        return;
    }
    if !metadata.is_dir() {
        return;
    }
    let mut children = match fs::read_dir(path) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect::<Vec<_>>(),
        Err(error) => panic!(
            "failed to enumerate build-identity input {}: {error}",
            path.display()
        ),
    };
    children.sort();
    for child in children {
        collect(&child, files);
    }
}
