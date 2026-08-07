use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let mut files = Vec::new();
    for root in ["src", "schemas", "advisories", "policies"] {
        collect(Path::new(root), &mut files);
    }
    for file in ["Cargo.toml", "Cargo.lock", "THREATS.md"] {
        let path = PathBuf::from(file);
        if path.is_file() {
            files.push(path);
        }
    }
    files.sort();

    let mut hasher = Sha256::new();
    hasher.update(b"layerfault-build-identity\0");
    for path in &files {
        println!("cargo:rerun-if-changed={}", path.display());
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
    println!("cargo:rustc-env=LAYERFAULT_BUILD_ID=sha256:{hex}");
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
