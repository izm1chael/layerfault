use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const SECTION: &[u8] = b"\n--LAYERFAULT-FUZZ-SECTION--\n";

pub fn split_sections(data: &[u8], max_parts: usize) -> Vec<&[u8]> {
    if max_parts <= 1 {
        return vec![data];
    }
    let mut parts = Vec::new();
    let mut start = 0usize;
    while parts.len() + 1 < max_parts {
        let Some(relative) = find_subslice(&data[start..], SECTION) else {
            break;
        };
        let end = start + relative;
        parts.push(&data[start..end]);
        start = end + SECTION.len();
    }
    parts.push(&data[start..]);
    parts
}

pub fn part<'a>(parts: &'a [&'a [u8]], index: usize) -> &'a [u8] {
    parts.get(index).copied().unwrap_or_default()
}

pub fn replace_token(data: &[u8], token: &[u8], replacement: &[u8]) -> Vec<u8> {
    if token.is_empty() {
        return data.to_vec();
    }
    let mut out = Vec::with_capacity(data.len().saturating_add(replacement.len()));
    let mut cursor = 0usize;
    while let Some(relative) = find_subslice(&data[cursor..], token) {
        let at = cursor + relative;
        out.extend_from_slice(&data[cursor..at]);
        out.extend_from_slice(replacement);
        cursor = at + token.len();
    }
    out.extend_from_slice(&data[cursor..]);
    out
}

pub fn write_file(root: &Path, relative: &str, bytes: &[u8]) -> io::Result<PathBuf> {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&path, bytes)?;
    Ok(path)
}

#[cfg(unix)]
pub fn symlink_file(target: &Path, link: &Path) -> io::Result<()> {
    if let Some(parent) = link.parent() {
        fs::create_dir_all(parent)?;
    }
    // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path
    std::os::unix::fs::symlink(target, link)
}

#[cfg(windows)]
pub fn symlink_file(target: &Path, link: &Path) -> io::Result<()> {
    if let Some(parent) = link.parent() {
        fs::create_dir_all(parent)?;
    }
    std::os::windows::fs::symlink_file(target, link)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
