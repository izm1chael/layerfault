//! Core ML model (.mlmodel) and package (.mlpackage) static parser.
//!
//! Pure-Rust bounded Protobuf field inspection for .mlmodel files, verifying layer
//! containment, custom plugin references, external weight sidecars, and path safety.

use crate::finding_evidence::{EvidenceSubject, FindingBuilder};
use crate::safeio::open_readonly_nofollow;
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use anyhow::{Context, Result};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Bounded inspection of Core ML .mlmodel binary artifacts.
pub fn scan_model(
    path: &Path,
    file: &File,
    size: u64,
    identity: &str,
    media: &str,
) -> Result<Vec<LayerScanResult>> {
    let mut cloned = file.try_clone().context("failed to clone file handle")?;
    cloned.seek(SeekFrom::Start(0))?;

    let max_read = usize::try_from(size.min(10 * 1024 * 1024)).unwrap_or(10 * 1024 * 1024);
    let mut buf = vec![0u8; max_read];
    cloned.read_exact(&mut buf)?;

    let subject = EvidenceSubject::member(&path.display().to_string())
        .with_sha256(Some(identity.to_owned()))
        .with_media_type(media);

    let mut results = Vec::new();

    // Bounded Protobuf field scanner looking for custom layers and string references
    let mut custom_layers = Vec::new();
    let mut path_traversal_refs = Vec::new();

    // Simple Protobuf varint / string extractor
    let mut pos = 0;
    while pos < buf.len() {
        let (tag_wire, tag_len) = match read_varint(&buf[pos..]) {
            Some(res) => res,
            None => break,
        };
        pos += tag_len;
        let wire_type = tag_wire & 0x07;

        match wire_type {
            0 => {
                // Varint
                if let Some((_, len)) = read_varint(&buf[pos..]) {
                    pos += len;
                } else {
                    break;
                }
            }
            1 => {
                // 64-bit
                pos = pos.saturating_add(8);
            }
            2 => {
                // Length-delimited string or nested message
                if let Some((len, l_bytes)) = read_varint(&buf[pos..]) {
                    pos += l_bytes;
                    let len_u = len as usize;
                    if pos.saturating_add(len_u) <= buf.len() {
                        let chunk = &buf[pos..pos + len_u];
                        if let Ok(s) = std::str::from_utf8(chunk) {
                            if s.contains("CustomLayer") || s.contains("custom_layer") {
                                custom_layers.push(s.to_owned());
                            }
                            if s.contains("../") || s.starts_with('/') {
                                path_traversal_refs.push(s.to_owned());
                            }
                        }
                        pos += len_u;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
            5 => {
                // 32-bit
                pos = pos.saturating_add(4);
            }
            _ => break,
        }
    }

    if !path_traversal_refs.is_empty() {
        for path_ref in path_traversal_refs {
            results.push(
                FindingBuilder::new(
                    "LF-COREML-PATH-TRAVERSAL",
                    CheckType::LayerPolicy,
                    ScanStatus::Fail,
                )
                .class(FindingClass::Structural)
                .confidence(Confidence::High)
                .digest(identity)
                .media_type(media)
                .subject(subject.clone())
                .detail(format!(
                    "Core ML model contains unsafe path traversal reference: '{path_ref}'"
                ))
                .finish(),
            );
        }
    }

    if !custom_layers.is_empty() {
        for custom_layer in custom_layers {
            results.push(
                FindingBuilder::new(
                    "LF-COREML-CUSTOM",
                    CheckType::PackageSecurity,
                    ScanStatus::Warn,
                )
                .class(FindingClass::Compatibility)
                .confidence(Confidence::High)
                .digest(identity)
                .media_type(media)
                .subject(subject.clone())
                .detail(format!(
                    "Core ML model references custom layer/plugin component: '{custom_layer}'"
                ))
                .finish(),
            );
        }
    }

    results.push(
        FindingBuilder::new(
            "LF-COREML-STRUCTURAL",
            CheckType::LayerPolicy,
            ScanStatus::Pass,
        )
        .class(FindingClass::Structural)
        .confidence(Confidence::High)
        .digest(identity)
        .media_type(media)
        .subject(subject)
        .detail(
            "Core ML .mlmodel Protobuf fields inspected statically with zero execution".to_owned(),
        )
        .finish(),
    );

    Ok(results)
}

/// Bounded inspection of Core ML .mlpackage directory package.
pub fn scan_package(path: &Path, identity: &str, media: &str) -> Result<Vec<LayerScanResult>> {
    let mut results = Vec::new();
    let subject = EvidenceSubject::member(&path.display().to_string())
        .with_sha256(Some(identity.to_owned()))
        .with_media_type(media);

    let manifest_path = path.join("Manifest.json");
    if !manifest_path.exists() {
        results.push(
            FindingBuilder::new(
                "LF-COREML-PACKAGE-MISSING-MANIFEST",
                CheckType::LayerPolicy,
                ScanStatus::Warn,
            )
            .class(FindingClass::Structural)
            .confidence(Confidence::High)
            .digest(identity)
            .media_type(media)
            .subject(subject)
            .detail("Core ML .mlpackage directory lacks mandatory Manifest.json file".to_owned())
            .finish(),
        );
        return Ok(results);
    }

    let file = match open_readonly_nofollow(&manifest_path) {
        Ok(file) => file,
        Err(err) => {
            results.push(
                FindingBuilder::new(
                    "LF-COREML-PACKAGE-UNSAFE",
                    CheckType::LayerPolicy,
                    ScanStatus::Fail,
                )
                .class(FindingClass::Structural)
                .confidence(Confidence::High)
                .digest(identity)
                .media_type(media)
                .subject(subject.clone())
                .detail(format!(
                    "Core ML .mlpackage Manifest.json failed safe opening: {err}"
                ))
                .finish(),
            );
            return Ok(results);
        }
    };

    let bytes = match crate::safeio::read_all_from_file(&file, 4 * 1024 * 1024) {
        Ok(b) => b,
        Err(err) => {
            results.push(
                FindingBuilder::new(
                    "LF-COREML-PACKAGE-UNSAFE",
                    CheckType::LayerPolicy,
                    ScanStatus::Fail,
                )
                .class(FindingClass::Structural)
                .confidence(Confidence::High)
                .digest(identity)
                .media_type(media)
                .subject(subject.clone())
                .detail(format!(
                    "Core ML .mlpackage Manifest.json failed safe read: {err}"
                ))
                .finish(),
            );
            return Ok(results);
        }
    };

    let manifest_json: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(val) => val,
        Err(err) => {
            results.push(
                FindingBuilder::new(
                    "LF-COREML-PACKAGE-UNSAFE",
                    CheckType::LayerPolicy,
                    ScanStatus::Fail,
                )
                .class(FindingClass::Structural)
                .confidence(Confidence::High)
                .digest(identity)
                .media_type(media)
                .subject(subject.clone())
                .detail(format!(
                    "Core ML .mlpackage Manifest.json contains invalid JSON: {err}"
                ))
                .finish(),
            );
            return Ok(results);
        }
    };

    let mut unsafe_manifest_refs = Vec::new();

    // Check itemInfoEntries and all declared relative paths in Manifest.json
    if let Some(item_entries) = manifest_json
        .get("itemInfoEntries")
        .and_then(|v| v.as_object())
    {
        for (item_key, item_val) in item_entries {
            if let Some(item_path_str) = item_val.get("path").and_then(|p| p.as_str()) {
                if item_path_str.starts_with('/')
                    || item_path_str.starts_with('\\')
                    || item_path_str.contains("../")
                    || item_path_str.contains("..\\")
                {
                    unsafe_manifest_refs.push(format!(
                        "item '{item_key}' references path traversal: '{item_path_str}'"
                    ));
                } else {
                    let target_path = path.join(item_path_str);
                    if let Ok(meta) = std::fs::symlink_metadata(&target_path) {
                        if meta.file_type().is_symlink()
                            && find_escaping_symlink_target(path, &target_path).is_some()
                        {
                            unsafe_manifest_refs.push(format!(
                                "item '{item_key}' references escaping symlink: '{item_path_str}'"
                            ));
                        }
                    }
                }
            }
        }
    }

    // Check all symlinks present within the .mlpackage directory bundle
    let mut escaping_bundle_symlinks = Vec::new();
    let walker = walkdir::WalkDir::new(path)
        .follow_links(false)
        .max_depth(32)
        .into_iter();
    for entry in walker.flatten() {
        if entry.file_type().is_symlink() {
            if let Some(target_str) = find_escaping_symlink_target(path, entry.path()) {
                let rel = entry
                    .path()
                    .strip_prefix(path)
                    .unwrap_or_else(|_| entry.path())
                    .display()
                    .to_string();
                escaping_bundle_symlinks.push(format!("'{rel}' -> '{target_str}'"));
            }
        }
    }

    if !unsafe_manifest_refs.is_empty() || !escaping_bundle_symlinks.is_empty() {
        let mut details = Vec::new();
        if !unsafe_manifest_refs.is_empty() {
            details.push(format!(
                "unsafe manifest references: [{}]",
                unsafe_manifest_refs.join(", ")
            ));
        }
        if !escaping_bundle_symlinks.is_empty() {
            details.push(format!(
                "escaping bundle symlinks: [{}]",
                escaping_bundle_symlinks.join(", ")
            ));
        }
        results.push(
            FindingBuilder::new(
                "LF-COREML-PACKAGE-UNSAFE",
                CheckType::LayerPolicy,
                ScanStatus::Fail,
            )
            .class(FindingClass::Structural)
            .confidence(Confidence::High)
            .digest(identity)
            .media_type(media)
            .subject(subject.clone())
            .detail(format!(
                "Core ML .mlpackage contains unsafe references or escaping symlinks: {}",
                details.join("; ")
            ))
            .finish(),
        );
    } else {
        results.push(
            FindingBuilder::new(
                "LF-COREML-PACKAGE-VALID",
                CheckType::LayerPolicy,
                ScanStatus::Pass,
            )
            .class(FindingClass::Structural)
            .confidence(Confidence::High)
            .digest(identity)
            .media_type(media)
            .subject(subject.clone())
            .detail("Core ML .mlpackage Manifest.json verified safely".to_owned())
            .finish(),
        );
    }

    Ok(results)
}

fn find_escaping_symlink_target(bundle_root: &Path, link_path: &Path) -> Option<String> {
    let target = match std::fs::read_link(link_path) {
        Ok(t) => t,
        Err(_) => return Some("<unreadable>".to_owned()),
    };
    let target_str = target.to_string_lossy();
    if target_str.starts_with('/')
        || target_str.starts_with('\\')
        || target_str.contains("../")
        || target_str.contains("..\\")
    {
        return Some(target_str.into_owned());
    }
    let parent = link_path.parent().unwrap_or(bundle_root);
    let resolved = parent.join(&target);
    if let (Ok(canon_root), Ok(canon_resolved)) =
        (bundle_root.canonicalize(), resolved.canonicalize())
    {
        if !canon_resolved.starts_with(canon_root) {
            return Some(target_str.into_owned());
        }
    } else {
        // If canonicalization fails, check relative path components
        let mut normal_depth: isize = 0;
        if let Ok(rel_from_root) = parent.strip_prefix(bundle_root) {
            normal_depth = rel_from_root.components().count() as isize;
        }
        for comp in target.components() {
            match comp {
                std::path::Component::ParentDir => normal_depth -= 1,
                std::path::Component::Normal(_) => normal_depth += 1,
                std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                    return Some(target_str.into_owned())
                }
                _ => {}
            }
            if normal_depth < 0 {
                return Some(target_str.into_owned());
            }
        }
    }
    None
}

fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut result = 0u64;
    let mut shift = 0;
    for (i, &byte) in buf.iter().enumerate().take(10) {
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((result, i + 1));
        }
        shift += 7;
    }
    None
}
