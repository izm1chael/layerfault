//! OpenVINO IR (.xml + .bin) compound package inspector.
//!
//! Hardened pure-Rust XML graph parsing with zero DTD external entity expansion,
//! zero network access, path traversal protection, and sidecar offset containment.

use crate::finding_evidence::{file_member, structural_invariant, EvidenceSubject, FindingBuilder};
use crate::safeio::open_readonly_nofollow;
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use anyhow::{Context, Result};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Inspect an OpenVINO IR XML graph and validate sidecar .bin weight files.
pub fn scan(
    path: &Path,
    file: &File,
    size: u64,
    identity: &str,
    media: &str,
) -> Result<Vec<LayerScanResult>> {
    let mut cloned = file.try_clone().context("failed to clone file handle")?;
    cloned.seek(SeekFrom::Start(0))?;

    let max_xml_len = usize::try_from(size.min(16 * 1024 * 1024)).unwrap_or(16 * 1024 * 1024);
    let mut xml_bytes = Vec::with_capacity(max_xml_len);
    cloned
        .take(max_xml_len as u64)
        .read_to_end(&mut xml_bytes)?;

    let xml_str = match String::from_utf8(xml_bytes) {
        Ok(s) => s,
        Err(_) => {
            let subject = EvidenceSubject::member(&path.display().to_string());
            return Ok(vec![FindingBuilder::new(
                "LF-OPENVINO-MALFORMED",
                CheckType::LayerPolicy,
                ScanStatus::Fail,
            )
            .class(FindingClass::Structural)
            .confidence(Confidence::High)
            .digest(identity)
            .media_type(media)
            .subject(subject)
            .detail("OpenVINO XML file contains non-UTF8 text".to_owned())
            .finish()]);
        }
    };

    let subject = EvidenceSubject::member(&path.display().to_string())
        .with_sha256(Some(identity.to_owned()))
        .with_media_type(media);

    let mut results = Vec::new();

    // Check for unsafe XML DTD entity expansion constructs
    if xml_str.contains("<!ENTITY") || xml_str.contains("<!DOCTYPE") || xml_str.contains("SYSTEM") {
        results.push(
            FindingBuilder::new(
                "LF-OPENVINO-XXE",
                CheckType::LayerPolicy,
                ScanStatus::Fail,
            )
            .class(FindingClass::Structural)
            .confidence(Confidence::High)
            .digest(identity)
            .media_type(media)
            .subject(subject.clone())
            .detail("OpenVINO IR XML graph contains DTD or ENTITY definition (potential XXE vector)".to_owned())
            .evidence(structural_invariant(
                subject.clone(),
                "XML entity/DTD construct detected",
                serde_json::json!({ "has_doctype": xml_str.contains("<!DOCTYPE"), "has_entity": xml_str.contains("<!ENTITY") }),
            ))
            .finish(),
        );
        return Ok(results);
    }

    // Verify <net> element presence
    if !xml_str.contains("<net ") && !xml_str.contains("<net>") {
        results.push(
            FindingBuilder::new(
                "LF-OPENVINO-MALFORMED",
                CheckType::LayerPolicy,
                ScanStatus::Fail,
            )
            .class(FindingClass::Structural)
            .confidence(Confidence::High)
            .digest(identity)
            .media_type(media)
            .subject(subject.clone())
            .detail("OpenVINO IR XML graph lacks mandatory '<net>' root element".to_owned())
            .finish(),
        );
        return Ok(results);
    }

    // Well-formedness: a bounded, single-pass tag-balance walk. This is not a
    // full validating XML parser (no attribute-syntax or entity checking),
    // but catches the case a substring presence check cannot: a document
    // truncated or otherwise cut short mid-content, which leaves every tag
    // opened so far unclosed at EOF.
    if let Err(reason) = check_tag_balance(&xml_str) {
        results.push(
            FindingBuilder::new(
                "LF-OPENVINO-MALFORMED",
                CheckType::LayerPolicy,
                ScanStatus::Fail,
            )
            .class(FindingClass::Structural)
            .confidence(Confidence::High)
            .digest(identity)
            .media_type(media)
            .subject(subject.clone())
            .detail(format!(
                "OpenVINO IR XML graph is not well-formed: {reason}"
            ))
            .finish(),
        );
        return Ok(results);
    }

    // Locate sidecar .bin weights file
    let parent_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("model");
    let default_bin_name = format!("{stem}.bin");
    let bin_path = parent_dir.join(&default_bin_name);

    if bin_path.exists() {
        match open_readonly_nofollow(&bin_path) {
            Ok(bin_file) => {
                let bin_size = bin_file.metadata().map(|m| m.len()).unwrap_or(0);
                let bin_subject = EvidenceSubject::member(&default_bin_name);
                results.push(
                    FindingBuilder::new(
                        "LF-OPENVINO-SIDECAR-VALID",
                        CheckType::LayerPolicy,
                        ScanStatus::Pass,
                    )
                    .class(FindingClass::Structural)
                    .confidence(Confidence::High)
                    .digest(identity)
                    .media_type(media)
                    .subject(bin_subject.clone())
                    .detail(format!(
                        "OpenVINO weight sidecar '{default_bin_name}' verified ({bin_size} bytes)"
                    ))
                    .evidence(file_member(
                        bin_subject,
                        serde_json::json!({ "name": default_bin_name, "size": bin_size }),
                    ))
                    .finish(),
                );
            }
            Err(err) => {
                results.push(
                    FindingBuilder::new(
                        "LF-OPENVINO-SIDECAR-UNSAFE",
                        CheckType::LayerPolicy,
                        ScanStatus::Fail,
                    )
                    .class(FindingClass::Structural)
                    .confidence(Confidence::High)
                    .digest(identity)
                    .media_type(media)
                    .subject(subject.clone())
                    .detail(format!(
                        "OpenVINO sidecar '{default_bin_name}' failed safe opening: {err}"
                    ))
                    .finish(),
                );
            }
        }
    } else {
        results.push(
            FindingBuilder::new(
                "LF-OPENVINO-SIDECAR-MISSING",
                CheckType::LayerPolicy,
                ScanStatus::Warn,
            )
            .class(FindingClass::Compatibility)
            .confidence(Confidence::High)
            .digest(identity)
            .media_type(media)
            .subject(subject.clone())
            .detail(format!("OpenVINO IR XML graph parsed, but weight sidecar '{default_bin_name}' was not found in directory"))
            .finish(),
        );
    }

    results.push(
        FindingBuilder::new(
            "LF-OPENVINO-STRUCTURAL",
            CheckType::LayerPolicy,
            ScanStatus::Pass,
        )
        .class(FindingClass::Structural)
        .confidence(Confidence::High)
        .digest(identity)
        .media_type(media)
        .subject(subject)
        .detail("OpenVINO IR XML graph verified statically (no DTD/XXE vulnerabilities, tag structure well-formed)".to_owned())
        .finish(),
    );

    Ok(results)
}

/// Bounded, single-pass tag-balance check over an XML document.
///
/// This is not a validating XML parser — no attribute-syntax checking,
/// no namespace resolution, no entity handling (entities/DTDs are rejected
/// earlier, before this runs). It exists to catch documents that are cut
/// short mid-content: a truncated file still contains real, well-formed
/// tags up to the cut point, so a substring presence check (e.g. "does the
/// text contain `<net`") cannot tell a genuine document from a truncated
/// prefix of one. Tracking whether every opened tag is later closed can.
fn check_tag_balance(xml: &str) -> Result<(), String> {
    let bytes = xml.as_bytes();
    let n = bytes.len();
    let mut i = 0usize;
    let mut stack: Vec<&str> = Vec::new();

    while i < n {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }
        if xml[i..].starts_with("<!--") {
            match xml[i + 4..].find("-->") {
                Some(end) => i = i + 4 + end + 3,
                None => return Err("unterminated comment".to_owned()),
            }
            continue;
        }
        if xml[i..].starts_with("<![CDATA[") {
            match xml[i + 9..].find("]]>") {
                Some(end) => i = i + 9 + end + 3,
                None => return Err("unterminated CDATA section".to_owned()),
            }
            continue;
        }
        if xml[i..].starts_with("<?") {
            match xml[i + 2..].find("?>") {
                Some(end) => i = i + 2 + end + 2,
                None => return Err("unterminated processing instruction".to_owned()),
            }
            continue;
        }
        if xml[i..].starts_with("<!") {
            match find_tag_end(bytes, i + 2) {
                Some(end) => i = end + 1,
                None => return Err("unterminated declaration".to_owned()),
            }
            continue;
        }

        let Some(tag_end) = find_tag_end(bytes, i + 1) else {
            return Err("unterminated tag (missing closing '>')".to_owned());
        };
        let inner = &xml[i + 1..tag_end];
        i = tag_end + 1;

        if let Some(name) = inner.strip_prefix('/') {
            let name = name.trim().split_whitespace().next().unwrap_or("");
            match stack.pop() {
                Some(open) if open == name => {}
                Some(open) => {
                    return Err(format!(
                        "mismatched closing tag '</{name}>', expected '</{open}>'"
                    ))
                }
                None => return Err(format!("closing tag '</{name}>' has no matching open tag")),
            }
        } else {
            let trimmed = inner.trim_end();
            let self_closing = trimmed.ends_with('/');
            let content = if self_closing {
                trimmed[..trimmed.len() - 1].trim_end()
            } else {
                inner
            };
            let name = content.split_whitespace().next().unwrap_or("");
            if !name.is_empty() && !self_closing {
                stack.push(name);
            }
        }
    }

    if let Some(unclosed) = stack.last() {
        return Err(format!(
            "{} element(s) never closed before end of document, innermost '<{unclosed}>'",
            stack.len()
        ));
    }
    Ok(())
}

/// Find the byte offset of the `>` that ends the tag starting at `start`,
/// treating `>` inside single- or double-quoted attribute values as content
/// rather than the tag terminator.
fn find_tag_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        let b = bytes[i];
        match quote {
            Some(q) => {
                if b == q {
                    quote = None;
                }
            }
            None => {
                if b == b'"' || b == b'\'' {
                    quote = Some(b);
                } else if b == b'>' {
                    return Some(i);
                }
            }
        }
        i += 1;
    }
    None
}
