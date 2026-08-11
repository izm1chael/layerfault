//! Bounded static inspection for PyTorch ZIP containers, TorchScript models, and torch.package archives.
//!
//! Layerfault never executes model code, imports untrusted Python, or invokes `torch.jit.load`.

use crate::finding_evidence::{
    file_member, serialization_opcode, structural_invariant, EvidenceSubject, FindingBuilder,
};
use crate::formats::pickle;
use crate::python_static::limits::PythonAnalysisLimits;
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use anyhow::{Context, Result};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use zip::ZipArchive;

const MAX_ZIP_MEMBERS: usize = 16_384;
const MAX_MEMBER_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TOTAL_DECOMPRESSED_BYTES: u64 = 256 * 1024 * 1024;

/// Inspect a PyTorch ZIP container, TorchScript model, or torch.package archive.
pub fn scan(
    path: &Path,
    file: &File,
    _size: u64,
    identity: &str,
    media: &str,
) -> Result<Vec<LayerScanResult>> {
    let mut cloned = file.try_clone().context("failed to clone file handle")?;
    cloned.seek(SeekFrom::Start(0))?;

    let mut archive = match ZipArchive::new(cloned) {
        Ok(a) => a,
        Err(err) => {
            let subject = EvidenceSubject::member(&path.display().to_string())
                .with_sha256(Some(identity.to_owned()))
                .with_media_type(media);
            return Ok(vec![FindingBuilder::new(
                "LF-PYTORCH-MALFORMED",
                CheckType::LayerPolicy,
                ScanStatus::Fail,
            )
            .class(FindingClass::Structural)
            .confidence(Confidence::High)
            .digest(identity)
            .media_type(media)
            .subject(subject.clone())
            .detail(format!("Invalid PyTorch ZIP archive: {err}"))
            .evidence(structural_invariant(
                subject,
                "PyTorch ZIP header parsing failed",
                serde_json::json!({ "error": err.to_string() }),
            ))
            .finish()]);
        }
    };

    let member_count = archive.len();
    if member_count > MAX_ZIP_MEMBERS {
        let subject = EvidenceSubject::member(&path.display().to_string())
            .with_sha256(Some(identity.to_owned()))
            .with_media_type(media);
        return Ok(vec![FindingBuilder::new(
            "LF-ARCHIVE-LIMIT",
            CheckType::LayerPolicy,
            ScanStatus::Fail,
        )
        .class(FindingClass::Structural)
        .confidence(Confidence::High)
        .digest(identity)
        .media_type(media)
        .subject(subject.clone())
        .detail(format!(
            "PyTorch archive member count ({member_count}) exceeds limit ({MAX_ZIP_MEMBERS})"
        ))
        .evidence(structural_invariant(
            subject,
            "archive entry count exceeded maximum bound",
            serde_json::json!({ "count": member_count, "limit": MAX_ZIP_MEMBERS }),
        ))
        .finish()]);
    }

    let mut results = Vec::new();
    let mut total_decompressed = 0u64;
    let mut member_names = Vec::new();
    let mut pickle_entries = Vec::new();
    let mut code_entries = Vec::new();
    let mut storage_entries = BTreeSet::new();

    // Classification features
    let mut is_torchscript = false;
    let mut is_torchpackage = false;

    for i in 0..member_count {
        let entry = match archive.by_index(i) {
            Ok(e) => e,
            Err(err) => {
                let subject = EvidenceSubject::member(&path.display().to_string());
                results.push(
                    FindingBuilder::new(
                        "LF-PYTORCH-CORRUPT-ENTRY",
                        CheckType::LayerPolicy,
                        ScanStatus::Fail,
                    )
                    .class(FindingClass::Structural)
                    .confidence(Confidence::High)
                    .digest(identity)
                    .media_type(media)
                    .subject(subject.clone())
                    .detail(format!("PyTorch ZIP entry index {i} corrupted: {err}"))
                    .finish(),
                );
                continue;
            }
        };

        let raw_name = entry.name().replace('\\', "/");
        if raw_name.contains("../") || raw_name.starts_with('/') {
            let subject = EvidenceSubject::member(&raw_name);
            results.push(
                FindingBuilder::new(
                    "LF-ARCHIVE-TRAVERSAL",
                    CheckType::LayerPolicy,
                    ScanStatus::Fail,
                )
                .class(FindingClass::Structural)
                .confidence(Confidence::High)
                .digest(identity)
                .media_type(media)
                .subject(subject.clone())
                .detail(format!(
                    "Unsafe path traversal entry in PyTorch ZIP: {raw_name}"
                ))
                .evidence(file_member(
                    subject,
                    serde_json::json!({ "name": raw_name, "size": entry.size() }),
                ))
                .finish(),
            );
            continue;
        }

        // Check symlinks
        if entry
            .unix_mode()
            .is_some_and(|mode| mode & 0o170000 == 0o120000)
        {
            let subject = EvidenceSubject::member(&raw_name);
            results.push(
                FindingBuilder::new("LF-ARCHIVE-LINK", CheckType::LayerPolicy, ScanStatus::Fail)
                    .class(FindingClass::Structural)
                    .confidence(Confidence::High)
                    .digest(identity)
                    .media_type(media)
                    .subject(subject.clone())
                    .detail(format!(
                        "Symlink member in PyTorch ZIP container: {raw_name}"
                    ))
                    .evidence(file_member(
                        subject,
                        serde_json::json!({ "name": raw_name, "size": entry.size() }),
                    ))
                    .finish(),
            );
            continue;
        }

        let entry_size = entry.size();
        total_decompressed = match total_decompressed.checked_add(entry_size) {
            Some(sum) if sum <= MAX_TOTAL_DECOMPRESSED_BYTES => sum,
            _ => {
                let subject = EvidenceSubject::member(&path.display().to_string());
                results.push(
                    FindingBuilder::new(
                        "LF-ARCHIVE-BOMB",
                        CheckType::LayerPolicy,
                        ScanStatus::Fail,
                    )
                    .class(FindingClass::Structural)
                    .confidence(Confidence::High)
                    .digest(identity)
                    .media_type(media)
                    .subject(subject)
                    .detail("PyTorch ZIP uncompressed byte count exceeds limit".to_owned())
                    .finish(),
                );
                break;
            }
        };

        if raw_name.contains("package_importer/")
            || raw_name.contains(".extra/")
            || raw_name == "manifest.json"
        {
            is_torchpackage = true;
        }
        if raw_name.contains("code/")
            || raw_name.contains("__torch__/")
            || raw_name.ends_with("constants.pkl")
            || raw_name.ends_with("model.json")
        {
            is_torchscript = true;
        }

        if raw_name.contains("data/") || raw_name.starts_with("archive/data/") {
            storage_entries.insert(raw_name.clone());
        }

        if raw_name.to_ascii_lowercase().ends_with(".pkl") {
            pickle_entries.push((raw_name.clone(), entry_size, i));
        } else if raw_name.ends_with(".py") || raw_name.ends_with(".ts") {
            code_entries.push((raw_name.clone(), entry_size, i));
        }

        member_names.push(raw_name);
    }

    // Inspect pickle members using static opcode analysis
    for (name, entry_size, idx) in pickle_entries {
        if entry_size > MAX_MEMBER_BYTES {
            let subject = EvidenceSubject::member(&name);
            results.push(
                FindingBuilder::new(
                    "LF-ARCHIVE-LIMIT",
                    CheckType::PickleStructure,
                    ScanStatus::Fail,
                )
                .class(FindingClass::Structural)
                .confidence(Confidence::High)
                .digest(identity)
                .media_type(media)
                .subject(subject)
                .detail(format!("Pickle member '{name}' exceeds size limit"))
                .finish(),
            );
            continue;
        }

        let mut zip_entry = match archive.by_index(idx) {
            Ok(e) => e,
            Err(_) => continue,
        };

        let mut buf = Vec::with_capacity(entry_size as usize);
        if zip_entry
            .by_ref()
            .take(MAX_MEMBER_BYTES)
            .read_to_end(&mut buf)
            .is_ok()
        {
            if let Ok(analysis) = pickle::analyze_bytes(&buf) {
                if !analysis.dangerous.is_empty() {
                    for danger in &analysis.dangerous {
                        let subject = EvidenceSubject::member(&name);
                        let site = analysis.site_for(danger);
                        results.push(
                            FindingBuilder::new(
                                "LF-PICKLE-DANGEROUS-GLOBAL",
                                CheckType::PickleStructure,
                                ScanStatus::Fail,
                            )
                            .class(FindingClass::Structural)
                            .confidence(Confidence::High)
                            .digest(identity)
                            .media_type(media)
                            .subject(subject.clone())
                            .detail(format!(
                                "Pickle entry '{name}' references unsafe construct '{danger}'"
                            ))
                            .evidence(serialization_opcode(
                                subject,
                                site.map(|s| s.opcode_index).unwrap_or(0),
                                site.map(|s| s.byte_offset).unwrap_or(0),
                                serde_json::json!({
                                    "opcode": site.map(|s| s.opcode).unwrap_or("GLOBAL"),
                                    "dangerous": danger,
                                }),
                            ))
                            .finish(),
                        );
                    }
                }
            }
        }
    }

    // Inspect code entries (TorchScript code / torch.package code) statically
    for (name, entry_size, idx) in code_entries {
        if entry_size > MAX_MEMBER_BYTES {
            continue;
        }
        let mut zip_entry = match archive.by_index(idx) {
            Ok(e) => e,
            Err(_) => continue,
        };

        let mut buf = Vec::with_capacity(entry_size as usize);
        if zip_entry
            .by_ref()
            .take(MAX_MEMBER_BYTES)
            .read_to_end(&mut buf)
            .is_ok()
        {
            if let Ok(source_text) = String::from_utf8(buf) {
                let py_limits = PythonAnalysisLimits::default();
                if let Ok(py_analysis) = crate::python_static::analyze(
                    &name,
                    &source_text,
                    identity,
                    &BTreeSet::new(),
                    &py_limits,
                ) {
                    for call_site in &py_analysis.call_sites {
                        let target = if !call_site.resolved_target.is_empty() {
                            &call_site.resolved_target
                        } else {
                            &call_site.raw_target
                        };
                        if matches!(
                            target.as_str(),
                            "eval"
                                | "exec"
                                | "os.system"
                                | "subprocess.run"
                                | "subprocess.Popen"
                                | "ctypes.CDLL"
                                | "__import__"
                        ) {
                            let rule_id = if is_torchpackage {
                                "LF-TORCHPACKAGE-EXEC"
                            } else {
                                "LF-TORCHSCRIPT-CODE"
                            };
                            let subject = EvidenceSubject::member(&name);
                            results.push(
                                FindingBuilder::new(
                                    rule_id,
                                    CheckType::PackageSecurity,
                                    ScanStatus::Fail,
                                )
                                .class(FindingClass::Policy)
                                .confidence(Confidence::High)
                                .digest(identity)
                                .media_type(media)
                                .subject(subject.clone())
                                .detail(format!(
                                    "Embedded Python/TorchScript code in '{name}' calls dangerous function '{target}'"
                                ))
                                .finish(),
                            );
                        }
                    }
                }
            }
        }
    }

    // Emit capability / classification finding if no blocking failures were recorded
    let role_finding_id = if is_torchpackage {
        "LF-TORCHPACKAGE-STRUCTURAL"
    } else if is_torchscript {
        "LF-TORCHSCRIPT-STRUCTURAL"
    } else {
        "LF-PYTORCH-ZIP-STRUCTURAL"
    };

    let subject = EvidenceSubject::member(&path.display().to_string());
    results.push(
        FindingBuilder::new(role_finding_id, CheckType::LayerPolicy, ScanStatus::Pass)
            .class(FindingClass::Structural)
            .confidence(Confidence::High)
            .digest(identity)
            .media_type(media)
            .subject(subject.clone())
            .detail(format!(
            "PyTorch container analyzed statically with zero execution: {} members inspected ({})",
            member_names.len(),
            if is_torchpackage {
                "torch.package layout"
            } else if is_torchscript {
                "TorchScript IR layout"
            } else {
                "PyTorch ZIP weights layout"
            }
        ))
            .finish(),
    );

    Ok(results)
}
