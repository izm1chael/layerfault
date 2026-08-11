use super::detect::ArchiveFormat;
use super::limits::ArchiveBudgetTracker;
use super::member::{format_virtual_subject, normalize_member_path, ArchiveMemberTracker};
use super::{ArchiveCoverage, ArchiveMemberReport, ArchiveReport, CoverageState};
use crate::safeio::open_readonly_nofollow;
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use anyhow::{anyhow, Context, Result};
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use tar::Archive;
use tempfile::NamedTempFile;

pub fn inspect_tar(
    display_path: &Path,
    file: &File,
    identity: &str,
    budget: &mut ArchiveBudgetTracker,
    is_gz: bool,
    format: ArchiveFormat,
    global_budget: &crate::budget::ScanBudget,
) -> Result<ArchiveReport> {
    budget.check_depth().map_err(|e| anyhow!(e))?;
    budget.check_nested_archives().map_err(|e| anyhow!(e))?;

    let mut cloned_file = file.try_clone().with_context(|| {
        format!(
            "Unable to clone file handle for '{}'",
            display_path.display()
        )
    })?;
    cloned_file.seek(SeekFrom::Start(0))?;

    let reader: Box<dyn Read> = if is_gz {
        Box::new(GzDecoder::new(cloned_file))
    } else {
        Box::new(cloned_file)
    };

    let mut archive = Archive::new(reader);
    let mut member_reports = Vec::new();
    let mut findings = Vec::new();
    let mut tracker = ArchiveMemberTracker::new();
    let mut coverage_state = CoverageState::Complete;
    let mut coverage_details = Vec::new();
    let mut inspected_members = 0usize;
    let mut skipped_members = 0usize;
    let mut total_uncompressed = 0u64;

    let entries = match archive.entries() {
        Ok(entries) => entries,
        Err(err) => {
            return Ok(ArchiveReport {
                format,
                members: Vec::new(),
                findings: vec![make_finding(
                    identity,
                    CheckType::PackageSecurity,
                    ScanStatus::Fail,
                    FindingClass::Structural,
                    Confidence::High,
                    "LF-ARCHIVE-MALFORMED",
                    format!("Invalid TAR archive header: {}", err),
                )],
                coverage: ArchiveCoverage {
                    state: CoverageState::Incomplete,
                    inspected_members: 0,
                    skipped_members: 0,
                    total_uncompressed_bytes: 0,
                    details: vec!["Invalid TAR header stream".to_owned()],
                },
            });
        }
    };

    for (index, entry_res) in entries.enumerate() {
        if global_budget.check().is_err() {
            coverage_state = CoverageState::Incomplete;
            coverage_details.push(format!(
                "Scan deadline/cancellation reached while reading TAR entry index {}",
                index
            ));
            break;
        }
        if budget.add_member().is_err() {
            coverage_state = CoverageState::Incomplete;
            coverage_details.push("Cumulative member limit exceeded".to_owned());
            findings.push(make_finding(
                identity,
                CheckType::PackageSecurity,
                ScanStatus::Fail,
                FindingClass::Structural,
                Confidence::High,
                "LF-ARCHIVE-LIMIT",
                format!(
                    "Cumulative member limit exceeded while reading TAR entry index {}",
                    index
                ),
            ));
            break;
        }

        let mut entry = match entry_res {
            Ok(entry) => entry,
            Err(err) => {
                coverage_state = CoverageState::Incomplete;
                skipped_members += 1;
                findings.push(make_finding(
                    identity,
                    CheckType::PackageSecurity,
                    ScanStatus::Fail,
                    FindingClass::Structural,
                    Confidence::High,
                    "LF-ARCHIVE-MALFORMED",
                    format!("Truncated or malformed TAR entry index {}: {}", index, err),
                ));
                break;
            }
        };

        let raw_name = match entry.path() {
            Ok(p) => p.to_string_lossy().to_string(),
            Err(err) => {
                coverage_state = CoverageState::Incomplete;
                skipped_members += 1;
                findings.push(make_finding(
                    identity,
                    CheckType::PackageSecurity,
                    ScanStatus::Fail,
                    FindingClass::Structural,
                    Confidence::High,
                    "LF-ARCHIVE-MALFORMED",
                    format!("Invalid UTF-8/path in TAR entry index {}: {}", index, err),
                ));
                continue;
            }
        };

        let entry_type = entry.header().entry_type();
        let is_dir = entry_type.is_dir();
        let is_symlink = entry_type.is_symlink();
        let is_hardlink = entry_type.is_hard_link();
        let size_uncompressed = entry.header().size().unwrap_or(0);

        let norm_res = normalize_member_path(&raw_name, budget.limits.max_path_bytes);
        let norm_path = match norm_res {
            Ok(np) => np,
            Err(err) => {
                coverage_state = CoverageState::Incomplete;
                coverage_details.push(format!("Unsafe TAR member path '{}': {}", raw_name, err));
                findings.push(make_finding(
                    identity,
                    CheckType::PackageSecurity,
                    ScanStatus::Fail,
                    FindingClass::Structural,
                    Confidence::High,
                    "LF-ARCHIVE-TRAVERSAL",
                    format!("TAR entry '{}' uses unsafe path: {}", raw_name, err),
                ));
                member_reports.push(ArchiveMemberReport {
                    virtual_path: format_virtual_subject(identity, &raw_name),
                    raw_name: raw_name.clone(),
                    size_compressed: 0,
                    size_uncompressed,
                    sha256: None,
                    is_dir,
                    is_symlink,
                    is_hardlink,
                    link_target: None,
                    is_encrypted: false,
                    format_smuggling: false,
                });
                skipped_members += 1;
                continue;
            }
        };

        let virt_path = format_virtual_subject(identity, &norm_path.virtual_path);
        let (is_dup, case_collision) = tracker.record(&norm_path.virtual_path);

        if is_dup {
            findings.push(make_finding(
                &virt_path,
                CheckType::PackageSecurity,
                ScanStatus::Fail,
                FindingClass::Structural,
                Confidence::High,
                "LF-ARCHIVE-DUPLICATE",
                format!(
                    "TAR archive contains duplicate entry for normalized path '{}'",
                    norm_path.virtual_path
                ),
            ));
        }

        if let Some(collision) = case_collision {
            findings.push(make_finding(
                &virt_path,
                CheckType::PackageSecurity,
                ScanStatus::Warn,
                FindingClass::Compatibility,
                Confidence::Medium,
                "LF-ARCHIVE-DUPLICATE",
                format!(
                    "TAR archive entry '{}' case-collides with existing entry '{}'",
                    norm_path.virtual_path, collision
                ),
            ));
        }

        let mut link_target = None;
        if is_symlink || is_hardlink {
            if let Ok(Some(target_path)) = entry.link_name() {
                link_target = Some(target_path.to_string_lossy().to_string());
            }
            let link_kind = if is_symlink {
                "symbolic link"
            } else {
                "hardlink"
            };
            findings.push(make_finding(
                &virt_path,
                CheckType::PackageSecurity,
                ScanStatus::Warn,
                FindingClass::Structural,
                Confidence::High,
                "LF-ARCHIVE-LINK",
                format!(
                    "TAR entry '{}' is a {} -> '{}'",
                    norm_path.virtual_path,
                    link_kind,
                    link_target.as_deref().unwrap_or("<unreadable>")
                ),
            ));
            member_reports.push(ArchiveMemberReport {
                virtual_path: virt_path,
                raw_name,
                size_compressed: 0,
                size_uncompressed,
                sha256: None,
                is_dir: false,
                is_symlink,
                is_hardlink,
                link_target,
                is_encrypted: false,
                format_smuggling: false,
            });
            inspected_members += 1;
            continue;
        }

        if is_dir {
            member_reports.push(ArchiveMemberReport {
                virtual_path: virt_path,
                raw_name,
                size_compressed: 0,
                size_uncompressed: 0,
                sha256: None,
                is_dir: true,
                is_symlink: false,
                is_hardlink: false,
                link_target: None,
                is_encrypted: false,
                format_smuggling: false,
            });
            inspected_members += 1;
            continue;
        }

        // Check member uncompressed limit
        if size_uncompressed > budget.limits.max_uncompressed_member_bytes {
            coverage_state = CoverageState::Incomplete;
            coverage_details.push(format!(
                "Member '{}' uncompressed size ({}) exceeds limit ({})",
                norm_path.virtual_path,
                size_uncompressed,
                budget.limits.max_uncompressed_member_bytes
            ));
            findings.push(make_finding(
                &virt_path,
                CheckType::PackageSecurity,
                ScanStatus::Fail,
                FindingClass::Structural,
                Confidence::High,
                "LF-ARCHIVE-LIMIT",
                format!(
                    "TAR entry '{}' declared size {} bytes exceeds member safety limit {}",
                    norm_path.virtual_path,
                    size_uncompressed,
                    budget.limits.max_uncompressed_member_bytes
                ),
            ));
            skipped_members += 1;
            continue;
        }

        // Decompress member into tempfile with byte cap enforcement
        let decomp_res = decompress_tar_member(&mut entry, budget, global_budget);
        let (temp_file, member_sha256, actual_uncompressed) = match decomp_res {
            Ok(val) => val,
            Err(err_msg) => {
                coverage_state = CoverageState::Incomplete;
                coverage_details.push(format!(
                    "Decompression cap error on TAR entry '{}': {}",
                    norm_path.virtual_path, err_msg
                ));
                findings.push(make_finding(
                    &virt_path,
                    CheckType::PackageSecurity,
                    ScanStatus::Fail,
                    FindingClass::Structural,
                    Confidence::High,
                    "LF-ARCHIVE-BOMB",
                    format!(
                        "TAR entry '{}' failed streaming decompression limits: {}",
                        norm_path.virtual_path, err_msg
                    ),
                ));
                skipped_members += 1;
                continue;
            }
        };

        total_uncompressed = total_uncompressed.saturating_add(actual_uncompressed);
        inspected_members += 1;

        member_reports.push(ArchiveMemberReport {
            virtual_path: virt_path.clone(),
            raw_name: raw_name.clone(),
            size_compressed: 0,
            size_uncompressed: actual_uncompressed,
            sha256: Some(member_sha256.clone()),
            is_dir: false,
            is_symlink: false,
            is_hardlink: false,
            link_target: None,
            is_encrypted: false,
            format_smuggling: false,
        });

        // Dispatch member downstream to scanners
        let member_findings = dispatch_tar_member_scan(
            &norm_path.virtual_path,
            &virt_path,
            temp_file.path(),
            actual_uncompressed,
            &member_sha256,
            budget,
            global_budget,
        )?;
        findings.extend(member_findings);
    }

    if findings.iter().any(|f| {
        f.status == ScanStatus::Fail
            || f.matches.iter().any(|m| {
                m.contains("LF-ARCHIVE-LIMIT")
                    || m.contains("LF-ARCHIVE-BOMB")
                    || m.contains("LF-ARCHIVE-NESTED")
                    || m.contains("LF-ARCHIVE-TRAVERSAL")
                    || m.contains("LF-ARCHIVE-ENCRYPTED")
            })
    }) {
        coverage_state = CoverageState::Incomplete;
    }

    Ok(ArchiveReport {
        format,
        members: member_reports,
        findings,
        coverage: ArchiveCoverage {
            state: coverage_state,
            inspected_members,
            skipped_members,
            total_uncompressed_bytes: total_uncompressed,
            details: coverage_details,
        },
    })
}

fn decompress_tar_member<R: Read>(
    reader: &mut R,
    budget: &mut ArchiveBudgetTracker,
    global_budget: &crate::budget::ScanBudget,
) -> Result<(NamedTempFile, String, u64), String> {
    let mut temp = NamedTempFile::new().map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total_read = 0u64;

    loop {
        let count = reader.read(&mut buffer).map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }

        total_read = total_read
            .checked_add(count as u64)
            .ok_or_else(|| "Member byte count overflow".to_string())?;

        if total_read > budget.limits.max_uncompressed_member_bytes {
            return Err(format!(
                "Decompressed member size ({}) exceeded member limit ({})",
                total_read, budget.limits.max_uncompressed_member_bytes
            ));
        }

        budget.add_uncompressed_bytes(count as u64)?;
        global_budget
            .consume(
                crate::budget::BudgetDimension::DecompressedBytes,
                count as u64,
                "tar decompression",
            )
            .map_err(|error| error.to_string())?;
        global_budget
            .consume(
                crate::budget::BudgetDimension::TemporaryDiskBytes,
                count as u64,
                "tar staging",
            )
            .map_err(|error| error.to_string())?;

        hasher.update(&buffer[..count]);
        temp.write_all(&buffer[..count])
            .map_err(|e| e.to_string())?;
        crate::perf_metrics::record_temp_disk_bytes(count as u64);
    }

    temp.flush().map_err(|e| e.to_string())?;

    let hash_hex = format!("sha256:{}", hex::encode(hasher.finalize()));
    Ok((temp, hash_hex, total_read))
}

fn dispatch_tar_member_scan(
    rel_path: &str,
    virt_path: &str,
    content_path: &Path,
    size: u64,
    digest: &str,
    budget: &mut ArchiveBudgetTracker,
    global_budget: &crate::budget::ScanBudget,
) -> Result<Vec<LayerScanResult>> {
    let mut out = Vec::new();
    let file = open_readonly_nofollow(content_path)?;
    let ext = Path::new(rel_path)
        .extension()
        .and_then(|v| v.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    // Check if member is a nested archive
    let mut prefix_buf = [0_u8; 512];
    let mut cloned = file.try_clone()?;
    cloned.seek(SeekFrom::Start(0))?;
    let n = cloned.read(&mut prefix_buf)?;
    let prefix = &prefix_buf[..n];

    let detection = super::detect::detect_archive_format(Path::new(rel_path), prefix);
    if detection.format != ArchiveFormat::Unknown {
        if budget.current_depth + 1 > budget.limits.max_depth
            || budget.total_nested_archives_seen + 1 > budget.limits.max_nested_archives
        {
            out.push(make_finding(
                digest,
                CheckType::PackageSecurity,
                ScanStatus::Warn,
                FindingClass::Structural,
                Confidence::High,
                "LF-ARCHIVE-NESTED",
                format!(
                    "Nested archive '{}' exceeded recursion/nested limit; deep scanning skipped",
                    rel_path
                ),
            ));
        } else if budget.enter_nested().is_ok() {
            let is_nested_wheel = detection.format == ArchiveFormat::Wheel;
            match detection.format {
                ArchiveFormat::Zip | ArchiveFormat::Wheel => {
                    let child_report = super::zip::inspect_zip(
                        content_path,
                        &file,
                        virt_path,
                        budget,
                        is_nested_wheel,
                        detection.format,
                        global_budget,
                    )?;
                    out.extend(child_report.findings);
                }
                ArchiveFormat::Tar | ArchiveFormat::TarGz => {
                    let child_report = inspect_tar(
                        content_path,
                        &file,
                        virt_path,
                        budget,
                        detection.format == ArchiveFormat::TarGz,
                        detection.format,
                        global_budget,
                    )?;
                    out.extend(child_report.findings);
                }
                ArchiveFormat::Unknown => {}
            }
            budget.leave_nested();
        } else {
            out.push(make_finding(
                digest,
                CheckType::PackageSecurity,
                ScanStatus::Warn,
                FindingClass::Structural,
                Confidence::High,
                "LF-ARCHIVE-NESTED",
                format!(
                    "Nested archive '{}' exceeded recursion/nested limit; deep scanning skipped",
                    rel_path
                ),
            ));
        }
        return Ok(out);
    }

    // Model artifact check
    let identification =
        crate::formats::ArtifactIdentification::identify(Path::new(rel_path), prefix);
    if identification.selected != crate::formats::ArtifactFormat::Unknown
        || !identification.contradictions.is_empty()
    {
        let scan_format = if identification.selected != crate::formats::ArtifactFormat::Unknown {
            identification.selected
        } else {
            identification
                .extension_claim
                .unwrap_or(crate::formats::ArtifactFormat::Unknown)
        };
        match crate::formats::artifact::inspect_opened_file_with_sha256_budget(
            content_path,
            &file,
            scan_format,
            crate::formats::artifact::ArtifactScanMode::Full,
            digest,
            global_budget,
        ) {
            Ok(report) => {
                for mut res in report.results {
                    res.layer_digest = digest.to_owned();
                    out.push(res);
                }
            }
            Err(err) => {
                out.push(make_finding(
                    digest,
                    CheckType::PackageSecurity,
                    ScanStatus::Fail,
                    FindingClass::Structural,
                    Confidence::High,
                    "LF-PACKAGE-ARTIFACT",
                    format!(
                        "Archive member artifact '{}' failed scanning: {}",
                        rel_path, err
                    ),
                ));
            }
        }
        return Ok(out);
    }

    // Binary / executable check
    if crate::scanner::BinaryScanner::looks_executable_prefix(prefix) {
        let binary = crate::scanner::BinaryScanner::scan_file(
            &file,
            size,
            digest,
            "application/vnd.layerfault.archive-member",
        )?;
        if binary.status == ScanStatus::Fail {
            out.push(binary);
        }
    }

    if is_native_ext(&ext) {
        out.push(make_finding(
            digest,
            CheckType::PackageSecurity,
            ScanStatus::Warn,
            FindingClass::ContentIndicator,
            Confidence::High,
            "LF-PACKAGE-CODE",
            format!(
                "Archive contains native/executable code member '{}'",
                rel_path
            ),
        ));
    }

    // Python static analysis
    if ext == "py" {
        let limits = crate::python_static::limits::PythonAnalysisLimits::default();
        if size as usize <= limits.max_source_bytes {
            let mut reader = file.try_clone()?;
            reader.seek(SeekFrom::Start(0))?;
            if let Ok(source_bytes) =
                crate::safeio::read_all_from_file(&reader, limits.max_source_bytes as u64)
            {
                if let Ok(source_str) = std::str::from_utf8(&source_bytes) {
                    global_budget
                        .consume(
                            crate::budget::BudgetDimension::ParserWorkUnits,
                            source_bytes.len() as u64,
                            "python parser",
                        )
                        .map_err(|error| anyhow!("global scan budget exhausted: {error}"))?;
                    global_budget
                        .consume(crate::budget::BudgetDimension::AstNodes, 1, "python AST")
                        .map_err(|error| anyhow!("global scan budget exhausted: {error}"))?;
                    let started = std::time::Instant::now();
                    let empty_map = std::collections::BTreeSet::new();
                    if let Ok(semantic_findings) =
                        crate::python_static::analyze_and_convert_findings(
                            rel_path, source_str, digest, &empty_map, &limits, started,
                        )
                    {
                        out.extend(semantic_findings);
                    }
                }
            }
        }
    }

    Ok(out)
}

fn is_native_ext(ext: &str) -> bool {
    matches!(ext, "so" | "dll" | "dylib" | "exe" | "pyd" | "node")
}

fn make_finding(
    digest: &str,
    check_type: CheckType,
    status: ScanStatus,
    class: FindingClass,
    confidence: Confidence,
    rule: &str,
    detail: String,
) -> LayerScanResult {
    let media_type = "application/vnd.layerfault.archive";
    let subject = crate::finding_evidence::EvidenceSubject::identity(digest, media_type)
        .with_sha256(Some(digest.to_owned()));
    crate::finding_evidence::FindingBuilder::new(rule, check_type, status)
        .class(class)
        .confidence(confidence)
        .digest(digest)
        .media_type(media_type)
        .subject(subject)
        .detail(detail)
        .match_note("archive finding")
        .evidence_unavailable(
            "archive-level structural/coverage condition without a single attributable member",
        )
        .finish()
}
