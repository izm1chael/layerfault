use super::detect::ArchiveFormat;
use super::limits::ArchiveBudgetTracker;
use super::member::{format_virtual_subject, normalize_member_path, ArchiveMemberTracker};
use super::{ArchiveCoverage, ArchiveMemberReport, ArchiveReport, CoverageState};
use crate::safeio::open_readonly_nofollow;
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use anyhow::{anyhow, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use tempfile::NamedTempFile;
use zip::ZipArchive;

pub fn inspect_zip(
    display_path: &Path,
    file: &File,
    identity: &str,
    budget: &mut ArchiveBudgetTracker,
    is_wheel: bool,
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

    let mut archive = ZipArchive::new(cloned_file)
        .with_context(|| format!("Invalid ZIP archive header in '{}'", display_path.display()))?;

    let member_count = archive.len();
    if member_count > budget.limits.max_members_per_archive {
        let report_findings = vec![make_finding(
            identity,
            CheckType::PackageSecurity,
            ScanStatus::Fail,
            FindingClass::Structural,
            Confidence::High,
            "LF-ARCHIVE-LIMIT",
            format!(
                "ZIP archive entry count ({}) exceeds maximum per-archive limit ({})",
                member_count, budget.limits.max_members_per_archive
            ),
        )];
        return Ok(ArchiveReport {
            format,
            members: Vec::new(),
            findings: report_findings,
            coverage: ArchiveCoverage {
                state: CoverageState::Incomplete,
                inspected_members: 0,
                skipped_members: member_count,
                total_uncompressed_bytes: 0,
                details: vec!["Archive member count limit exceeded".to_owned()],
            },
        });
    }

    let mut member_reports = Vec::new();
    let mut findings = Vec::new();
    let mut tracker = ArchiveMemberTracker::new();
    let mut coverage_state = CoverageState::Complete;
    let mut coverage_details = Vec::new();
    let mut inspected_members = 0usize;
    let mut skipped_members = 0usize;
    let mut total_uncompressed = 0u64;

    // Wheel RECORD map: relative_path -> (expected_sha256, expected_size)
    let mut wheel_record_map: BTreeMap<String, (String, u64)> = BTreeMap::new();
    let mut member_digests: BTreeMap<String, (String, u64)> = BTreeMap::new();

    for i in 0..member_count {
        if global_budget.check().is_err() {
            coverage_state = CoverageState::Incomplete;
            coverage_details.push(format!(
                "Scan deadline/cancellation reached while reading ZIP entry index {}",
                i
            ));
            skipped_members += member_count - i;
            break;
        }
        if budget.add_member().is_err() {
            coverage_state = CoverageState::Incomplete;
            coverage_details.push("Cumulative member limit exceeded".to_owned());
            skipped_members += member_count - i;
            findings.push(make_finding(
                identity,
                CheckType::PackageSecurity,
                ScanStatus::Fail,
                FindingClass::Structural,
                Confidence::High,
                "LF-ARCHIVE-LIMIT",
                format!(
                    "Cumulative member limit exceeded while reading entry index {}",
                    i
                ),
            ));
            break;
        }

        let mut zip_entry = match archive.by_index(i) {
            Ok(entry) => entry,
            Err(err) => {
                let err_msg = err.to_string();
                let lower_err = err_msg.to_ascii_lowercase();
                if lower_err.contains("password") || lower_err.contains("encrypt") {
                    coverage_state = CoverageState::Incomplete;
                    coverage_details.push(format!("Encrypted member at index {}", i));
                    findings.push(make_finding(
                        identity,
                        CheckType::PackageSecurity,
                        ScanStatus::Warn,
                        FindingClass::Structural,
                        Confidence::High,
                        "LF-ARCHIVE-ENCRYPTED",
                        format!(
                            "ZIP entry at index {} is encrypted; content inspection skipped: {}",
                            i, err_msg
                        ),
                    ));
                    member_reports.push(ArchiveMemberReport {
                        virtual_path: format!("{identity}!/member_{i}"),
                        raw_name: format!("member_{i}"),
                        size_compressed: 0,
                        size_uncompressed: 0,
                        sha256: None,
                        is_dir: false,
                        is_symlink: false,
                        is_hardlink: false,
                        link_target: None,
                        is_encrypted: true,
                        format_smuggling: false,
                    });
                    skipped_members += 1;
                    continue;
                }
                coverage_state = CoverageState::Incomplete;
                skipped_members += 1;
                findings.push(make_finding(
                    identity,
                    CheckType::PackageSecurity,
                    ScanStatus::Fail,
                    FindingClass::Structural,
                    Confidence::High,
                    "LF-ARCHIVE-MALFORMED",
                    format!("Malformed central directory entry index {}: {}", i, err),
                ));
                continue;
            }
        };

        let raw_name = zip_entry.name().to_owned();
        let is_dir = zip_entry.is_dir();
        let size_compressed = zip_entry.compressed_size();
        let size_uncompressed = zip_entry.size();
        let is_encrypted = zip_entry.encrypted();

        // Check Unix mode for symlinks (0o120000 == 0120000 in octal)
        let mode = zip_entry.unix_mode().unwrap_or(0);
        let is_symlink = (mode & 0o170000) == 0o120000;

        let norm_res = normalize_member_path(&raw_name, budget.limits.max_path_bytes);
        let norm_path = match norm_res {
            Ok(np) => np,
            Err(err) => {
                coverage_state = CoverageState::Incomplete;
                coverage_details.push(format!("Unsafe member path '{}': {}", raw_name, err));
                findings.push(make_finding(
                    identity,
                    CheckType::PackageSecurity,
                    ScanStatus::Fail,
                    FindingClass::Structural,
                    Confidence::High,
                    "LF-ARCHIVE-TRAVERSAL",
                    format!("ZIP entry '{}' uses unsafe path: {}", raw_name, err),
                ));
                member_reports.push(ArchiveMemberReport {
                    virtual_path: format_virtual_subject(identity, &raw_name),
                    raw_name: raw_name.clone(),
                    size_compressed,
                    size_uncompressed,
                    sha256: None,
                    is_dir,
                    is_symlink,
                    is_hardlink: false,
                    link_target: None,
                    is_encrypted,
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
                    "ZIP archive contains duplicate entry for normalized path '{}'",
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
                    "ZIP archive entry '{}' case-collides with existing entry '{}'",
                    norm_path.virtual_path, collision
                ),
            ));
        }

        if is_encrypted {
            coverage_state = CoverageState::Incomplete;
            coverage_details.push(format!("Encrypted member '{}'", norm_path.virtual_path));
            findings.push(make_finding(
                &virt_path,
                CheckType::PackageSecurity,
                ScanStatus::Warn,
                FindingClass::Structural,
                Confidence::High,
                "LF-ARCHIVE-ENCRYPTED",
                format!(
                    "ZIP entry '{}' is encrypted; content inspection skipped",
                    norm_path.virtual_path
                ),
            ));
            member_reports.push(ArchiveMemberReport {
                virtual_path: virt_path,
                raw_name,
                size_compressed,
                size_uncompressed,
                sha256: None,
                is_dir,
                is_symlink,
                is_hardlink: false,
                link_target: None,
                is_encrypted: true,
                format_smuggling: false,
            });
            skipped_members += 1;
            continue;
        }

        let mut link_target = None;
        if is_symlink {
            let mut target_buf = Vec::new();
            if zip_entry.read_to_end(&mut target_buf).is_ok() {
                link_target = Some(String::from_utf8_lossy(&target_buf).to_string());
            }
            findings.push(make_finding(
                &virt_path,
                CheckType::PackageSecurity,
                ScanStatus::Warn,
                FindingClass::Structural,
                Confidence::High,
                "LF-ARCHIVE-LINK",
                format!(
                    "ZIP entry '{}' is a symbolic link -> '{}'",
                    norm_path.virtual_path,
                    link_target.as_deref().unwrap_or("<unreadable>")
                ),
            ));
            member_reports.push(ArchiveMemberReport {
                virtual_path: virt_path,
                raw_name,
                size_compressed,
                size_uncompressed,
                sha256: None,
                is_dir,
                is_symlink: true,
                is_hardlink: false,
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

        // Enforce member uncompressed byte cap
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
                "LF-ARCHIVE-BOMB",
                format!(
                    "ZIP entry '{}' declared size {} bytes exceeds member safety limit {}",
                    norm_path.virtual_path,
                    size_uncompressed,
                    budget.limits.max_uncompressed_member_bytes
                ),
            ));
            skipped_members += 1;
            continue;
        }

        // Stream decompress member into private temp file with byte/ratio enforcement
        let decomp_res = decompress_member_to_tempfile(
            &mut zip_entry,
            &norm_path.virtual_path,
            size_compressed,
            size_uncompressed,
            budget,
            global_budget,
        );

        let (temp_file, member_sha256, actual_uncompressed) = match decomp_res {
            Ok(val) => val,
            Err(err_msg) => {
                coverage_state = CoverageState::Incomplete;
                coverage_details.push(format!(
                    "Decompression cap/ratio error on '{}': {}",
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
                        "ZIP entry '{}' failed streaming decompression limits: {}",
                        norm_path.virtual_path, err_msg
                    ),
                ));
                skipped_members += 1;
                continue;
            }
        };

        total_uncompressed = total_uncompressed.saturating_add(actual_uncompressed);
        inspected_members += 1;

        member_digests.insert(
            norm_path.virtual_path.clone(),
            (member_sha256.clone(), actual_uncompressed),
        );

        member_reports.push(ArchiveMemberReport {
            virtual_path: virt_path.clone(),
            raw_name: raw_name.clone(),
            size_compressed,
            size_uncompressed: actual_uncompressed,
            sha256: Some(member_sha256.clone()),
            is_dir: false,
            is_symlink: false,
            is_hardlink: false,
            link_target: None,
            is_encrypted: false,
            format_smuggling: false,
        });

        // Wheel RECORD parsing
        if is_wheel && norm_path.virtual_path.ends_with(".dist-info/RECORD") {
            if let Ok(content_bytes) = std::fs::read(temp_file.path()) {
                if let Ok(content_str) = std::str::from_utf8(&content_bytes) {
                    parse_wheel_record(content_str, &mut wheel_record_map);
                }
            }
        }

        // Wheel METADATA parsing
        if is_wheel && norm_path.virtual_path.ends_with(".dist-info/METADATA") {
            if let Ok(content_bytes) = std::fs::read(temp_file.path()) {
                if let Ok(content_str) = std::str::from_utf8(&content_bytes) {
                    parse_wheel_metadata(content_str, &virt_path, &member_sha256, &mut findings);
                }
            }
        }

        // Dispatch member downstream to scanners
        let member_findings = dispatch_member_scan(
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

    // Wheel RECORD verification
    if is_wheel {
        verify_wheel_records(&wheel_record_map, &member_digests, identity, &mut findings);
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

fn decompress_member_to_tempfile<R: Read>(
    reader: &mut R,
    _member_path: &str,
    compressed_size: u64,
    _declared_uncompressed: u64,
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
                "zip decompression",
            )
            .map_err(|error| error.to_string())?;
        global_budget
            .consume(
                crate::budget::BudgetDimension::TemporaryDiskBytes,
                count as u64,
                "zip staging",
            )
            .map_err(|error| error.to_string())?;

        // Compression ratio check
        if compressed_size > 0 && total_read > 256 * 1024 {
            let ratio = (total_read as f64) / (compressed_size as f64);
            if ratio > budget.limits.max_compression_ratio {
                return Err(format!(
                    "Decompression ratio ({:.1}x) exceeded max limit ({:.1}x)",
                    ratio, budget.limits.max_compression_ratio
                ));
            }
        }

        hasher.update(&buffer[..count]);
        temp.write_all(&buffer[..count])
            .map_err(|e| e.to_string())?;
        crate::perf_metrics::record_temp_disk_bytes(count as u64);
    }

    temp.flush().map_err(|e| e.to_string())?;

    let hash_hex = format!("sha256:{}", hex::encode(hasher.finalize()));
    Ok((temp, hash_hex, total_read))
}

fn dispatch_member_scan(
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
    let ext = crate::safeio::portable_extension(rel_path).to_ascii_lowercase();

    // Check if member is a nested archive
    let mut prefix_buf = [0_u8; 512];
    let mut cloned = file.try_clone()?;
    cloned.seek(SeekFrom::Start(0))?;
    let n = cloned.read(&mut prefix_buf)?;
    let prefix = &prefix_buf[..n];

    let detection = super::detect::detect_archive_format_name(rel_path, prefix);
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
                    let child_report = inspect_zip(
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
                    let child_report = super::tar::inspect_tar(
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
    let identification = crate::formats::ArtifactIdentification::identify_name(rel_path, prefix);
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

    // Script-language semantic analysis (Python, Shell, PowerShell and
    // JavaScript/TypeScript).
    if ext == "py"
        || matches!(
            ext.as_str(),
            "sh" | "bash"
                | "zsh"
                | "ps1"
                | "psm1"
                | "psd1"
                | "js"
                | "mjs"
                | "cjs"
                | "ts"
                | "tsx"
                | "jsx"
        )
    {
        let empty_map = std::collections::BTreeSet::new();
        out.extend(crate::language_frontend::scan_language_member(
            &ext,
            rel_path,
            &file,
            size,
            digest,
            &empty_map,
            global_budget,
        )?);
    }

    Ok(out)
}

fn parse_wheel_record(content: &str, out_map: &mut BTreeMap<String, (String, u64)>) {
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split(',').collect();
        if parts.len() >= 3 {
            let path = parts[0].trim_matches('"').to_owned();
            let hash_str = parts[1].trim();
            let size_str = parts[2].trim();

            if let Ok(size) = size_str.parse::<u64>() {
                // Record hash format is typically sha256=base64url or hex
                out_map.insert(path, (hash_str.to_owned(), size));
            }
        }
    }
}

fn parse_wheel_metadata(
    content: &str,
    virt_path: &str,
    digest: &str,
    findings: &mut Vec<LayerScanResult>,
) {
    let mut req_dists = Vec::new();
    for line in content.lines() {
        if line.starts_with("Requires-Dist:") {
            if let Some(val) = line.strip_prefix("Requires-Dist:") {
                req_dists.push(val.trim().to_owned());
            }
        }
    }
    if !req_dists.is_empty() {
        findings.push(make_finding(
            digest,
            CheckType::PackageSecurity,
            ScanStatus::Pass,
            FindingClass::Informational,
            Confidence::High,
            "LF-ARCHIVE-SECURITY-MEMBER",
            format!(
                "Wheel METADATA in '{}' declares {} dependencies: {}",
                virt_path,
                req_dists.len(),
                req_dists.join(", ")
            ),
        ));
    }
}

fn verify_wheel_records(
    record_map: &BTreeMap<String, (String, u64)>,
    member_digests: &BTreeMap<String, (String, u64)>,
    archive_identity: &str,
    findings: &mut Vec<LayerScanResult>,
) {
    if record_map.is_empty() {
        return;
    }
    for (rel_path, (expected_hash_spec, expected_size)) in record_map {
        // RECORD itself and signature files legitimately omit hash/size
        if expected_hash_spec.is_empty() && *expected_size == 0 {
            continue;
        }

        if let Some((actual_sha256, actual_size)) = member_digests.get(rel_path) {
            if actual_size != expected_size {
                findings.push(make_finding(
                    archive_identity,
                    CheckType::PackageSecurity,
                    ScanStatus::Fail,
                    FindingClass::Integrity,
                    Confidence::High,
                    "LF-WHEEL-RECORD-MISMATCH",
                    format!(
                        "Wheel RECORD size mismatch for '{}': declared {} bytes, observed {} bytes",
                        rel_path, expected_size, actual_size
                    ),
                ));
            }

            // Verify hash if sha256 prefix is available
            if let Some(sha256_b64) = expected_hash_spec.strip_prefix("sha256=") {
                // Remove trailing padding '=' if any
                let clean_b64 = sha256_b64.trim_end_matches('=');
                let hex_hash = actual_sha256
                    .strip_prefix("sha256:")
                    .unwrap_or(actual_sha256);
                if let Ok(decoded_bytes) = hex::decode(hex_hash) {
                    let b64_standard = base64_url_to_standard(clean_b64);
                    if let Ok(expected_bytes) = base64_decode(&b64_standard) {
                        if decoded_bytes != expected_bytes {
                            findings.push(make_finding(
                                archive_identity,
                                CheckType::PackageSecurity,
                                ScanStatus::Fail,
                                FindingClass::Integrity,
                                Confidence::High,
                                "LF-WHEEL-RECORD-MISMATCH",
                                format!("Wheel RECORD hash mismatch for member '{}'", rel_path),
                            ));
                        }
                    }
                }
            }
        }
    }
}

fn base64_url_to_standard(s: &str) -> String {
    let mut out = s.replace('-', "+").replace('_', "/");
    while out.len() & 3 != 0 {
        out.push('=');
    }
    out
}

fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    // Simple standard base64 decode helper
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let s = s.trim_end_matches('=');
    let mut dbuf = 0u32;
    let mut bits = 0;
    let mut out = Vec::new();

    for &b in s.as_bytes() {
        let pos = ALPHABET
            .iter()
            .position(|&c| c == b)
            .ok_or("invalid b64 char")?;
        dbuf = (dbuf << 6) | (pos as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((dbuf >> bits) as u8);
            dbuf &= (1 << bits) - 1;
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
