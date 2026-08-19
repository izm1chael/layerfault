use super::*;

pub fn inspect_member(display_path: &Path, content_path: &Path) -> Result<Vec<LayerScanResult>> {
    let budget =
        crate::budget::ScanBudget::new(crate::budget::ScanBudgetProfile::Default.limits())?;
    inspect_member_with_budget(display_path, content_path, &budget)
}

pub fn inspect_member_with_budget(
    display_path: &Path,
    content_path: &Path,
    budget: &crate::budget::ScanBudget,
) -> Result<Vec<LayerScanResult>> {
    let file = open_readonly_nofollow(content_path)?;
    let size = file.metadata()?.len();
    let rel = display_path.display().to_string();
    let ext = display_path
        .extension()
        .and_then(|v| v.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let lower = rel.to_ascii_lowercase();

    let session = crate::scanner::ScanSession::new(content_path, &file)?;
    let mut observers: Vec<Box<dyn crate::scanner::StreamObserver>> = Vec::new();

    let file_prefix = prefix(&file, 512)?;
    let executable_candidate = crate::scanner::BinaryScanner::looks_executable_prefix(
        &file_prefix[..file_prefix.len().min(8)],
    );
    if executable_candidate {
        observers.push(Box::new(crate::scanner::BinaryStreamObserver::with_file(
            file.try_clone()?,
            size,
        )));
    }

    let is_text = is_text_candidate(&ext, &lower) && !is_tokenizer_vocabulary_path(&rel);
    if is_text {
        observers.push(Box::new(crate::scanner::TextStreamObserver::new(&rel)));
    }

    let (digest, session_findings) =
        session.run("application/vnd.layerfault.package-member", observers)?;

    let evidence = capture_custom_code_evidence(&rel, &file)?;
    let empty_auto_map = BTreeSet::new();
    let mut findings = scan_package_file(
        None,
        display_path,
        &rel,
        &file,
        size,
        &digest,
        &evidence,
        &empty_auto_map,
        &session_findings,
        budget,
    )?;
    let changed = if crate::hashcache::eligible(size) {
        !crate::hashcache::identity_unchanged(content_path, &file, &session.identity_before)?
    } else {
        crate::hashcache::sha256_uncached_prefixed(&file)? != digest
    };
    if changed {
        let observed = crate::hashcache::sha256_uncached_prefixed(&file)
            .unwrap_or_else(|_| "<unreadable after change>".to_owned());
        let subject = member_subject(&rel, &digest, Some(size));
        findings.push(
            finding(
                &digest,
                CheckType::PackageSecurity,
                ScanStatus::Fail,
                FindingClass::Integrity,
                Confidence::High,
                "LF-PACKAGE-RACE",
                format!("Package member '{rel}' changed while it was being scanned"),
            )
            .subject(subject.clone())
            .evidence(hash_mismatch(subject, &digest, &observed))
            .finish(),
        );
    }
    Ok(findings)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn scan_package_file(
    package_root: Option<&Path>,
    path: &Path,
    rel: &str,
    file: &std::fs::File,
    size: u64,
    digest: &str,
    evidence: &PackageMemberEvidence,
    auto_map_modules: &BTreeSet<String>,
    session_findings: &[LayerScanResult],
    budget: &crate::budget::ScanBudget,
) -> Result<Vec<LayerScanResult>> {
    let mut out = Vec::new();
    let subject = member_subject(rel, digest, Some(size));
    let file_prefix = prefix(file, 512)?;
    let archive_detection =
        crate::archive::detect_archive_format_confirmed(path, &file_prefix, file);
    if archive_detection.format != crate::archive::ArchiveFormat::Unknown {
        let archive_limits = crate::archive::ArchiveLimits::default();
        match crate::archive::inspect_opened(path, file, rel, &archive_limits, 0, budget) {
            Ok(archive_report) => {
                out.extend(archive_report.findings);
                return Ok(out);
            }
            Err(error) => {
                out.push(
                    finding(
                        digest,
                        CheckType::PackageSecurity,
                        ScanStatus::Fail,
                        FindingClass::Structural,
                        Confidence::High,
                        "LF-ARCHIVE-MALFORMED",
                        format!(
                            "Archive container '{}' failed inspection safely: {error}",
                            rel
                        ),
                    )
                    .subject(subject.clone())
                    .evidence_unavailable(
                        "archive parser failed before member evidence could be captured",
                    )
                    .finish(),
                );
                return Ok(out);
            }
        }
    }

    let format = ArtifactFormat::detect(path, &file_prefix[..file_prefix.len().min(8)]);
    if format != ArtifactFormat::Unknown {
        match artifact::inspect_opened_file_with_sha256_budget(
            path,
            file,
            format,
            artifact::ArtifactScanMode::Full,
            digest,
            budget,
        ) {
            Ok(report) => out.extend(report.results),
            Err(error) => out.push(
                finding(
                    digest,
                    CheckType::PackageSecurity,
                    ScanStatus::Fail,
                    FindingClass::Structural,
                    Confidence::High,
                    "LF-PACKAGE-ARTIFACT",
                    format!("Artifact '{rel}' failed package validation safely: {error}"),
                )
                .subject(subject.clone())
                .evidence(crate::finding_evidence::structural_invariant(
                    subject.clone(),
                    "artifact parser rejected the member",
                    serde_json::json!({ "format": format!("{format:?}"), "parser_error": error.to_string() }),
                ))
                .finish(),
            ),
        }
        return Ok(out);
    }

    let lower = rel.to_ascii_lowercase();
    let ext = path
        .extension()
        .and_then(|v| v.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    if unsafe_serialization_name(&lower) {
        // Bare/ZIP pickle names are dispatched above through ArtifactFormat::Pickle.
        // Reaching here therefore means a compressed/opaque serialization name
        // whose payload is not transparently decompressed in this pass. Keep it
        // review-required instead of inventing a blanket unsafe-format BLOCK.
        out.push(
            finding(
                digest,
                CheckType::PackageSecurity,
                ScanStatus::Warn,
                FindingClass::Compatibility,
                Confidence::High,
                "LF-PICKLE-OPAQUE-COMPRESSED",
                format!("Package file '{rel}' has a pickle/PyTorch serialization name behind unsupported compression; opcode analysis could not verify the payload"),
            )
            .subject(subject.clone())
            .evidence(file_member(
                subject.clone(),
                serde_json::json!({
                    "package_relative_path": rel,
                    "size": size,
                    "condition": "serialization name behind compression Layerfault does not decode in this pass",
                }),
            ))
            .finish(),
        );
    } else if ext == "bin" {
        out.push(
            finding(
                digest,
                CheckType::PackageSecurity,
                ScanStatus::Warn,
                FindingClass::Compatibility,
                Confidence::Medium,
                "LF-SERIALIZATION-BIN",
                format!("Legacy .bin artifact '{rel}' is opaque to Layerfault; verify the producer and loading path before use"),
            )
            .subject(subject.clone())
            .evidence(file_member(
                subject.clone(),
                serde_json::json!({
                    "package_relative_path": rel,
                    "size": size,
                    "condition": "no structural parser for the '.bin' member",
                }),
            ))
            .finish(),
        );
    }

    let executable_prefix = prefix(file, 8)?;
    let mut native_metadata = None;
    if crate::scanner::BinaryScanner::looks_executable_prefix(&executable_prefix) {
        let binary_finding = session_findings
            .iter()
            .find(|f| f.check_type == CheckType::BinarySteganography);
        if let Some(binary) = binary_finding {
            if binary.status == ScanStatus::Fail {
                out.push(binary.clone());
            }
        } else {
            let binary = crate::scanner::BinaryScanner::scan_file(
                file,
                size,
                digest,
                "application/vnd.layerfault.package-member",
            )?;
            if binary.status == ScanStatus::Fail {
                out.push(binary);
            }
        }
        if let Ok((meta, capability_findings)) =
            crate::scanner::BinaryScanner::inspect_file_capabilities(file, size, digest, rel)
        {
            native_metadata = meta;
            out.extend(capability_findings);
        }
    }

    if is_native_or_script(&ext, &lower) {
        let facts = if let Some(ref meta) = native_metadata {
            serde_json::json!({
                "package_relative_path": rel,
                "extension": ext,
                "size": size,
                "sha256": digest,
                "metadata": meta,
                "condition": "executable or custom-code member in a model package",
            })
        } else {
            serde_json::json!({
                "package_relative_path": rel,
                "extension": ext,
                "size": size,
                "sha256": digest,
                "condition": "executable or custom-code member in a model package",
            })
        };
        out.push(
            finding(
                digest,
                CheckType::PackageSecurity,
                ScanStatus::Warn,
                FindingClass::ContentIndicator,
                Confidence::High,
                "LF-PACKAGE-CODE",
                format!("Package contains executable/custom-code artifact '{rel}'; weight-only packages normally do not require executable content"),
            )
            .subject(subject.clone())
            .evidence(file_member(subject.clone(), facts))
            .finish(),
        );
    }

    let is_setup_py = lower.ends_with("setup.py");
    let is_shell_ext = matches!(ext.as_str(), "sh" | "bash" | "zsh");
    let is_powershell_ext = matches!(ext.as_str(), "ps1" | "psm1" | "psd1");
    let is_js_ext = matches!(ext.as_str(), "js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx");
    if (ext == "py" || is_shell_ext || is_powershell_ext || is_js_ext)
        && !is_setup_py
        && !is_documentation_path(rel)
        && !is_tokenizer_vocabulary_path(rel)
    {
        out.extend(crate::language_frontend::scan_language_member(
            &ext,
            rel,
            file,
            size,
            digest,
            auto_map_modules,
            budget,
        )?);
    }

    if let Some(kind) = crate::dependencies::classify_manifest(&lower, &ext) {
        let mut reader = file.try_clone()?;
        reader.seek(SeekFrom::Start(0))?;
        if let Ok(dependency_findings) = crate::dependencies::inspect_member(
            package_root,
            rel,
            &reader,
            digest,
            kind,
            auto_map_modules,
        ) {
            out.extend(dependency_findings);
        }
    }

    if is_text_candidate(&ext, &lower) {
        // Tokenizer/vocabulary payloads are large data dictionaries and can
        // legitimately contain source-shaped tokens.  Their complete JSON is
        // still streamed by `capture_custom_code_evidence`, but avoid a second
        // full byte traversal that cannot produce generic code findings.
        if !is_tokenizer_vocabulary_path(rel) {
            scan_text_streaming(rel, digest, file, &mut out)?;
        }
        if ext == "json" {
            scan_json_evidence(rel, digest, evidence, &mut out);
        }
    }

    if out.is_empty() {
        out.push(
            finding(
                digest,
                CheckType::PackageSecurity,
                ScanStatus::Pass,
                FindingClass::Informational,
                Confidence::High,
                "LF-PACKAGE-FILE",
                format!("Package file '{rel}' hashed; no high-confidence package-security indicator matched"),
            )
            .subject(subject)
            // A PASS records what was examined; there is no triggering evidence
            // to attach because nothing fired.
            .evidence_not_applicable()
            .finish(),
        );
    }
    Ok(out)
}
