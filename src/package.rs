use crate::finding_evidence::{
    config_value, file_member, hash_mismatch, source_excerpt, symlink_target, EvidenceSubject,
    FindingBuilder, MAX_EVIDENCE_PER_FINDING,
};
use crate::formats::{artifact, ArtifactFormat};
use crate::safeio::open_readonly_nofollow;
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use anyhow::{anyhow, bail, Context, Result};
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};
use walkdir::WalkDir;

const TEXT_STREAM_CHUNK_BYTES: usize = 256 * 1024;
const TEXT_STREAM_OVERLAP_BYTES: usize = 8 * 1024;
const PACKAGE_MEDIA_TYPE: &str = "application/vnd.layerfault.package";
/// Lines of context captured around a matched primitive.
const EXCERPT_CONTEXT_LINES: u64 = 3;
/// Upper bound on bytes re-read from a member to build one excerpt.
const EXCERPT_READ_BYTES: usize = 8 * 1024;
const MAX_PACKAGE_ENTRIES: usize = 100_000;
const MAX_PACKAGE_DEPTH: usize = 64;
const MAX_PACKAGE_PATH_BYTES: usize = 4096;
const MAX_PACKAGE_TOTAL_BYTES: u64 = 1024 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, serde::Serialize)]
pub struct PackageEntry {
    pub relative_path: String,
    pub kind: String,
    pub size: u64,
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest_cache: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PackageReport {
    pub root: String,
    pub fingerprint: String,
    pub files: Vec<PackageEntry>,
    pub total_bytes: u64,
    pub findings: Vec<LayerScanResult>,
    /// Structural relationships between findings, such as a configuration
    /// reference resolving to a module that carries a code-execution primitive.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub correlations: Vec<crate::finding_evidence::FindingCorrelation>,
    /// What the scan actually examined.
    pub coverage: crate::coverage::Coverage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics: Option<crate::scanner::ScanMetrics>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PackageFingerprintReport {
    pub root: String,
    pub fingerprint: String,
    pub files: Vec<PackageEntry>,
    pub total_bytes: u64,
}

/// Maximum `auto_map` entries retained as evidence from one configuration.
const MAX_AUTO_MAP_ENTRIES: usize = 32;
/// Maximum characters retained for a captured JSON key path or value.
const MAX_JSON_EVIDENCE_CHARS: usize = 512;

#[derive(Default)]
struct PackageMemberEvidence {
    relative_path: String,
    auto_map: bool,
    remote_trust: bool,
    modules: BTreeSet<String>,
    module_scope_operation: Option<&'static str>,
    json_parse_error: Option<String>,
    /// Exact `auto_map` key paths and the symbols they reference, so a finding
    /// can show `auto_map.AutoModel = "modeling_custom.CustomModel"` rather
    /// than merely asserting that custom code mapping exists.
    auto_map_entries: std::collections::BTreeMap<String, String>,
    /// The exact key that enabled remote code.
    remote_trust_key: Option<String>,
}

struct PackageDiscovery {
    paths: Vec<PathBuf>,
    symlinks: Vec<(String, Option<PathBuf>)>,
}

impl PackageReport {
    pub fn blocking(&self) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.status == ScanStatus::Fail)
    }
}

pub fn inspect(root: &Path) -> Result<PackageReport> {
    let metadata = std::fs::symlink_metadata(root)
        .with_context(|| format!("Unable to inspect package root '{}'", root.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(anyhow!("Package root '{}' is a symlink; supply the real package directory so identity and scan boundaries are explicit", root.display()));
    }
    if !metadata.is_dir() {
        return Err(anyhow!("'{}' is not a directory", root.display()));
    }

    let root = root
        .canonicalize()
        .with_context(|| format!("Unable to canonicalize package root '{}'", root.display()))?;
    let mut findings = Vec::new();
    let mut discovery = discover_package(&root)?;
    for (rel, target) in discovery.symlinks {
        let rendered = target
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "<unreadable>".to_owned());
        let subject = EvidenceSubject::member(&rel).with_media_type(PACKAGE_MEDIA_TYPE);
        findings.push(
            finding(
                &format!("package:{rel}"),
                CheckType::PackageSecurity,
                ScanStatus::Fail,
                FindingClass::Structural,
                Confidence::High,
                "LF-PACKAGE-SYMLINK",
                format!("Package contains symlink '{rel}' -> '{rendered}'; model packages are fingerprinted and scanned without following links"),
            )
            .subject(subject.clone())
            // The declared target is recorded as read; Layerfault deliberately
            // does not resolve it further to enrich this evidence.
            .evidence(symlink_target(subject, &rel, target.as_ref().map(|_| rendered.as_str())))
            .finish(),
        );
    }
    discovery
        .paths
        .sort_by_key(|path| safe_relative(&root, path).unwrap_or_default());
    let mut files = Vec::new();
    let mut member_evidence = Vec::new();
    let mut total_bytes = 0_u64;

    let mut auto_map_modules = BTreeSet::new();
    for path in &discovery.paths {
        if let Ok(rel) = safe_relative(&root, path) {
            if rel.to_ascii_lowercase().ends_with(".json") {
                if let Ok(file) = open_readonly_nofollow(path) {
                    if let Ok(ev) = capture_custom_code_evidence(&rel, &file) {
                        if ev.auto_map {
                            auto_map_modules.extend(ev.modules);
                        }
                    }
                }
            }
        }
    }

    let mut aggregate_metrics = crate::scanner::ScanMetrics::default();

    for path in discovery.paths {
        let rel = safe_relative(&root, &path)?;
        let file = open_readonly_nofollow(&path)?;
        let size = file.metadata()?.len();
        total_bytes = checked_package_total(total_bytes, size)?;

        let session = crate::scanner::ScanSession::new(&path, &file)?;
        let ext = path
            .extension()
            .and_then(|v| v.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let lower = rel.to_ascii_lowercase();

        let mut observers: Vec<Box<dyn crate::scanner::StreamObserver>> = Vec::new();

        let file_prefix = prefix(&file, 512)?;
        let executable_candidate = crate::scanner::BinaryScanner::looks_executable_prefix(
            &file_prefix[..file_prefix.len().min(8)],
        );
        if executable_candidate {
            observers.push(Box::new(crate::scanner::BinaryStreamObserver::new()));
        }

        let is_text = is_text_candidate(&ext, &lower) && !is_tokenizer_vocabulary_path(&rel);
        if is_text {
            observers.push(Box::new(crate::scanner::TextStreamObserver::new(&rel)));
        }

        let (digest, session_findings) =
            session.run("application/vnd.layerfault.package-member", observers)?;

        {
            let m = session.metrics.borrow();
            aggregate_metrics.bytes_read_sequential += m.bytes_read_sequential;
            aggregate_metrics.full_passes += m.full_passes;
            aggregate_metrics.cache_hits += m.cache_hits;
            aggregate_metrics.cache_misses += m.cache_misses;
            aggregate_metrics.random_read_bytes += m.random_read_bytes;
        }

        let cache_hit = session.metrics.borrow().cache_hits > 0;
        let kind = classify(&path);
        files.push(PackageEntry {
            relative_path: rel.clone(),
            kind: kind.to_owned(),
            size,
            sha256: Some(digest.clone()),
            digest_cache: Some(if cache_hit {
                "HIT".to_owned()
            } else if crate::hashcache::digest_eligible(size) {
                "MISS".to_owned()
            } else {
                "BYPASS_SMALL".to_owned()
            }),
        });

        let evidence = capture_custom_code_evidence(&rel, &file)?;
        findings.extend(scan_package_file(
            Some(&root),
            &path,
            &rel,
            &file,
            size,
            &digest,
            &evidence,
            &auto_map_modules,
            &session_findings,
        )?);
        member_evidence.push(evidence);
        let changed = if crate::hashcache::eligible(size) {
            !crate::hashcache::identity_unchanged(&path, &file, &session.identity_before)?
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
                    format!("Package file '{rel}' changed while it was being scanned"),
                )
                .subject(subject.clone())
                // Only the two identities Layerfault actually measured.
                .evidence(hash_mismatch(subject, &digest, &observed))
                .finish(),
            );
        }
    }

    correlate_custom_code(&files, &member_evidence, &mut findings);

    let fingerprint = package_fingerprint(&files);
    findings.sort_by(|a, b| {
        a.matches
            .cmp(&b.matches)
            .then_with(|| a.layer_digest.cmp(&b.layer_digest))
    });

    // Correlate only after findings are complete and ordered, so the derived
    // relationships are deterministic for a given package.
    let correlations = crate::correlate::correlate(&findings);
    let mut coverage = crate::coverage::Coverage::complete(files.len() as u64, total_bytes);
    if findings
        .iter()
        .any(|item| item.evidence_state == Some(crate::finding_evidence::EvidenceState::Partial))
    {
        coverage.evidence_limited(
            "evidence collection for at least one member reached its bounded limit",
        );
    }

    Ok(PackageReport {
        root: root.display().to_string(),
        fingerprint,
        files,
        total_bytes,
        findings,
        correlations,
        coverage,
        metrics: Some(aggregate_metrics),
    })
}

pub fn fingerprint(root: &Path) -> Result<String> {
    Ok(fingerprint_report(root)?.fingerprint)
}

/// Compute package identity without running the deep security scanners. The
/// same no-follow hashing and race checks are retained, so callers that only
/// need a stable package identity no longer pay for duplicate content parsing.
pub fn fingerprint_report(root: &Path) -> Result<PackageFingerprintReport> {
    let metadata = std::fs::symlink_metadata(root)
        .with_context(|| format!("Unable to inspect package root '{}'", root.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(anyhow!("Package root '{}' is a symlink; supply the real package directory so identity boundaries are explicit", root.display()));
    }
    if !metadata.is_dir() {
        return Err(anyhow!("'{}' is not a directory", root.display()));
    }
    let root = root.canonicalize()?;
    let mut discovery = discover_package(&root)?;
    if let Some((rel, _)) = discovery.symlinks.first() {
        return Err(anyhow!(
            "Package contains symlink '{}'; fingerprint-only identity refuses ambiguous package members",
            rel
        ));
    }
    discovery
        .paths
        .sort_by_key(|path| safe_relative(&root, path).unwrap_or_default());
    let mut files = Vec::new();
    let mut total_bytes = 0_u64;
    for path in discovery.paths {
        let rel = safe_relative(&root, &path)?;
        let file = open_readonly_nofollow(&path)?;
        let size = file.metadata()?.len();
        let hash = crate::hashcache::sha256_prefixed(&path, &file)?;
        if !crate::hashcache::identity_unchanged(&path, &file, &hash.identity)? {
            return Err(anyhow!(
                "Package file '{}' changed while its fingerprint was being computed",
                rel
            ));
        }
        total_bytes = checked_package_total(total_bytes, size)?;
        files.push(PackageEntry {
            relative_path: rel,
            kind: classify(&path).to_owned(),
            size,
            sha256: Some(hash.sha256),
            digest_cache: Some(if hash.cache_hit {
                "HIT".to_owned()
            } else if crate::hashcache::digest_eligible(size) {
                "MISS".to_owned()
            } else {
                "BYPASS_SMALL".to_owned()
            }),
        });
    }
    let fingerprint = package_fingerprint(&files);
    Ok(PackageFingerprintReport {
        root: root.display().to_string(),
        fingerprint,
        files,
        total_bytes,
    })
}

fn discover_package(root: &Path) -> Result<PackageDiscovery> {
    let mut paths = Vec::new();
    let mut symlinks = Vec::new();
    let mut entries = 0usize;
    let mut declared_bytes = 0u64;
    let mut walker = WalkDir::new(root).follow_links(false).into_iter();
    while let Some(entry) = walker.next() {
        let entry = entry?;
        if entry.depth() == 0 {
            continue;
        }
        if entry.depth() > MAX_PACKAGE_DEPTH {
            bail!(
                "Package entry '{}' exceeds maximum traversal depth {MAX_PACKAGE_DEPTH}",
                entry.path().display()
            );
        }
        let rel = safe_relative(root, entry.path())?;
        if ignored_path(&rel) {
            if entry.file_type().is_dir() {
                walker.skip_current_dir();
            }
            continue;
        }
        entries = entries.saturating_add(1);
        enforce_package_discovery_limits(entries, entry.depth(), rel.len(), declared_bytes)?;
        if entry.file_type().is_symlink() {
            symlinks.push((rel, std::fs::read_link(entry.path()).ok()));
            continue;
        }
        if entry.file_type().is_file() {
            declared_bytes = checked_package_total(declared_bytes, entry.metadata()?.len())?;
            paths.push(entry.into_path());
        }
    }
    Ok(PackageDiscovery { paths, symlinks })
}

fn enforce_package_discovery_limits(
    entries: usize,
    depth: usize,
    path_bytes: usize,
    total_bytes: u64,
) -> Result<()> {
    if entries > MAX_PACKAGE_ENTRIES {
        bail!("Package exceeds maximum entry count {MAX_PACKAGE_ENTRIES}");
    }
    if depth > MAX_PACKAGE_DEPTH {
        bail!("Package exceeds maximum traversal depth {MAX_PACKAGE_DEPTH}");
    }
    if path_bytes > MAX_PACKAGE_PATH_BYTES {
        bail!("Package member path exceeds {MAX_PACKAGE_PATH_BYTES} bytes");
    }
    if total_bytes > MAX_PACKAGE_TOTAL_BYTES {
        bail!("Package exceeds maximum aggregate size {MAX_PACKAGE_TOTAL_BYTES} bytes");
    }
    Ok(())
}

fn checked_package_total(current: u64, next: u64) -> Result<u64> {
    let total = current
        .checked_add(next)
        .ok_or_else(|| anyhow!("Package aggregate size overflow"))?;
    enforce_package_discovery_limits(0, 0, 0, total)?;
    Ok(total)
}

pub fn inspect_member(display_path: &Path, content_path: &Path) -> Result<Vec<LayerScanResult>> {
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
        observers.push(Box::new(crate::scanner::BinaryStreamObserver::new()));
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

fn package_fingerprint(files: &[PackageEntry]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"layerfault-package-identity\0");
    for entry in files {
        hasher.update(entry.relative_path.as_bytes());
        hasher.update([0]);
        hasher.update(entry.kind.as_bytes());
        hasher.update([0]);
        hasher.update(entry.size.to_string().as_bytes());
        hasher.update([0]);
        hasher.update(entry.sha256.as_deref().unwrap_or("missing").as_bytes());
        hasher.update([0xff]);
    }
    format!("lfpkg:sha256:{}", hex::encode(hasher.finalize()))
}

#[allow(clippy::too_many_arguments)]
fn scan_package_file(
    package_root: Option<&Path>,
    path: &Path,
    rel: &str,
    file: &std::fs::File,
    size: u64,
    digest: &str,
    evidence: &PackageMemberEvidence,
    auto_map_modules: &BTreeSet<String>,
    session_findings: &[LayerScanResult],
) -> Result<Vec<LayerScanResult>> {
    let mut out = Vec::new();
    let subject = member_subject(rel, digest, Some(size));
    let file_prefix = prefix(file, 512)?;
    let archive_detection = crate::archive::detect_archive_format(path, &file_prefix);
    if archive_detection.format != crate::archive::ArchiveFormat::Unknown {
        let archive_limits = crate::archive::ArchiveLimits::default();
        match crate::archive::inspect_opened(path, file, rel, &archive_limits, 0) {
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
        match artifact::inspect_opened_file_with_sha256(
            path,
            file,
            format,
            artifact::ArtifactScanMode::Full,
            digest,
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
    if ext == "py"
        && !is_setup_py
        && !is_documentation_path(rel)
        && !is_tokenizer_vocabulary_path(rel)
    {
        let limits = crate::python_static::limits::PythonAnalysisLimits::default();
        if size as usize <= limits.max_source_bytes {
            let mut reader = file.try_clone()?;
            reader.seek(SeekFrom::Start(0))?;
            if let Ok(source_bytes) =
                crate::safeio::read_all_from_file(&reader, limits.max_source_bytes as u64)
            {
                if let Ok(source_str) = std::str::from_utf8(&source_bytes) {
                    let started = std::time::Instant::now();
                    if let Ok(semantic_findings) =
                        crate::python_static::analyze_and_convert_findings(
                            rel,
                            source_str,
                            digest,
                            auto_map_modules,
                            &limits,
                            started,
                        )
                    {
                        out.extend(semantic_findings);
                    }
                }
            }
        }
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

fn scan_json_evidence(
    rel: &str,
    digest: &str,
    evidence: &PackageMemberEvidence,
    out: &mut Vec<LayerScanResult>,
) {
    let subject = member_subject(rel, digest, None);
    if evidence.auto_map {
        let referenced = evidence
            .auto_map_entries
            .values()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        let detail = if referenced.is_empty() {
            format!("'{rel}' contains Hugging Face auto_map metadata that can route loading through custom model code")
        } else {
            format!("'{rel}' maps model loading to custom code via auto_map: {referenced}")
        };
        let mut builder = finding(
            digest,
            CheckType::PackageSecurity,
            ScanStatus::Warn,
            FindingClass::ContentIndicator,
            Confidence::High,
            "LF-CODE-AUTO-MAP",
            detail,
        )
        .subject(subject.clone());
        for (key, value) in &evidence.auto_map_entries {
            builder = builder.evidence(config_value(
                subject.clone(),
                key,
                serde_json::Value::String(value.clone()),
                "Configuration maps a model loading entry point to publisher-supplied code",
            ));
        }
        if evidence.auto_map_entries.is_empty() {
            builder = builder.evidence_unavailable(
                "auto_map was present but no string symbol reference was resolved from it",
            );
        }
        out.push(builder.finish());
    }
    if evidence.remote_trust {
        let key = evidence
            .remote_trust_key
            .clone()
            .unwrap_or_else(|| "trust_remote_code".to_owned());
        out.push(
            finding(
                digest,
                CheckType::PackageSecurity,
                ScanStatus::Warn,
                FindingClass::ContentIndicator,
                Confidence::High,
                "LF-CODE-REMOTE-TRUST",
                format!("'{rel}' sets {key} = true; custom code should be reviewed before loading"),
            )
            .subject(subject.clone())
            .evidence(config_value(
                subject.clone(),
                &key,
                serde_json::Value::Bool(true),
                "Configuration explicitly permits execution of publisher-supplied code",
            ))
            .finish(),
        );
    }
    if let Some(error) = evidence.json_parse_error.as_deref() {
        out.push(
            finding(
                digest,
                CheckType::PackageSecurity,
                ScanStatus::Warn,
                FindingClass::Structural,
                Confidence::High,
                "LF-PACKAGE-JSON-INVALID",
                format!("JSON/config '{rel}' could not be parsed completely: {error}"),
            )
            .subject(subject.clone())
            .evidence(crate::finding_evidence::structural_invariant(
                subject,
                "configuration could not be fully parsed",
                serde_json::json!({ "parser_error": error }),
            ))
            .finish(),
        );
    }
}

fn scan_text_streaming(
    rel: &str,
    digest: &str,
    file: &std::fs::File,
    out: &mut Vec<LayerScanResult>,
) -> Result<()> {
    let documentation = is_documentation_path(rel);
    // Tokenizer/vocabulary payloads are data dictionaries, not executable
    // source.  They can legitimately contain source-code-shaped tokens such as
    // `exec(` or `os.system(`.  Continue streaming the entire file and run
    // targeted JSON/HF metadata extraction, but do not promote vocabulary
    // entries to custom-code findings.
    let vocabulary_data = is_tokenizer_vocabulary_path(rel);
    let dangerous = [
        ("os.system(", "LF-CODE-OS-SYSTEM"),
        ("subprocess.popen", "LF-CODE-SUBPROCESS"),
        ("subprocess.run", "LF-CODE-SUBPROCESS"),
        ("eval(", "LF-CODE-EVAL"),
        ("exec(", "LF-CODE-EXEC"),
        ("ctypes.cdll", "LF-CODE-CTYPES"),
        ("socket.socket", "LF-CODE-NETWORK"),
        ("requests.get(", "LF-CODE-NETWORK"),
        ("requests.post(", "LF-CODE-NETWORK"),
        ("urllib.request", "LF-CODE-NETWORK"),
    ];
    let jinja = [
        "__class__",
        "__mro__",
        "__subclasses__",
        "__globals__",
        "cycler.__init__",
        "namespace.__init__",
    ];
    let mut hits = MatchCollector::default();
    let mut jinja_seen = false;
    let mut template_marker_seen = rel.to_ascii_lowercase().contains("template");
    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let mut chunk = vec![0_u8; TEXT_STREAM_CHUNK_BYTES];
    let mut carry = Vec::<u8>::new();
    // Absolute file offset of `window[0]`, and the 1-based line number at that
    // offset. Both advance by the freshly consumed bytes only, so the replayed
    // overlap region is never counted twice.
    let mut window_start = 0_u64;
    let mut window_start_line = 1_u64;
    loop {
        let count = reader.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        let mut window = Vec::with_capacity(carry.len() + count);
        window.extend_from_slice(&carry);
        window.extend_from_slice(&chunk[..count]);
        let lower = String::from_utf8_lossy(&window).to_ascii_lowercase();
        if !documentation && !vocabulary_data {
            for (needle, rule) in dangerous {
                for (offset, _) in lower.match_indices(needle) {
                    // `lower` is a lossy decode, so its byte offsets can differ
                    // from the raw window's on invalid UTF-8. Clamp instead of
                    // trusting the index.
                    let local = offset.min(window.len());
                    let absolute = window_start.saturating_add(local as u64);
                    let line =
                        window_start_line.saturating_add(count_newlines(&window[..local]) as u64);
                    hits.record(rule, needle, absolute, line);
                }
            }
        }
        if !vocabulary_data {
            jinja_seen |= jinja.iter().any(|needle| lower.contains(needle));
            template_marker_seen |= lower.contains("{{");
            for needle in jinja {
                for (offset, _) in lower.match_indices(needle) {
                    let local = offset.min(window.len());
                    let absolute = window_start.saturating_add(local as u64);
                    let line =
                        window_start_line.saturating_add(count_newlines(&window[..local]) as u64);
                    hits.record("LF-TEMPLATE-INTROSPECTION", needle, absolute, line);
                }
            }
        }
        let keep = window.len().min(TEXT_STREAM_OVERLAP_BYTES);
        let consumed = window.len() - keep;
        window_start_line =
            window_start_line.saturating_add(count_newlines(&window[..consumed]) as u64);
        window_start = window_start.saturating_add(consumed as u64);
        carry.clear();
        carry.extend_from_slice(&window[window.len() - keep..]);
    }

    let subject = member_subject(rel, digest, file.metadata().ok().map(|meta| meta.len()));
    for rule in hits.rules() {
        if rule == "LF-TEMPLATE-INTROSPECTION" {
            continue;
        }
        let primitive = match rule {
            "LF-CODE-OS-SYSTEM" => "os.system",
            "LF-CODE-SUBPROCESS" => "subprocess",
            "LF-CODE-EVAL" => "eval",
            "LF-CODE-EXEC" => "exec",
            "LF-CODE-CTYPES" => "ctypes",
            "LF-CODE-NETWORK" => "network access",
            _ => "security-sensitive primitive",
        };
        let matches = hits.take(rule);
        let detail = format!(
            "Custom code/config '{}' contains security-relevant primitive '{}' at {}; the entire file was streamed and review is required before enabling custom code",
            rel,
            primitive,
            describe_lines(&matches)
        );
        out.push(
            finding(
                digest,
                CheckType::PackageSecurity,
                ScanStatus::Warn,
                FindingClass::ContentIndicator,
                Confidence::High,
                rule,
                detail,
            )
            .subject(subject.clone())
            .evidence_all(excerpt_evidence(&subject, file, &matches))
            .truncated(hits.truncated(rule))
            .finish(),
        );
    }
    if jinja_seen && template_marker_seen {
        let matches = hits.take("LF-TEMPLATE-INTROSPECTION");
        let detail = format!(
            "Template/config '{}' contains Python/Jinja introspection primitives at {}; review template execution context before use",
            rel,
            describe_lines(&matches)
        );
        out.push(
            finding(
                digest,
                CheckType::PackageSecurity,
                ScanStatus::Warn,
                FindingClass::ContentIndicator,
                Confidence::High,
                "LF-TEMPLATE-INTROSPECTION",
                detail,
            )
            .subject(subject.clone())
            .evidence_all(excerpt_evidence(&subject, file, &matches))
            .finish(),
        );
    }
    Ok(())
}

/// One accepted primitive match inside a package member.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TextMatch {
    needle: &'static str,
    offset: u64,
    line: u64,
}

/// Bounded, deduplicated, deterministic collection of primitive matches.
///
/// Chunks are replayed with an 8 KiB overlap so a primitive straddling a chunk
/// boundary is still found. That means the same match can be seen twice, so
/// acceptance is keyed on the absolute file offset rather than the position
/// inside the current window.
#[derive(Default)]
struct MatchCollector {
    matches: std::collections::BTreeMap<&'static str, Vec<TextMatch>>,
    suppressed: std::collections::BTreeMap<&'static str, usize>,
}

impl MatchCollector {
    fn record(&mut self, rule: &'static str, needle: &'static str, offset: u64, line: u64) {
        let entries = self.matches.entry(rule).or_default();
        if entries.iter().any(|entry| entry.offset == offset) {
            return;
        }
        if entries.len() >= MAX_EVIDENCE_PER_FINDING {
            *self.suppressed.entry(rule).or_default() += 1;
            return;
        }
        entries.push(TextMatch {
            needle,
            offset,
            line,
        });
    }

    fn rules(&self) -> Vec<&'static str> {
        self.matches.keys().copied().collect()
    }

    fn take(&self, rule: &str) -> Vec<TextMatch> {
        let mut out = self.matches.get(rule).cloned().unwrap_or_default();
        out.sort_by_key(|entry| entry.offset);
        out
    }

    fn truncated(&self, rule: &str) -> bool {
        self.suppressed.get(rule).copied().unwrap_or(0) > 0
    }
}

fn count_newlines(bytes: &[u8]) -> usize {
    bytes.iter().filter(|byte| **byte == b'\n').count()
}

fn describe_lines(matches: &[TextMatch]) -> String {
    if matches.is_empty() {
        return "an undetermined position".to_owned();
    }
    let rendered = matches
        .iter()
        .take(4)
        .map(|entry| format!("line {}", entry.line))
        .collect::<Vec<_>>()
        .join(", ");
    if matches.len() > 4 {
        format!("{rendered} and {} more", matches.len() - 4)
    } else {
        rendered
    }
}

/// Build bounded source excerpts for accepted matches.
///
/// Each excerpt is a small positional re-read of the member, never a full load:
/// a hostile multi-gigabyte file yields at most `EXCERPT_READ_BYTES` per match.
fn excerpt_evidence(
    subject: &EvidenceSubject,
    file: &std::fs::File,
    matches: &[TextMatch],
) -> Vec<crate::finding_evidence::FindingEvidence> {
    matches
        .iter()
        .filter_map(|entry| {
            let (text, _) = read_excerpt_window(file, entry.offset, entry.line).ok()?;
            // The location names the line the primitive is actually on. The
            // excerpt carries surrounding context, but pointing a reviewer at
            // the first context line would misreport where the match is.
            Some(source_excerpt(
                subject.clone(),
                entry.line,
                entry.line,
                entry.needle,
                &text,
            ))
        })
        .collect()
}

fn read_excerpt_window(file: &std::fs::File, offset: u64, line: u64) -> Result<(String, u64)> {
    let half = (EXCERPT_READ_BYTES / 2) as u64;
    let start = offset.saturating_sub(half);
    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(start))?;
    let mut buffer = vec![0_u8; EXCERPT_READ_BYTES];
    let read = reader.read(&mut buffer)?;
    buffer.truncate(read);
    let decoded = String::from_utf8_lossy(&buffer).into_owned();

    // Locate the match inside the window, then keep a few lines either side.
    let local = usize::try_from(offset.saturating_sub(start)).unwrap_or(0);
    let local = local.min(decoded.len());
    let before = &decoded[..floor_boundary(&decoded, local)];
    let leading_newlines = count_newlines(before.as_bytes()) as u64;

    let mut prefix_lines: Vec<&str> = before.split('\n').collect();
    // A window that does not start at the file start may begin mid-line; drop
    // that partial line rather than presenting it as a complete one.
    if start > 0 && !prefix_lines.is_empty() {
        prefix_lines.remove(0);
    }
    let context = EXCERPT_CONTEXT_LINES as usize;
    let kept_before = prefix_lines.len().min(context);
    let prefix = prefix_lines[prefix_lines.len() - kept_before..].join("\n");

    let after = &decoded[floor_boundary(&decoded, local)..];
    let suffix_lines: Vec<&str> = after.split('\n').take(context + 1).collect();
    let suffix = suffix_lines.join("\n");

    let mut text = String::new();
    if !prefix.is_empty() {
        text.push_str(&prefix);
        text.push('\n');
    }
    text.push_str(&suffix);

    // The reported first line is the match line minus the context actually kept.
    let _ = leading_newlines;
    let first_line = line.saturating_sub(kept_before as u64).max(1);
    Ok((text, first_line))
}

fn floor_boundary(value: &str, mut index: usize) -> usize {
    if index >= value.len() {
        return value.len();
    }
    while index > 0 && !value.is_char_boundary(index) {
        index -= 1;
    }
    index
}

pub(crate) fn is_tokenizer_vocabulary_path(rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel).to_ascii_lowercase();
    matches!(
        name.as_str(),
        "tokenizer.json" | "vocab.json" | "merges.txt" | "added_tokens.json"
    ) || name.starts_with("vocab.")
}

pub(crate) fn is_documentation_path(rel: &str) -> bool {
    let lower = rel.to_ascii_lowercase();
    lower.split('/').any(|part| part == "docs")
        || lower.ends_with(".md")
        || lower.ends_with(".rst")
        || lower
            .rsplit('/')
            .next()
            .is_some_and(|name| name.starts_with("readme"))
}

fn capture_custom_code_evidence(rel: &str, file: &std::fs::File) -> Result<PackageMemberEvidence> {
    let mut evidence = PackageMemberEvidence {
        relative_path: rel.to_owned(),
        ..PackageMemberEvidence::default()
    };
    let lower = rel.to_ascii_lowercase();
    if lower.ends_with(".json") {
        if let Err(error) = stream_custom_loader_metadata(file, &mut evidence) {
            evidence.json_parse_error = Some(error.to_string());
        }
    } else if lower.ends_with(".py") {
        evidence.module_scope_operation = module_scope_operation_file(file)?;
    }
    Ok(evidence)
}

#[derive(Clone, Copy)]
enum JsonMetadataContext {
    Normal,
    AutoMap,
    RemoteTrust,
}

struct JsonMetadataSeed<'a> {
    evidence: &'a mut PackageMemberEvidence,
    context: JsonMetadataContext,
    /// Dotted JSON key path to the value currently being visited, so evidence
    /// can name the exact location (`auto_map.AutoModel`) rather than the file.
    key_path: String,
}

impl<'de> DeserializeSeed<'de> for JsonMetadataSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(JsonMetadataVisitor {
            evidence: self.evidence,
            context: self.context,
            key_path: self.key_path,
        })
    }
}

struct JsonMetadataVisitor<'a> {
    evidence: &'a mut PackageMemberEvidence,
    context: JsonMetadataContext,
    key_path: String,
}

impl<'de> Visitor<'de> for JsonMetadataVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("arbitrary JSON metadata")
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
        if matches!(self.context, JsonMetadataContext::RemoteTrust) && value {
            self.evidence.remote_trust = true;
            if self.evidence.remote_trust_key.is_none() {
                self.evidence.remote_trust_key = Some(bounded_json_text(&self.key_path));
            }
        }
        Ok(())
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E> {
        if matches!(self.context, JsonMetadataContext::AutoMap) {
            collect_module_reference(value, &mut self.evidence.modules);
            if self.evidence.auto_map_entries.len() < MAX_AUTO_MAP_ENTRIES {
                self.evidence
                    .auto_map_entries
                    .insert(bounded_json_text(&self.key_path), bounded_json_text(value));
            }
        }
        Ok(())
    }

    fn visit_string<E: serde::de::Error>(
        self,
        value: String,
    ) -> std::result::Result<Self::Value, E> {
        self.visit_str(&value)
    }

    fn visit_none<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> std::result::Result<Self::Value, E> {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> std::result::Result<Self::Value, E> {
        Ok(())
    }
    fn visit_f64<E>(self, _: f64) -> std::result::Result<Self::Value, E> {
        Ok(())
    }

    fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut index = 0_usize;
        while seq
            .next_element_seed(JsonMetadataSeed {
                evidence: &mut *self.evidence,
                context: self.context,
                key_path: format!("{}[{index}]", self.key_path),
            })?
            .is_some()
        {
            index = index.saturating_add(1);
        }
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        while let Some(key) = map.next_key::<String>()? {
            let context = if key.eq_ignore_ascii_case("auto_map") {
                self.evidence.auto_map = true;
                JsonMetadataContext::AutoMap
            } else if key.eq_ignore_ascii_case("trust_remote_code") {
                JsonMetadataContext::RemoteTrust
            } else {
                self.context
            };
            let key_path = if self.key_path.is_empty() {
                key.clone()
            } else {
                format!("{}.{key}", self.key_path)
            };
            map.next_value_seed(JsonMetadataSeed {
                evidence: &mut *self.evidence,
                context,
                key_path,
            })?;
        }
        Ok(())
    }
}

fn stream_custom_loader_metadata(
    file: &std::fs::File,
    evidence: &mut PackageMemberEvidence,
) -> Result<()> {
    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let mut de = serde_json::Deserializer::from_reader(BufReader::new(reader));
    JsonMetadataSeed {
        evidence,
        context: JsonMetadataContext::Normal,
        key_path: String::new(),
    }
    .deserialize(&mut de)
    .map_err(|error| anyhow!(error))?;
    de.end().map_err(|error| anyhow!(error))?;
    Ok(())
}

/// Bound a captured JSON key or value before it becomes evidence.
fn bounded_json_text(value: &str) -> String {
    if value.chars().count() <= MAX_JSON_EVIDENCE_CHARS {
        return value.to_owned();
    }
    value.chars().take(MAX_JSON_EVIDENCE_CHARS).collect()
}

fn collect_module_reference(value: &str, modules: &mut BTreeSet<String>) {
    if let Some((module, _)) = value.rsplit_once('.') {
        if module.len() <= 4096
            && module.split('.').all(|part| {
                !part.is_empty() && part.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            })
        {
            modules.insert(module.to_owned());
        }
    }
}

fn module_scope_operation_file(file: &std::fs::File) -> Result<Option<&'static str>> {
    #[derive(Clone, Copy)]
    enum LineState {
        Pending,
        Eligible,
        Ignored,
    }

    fn classify_prefix(prefix: &[u8]) -> Option<LineState> {
        let first = prefix.first().copied()?;
        if matches!(first, b' ' | b'\t' | b'#' | b'@') {
            return Some(LineState::Ignored);
        }
        for declaration in [b"def ".as_slice(), b"class ".as_slice()] {
            if declaration.starts_with(prefix) {
                return if declaration == prefix {
                    Some(LineState::Ignored)
                } else {
                    None
                };
            }
        }
        Some(LineState::Eligible)
    }

    fn push_operation_byte(tail: &mut Vec<u8>, byte: u8) -> Option<&'static str> {
        const MAX_NEEDLE: usize = 32;
        tail.push(byte.to_ascii_lowercase());
        if tail.len() > MAX_NEEDLE {
            let drop = tail.len() - MAX_NEEDLE;
            tail.drain(..drop);
        }
        for (needle, operation) in [
            (b"os.system(".as_slice(), "os.system"),
            (b"subprocess.run(".as_slice(), "subprocess.run"),
            (b"subprocess.popen(".as_slice(), "subprocess.Popen"),
            (b"exec(".as_slice(), "exec"),
            (b"eval(".as_slice(), "eval"),
            (b"socket.socket(".as_slice(), "socket.socket"),
            (b"requests.".as_slice(), "requests network access"),
            (b"urllib.request".as_slice(), "urllib network access"),
            (b"ctypes.".as_slice(), "ctypes native loading"),
            (b".write_text(".as_slice(), "Path.write_text"),
            (b".write_bytes(".as_slice(), "Path.write_bytes"),
            (b".unlink(".as_slice(), "Path.unlink"),
            (b".remove(".as_slice(), "remove"),
            (b".rename(".as_slice(), "rename"),
        ] {
            if tail.ends_with(needle) {
                return Some(operation);
            }
        }
        None
    }

    let mut reader = BufReader::new(file.try_clone()?);
    reader.seek(SeekFrom::Start(0))?;
    let mut state = LineState::Pending;
    let mut prefix = Vec::<u8>::with_capacity(8);
    let mut tail = Vec::<u8>::with_capacity(32);
    loop {
        let buf = reader.fill_buf()?;
        if buf.is_empty() {
            break;
        }
        let consumed = buf.len();
        for &byte in buf {
            if byte == b'\n' || byte == b'\r' {
                state = LineState::Pending;
                prefix.clear();
                tail.clear();
                continue;
            }
            match state {
                LineState::Ignored => {}
                LineState::Eligible => {
                    if let Some(operation) = push_operation_byte(&mut tail, byte) {
                        return Ok(Some(operation));
                    }
                }
                LineState::Pending => {
                    if prefix.len() < 8 {
                        prefix.push(byte);
                    }
                    if let Some(classified) = classify_prefix(&prefix) {
                        state = classified;
                        if matches!(state, LineState::Eligible) {
                            for prior in prefix.drain(..) {
                                if let Some(operation) = push_operation_byte(&mut tail, prior) {
                                    return Ok(Some(operation));
                                }
                            }
                        }
                    }
                }
            }
        }
        reader.consume(consumed);
    }
    Ok(None)
}

fn correlate_custom_code(
    files: &[PackageEntry],
    evidence: &[PackageMemberEvidence],
    findings: &mut Vec<LayerScanResult>,
) {
    let mut modules = BTreeSet::new();
    let mut package_remote_trust = false;
    for item in evidence {
        if item.auto_map {
            modules.extend(item.modules.iter().cloned());
        }
        package_remote_trust |= item.remote_trust;
    }
    if !modules.is_empty() {
        for module in modules {
            let module_path = format!("{}.py", module.replace('.', "/"));
            let Some(entry) = files
                .iter()
                .find(|entry| entry.relative_path.eq_ignore_ascii_case(&module_path))
            else {
                continue;
            };
            let Some(item) = evidence.iter().find(|item| {
                item.relative_path
                    .eq_ignore_ascii_case(&entry.relative_path)
            }) else {
                continue;
            };
            let Some(operation) = item.module_scope_operation else {
                continue;
            };
            let trust_context = if package_remote_trust {
                "; package metadata also sets trust_remote_code=true"
            } else {
                "; this code becomes importable when the caller enables trust_remote_code at runtime"
            };
            let digest = entry.sha256.as_deref().unwrap_or("module");
            let subject = member_subject(&entry.relative_path, digest, Some(entry.size));
            findings.push(
            finding(
                digest,
                CheckType::PackageSecurity,
                ScanStatus::Fail,
                FindingClass::ContentIndicator,
                Confidence::High,
                "LF-CODE-IMPORT-SIDE-EFFECT",
                format!(
                    "Hugging Face auto_map routes loading through '{}', which performs '{}' at module scope{}",
                    entry.relative_path, operation, trust_context
                ),
            )
            .subject(subject.clone())
            // The relationship itself is the evidence: a configuration
            // reference resolving to a module that acts at import time.
            .evidence(crate::finding_evidence::path_relationship(
                subject,
                "auto_map reference resolves to a module with import-time behaviour",
                serde_json::json!({
                    "referenced_module": module,
                    "resolved_module_path": entry.relative_path,
                    "module_scope_operation": operation,
                    "package_trust_remote_code": package_remote_trust,
                }),
            ))
            .finish(),
        );
        }
    }

    // Python to native binary capability correlation
    let py_native_loads: Vec<_> = findings
        .iter()
        .filter(|f| f.matches.iter().any(|m| m.contains("LF-PY-NATIVE-LOAD")))
        .cloned()
        .collect();

    for py_finding in py_native_loads {
        let py_rel = py_finding
            .subject
            .as_ref()
            .and_then(|s| s.package_relative_path.as_deref())
            .unwrap_or("")
            .to_owned();
        if py_rel.is_empty() {
            continue;
        }

        for ev in &py_finding.evidence {
            if let Some(ref structured) = ev.structured {
                let call_target = structured["call_target"]
                    .as_str()
                    .unwrap_or("native_loader");
                let command_evidence = structured["command_evidence"].as_str();

                if let Some(target_arg) = command_evidence {
                    let cleaned_arg = target_arg.trim_matches(&['\'', '"', ' ', '.'][..]);
                    let basename = std::path::Path::new(cleaned_arg)
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or(cleaned_arg);

                    if let Some(native_entry) = files.iter().find(|e| {
                        let e_base = std::path::Path::new(&e.relative_path)
                            .file_name()
                            .and_then(|s| s.to_str())
                            .unwrap_or(&e.relative_path);
                        e_base.eq_ignore_ascii_case(basename)
                            || e.relative_path.eq_ignore_ascii_case(cleaned_arg)
                    }) {
                        let native_rel = &native_entry.relative_path;
                        let native_digest = native_entry.sha256.as_deref().unwrap_or("native");

                        let py_subject =
                            member_subject(&py_rel, py_finding.layer_digest.as_str(), None);
                        let native_subject =
                            member_subject(native_rel, native_digest, Some(native_entry.size));

                        let detail = format!(
                            "Python script '{py_rel}' loads native library '{native_rel}' via '{call_target}'; native library possesses capability imports"
                        );

                        findings.push(
                            finding(
                                py_finding.layer_digest.as_str(),
                                CheckType::PackageSecurity,
                                ScanStatus::Warn,
                                FindingClass::ContentIndicator,
                                Confidence::High,
                                "LF-CORR-CUSTOM-LOADER-NATIVE",
                                detail,
                            )
                            .subject(py_subject.clone())
                            .evidence(crate::finding_evidence::path_relationship(
                                py_subject,
                                &format!("{py_rel} -> {call_target} -> {native_rel}"),
                                serde_json::json!({
                                    "python_script": py_rel,
                                    "loader_call": call_target,
                                    "native_library": native_rel,
                                    "target_arg": target_arg,
                                    "target_subject": native_subject.canonical_name(),
                                }),
                            ))
                            .finish(),
                        );
                    }
                }
            }
        }
    }
}

fn unsafe_serialization_name(lower: &str) -> bool {
    let filename = lower.rsplit('/').next().unwrap_or(lower);
    let mut candidate = filename;
    for _ in 0..8 {
        if matches!(
            Path::new(candidate)
                .extension()
                .and_then(|value| value.to_str())
                .unwrap_or(""),
            "pkl" | "pickle" | "joblib" | "pt" | "pth" | "ckpt"
        ) {
            return true;
        }
        let Some(stripped) = strip_compression_suffix(candidate) else {
            break;
        };
        candidate = stripped;
    }
    false
}

fn strip_compression_suffix(value: &str) -> Option<&str> {
    for suffix in [
        ".gz", ".bz2", ".xz", ".lzma", ".z", ".zlib", ".deflate", ".zst",
    ] {
        if let Some(stripped) = value.strip_suffix(suffix) {
            return Some(stripped);
        }
    }
    None
}

fn is_native_or_script(ext: &str, lower: &str) -> bool {
    matches!(
        ext,
        "py" | "sh" | "ps1" | "bat" | "cmd" | "exe" | "dll" | "so" | "dylib" | "node" | "jar"
    ) || lower.ends_with("setup.py")
}

fn is_text_candidate(ext: &str, lower: &str) -> bool {
    matches!(
        ext,
        "json"
            | "txt"
            | "md"
            | "py"
            | "sh"
            | "ps1"
            | "toml"
            | "yaml"
            | "yml"
            | "jinja"
            | "jinja2"
            | "tmpl"
    ) || lower.ends_with("requirements.txt")
        || lower.ends_with("modelfile")
}

fn classify(path: &Path) -> &'static str {
    let lower = path
        .file_name()
        .and_then(|v| v.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let ext = path
        .extension()
        .and_then(|v| v.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if ArtifactFormat::detect(path, &[]) != ArtifactFormat::Unknown {
        "model-artifact"
    } else if matches!(ext.as_str(), "py" | "sh" | "ps1" | "bat" | "cmd") {
        "code"
    } else if matches!(ext.as_str(), "so" | "dll" | "dylib" | "exe") {
        "native"
    } else if unsafe_serialization_name(&lower) || lower.ends_with("pytorch_model.bin") {
        "serialization"
    } else if crate::dependencies::classify_manifest(&lower, &ext).is_some() {
        "dependency-manifest"
    } else if matches!(ext.as_str(), "json" | "toml" | "yaml" | "yml") {
        "config"
    } else {
        "other"
    }
}

fn ignored_path(rel: &str) -> bool {
    rel.split('/').any(|part| {
        matches!(
            part,
            ".git" | "target" | "__pycache__" | ".cache" | ".venv" | "venv"
        )
    })
}

fn safe_relative(root: &Path, path: &Path) -> Result<String> {
    let rel = path
        .strip_prefix(root)
        .with_context(|| format!("'{}' escaped package root", path.display()))?;
    let mut out = Vec::new();
    for component in rel.components() {
        match component {
            Component::Normal(value) => {
                let value = value.to_str().ok_or_else(|| anyhow!("Package-relative path contains non-UTF-8 component; canonical package identities require portable UTF-8 member names"))?;
                out.push(value.to_owned());
            }
            _ => return Err(anyhow!("Unsafe package-relative path '{}'", rel.display())),
        }
    }
    Ok(out.join("/"))
}

fn prefix(file: &std::fs::File, limit: usize) -> Result<Vec<u8>> {
    let mut cloned = file.try_clone()?;
    cloned.seek(SeekFrom::Start(0))?;
    let mut bytes = vec![0_u8; limit];
    let n = cloned.read(&mut bytes)?;
    bytes.truncate(n);
    Ok(bytes)
}

/// Start a package finding.
///
/// Returns a builder so the caller can attach the exact member subject and the
/// evidence that caused the detector to fire. Callers that genuinely have no
/// evidence must say why via `evidence_unavailable`; the builder records
/// `UNAVAILABLE` rather than leaving absence ambiguous.
fn finding(
    digest: &str,
    check_type: CheckType,
    status: ScanStatus,
    class: FindingClass,
    confidence: Confidence,
    rule: &str,
    detail: String,
) -> FindingBuilder {
    FindingBuilder::new(rule, check_type, status)
        .class(class)
        .confidence(confidence)
        .digest(digest)
        .media_type(PACKAGE_MEDIA_TYPE)
        .match_note("package finding")
        .detail(detail)
}

/// The canonical subject for a package member.
///
/// Always identified by its package-relative path, never by the absolute or
/// staging path it happens to occupy during this scan: hub review and the
/// hosted worker both stage downloads into temporary directories, and those
/// paths must never become a finding's identity.
fn member_subject(rel: &str, digest: &str, size: Option<u64>) -> EvidenceSubject {
    EvidenceSubject::member(rel)
        .with_sha256(Some(digest.to_owned()))
        .with_size(size)
        .with_media_type(PACKAGE_MEDIA_TYPE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use crate::finding_evidence::{EvidenceKind, EvidenceLocation, EvidenceState};

    fn finding_for<'a>(findings: &'a [LayerScanResult], rule: &str) -> Option<&'a LayerScanResult> {
        findings
            .iter()
            .find(|finding| crate::policy::rule_id(finding) == rule)
    }

    fn text_lines(finding: &LayerScanResult) -> Vec<u64> {
        finding
            .evidence
            .iter()
            .filter_map(|record| match record.location {
                Some(EvidenceLocation::Text { line_start, .. }) => Some(line_start),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn custom_code_evidence_records_exact_line_and_excerpt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        let source = "import os\n\n\ndef load(path):\n    # helper\n    subprocess.run([\"/bin/sh\"])\n    return path\n";
        fs::write(root.join("modeling_custom.py"), source).expect("write");
        let report = inspect(root).expect("inspect");

        let finding =
            finding_for(&report.findings, "LF-CODE-SUBPROCESS").expect("subprocess finding");
        assert_eq!(finding.evidence_state, Some(EvidenceState::Available));
        assert_eq!(
            finding
                .subject
                .as_ref()
                .and_then(|s| s.package_relative_path.as_deref()),
            Some("modeling_custom.py")
        );
        assert!(finding
            .subject
            .as_ref()
            .and_then(|s| s.sha256.as_deref())
            .is_some_and(|digest| digest.starts_with("sha256:")));

        assert_eq!(text_lines(finding), vec![6], "match is on line 6");
        let record = &finding.evidence[0];
        assert_eq!(record.kind, EvidenceKind::SourceExcerpt);
        assert_eq!(record.match_value.as_deref(), Some("subprocess.run"));
        assert!(record
            .excerpt
            .as_deref()
            .expect("excerpt")
            .contains("subprocess.run"));
        assert!(finding
            .finding_id
            .as_deref()
            .is_some_and(|id| id.starts_with("lffinding:sha256:")));
    }

    #[test]
    fn primitive_spanning_a_chunk_boundary_reports_one_correct_line() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        // Pad with whole lines so the primitive straddles the 256 KiB chunk
        // boundary and lands inside the replayed overlap window.
        let line = "x = 1\n"; // 6 bytes
        let pad_lines = (TEXT_STREAM_CHUNK_BYTES / line.len()) + 1;
        let mut source = line.repeat(pad_lines);
        // Trim back so the needle starts a few bytes before the boundary.
        source.truncate(TEXT_STREAM_CHUNK_BYTES - 4);
        let lines_before = source.matches('\n').count() as u64;
        source.push_str("subprocess.run([\"/bin/sh\"])\ntrailer = 2\n");
        fs::write(root.join("boundary.py"), &source).expect("write");

        let report = inspect(root).expect("inspect");
        let finding =
            finding_for(&report.findings, "LF-CODE-SUBPROCESS").expect("subprocess finding");
        let lines = text_lines(finding);
        assert_eq!(lines.len(), 1, "overlap must not double-report the match");
        assert_eq!(lines[0], lines_before + 1);
    }

    #[test]
    fn repeated_primitives_are_bounded_and_deterministic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        let source = "subprocess.run(1)\n".repeat(MAX_EVIDENCE_PER_FINDING * 4);
        fs::write(root.join("flood.py"), &source).expect("write");

        let first = inspect(root).expect("inspect");
        let second = inspect(root).expect("inspect");
        // The semantic Python analyzer also flags LF-CODE-SUBPROCESS (one
        // finding per call site); pick the aggregated streaming-scanner
        // finding specifically, which is the one whose bounding this test
        // covers.
        let most_evidence = |findings: &[LayerScanResult]| {
            findings
                .iter()
                .filter(|finding| crate::policy::rule_id(finding) == "LF-CODE-SUBPROCESS")
                .max_by_key(|finding| finding.evidence.len())
                .expect("finding")
                .clone()
        };
        let a = most_evidence(&first.findings);
        let b = most_evidence(&second.findings);
        let a = &a;
        let b = &b;
        assert!(a.evidence.len() <= MAX_EVIDENCE_PER_FINDING);
        assert_eq!(
            text_lines(a),
            text_lines(b),
            "evidence must be deterministic"
        );
        assert_eq!(a.finding_id, b.finding_id);
        assert_eq!(a.evidence_state, Some(EvidenceState::Partial));
    }

    #[test]
    fn credentials_in_custom_code_are_redacted_in_evidence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        let source = "import requests\nTOKEN = \"hf_abcdefghijklmnopqrstuvwxyz0123456789\"\nrequests.post(url, headers={\"Authorization\": \"Bearer abcdefghijklmnopqrstuvwxyz\"})\n";
        fs::write(root.join("net.py"), source).expect("write");
        let report = inspect(root).expect("inspect");
        // Both the streaming text scanner and the semantic Python analyzer can
        // independently flag LF-CODE-NETWORK for this file; check across all
        // of them rather than assuming a specific one is first.
        let network_findings: Vec<&LayerScanResult> = report
            .findings
            .iter()
            .filter(|finding| crate::policy::rule_id(finding) == "LF-CODE-NETWORK")
            .collect();
        assert!(!network_findings.is_empty(), "expected a network finding");
        let excerpts = network_findings
            .iter()
            .flat_map(|finding| finding.evidence.iter())
            .filter_map(|record| record.excerpt.as_deref())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !excerpts.contains("hf_abcdefghijklmnopqrstuvwxyz0123456789"),
            "token must not be reproduced in evidence"
        );
        assert!(excerpts.contains("<redacted sha256:"));
        assert!(network_findings
            .iter()
            .flat_map(|finding| finding.evidence.iter())
            .any(|record| record.redactions > 0));
    }

    #[test]
    fn terminal_escapes_in_custom_code_are_neutralised() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        let source = "banner = \"\u{1b}[2J\u{1b}[31mPWNED\"\nsubprocess.run(x)\n";
        fs::write(root.join("ansi.py"), source).expect("write");
        let report = inspect(root).expect("inspect");
        let finding =
            finding_for(&report.findings, "LF-CODE-SUBPROCESS").expect("subprocess finding");
        let rendered = serde_json::to_string(&finding.evidence).expect("serialize");
        assert!(!rendered.contains('\u{1b}'));
    }

    #[test]
    fn auto_map_evidence_names_the_key_and_referenced_symbol() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        fs::write(
            root.join("config.json"),
            br#"{"auto_map": {"AutoModel": "modeling_custom.CustomModel"}, "trust_remote_code": true}"#,
        )
        .expect("write");
        let report = inspect(root).expect("inspect");

        let auto_map = finding_for(&report.findings, "LF-CODE-AUTO-MAP").expect("auto_map finding");
        let record = auto_map.evidence.first().expect("config evidence");
        assert_eq!(record.kind, EvidenceKind::ConfigValue);
        assert_eq!(
            record.location,
            Some(EvidenceLocation::Metadata {
                key: "auto_map.AutoModel".to_owned()
            })
        );
        assert_eq!(
            record.structured.as_ref().and_then(|v| v["value"].as_str()),
            Some("modeling_custom.CustomModel")
        );

        let trust =
            finding_for(&report.findings, "LF-CODE-REMOTE-TRUST").expect("trust_remote_code");
        let record = trust.evidence.first().expect("config evidence");
        assert_eq!(
            record.structured.as_ref().map(|v| v["value"].clone()),
            Some(serde_json::Value::Bool(true))
        );
    }

    #[test]
    fn symlink_evidence_records_path_and_declared_target() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        fs::write(root.join("real.txt"), b"data").expect("write");
        #[cfg(unix)]
        std::os::unix::fs::symlink("../outside", root.join("link")).expect("symlink");
        #[cfg(not(unix))]
        return;
        let report = inspect(root).expect("inspect");
        let finding = finding_for(&report.findings, "LF-PACKAGE-SYMLINK").expect("symlink finding");
        let record = finding.evidence.first().expect("symlink evidence");
        assert_eq!(record.kind, EvidenceKind::SymlinkTarget);
        let structured = record.structured.as_ref().expect("structured");
        assert_eq!(structured["package_relative_path"], "link");
        assert_eq!(structured["target"], "../outside");
    }

    #[test]
    fn auto_map_and_capability_correlate_end_to_end() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        fs::write(
            root.join("config.json"),
            br#"{"auto_map": {"AutoModel": "modeling_custom.CustomModel"}}"#,
        )
        .expect("write");
        fs::write(
            root.join("modeling_custom.py"),
            b"class CustomModel:\n    def __init__(self):\n        subprocess.run([\"id\"])\n",
        )
        .expect("write");

        let report = inspect(root).expect("inspect");
        let correlations = crate::correlate::correlate(&report.findings);
        let chain = correlations
            .iter()
            .find(|c| c.id == "LF-CORR-CUSTOM-LOADER-PROCESS")
            .expect("custom loader correlation");
        assert_eq!(chain.confidence, Confidence::High);
        assert_eq!(chain.finding_ids.len(), 2);
        assert!(chain.summary.contains("modeling_custom.py:3"));
    }

    #[test]
    fn package_resource_limits_fail_closed() {
        assert!(enforce_package_discovery_limits(MAX_PACKAGE_ENTRIES + 1, 1, 1, 0).is_err());
        assert!(enforce_package_discovery_limits(1, MAX_PACKAGE_DEPTH + 1, 1, 0).is_err());
        assert!(enforce_package_discovery_limits(1, 1, MAX_PACKAGE_PATH_BYTES + 1, 0).is_err());
        assert!(checked_package_total(MAX_PACKAGE_TOTAL_BYTES, 1).is_err());
    }

    #[test]
    fn package_fingerprint_is_path_stable() -> Result<()> {
        let a = std::env::temp_dir().join(format!("layerfault-package-a-{}", std::process::id()));
        let b = std::env::temp_dir().join(format!("layerfault-package-b-{}", std::process::id()));
        let _ = fs::remove_dir_all(&a);
        let _ = fs::remove_dir_all(&b);
        fs::create_dir_all(&a)?;
        fs::create_dir_all(&b)?;
        fs::write(a.join("config.json"), b"{\"architectures\":[\"Test\"]}")?;
        fs::write(b.join("config.json"), b"{\"architectures\":[\"Test\"]}")?;
        assert_eq!(fingerprint(&a)?, fingerprint(&b)?);
        fs::write(b.join("config.json"), b"{\"architectures\":[\"Changed\"]}")?;
        assert_ne!(fingerprint(&a)?, fingerprint(&b)?);
        let _ = fs::remove_dir_all(a);
        let _ = fs::remove_dir_all(b);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_member_name_is_rejected() -> Result<()> {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let root =
            std::env::temp_dir().join(format!("layerfault-package-nonutf8-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        let name = OsString::from_vec(vec![b'm', b'o', b'd', b'e', b'l', 0xff]);
        fs::write(root.join(name), b"fixture")?;
        assert!(inspect(&root).is_err());
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn unsafe_serialization_blocks() -> Result<()> {
        let root =
            std::env::temp_dir().join(format!("layerfault-package-pickle-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        fs::write(root.join("model.pkl"), [0x80_u8, 4, 1, 2, 3])?;
        let report = inspect(&root)?;
        assert!(report.findings.iter().any(|f| f
            .matches
            .iter()
            .any(|m| m.contains("LF-PICKLE-MALFORMED"))
            && f.status == ScanStatus::Fail));
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn nested_compressed_joblib_warns_when_payload_is_opaque() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "layerfault-package-double-compressed-joblib-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        fs::write(
            root.join("exploit_double_compression.joblib.gz.bz2"),
            b"BZh91AY&SYbounded-fixture",
        )?;
        let report = inspect(&root)?;
        assert!(report.findings.iter().any(|finding| {
            finding.status == ScanStatus::Warn
                && finding
                    .matches
                    .iter()
                    .any(|value| value.contains("LF-PICKLE-OPAQUE-COMPRESSED"))
        }));
        assert!(report
            .files
            .iter()
            .any(|entry| entry.kind == "serialization"));
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn compression_suffix_without_serialization_inner_name_does_not_block() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "layerfault-package-compressed-data-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        fs::write(
            root.join("weights.dat.gz.bz2"),
            b"BZh91AY&SYbounded-fixture",
        )?;
        let report = inspect(&root)?;
        assert!(!report.findings.iter().any(|finding| {
            finding.status == ScanStatus::Fail
                && finding
                    .matches
                    .iter()
                    .any(|value| value.contains("LF-PICKLE-MALFORMED"))
        }));
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn documentation_examples_do_not_emit_code_primitive_findings() -> Result<()> {
        let root =
            std::env::temp_dir().join(format!("layerfault-package-docs-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        fs::write(
            root.join("README.md"),
            b"The example calls os.system(...) and exec(...).",
        )?;
        let report = inspect(&root)?;
        assert!(!report.findings.iter().any(|finding| {
            finding
                .matches
                .iter()
                .any(|value| value.contains("LF-CODE-OS-SYSTEM") || value.contains("LF-CODE-EXEC"))
        }));
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn custom_loader_module_scope_side_effect_blocks() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "layerfault-package-custom-code-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        fs::write(
            root.join("config.json"),
            br#"{"auto_map":{"AutoModel":"modeling_example.Example"},"trust_remote_code":true}"#,
        )?;
        fs::write(
            root.join("modeling_example.py"),
            b"os.system('echo imported')\n",
        )?;
        let report = inspect(&root)?;
        assert!(report.findings.iter().any(|finding| {
            finding.status == ScanStatus::Fail
                && finding
                    .matches
                    .iter()
                    .any(|value| value.contains("LF-CODE-IMPORT-SIDE-EFFECT"))
        }));
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn custom_loader_function_side_effect_remains_warning() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "layerfault-package-custom-function-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        fs::write(
            root.join("config.json"),
            br#"{"auto_map":{"AutoModel":"modeling_example.Example"},"trust_remote_code":true}"#,
        )?;
        fs::write(
            root.join("modeling_example.py"),
            b"def load():\n    os.system('echo called')\n",
        )?;
        let report = inspect(&root)?;
        assert!(!report.findings.iter().any(|finding| {
            finding.status == ScanStatus::Fail
                && finding
                    .matches
                    .iter()
                    .any(|value| value.contains("LF-CODE-IMPORT-SIDE-EFFECT"))
        }));
        assert!(report.findings.iter().any(|finding| {
            finding.status == ScanStatus::Warn
                && finding
                    .matches
                    .iter()
                    .any(|value| value.contains("LF-CODE-OS-SYSTEM"))
        }));
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn large_json_is_fully_streamed_without_size_warning() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "layerfault-package-large-json-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        let padding = "a".repeat(6 * 1024 * 1024);
        fs::write(
            root.join("tokenizer.json"),
            serde_json::to_vec(&serde_json::json!({"padding": padding}))?,
        )?;
        let report = inspect(&root)?;
        assert!(!report.findings.iter().any(|finding| finding
            .matches
            .iter()
            .any(|value| value.contains("LF-PACKAGE-TEXT-LIMIT"))));
        assert!(!report.blocking());
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn tokenizer_vocabulary_code_tokens_do_not_become_custom_code_findings() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "layerfault-package-tokenizer-vocab-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        fs::write(
            root.join("tokenizer.json"),
            serde_json::to_vec(&serde_json::json!({
                "model": {
                    "vocab": {
                        "os.system(": 1,
                        "exec(": 2,
                        "__class__": 3,
                        "{{": 4
                    }
                }
            }))?,
        )?;
        let report = inspect(&root)?;
        assert!(!report.findings.iter().any(|finding| {
            finding.matches.iter().any(|value| {
                value.contains("LF-CODE-OS-SYSTEM")
                    || value.contains("LF-CODE-EXEC")
                    || value.contains("LF-TEMPLATE-INTROSPECTION")
            })
        }));
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn auto_map_late_in_large_json_still_correlates_custom_code() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "layerfault-package-large-json-automap-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        let padding = "a".repeat(6 * 1024 * 1024);
        fs::write(
            root.join("config.json"),
            serde_json::to_vec(&serde_json::json!({
                "padding": padding,
                "auto_map": {"AutoModel": "modeling_late.Example"}
            }))?,
        )?;
        fs::write(
            root.join("modeling_late.py"),
            b"os.system('echo imported')\n",
        )?;
        let report = inspect(&root)?;
        assert!(report.findings.iter().any(|finding| {
            finding.status == ScanStatus::Fail
                && finding
                    .matches
                    .iter()
                    .any(|value| value.contains("LF-CODE-IMPORT-SIDE-EFFECT"))
        }));
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn module_scope_side_effect_after_old_four_mib_boundary_still_blocks() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "layerfault-package-large-python-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        fs::write(
            root.join("config.json"),
            br#"{"auto_map":{"AutoModel":"modeling_large.Example"}}"#,
        )?;
        let mut source = String::from("payload = '");
        source.push_str(&"a".repeat(5 * 1024 * 1024));
        source.push_str("'; os.system('echo imported')\n");
        fs::write(root.join("modeling_large.py"), source)?;
        let report = inspect(&root)?;
        assert!(report.findings.iter().any(|finding| {
            finding.status == ScanStatus::Fail
                && finding
                    .matches
                    .iter()
                    .any(|value| value.contains("LF-CODE-IMPORT-SIDE-EFFECT"))
        }));
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn auto_map_import_side_effect_blocks_without_package_remote_trust_flag() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "layerfault-package-automap-runtime-trust-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        fs::write(
            root.join("config.json"),
            br#"{"auto_map":{"AutoModel":"modeling_example.Example"}}"#,
        )?;
        fs::write(
            root.join("modeling_example.py"),
            b"os.system('echo imported')\n",
        )?;
        let report = inspect(&root)?;
        assert!(report.findings.iter().any(|finding| {
            finding.status == ScanStatus::Fail
                && finding
                    .matches
                    .iter()
                    .any(|value| value.contains("LF-CODE-IMPORT-SIDE-EFFECT"))
        }));
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn renamed_elf_member_is_detected_by_content() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "layerfault-package-renamed-elf-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        let mut elf = vec![0_u8; 128];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        elf[16..18].copy_from_slice(&2_u16.to_le_bytes());
        elf[18..20].copy_from_slice(&62_u16.to_le_bytes());
        elf[40..48].copy_from_slice(&64_u64.to_le_bytes());
        elf[52..54].copy_from_slice(&64_u16.to_le_bytes());
        elf[58..60].copy_from_slice(&64_u16.to_le_bytes());
        elf[60..62].copy_from_slice(&1_u16.to_le_bytes());
        fs::write(root.join("weights.dat"), elf)?;
        let report = inspect(&root)?;
        assert!(report.findings.iter().any(|finding| finding
            .matches
            .iter()
            .any(|value| value.contains("T12-001"))));
        let _ = fs::remove_dir_all(root);
        Ok(())
    }
}
