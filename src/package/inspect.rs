use super::*;

pub fn inspect(root: &Path) -> Result<PackageReport> {
    let budget =
        crate::budget::ScanBudget::new(crate::budget::ScanBudgetProfile::Default.limits())?;
    inspect_with_budget(root, &budget)
}

/// Find every `.mlpackage` directory boundary within a package root: the
/// root itself, if its own name carries the extension, plus any nested
/// occurrence (bounded by the same traversal limits as package discovery).
/// Symlinked directories are not followed, matching `discover_package`.
fn mlpackage_boundaries(root: &Path) -> Vec<PathBuf> {
    let is_mlpackage_dir = |path: &Path| -> bool {
        path.is_dir()
            && path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("mlpackage"))
    };

    let mut boundaries = Vec::new();
    if is_mlpackage_dir(root) {
        boundaries.push(root.to_path_buf());
    }

    let mut walker = WalkDir::new(root)
        .follow_links(false)
        .max_depth(MAX_PACKAGE_DEPTH)
        .into_iter();
    while let Some(entry) = walker.next() {
        let Ok(entry) = entry else { continue };
        if entry.depth() == 0 {
            continue;
        }
        if entry.file_type().is_dir() && is_mlpackage_dir(entry.path()) {
            boundaries.push(entry.path().to_path_buf());
            walker.skip_current_dir();
        }
    }
    boundaries
}

pub(super) fn estimate_member_cost(path: &Path, size: u64) -> crate::scheduler::TaskCost {
    let ext = path
        .extension()
        .and_then(|v| v.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match ext.as_str() {
        "py" | "pyw" | "sh" | "bash" | "zsh" | "ps1" | "psm1" | "psd1" | "js" | "mjs" | "cjs"
        | "ts" | "tsx" | "jsx" => crate::scheduler::TaskCost::ast_parse(size),
        "zip" | "tar" | "tgz" | "gz" | "whl" => {
            crate::scheduler::TaskCost::archive_decompression(size.saturating_mul(2))
        }
        "so" | "dll" | "dylib" | "elf" | "exe" => crate::scheduler::TaskCost::native_parse(size),
        _ => {
            if size > 10 * 1024 * 1024 {
                crate::scheduler::TaskCost::large_sequential_io(size, 8 * 1024 * 1024)
            } else {
                crate::scheduler::TaskCost::small_io(size)
            }
        }
    }
}

pub fn inspect_with_budget(
    root: &Path,
    budget: &crate::budget::ScanBudget,
) -> Result<PackageReport> {
    let scheduler =
        crate::scheduler::AdaptiveScheduler::new(crate::scheduler::SchedulerConfig::detect(
            None,
            None,
            None,
            crate::scheduler::SchedulerMode::Adaptive,
            crate::budget::ScanBudgetProfile::Default,
        ));
    inspect_with_scheduler(root, budget, &scheduler)
}

#[derive(Debug, Clone)]
pub(super) struct PackageMemberHeader {
    pub(super) path: PathBuf,
    pub(super) rel: String,
    pub(super) size: u64,
    pub(super) sha256: String,
    pub(super) identity: crate::hashcache::FileIdentity,
    pub(super) cache_hit: bool,
    pub(super) kind: String,
}

#[derive(Debug)]
pub(super) struct VerifiedPackageMember {
    header: PackageMemberHeader,
    file: File,
}

#[derive(Debug)]
pub(super) struct MemberAnalysis {
    entry: PackageEntry,
    pub(super) findings: Vec<LayerScanResult>,
    evidence: PackageMemberEvidence,
    metrics: crate::scanner::ScanMetrics,
    pub(super) incomplete_reason: Option<String>,
    parser_failure: bool,
    control_failure: Option<crate::budget::BudgetFailure>,
}

pub(super) fn primary_evidence_location(
    finding: &LayerScanResult,
) -> Option<crate::finding_evidence::EvidenceLocation> {
    finding
        .evidence
        .iter()
        .filter_map(|evidence| evidence.location.clone())
        .min()
}

pub(super) fn sort_findings_canonically(findings: &mut [LayerScanResult]) {
    findings.sort_by(|a, b| {
        let path_a = a
            .subject
            .as_ref()
            .map(EvidenceSubject::canonical_name)
            .unwrap_or("");
        let path_b = b
            .subject
            .as_ref()
            .map(EvidenceSubject::canonical_name)
            .unwrap_or("");
        path_a
            .cmp(path_b)
            .then_with(|| a.rule_id.cmp(&b.rule_id))
            .then_with(|| a.finding_id.cmp(&b.finding_id))
            .then_with(|| primary_evidence_location(a).cmp(&primary_evidence_location(b)))
    });
}

pub(super) fn analyze_member(
    package_root: Option<&Path>,
    member: &VerifiedPackageMember,
    auto_map_modules: &BTreeSet<String>,
    budget: &crate::budget::ScanBudget,
    scheduler: &crate::scheduler::AdaptiveScheduler,
) -> Result<MemberAnalysis> {
    let header = &member.header;
    let member_budget = budget.child("package", &header.rel, None)?;
    let cost = estimate_member_cost(&header.path, header.size);
    let _permit = scheduler
        .acquire(cost, &member_budget)
        .map_err(|error| anyhow!("global scan budget/scheduler exhausted: {error}"))?;

    member_budget
        .consume(crate::budget::BudgetDimension::Objects, 1, "package member")
        .map_err(|error| anyhow!("global scan budget exhausted: {error}"))?;
    member_budget
        .consume(
            crate::budget::BudgetDimension::SourceBytes,
            header.size,
            "package member source",
        )
        .map_err(|error| anyhow!("global scan budget exhausted: {error}"))?;

    let file = &member.file;
    let session = crate::scanner::ScanSession::new(&header.path, file)?;

    let ext = header
        .path
        .extension()
        .and_then(|v| v.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let lower = header.rel.to_ascii_lowercase();

    let mut observers: Vec<Box<dyn crate::scanner::StreamObserver>> = Vec::new();

    let file_prefix = prefix(file, 512)?;
    let executable_candidate = crate::scanner::BinaryScanner::looks_executable_prefix(
        &file_prefix[..file_prefix.len().min(8)],
    );
    if executable_candidate {
        observers.push(Box::new(crate::scanner::BinaryStreamObserver::with_file(
            file.try_clone()?,
            header.size,
        )));
    }

    let is_text = is_text_candidate(&ext, &lower) && !is_tokenizer_vocabulary_path(&header.rel);
    if is_text {
        observers.push(Box::new(crate::scanner::TextStreamObserver::new(
            &header.rel,
        )));
    }

    let (digest, session_findings) =
        session.run("application/vnd.layerfault.package-member", observers)?;

    let session_metrics = session.metrics.borrow().clone();

    let mut file_for_evidence = file.try_clone()?;
    file_for_evidence.seek(SeekFrom::Start(0))?;
    let evidence = capture_custom_code_evidence(&header.rel, &file_for_evidence)?;

    let mut file_for_scan = file.try_clone()?;
    file_for_scan.seek(SeekFrom::Start(0))?;
    let mut member_findings = scan_package_file(
        package_root,
        &header.path,
        &header.rel,
        &file_for_scan,
        header.size,
        &digest,
        &evidence,
        auto_map_modules,
        &session_findings,
        &member_budget,
    )?;

    let descriptor_changed =
        !crate::hashcache::identity_unchanged(&header.path, &file_for_scan, &header.identity)?;
    let path_changed = match open_readonly_nofollow(&header.path) {
        Ok(current) => {
            crate::hashcache::capture_identity(&header.path, &current)? != header.identity
        }
        Err(_) => true,
    };
    let changed = descriptor_changed || path_changed || digest != header.sha256;
    if changed {
        let observed = crate::hashcache::sha256_uncached_prefixed(&file_for_scan)
            .unwrap_or_else(|_| "<unreadable after change>".to_owned());
        let subject = member_subject(&header.rel, &digest, Some(header.size));
        member_findings.push(
            finding(
                &digest,
                CheckType::PackageSecurity,
                ScanStatus::Fail,
                FindingClass::Integrity,
                Confidence::High,
                "LF-PACKAGE-RACE",
                format!(
                    "Package file '{}' changed while it was being scanned",
                    header.rel
                ),
            )
            .subject(subject.clone())
            .evidence(hash_mismatch(subject, &digest, &observed))
            .finish(),
        );
    }

    let cache_hit = header.cache_hit || session_metrics.cache_hits > 0;
    let entry = PackageEntry {
        relative_path: header.rel.clone(),
        kind: header.kind.clone(),
        size: header.size,
        sha256: Some(digest),
        digest_cache: Some(if cache_hit {
            "HIT".to_owned()
        } else if crate::hashcache::digest_eligible(header.size) {
            "MISS".to_owned()
        } else {
            "BYPASS_SMALL".to_owned()
        }),
    };

    let parser_failure = member_findings.iter().any(|finding| {
        matches!(
            finding.rule_id.as_deref(),
            Some("LF-ARCHIVE-MALFORMED" | "LF-PACKAGE-ARTIFACT")
        )
    });
    let incomplete_reason = if changed {
        Some(format!(
            "package member '{}' changed while it was being scanned",
            header.rel
        ))
    } else if parser_failure {
        Some(format!(
            "package member '{}' could not be parsed completely",
            header.rel
        ))
    } else {
        None
    };

    Ok(MemberAnalysis {
        entry,
        findings: member_findings,
        evidence,
        metrics: session_metrics,
        incomplete_reason,
        parser_failure,
        control_failure: None,
    })
}

pub(super) fn safe_analyze_member(
    package_root: Option<&Path>,
    member: &VerifiedPackageMember,
    auto_map_modules: &BTreeSet<String>,
    budget: &crate::budget::ScanBudget,
    scheduler: &crate::scheduler::AdaptiveScheduler,
) -> MemberAnalysis {
    isolate_member_analysis(&member.header, budget, || {
        analyze_member(package_root, member, auto_map_modules, budget, scheduler)
    })
}

pub(super) fn isolate_member_analysis<F>(
    header: &PackageMemberHeader,
    budget: &crate::budget::ScanBudget,
    work: F,
) -> MemberAnalysis
where
    F: FnOnce() -> Result<MemberAnalysis>,
{
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work));
    match result {
        Ok(Ok(analysis)) => analysis,
        Ok(Err(err)) => {
            let control_failure = budget.check().err().filter(|failure| failure.is_control());
            if let Some(failure) = control_failure {
                return MemberAnalysis {
                    entry: PackageEntry {
                        relative_path: header.rel.clone(),
                        kind: header.kind.clone(),
                        size: header.size,
                        sha256: Some(header.sha256.clone()),
                        digest_cache: Some("INTERRUPTED".to_owned()),
                    },
                    findings: Vec::new(),
                    evidence: PackageMemberEvidence {
                        relative_path: header.rel.clone(),
                        ..Default::default()
                    },
                    metrics: crate::scanner::ScanMetrics::default(),
                    incomplete_reason: Some(format!(
                        "package member '{}' was interrupted",
                        header.rel
                    )),
                    parser_failure: false,
                    control_failure: Some(failure),
                };
            }
            let fallback_sha = &header.sha256;
            let subject = member_subject(&header.rel, fallback_sha, Some(header.size));
            let error_finding = finding(
                fallback_sha,
                CheckType::PackageSecurity,
                ScanStatus::Fail,
                FindingClass::Structural,
                Confidence::High,
                "LF-PACKAGE-MEMBER-ERROR",
                format!(
                    "Package member '{}' failed inspection safely: {err}",
                    header.rel
                ),
            )
            .subject(subject)
            .finish();
            MemberAnalysis {
                entry: PackageEntry {
                    relative_path: header.rel.clone(),
                    kind: header.kind.clone(),
                    size: header.size,
                    sha256: Some(header.sha256.clone()),
                    digest_cache: Some("ERROR".to_owned()),
                },
                findings: vec![error_finding],
                evidence: PackageMemberEvidence {
                    relative_path: header.rel.clone(),
                    ..Default::default()
                },
                metrics: crate::scanner::ScanMetrics::default(),
                incomplete_reason: Some(err.to_string()),
                parser_failure: true,
                control_failure: None,
            }
        }
        Err(_panic_payload) => {
            let fallback_sha = &header.sha256;
            let subject = member_subject(&header.rel, fallback_sha, Some(header.size));
            let panic_finding = finding(
                fallback_sha,
                CheckType::PackageSecurity,
                ScanStatus::Fail,
                FindingClass::Structural,
                Confidence::High,
                "LF-PACKAGE-MEMBER-PANIC",
                format!(
                    "Package member '{}' panicked during inspection; isolated safely",
                    header.rel
                ),
            )
            .subject(subject)
            .finish();
            MemberAnalysis {
                entry: PackageEntry {
                    relative_path: header.rel.clone(),
                    kind: header.kind.clone(),
                    size: header.size,
                    sha256: Some(header.sha256.clone()),
                    digest_cache: Some("PANIC".to_owned()),
                },
                findings: vec![panic_finding],
                evidence: PackageMemberEvidence {
                    relative_path: header.rel.clone(),
                    ..Default::default()
                },
                metrics: crate::scanner::ScanMetrics::default(),
                incomplete_reason: Some("panic during member analysis".to_owned()),
                parser_failure: true,
                control_failure: None,
            }
        }
    }
}

pub(super) fn race_analysis(header: &PackageMemberHeader, observed: &str) -> MemberAnalysis {
    let subject = member_subject(&header.rel, &header.sha256, Some(header.size));
    let race = finding(
        &header.sha256,
        CheckType::PackageSecurity,
        ScanStatus::Fail,
        FindingClass::Integrity,
        Confidence::High,
        "LF-PACKAGE-RACE",
        format!(
            "Package file '{}' changed after its identity was established",
            header.rel
        ),
    )
    .subject(subject.clone())
    .evidence(hash_mismatch(subject, &header.sha256, observed))
    .finish();
    MemberAnalysis {
        entry: PackageEntry {
            relative_path: header.rel.clone(),
            kind: header.kind.clone(),
            size: header.size,
            sha256: Some(header.sha256.clone()),
            digest_cache: Some(if header.cache_hit {
                "HIT".to_owned()
            } else if crate::hashcache::digest_eligible(header.size) {
                "MISS".to_owned()
            } else {
                "BYPASS_SMALL".to_owned()
            }),
        },
        findings: vec![race],
        evidence: PackageMemberEvidence {
            relative_path: header.rel.clone(),
            ..Default::default()
        },
        metrics: crate::scanner::ScanMetrics::default(),
        incomplete_reason: Some(format!(
            "package member '{}' changed before analysis",
            header.rel
        )),
        parser_failure: false,
        control_failure: None,
    }
}

pub(super) fn prepare_verified_member(
    header: &PackageMemberHeader,
) -> std::result::Result<VerifiedPackageMember, Box<MemberAnalysis>> {
    let file = match open_readonly_nofollow(&header.path) {
        Ok(file) => file,
        Err(_) => return Err(Box::new(race_analysis(header, "<unreadable after change>"))),
    };
    let current = match crate::hashcache::capture_identity(&header.path, &file) {
        Ok(identity) => identity,
        Err(_) => return Err(Box::new(race_analysis(header, "<unreadable after change>"))),
    };
    if current != header.identity {
        let observed = crate::hashcache::sha256_uncached_prefixed(&file)
            .unwrap_or_else(|_| "<unreadable after change>".to_owned());
        return Err(Box::new(race_analysis(header, &observed)));
    }
    #[cfg(windows)]
    {
        let observed = crate::hashcache::sha256_uncached_prefixed(&file)
            .unwrap_or_else(|_| "<unreadable after change>".to_owned());
        if observed != header.sha256 {
            return Err(Box::new(race_analysis(header, &observed)));
        }
    }
    Ok(VerifiedPackageMember {
        header: header.clone(),
        file,
    })
}

pub fn inspect_with_scheduler(
    root: &Path,
    budget: &crate::budget::ScanBudget,
    scheduler: &crate::scheduler::AdaptiveScheduler,
) -> Result<PackageReport> {
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

    // Discover members safely and normalize paths.
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
            .evidence(symlink_target(subject, &rel, target.as_ref().map(|_| rendered.as_str())))
            .finish(),
        );
    }
    discovery
        .paths
        .sort_by_key(|path| safe_relative(&root, path).unwrap_or_default());

    // Establish member identities and hashes.
    let mut member_headers = Vec::with_capacity(discovery.paths.len());
    let mut auto_map_modules = BTreeSet::new();
    let mut total_bytes = 0_u64;
    let mut control_interruption: Option<(
        crate::budget::BudgetFailure,
        crate::budget::BudgetUsage,
    )> = None;

    for path in discovery.paths {
        if let Err((failure, usage)) = budget.checkpoint("package member loop") {
            control_interruption = Some((failure, usage));
            break;
        }
        let rel = safe_relative(&root, &path)?;
        let file = open_readonly_nofollow(&path)?;
        let size = file.metadata()?.len();

        let hash = crate::hashcache::sha256_prefixed(&path, &file)?;
        if rel.to_ascii_lowercase().ends_with(".json") {
            if let Ok(evidence) = capture_custom_code_evidence(&rel, &file) {
                if evidence.auto_map
                    && crate::hashcache::identity_unchanged(&path, &file, &hash.identity)?
                {
                    auto_map_modules.extend(evidence.modules);
                }
            }
        }
        total_bytes = checked_package_total(total_bytes, size)?;
        let kind = classify(&path, &file).to_owned();

        member_headers.push(PackageMemberHeader {
            path,
            rel,
            size,
            sha256: hash.sha256,
            identity: hash.identity,
            cache_hit: hash.cache_hit,
            kind,
        });
    }

    // Analyze members independently in parallel.
    let max_workers = scheduler.config().max_workers.max(1);
    let discovered_member_count = member_headers.len();
    let mut analyses = Vec::with_capacity(member_headers.len());
    for headers in member_headers.chunks(max_workers) {
        if let Err((failure, usage)) = budget.checkpoint("package analysis batch") {
            control_interruption = Some((failure, usage));
            break;
        }
        let prepared = headers
            .iter()
            .map(prepare_verified_member)
            .collect::<Vec<_>>();
        let mut batch = if max_workers == 1 || prepared.len() <= 1 {
            prepared
                .into_iter()
                .map(|member| match member {
                    Ok(member) => safe_analyze_member(
                        Some(&root),
                        &member,
                        &auto_map_modules,
                        budget,
                        scheduler,
                    ),
                    Err(analysis) => *analysis,
                })
                .collect::<Vec<_>>()
        } else {
            use rayon::prelude::*;
            prepared
                .into_par_iter()
                .map(|member| match member {
                    Ok(member) => safe_analyze_member(
                        Some(&root),
                        &member,
                        &auto_map_modules,
                        budget,
                        scheduler,
                    ),
                    Err(analysis) => *analysis,
                })
                .collect::<Vec<_>>()
        };
        let batch_control = batch.iter().find_map(|analysis| analysis.control_failure);
        analyses.append(&mut batch);
        if let Some(failure) = batch_control {
            let usage = budget
                .snapshot_with_operation(Some(failure), "package member analysis")
                .into_iter()
                .find(|usage| usage.dimension == crate::budget::BudgetDimension::WallClock)
                .expect("wall clock budget dimension exists");
            control_interruption = Some((failure, usage));
            break;
        }
    }

    // Merge results deterministically.
    let mut files = Vec::with_capacity(analyses.len());
    let mut member_evidence = Vec::with_capacity(analyses.len());
    let mut aggregate_metrics = crate::scanner::ScanMetrics::default();
    let mut incomplete_members = Vec::new();
    let mut parser_failures = 0_u64;

    for analysis in analyses {
        if let Some(reason) = analysis.incomplete_reason {
            incomplete_members.push(reason);
        }
        if analysis.parser_failure {
            parser_failures = parser_failures.saturating_add(1);
        }
        files.push(analysis.entry);
        member_evidence.push(analysis.evidence);
        aggregate_metrics.bytes_read_sequential += analysis.metrics.bytes_read_sequential;
        aggregate_metrics.full_passes += analysis.metrics.full_passes;
        aggregate_metrics.cache_hits += analysis.metrics.cache_hits;
        aggregate_metrics.cache_misses += analysis.metrics.cache_misses;
        aggregate_metrics.random_read_bytes += analysis.metrics.random_read_bytes;
        findings.extend(analysis.findings);
    }

    let fingerprint = package_fingerprint(&files);
    let (merkle_identity, merkle_manifest) = compute_merkle_tree(&files, None);

    // Construct the relationship graph.
    correlate_custom_code(&files, &member_evidence, &mut findings);
    // Correlate related findings.
    let evidence_bytes = serde_json::to_vec(&findings)?.len() as u64;
    let evidence_failure = if control_interruption.is_some() {
        None
    } else {
        budget
            .consume(
                crate::budget::BudgetDimension::RetainedEvidenceBytes,
                evidence_bytes,
                "package evidence retention",
            )
            .err()
    };
    if let Some(failure) = evidence_failure {
        let usage = budget
            .snapshot_with_operation(Some(failure), "package evidence retention")
            .into_iter()
            .find(|item| item.dimension == crate::budget::BudgetDimension::RetainedEvidenceBytes)
            .expect("budget dimension exists");
        let mut result = finding(
            &format!("package:{}", root.display()),
            CheckType::PackageSecurity,
            ScanStatus::Fail,
            FindingClass::Operational,
            Confidence::High,
            "LF-BUDGET-EVIDENCE",
            format!("Global retained-evidence budget exhausted: {failure}"),
        )
        .evidence_unavailable("retained evidence budget exhausted; package coverage is incomplete")
        .finish();
        result.evidence_reason = Some(serde_json::to_string(&usage)?);
        findings.push(result);
    }

    // Normalize only known executable configuration files. No imports or model code are executed.
    let mut declarative_facts = Vec::new();
    for entry in &files {
        let path = root.join(&entry.relative_path);
        if let Ok(file) = crate::safeio::open_readonly_nofollow(&path) {
            if let Ok(bytes) = crate::safeio::read_all_from_file(&file, 4 * 1024 * 1024) {
                if let Ok(mut facts) =
                    crate::model::declarative::normalized_config_facts(&entry.relative_path, &bytes)
                {
                    declarative_facts.append(&mut facts);
                }
            }
        }
    }
    let execution_edges = crate::model::declarative::detect(&declarative_facts, None);
    findings.extend(crate::model::declarative::findings(
        &execution_edges,
        &merkle_identity,
    ));

    let tokenizer_file_list = files
        .iter()
        .map(|e| e.relative_path.clone())
        .collect::<Vec<_>>();
    let tokenizer_security =
        crate::model::tokenizer::inspect_package(&root, &tokenizer_file_list, &merkle_identity)
            .ok();
    if let Some(report) = tokenizer_security.as_ref() {
        findings.extend(report.findings.clone());
    }

    // Additive, package-shape-triggered detector: MLX packages have no
    // directory-extension convention (unlike Core ML's `.mlpackage`), so
    // per-member classification alone never dispatches to the MLX checks.
    // This runs alongside — not instead of — generic member scanning.
    if crate::formats::mlx::looks_like_mlx_package(&root) {
        findings.extend(crate::formats::mlx::scan_package(
            &root,
            &merkle_identity,
            PACKAGE_MEDIA_TYPE,
        )?);
    }

    // Additive, package-shape-triggered detector: `.mlpackage` is a
    // directory-as-bundle convention, not a real file extension, so the
    // per-member walk above recurses straight through it and never treats
    // the enclosing directory as a distinct package boundary — it only ever
    // finds and classifies the inner `.mlmodel` file. Explicitly detect
    // `.mlpackage` boundaries (the root itself, or nested anywhere in a
    // larger package) and dispatch the Manifest.json integrity check for
    // each, alongside — not instead of — the generic member scan.
    for boundary in mlpackage_boundaries(&root) {
        findings.extend(crate::formats::coreml::scan_package(
            &boundary,
            &merkle_identity,
            PACKAGE_MEDIA_TYPE,
        )?);
    }

    sort_findings_canonically(&mut findings);

    let correlations = crate::correlate::correlate(&findings);

    // Aggregate coverage and package policy results.
    let mut coverage = crate::coverage::Coverage::complete(files.len() as u64, total_bytes);
    coverage.files_discovered = discovered_member_count as u64;
    let incomplete_member_count = incomplete_members.len() as u64;
    coverage.files_scanned = coverage
        .files_scanned
        .saturating_sub(incomplete_member_count);
    for reason in incomplete_members {
        coverage.omit(1, &reason, &[]);
    }
    let unscheduled = discovered_member_count.saturating_sub(files.len()) as u64;
    coverage.omit(
        unscheduled,
        "package members were not scheduled after scan interruption",
        &[],
    );
    for _ in 0..parser_failures {
        coverage.parser_failure("a package member parser failed safely");
    }
    coverage.budget =
        budget.snapshot_with_operation(evidence_failure, "package evidence retention");
    if let Some(failure) = evidence_failure {
        if let Some(usage) = coverage
            .budget
            .iter()
            .find(|item| item.failure == Some(failure))
            .cloned()
        {
            coverage.budget_exhausted(usage, "retained evidence budget exhausted");
        }
    }
    if findings
        .iter()
        .any(|item| item.evidence_state == Some(crate::finding_evidence::EvidenceState::Partial))
    {
        coverage.evidence_limited(
            "evidence collection for at least one member reached its bounded limit",
        );
    }
    if let Some((failure, usage)) = control_interruption {
        coverage.mark_control_interrupted(failure, usage);
    }
    coverage.set_elapsed_ms(budget.elapsed_ms());

    Ok(PackageReport {
        root: root.display().to_string(),
        fingerprint,
        merkle_identity,
        files,
        merkle_manifest,
        total_bytes,
        findings,
        execution_edges,
        tokenizer_security,
        correlations,
        coverage,
        metrics: Some(aggregate_metrics),
        incremental_diagnostics: None,
    })
}
