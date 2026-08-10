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
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PackageFingerprintReport {
    pub root: String,
    pub fingerprint: String,
    pub files: Vec<PackageEntry>,
    pub total_bytes: u64,
}

#[derive(Default)]
struct PackageMemberEvidence {
    relative_path: String,
    auto_map: bool,
    remote_trust: bool,
    modules: BTreeSet<String>,
    module_scope_operation: Option<&'static str>,
    json_parse_error: Option<String>,
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
        findings.push(finding(
                &format!("package:{rel}"),
                CheckType::PackageSecurity,
                ScanStatus::Fail,
                FindingClass::Structural,
                Confidence::High,
                "LF-PACKAGE-SYMLINK",
                format!("Package contains symlink '{}' -> '{}'; model packages are fingerprinted and scanned without following links", rel, target.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "<unreadable>".to_owned())),
            ));
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

    for path in discovery.paths {
        let rel = safe_relative(&root, &path)?;
        let file = open_readonly_nofollow(&path)?;
        let size = file.metadata()?.len();
        total_bytes = checked_package_total(total_bytes, size)?;
        let hash = crate::hashcache::sha256_prefixed(&path, &file)?;
        let digest = hash.sha256.clone();
        let kind = classify(&path);
        files.push(PackageEntry {
            relative_path: rel.clone(),
            kind: kind.to_owned(),
            size,
            sha256: Some(digest.clone()),
            digest_cache: Some(if hash.cache_hit {
                "HIT".to_owned()
            } else if crate::hashcache::digest_eligible(size) {
                "MISS".to_owned()
            } else {
                "BYPASS_SMALL".to_owned()
            }),
        });
        let evidence = capture_custom_code_evidence(&rel, &file)?;
        findings.extend(scan_package_file(
            &path,
            &rel,
            &file,
            size,
            &digest,
            &evidence,
            &auto_map_modules,
        )?);
        member_evidence.push(evidence);
        let changed = if crate::hashcache::eligible(size) {
            !crate::hashcache::identity_unchanged(&path, &file, &hash.identity)?
        } else {
            crate::hashcache::sha256_uncached_prefixed(&file)? != digest
        };
        if changed {
            findings.push(finding(
                &digest,
                CheckType::PackageSecurity,
                ScanStatus::Fail,
                FindingClass::Integrity,
                Confidence::High,
                "LF-PACKAGE-RACE",
                format!("Package file '{}' changed while it was being scanned", rel),
            ));
        }
    }

    correlate_custom_code(&files, &member_evidence, &mut findings);

    let fingerprint = package_fingerprint(&files);
    findings.sort_by(|a, b| {
        a.matches
            .cmp(&b.matches)
            .then_with(|| a.layer_digest.cmp(&b.layer_digest))
    });

    Ok(PackageReport {
        root: root.display().to_string(),
        fingerprint,
        files,
        total_bytes,
        findings,
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
    let hash = crate::hashcache::sha256_prefixed(content_path, &file)?;
    let digest = hash.sha256.clone();
    let rel = display_path.display().to_string();
    let evidence = capture_custom_code_evidence(&rel, &file)?;
    let empty_auto_map = BTreeSet::new();
    let mut findings = scan_package_file(
        display_path,
        &rel,
        &file,
        size,
        &digest,
        &evidence,
        &empty_auto_map,
    )?;
    let changed = if crate::hashcache::eligible(size) {
        !crate::hashcache::identity_unchanged(content_path, &file, &hash.identity)?
    } else {
        crate::hashcache::sha256_uncached_prefixed(&file)? != digest
    };
    if changed {
        findings.push(finding(
            &digest,
            CheckType::PackageSecurity,
            ScanStatus::Fail,
            FindingClass::Integrity,
            Confidence::High,
            "LF-PACKAGE-RACE",
            format!(
                "Package member '{}' changed while it was being scanned",
                rel
            ),
        ));
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

fn scan_package_file(
    path: &Path,
    rel: &str,
    file: &std::fs::File,
    size: u64,
    digest: &str,
    evidence: &PackageMemberEvidence,
    auto_map_modules: &BTreeSet<String>,
) -> Result<Vec<LayerScanResult>> {
    let mut out = Vec::new();
    let format = ArtifactFormat::detect(path, &prefix(file, 8)?);
    if format != ArtifactFormat::Unknown {
        match artifact::inspect_opened_file_with_sha256(
            path,
            file,
            format,
            artifact::ArtifactScanMode::Full,
            digest,
        ) {
            Ok(report) => out.extend(report.results),
            Err(error) => out.push(finding(
                digest,
                CheckType::PackageSecurity,
                ScanStatus::Fail,
                FindingClass::Structural,
                Confidence::High,
                "LF-PACKAGE-ARTIFACT",
                format!(
                    "Artifact '{}' failed package validation safely: {error}",
                    rel
                ),
            )),
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
        out.push(finding(
            digest,
            CheckType::PackageSecurity,
            ScanStatus::Warn,
            FindingClass::Compatibility,
            Confidence::High,
            "LF-PICKLE-OPAQUE-COMPRESSED",
            format!("Package file '{}' has a pickle/PyTorch serialization name behind unsupported compression; opcode analysis could not verify the payload", rel),
        ));
    } else if ext == "bin" {
        out.push(finding(
            digest,
            CheckType::PackageSecurity,
            ScanStatus::Warn,
            FindingClass::Compatibility,
            Confidence::Medium,
            "LF-SERIALIZATION-BIN",
            format!("Legacy .bin artifact '{}' is opaque to Layerfault; verify the producer and loading path before use", rel),
        ));
    }

    let executable_prefix = prefix(file, 8)?;
    if crate::scanner::BinaryScanner::looks_executable_prefix(&executable_prefix) {
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

    if is_native_or_script(&ext, &lower) {
        out.push(finding(
            digest,
            CheckType::PackageSecurity,
            ScanStatus::Warn,
            FindingClass::ContentIndicator,
            Confidence::High,
            "LF-PACKAGE-CODE",
            format!("Package contains executable/custom-code artifact '{}'; weight-only packages normally do not require executable content", rel),
        ));
    }

    if ext == "py" && !is_documentation_path(rel) && !is_tokenizer_vocabulary_path(rel) {
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
        out.push(finding(
            digest,
            CheckType::PackageSecurity,
            ScanStatus::Pass,
            FindingClass::Informational,
            Confidence::High,
            "LF-PACKAGE-FILE",
            format!(
                "Package file '{}' hashed; no high-confidence package-security indicator matched",
                rel
            ),
        ));
    }
    Ok(out)
}

fn scan_json_evidence(
    rel: &str,
    digest: &str,
    evidence: &PackageMemberEvidence,
    out: &mut Vec<LayerScanResult>,
) {
    if evidence.auto_map {
        out.push(finding(digest, CheckType::PackageSecurity, ScanStatus::Warn, FindingClass::ContentIndicator, Confidence::High, "LF-CODE-AUTO-MAP", format!("'{}' contains Hugging Face auto_map metadata that can route loading through custom model code", rel)));
    }
    if evidence.remote_trust {
        out.push(finding(digest, CheckType::PackageSecurity, ScanStatus::Warn, FindingClass::ContentIndicator, Confidence::High, "LF-CODE-REMOTE-TRUST", format!("'{}' explicitly enables trust_remote_code; custom code should be reviewed before loading", rel)));
    }
    if let Some(error) = evidence.json_parse_error.as_deref() {
        out.push(finding(
            digest,
            CheckType::PackageSecurity,
            ScanStatus::Warn,
            FindingClass::Structural,
            Confidence::High,
            "LF-PACKAGE-JSON-INVALID",
            format!(
                "JSON/config '{}' could not be parsed completely: {}",
                rel, error
            ),
        ));
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
    let mut found_rules = BTreeSet::<&'static str>::new();
    let mut jinja_seen = false;
    let mut template_marker_seen = rel.to_ascii_lowercase().contains("template");
    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let mut chunk = vec![0_u8; TEXT_STREAM_CHUNK_BYTES];
    let mut carry = Vec::<u8>::new();
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
                if lower.contains(needle) {
                    found_rules.insert(rule);
                }
            }
        }
        if !vocabulary_data {
            jinja_seen |= jinja.iter().any(|needle| lower.contains(needle));
            template_marker_seen |= lower.contains("{{");
        }
        let keep = window.len().min(TEXT_STREAM_OVERLAP_BYTES);
        carry.clear();
        carry.extend_from_slice(&window[window.len() - keep..]);
    }
    for rule in found_rules {
        let primitive = match rule {
            "LF-CODE-OS-SYSTEM" => "os.system",
            "LF-CODE-SUBPROCESS" => "subprocess",
            "LF-CODE-EVAL" => "eval",
            "LF-CODE-EXEC" => "exec",
            "LF-CODE-CTYPES" => "ctypes",
            "LF-CODE-NETWORK" => "network access",
            _ => "security-sensitive primitive",
        };
        out.push(finding(digest, CheckType::PackageSecurity, ScanStatus::Warn, FindingClass::ContentIndicator, Confidence::High, rule, format!("Custom code/config '{}' contains security-relevant primitive '{}'; the entire file was streamed and review is required before enabling custom code", rel, primitive)));
    }
    if jinja_seen && template_marker_seen {
        out.push(finding(digest, CheckType::PackageSecurity, ScanStatus::Warn, FindingClass::ContentIndicator, Confidence::High, "LF-TEMPLATE-INTROSPECTION", format!("Template/config '{}' contains Python/Jinja introspection primitives; review template execution context before use", rel)));
    }
    Ok(())
}

fn is_tokenizer_vocabulary_path(rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel).to_ascii_lowercase();
    matches!(
        name.as_str(),
        "tokenizer.json" | "vocab.json" | "merges.txt" | "added_tokens.json"
    ) || name.starts_with("vocab.")
}

fn is_documentation_path(rel: &str) -> bool {
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
        })
    }
}

struct JsonMetadataVisitor<'a> {
    evidence: &'a mut PackageMemberEvidence,
    context: JsonMetadataContext,
}

impl<'de> Visitor<'de> for JsonMetadataVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("arbitrary JSON metadata")
    }

    fn visit_bool<E>(self, value: bool) -> std::result::Result<Self::Value, E> {
        if matches!(self.context, JsonMetadataContext::RemoteTrust) && value {
            self.evidence.remote_trust = true;
        }
        Ok(())
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E> {
        if matches!(self.context, JsonMetadataContext::AutoMap) {
            collect_module_reference(value, &mut self.evidence.modules);
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
        while seq
            .next_element_seed(JsonMetadataSeed {
                evidence: &mut *self.evidence,
                context: self.context,
            })?
            .is_some()
        {}
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
            map.next_value_seed(JsonMetadataSeed {
                evidence: &mut *self.evidence,
                context,
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
    }
    .deserialize(&mut de)
    .map_err(|error| anyhow!(error))?;
    de.end().map_err(|error| anyhow!(error))?;
    Ok(())
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
    if modules.is_empty() {
        return;
    }

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
        findings.push(finding(
            entry.sha256.as_deref().unwrap_or("module"),
            CheckType::PackageSecurity,
            ScanStatus::Fail,
            FindingClass::ContentIndicator,
            Confidence::High,
            "LF-CODE-IMPORT-SIDE-EFFECT",
            format!(
                "Hugging Face auto_map routes loading through '{}', which performs '{}' at module scope{}",
                entry.relative_path, operation, trust_context
            ),
        ));
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

fn finding(
    digest: &str,
    check_type: CheckType,
    status: ScanStatus,
    class: FindingClass,
    confidence: Confidence,
    rule: &str,
    detail: String,
) -> LayerScanResult {
    LayerScanResult {
        layer_digest: digest.to_owned(),
        media_type: "application/vnd.layerfault.package".to_owned(),
        check_type,
        status,
        finding_class: class,
        confidence,
        detail: Some(detail),
        matches: vec![format!("[{rule}] package finding")],
        duration_ms: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

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
