//! Single-pass / shared-read static scan session and stream observer pipeline.
//!
//! Spec 11 — Generalizes single-pass scanning so one physical read stream feeds
//! multiple compatible observers (hashing, binary object discovery, text heuristics,
//! line/offset tracking) simultaneously while preserving random-access descriptor
//! sharing and strict TOCTOU identity validation.

use crate::finding_evidence::{file_member, EvidenceSubject, FindingBuilder};
use crate::hashcache::{
    capture_identity, digest_eligible, evidence_eligible, load_evidence, store_evidence,
    FileIdentity,
};
use crate::scanner::binary::BinaryStreamScanner;
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Maximum single-pass read chunk size (1 MiB).
pub const STREAM_CHUNK_BYTES: usize = 1024 * 1024;

/// Internal and diagnostic scan metrics exposed additively in report structures.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ScanMetrics {
    pub bytes_read_sequential: u64,
    pub full_passes: u32,
    pub cache_hits: u32,
    pub cache_misses: u32,
    pub random_read_bytes: u64,
}

impl ScanMetrics {
    pub fn record_sequential_read(&mut self, bytes: u64) {
        self.bytes_read_sequential = self.bytes_read_sequential.saturating_add(bytes);
    }

    pub fn record_full_pass(&mut self) {
        self.full_passes = self.full_passes.saturating_add(1);
    }

    pub fn record_cache_hit(&mut self) {
        self.cache_hits = self.cache_hits.saturating_add(1);
    }

    pub fn record_cache_miss(&mut self) {
        self.cache_misses = self.cache_misses.saturating_add(1);
    }

    pub fn record_random_read(&mut self, bytes: u64) {
        self.random_read_bytes = self.random_read_bytes.saturating_add(bytes);
    }
}

/// A compatible sequential observer that consumes stream chunks during a single-pass scan.
pub trait StreamObserver {
    /// Optional cache discriminator for evidence reuse (e.g. "binary_scan", "text_heuristics").
    fn cache_discriminator(&self) -> Option<&'static str> {
        None
    }

    /// Observe a slice of bytes read at absolute byte offset `offset` in the file.
    fn observe(&mut self, offset: u64, chunk: &[u8]) -> Result<()>;

    /// Finish observation after stream completion and return findings.
    fn finish(&mut self, digest: &str, media_type: &str) -> Result<Vec<LayerScanResult>>;
}

/// Hasher observer computing SHA-256 digest during a streaming read pass.
#[derive(Default)]
pub struct HasherObserver {
    hasher: Sha256,
    digest: Option<String>,
}

impl HasherObserver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn digest(&self) -> Option<&str> {
        self.digest.as_deref()
    }
}

impl StreamObserver for HasherObserver {
    fn cache_discriminator(&self) -> Option<&'static str> {
        None
    }

    fn observe(&mut self, _offset: u64, chunk: &[u8]) -> Result<()> {
        self.hasher.update(chunk);
        Ok(())
    }

    fn finish(&mut self, _digest: &str, _media_type: &str) -> Result<Vec<LayerScanResult>> {
        let digest_hex = hex::encode(self.hasher.clone().finalize());
        self.digest = Some(format!("sha256:{digest_hex}"));
        Ok(Vec::new())
    }
}

/// Observer wrapping `BinaryStreamScanner` to scan executable magic and object headers.
pub struct BinaryStreamObserver {
    scanner: Option<BinaryStreamScanner>,
}

impl BinaryStreamObserver {
    pub fn new() -> Self {
        Self {
            scanner: Some(BinaryStreamScanner::new()),
        }
    }
}

impl Default for BinaryStreamObserver {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamObserver for BinaryStreamObserver {
    fn cache_discriminator(&self) -> Option<&'static str> {
        Some("binary_scan")
    }

    fn observe(&mut self, offset: u64, chunk: &[u8]) -> Result<()> {
        if let Some(s) = &mut self.scanner {
            s.observe_at_offset(offset, chunk)?;
        }
        Ok(())
    }

    fn finish(&mut self, digest: &str, media_type: &str) -> Result<Vec<LayerScanResult>> {
        if let Some(s) = self.scanner.take() {
            Ok(vec![s.finish(digest, media_type)])
        } else {
            Ok(Vec::new())
        }
    }
}

/// Observer performing streaming text searches for dangerous python patterns and Jinja markers.
pub struct TextStreamObserver {
    rel_path: String,
    is_doc: bool,
    is_vocab: bool,
    dangerous: Vec<(&'static str, &'static str)>,
    jinja_needles: Vec<(&'static str, &'static str)>,
    carry: Vec<u8>,
    window_start: u64,
    window_start_line: u64,
    findings: Vec<LayerScanResult>,
    seen_rules: BTreeSet<String>,
}

impl TextStreamObserver {
    pub fn new(rel_path: &str) -> Self {
        let is_doc = crate::package::is_documentation_path(rel_path);
        let is_vocab = crate::package::is_tokenizer_vocabulary_path(rel_path);
        Self {
            rel_path: rel_path.to_owned(),
            is_doc,
            is_vocab,
            dangerous: vec![
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
            ],
            jinja_needles: vec![
                ("__class__", "LF-TEMPLATE-INTROSPECTION"),
                ("__mro__", "LF-TEMPLATE-INTROSPECTION"),
                ("__subclasses__", "LF-TEMPLATE-INTROSPECTION"),
                ("__globals__", "LF-TEMPLATE-INTROSPECTION"),
                ("cycler.__init__", "LF-TEMPLATE-INTROSPECTION"),
                ("namespace.__init__", "LF-TEMPLATE-INTROSPECTION"),
            ],
            carry: Vec::new(),
            window_start: 0,
            window_start_line: 1,
            findings: Vec::new(),
            seen_rules: BTreeSet::new(),
        }
    }
}

impl StreamObserver for TextStreamObserver {
    fn cache_discriminator(&self) -> Option<&'static str> {
        Some("text_heuristics")
    }

    fn observe(&mut self, offset: u64, chunk: &[u8]) -> Result<()> {
        let mut window = Vec::with_capacity(self.carry.len() + chunk.len());
        window.extend_from_slice(&self.carry);
        window.extend_from_slice(chunk);
        let lower = String::from_utf8_lossy(&window).to_ascii_lowercase();

        if !self.is_doc && !self.is_vocab {
            for (needle, rule) in &self.dangerous {
                if self.seen_rules.contains(*rule) {
                    continue;
                }
                if lower.contains(needle) {
                    self.seen_rules.insert((*rule).to_owned());
                }
            }
        }

        for (needle, rule) in &self.jinja_needles {
            if self.seen_rules.contains(*rule) {
                continue;
            }
            if lower.contains(needle) {
                self.seen_rules.insert((*rule).to_owned());
            }
        }

        let consumed = window.len().saturating_sub(512);
        if consumed > 0 {
            let consumed_bytes = &window[..consumed];
            let newlines = consumed_bytes.iter().filter(|&&b| b == b'\n').count() as u64;
            self.window_start_line = self.window_start_line.saturating_add(newlines);
            self.window_start = offset
                .saturating_add(chunk.len() as u64)
                .saturating_sub((window.len() - consumed) as u64);
            self.carry = window[consumed..].to_vec();
        } else {
            self.carry = window;
        }

        Ok(())
    }

    fn finish(&mut self, digest: &str, _media_type: &str) -> Result<Vec<LayerScanResult>> {
        let subject = EvidenceSubject::member(&self.rel_path)
            .with_sha256(Some(digest.to_owned()))
            .with_media_type("application/vnd.layerfault.package-member");

        let rule_details = [
            (
                "LF-CODE-OS-SYSTEM",
                "Package text file contains 'os.system(' execution call",
                ScanStatus::Warn,
                FindingClass::ContentIndicator,
                Confidence::High,
            ),
            (
                "LF-CODE-SUBPROCESS",
                "Package text file contains subprocess execution call",
                ScanStatus::Warn,
                FindingClass::ContentIndicator,
                Confidence::High,
            ),
            (
                "LF-CODE-EVAL",
                "Package text file contains dynamic eval execution call",
                ScanStatus::Warn,
                FindingClass::ContentIndicator,
                Confidence::High,
            ),
            (
                "LF-CODE-EXEC",
                "Package text file contains dynamic exec execution call",
                ScanStatus::Warn,
                FindingClass::ContentIndicator,
                Confidence::High,
            ),
            (
                "LF-CODE-CTYPES",
                "Package text file contains native ctypes library load call",
                ScanStatus::Warn,
                FindingClass::ContentIndicator,
                Confidence::High,
            ),
            (
                "LF-CODE-NETWORK",
                "Package text file contains outbound network request code",
                ScanStatus::Warn,
                FindingClass::ContentIndicator,
                Confidence::High,
            ),
            (
                "LF-TEMPLATE-INTROSPECTION",
                "Jinja template contains Python introspection expression",
                ScanStatus::Warn,
                FindingClass::ContentIndicator,
                Confidence::High,
            ),
        ];

        for (rule, detail, status, class, conf) in rule_details {
            if self.seen_rules.contains(rule) {
                let f = FindingBuilder::new(rule, CheckType::PackageSecurity, status)
                    .class(class)
                    .confidence(conf)
                    .digest(digest)
                    .subject(subject.clone())
                    .detail(detail)
                    .evidence(file_member(
                        subject.clone(),
                        serde_json::json!({
                            "package_relative_path": self.rel_path,
                            "rule": rule,
                            "match": detail,
                        }),
                    ))
                    .finish();
                self.findings.push(f);
            }
        }

        Ok(std::mem::take(&mut self.findings))
    }
}

/// Plan for session execution determined by eligibility and cache availability.
#[derive(Debug, Clone)]
pub struct ScanPlan {
    pub cached_digest: Option<String>,
    pub cached_observer_results: Vec<Option<Vec<LayerScanResult>>>,
    pub needs_stream_pass: bool,
}

/// Single-pass scan session maintaining file identity, descriptors, and observer passes.
pub struct ScanSession<'a> {
    pub path: &'a Path,
    pub file: &'a File,
    pub size: u64,
    pub identity_before: FileIdentity,
    pub metrics: RefCell<ScanMetrics>,
}

impl<'a> ScanSession<'a> {
    /// Create a scan session for an opened file. Captures initial file identity.
    pub fn new(path: &'a Path, file: &'a File) -> Result<Self> {
        let identity_before = capture_identity(path, file)?;
        let size = identity_before.len();
        Ok(Self {
            path,
            file,
            size,
            identity_before,
            metrics: RefCell::new(ScanMetrics::default()),
        })
    }

    /// Evaluate cache eligibility and load available cached digest / observer evidence.
    pub fn plan(&self, observers: &[Box<dyn StreamObserver>]) -> Result<ScanPlan> {
        let mut cached_digest = None;
        let mut needs_digest = true;

        if digest_eligible(self.size) {
            if let Ok(outcome) = crate::hashcache::sha256_prefixed(self.path, self.file) {
                if outcome.cache_hit {
                    cached_digest = Some(outcome.sha256);
                    needs_digest = false;
                    self.metrics.borrow_mut().record_cache_hit();
                } else {
                    self.metrics.borrow_mut().record_cache_miss();
                }
            }
        }

        let mut cached_observer_results = Vec::with_capacity(observers.len());
        let mut missing_observer = false;

        for obs in observers {
            if let Some(disc) = obs.cache_discriminator() {
                if evidence_eligible(self.size) {
                    if let Ok(Some(results)) = load_evidence::<Vec<LayerScanResult>>(
                        "scan_session",
                        self.path,
                        self.file,
                        disc,
                    ) {
                        cached_observer_results.push(Some(results));
                        self.metrics.borrow_mut().record_cache_hit();
                        continue;
                    } else {
                        self.metrics.borrow_mut().record_cache_miss();
                    }
                }
            }
            cached_observer_results.push(None);
            missing_observer = true;
        }

        let needs_stream_pass = needs_digest || missing_observer;
        Ok(ScanPlan {
            cached_digest,
            cached_observer_results,
            needs_stream_pass,
        })
    }

    /// Run the plan and execute at most one physical sequential read pass for uncached analyses.
    pub fn run(
        &self,
        media_type: &str,
        mut observers: Vec<Box<dyn StreamObserver>>,
    ) -> Result<(String, Vec<LayerScanResult>)> {
        let plan = self.plan(&observers)?;

        let mut final_results = Vec::new();
        let mut active_indices = Vec::new();

        for (idx, cached) in plan.cached_observer_results.into_iter().enumerate() {
            if let Some(res) = cached {
                final_results.extend(res);
            } else {
                active_indices.push(idx);
            }
        }

        let digest =
            if let (false, Some(cached)) = (plan.needs_stream_pass, plan.cached_digest.as_ref()) {
                cached.clone()
            } else {
                // Need physical streaming read pass
                let mut reader = self.file.try_clone()?;
                reader.seek(SeekFrom::Start(0))?;

                let mut hasher = Sha256::new();
                let compute_digest = plan.cached_digest.is_none();
                let mut read_buf = vec![0_u8; STREAM_CHUNK_BYTES];
                let mut offset = 0_u64;

                self.metrics.borrow_mut().record_full_pass();

                loop {
                    let count = reader.read(&mut read_buf)?;
                    if count == 0 {
                        break;
                    }
                    let chunk = &read_buf[..count];
                    self.metrics
                        .borrow_mut()
                        .record_sequential_read(count as u64);

                    if compute_digest {
                        hasher.update(chunk);
                    }

                    for &idx in &active_indices {
                        observers[idx].observe(offset, chunk)?;
                    }

                    offset = offset.saturating_add(count as u64);
                }

                let calculated_digest = if let Some(cd) = plan.cached_digest {
                    cd
                } else {
                    let hex_str = hex::encode(hasher.finalize());
                    format!("sha256:{hex_str}")
                };

                // Complete active observers
                for &idx in &active_indices {
                    let obs_results = observers[idx].finish(&calculated_digest, media_type)?;
                    if let Some(disc) = observers[idx].cache_discriminator() {
                        if evidence_eligible(self.size) {
                            let _ = store_evidence(
                                "scan_session",
                                self.path,
                                self.file,
                                &self.identity_before,
                                disc,
                                &obs_results,
                            );
                        }
                    }
                    final_results.extend(obs_results);
                }

                calculated_digest
            };

        // Strict TOCTOU identity check
        let identity_after = capture_identity(self.path, self.file)?;
        if identity_after != self.identity_before {
            return Err(anyhow!(
                "File '{}' was modified during scan execution",
                self.path.display()
            ));
        }

        Ok((digest, final_results))
    }

    /// Record positional / random read bytes performed by structural parsers.
    pub fn record_random_read(&self, bytes: u64) {
        self.metrics.borrow_mut().record_random_read(bytes);
    }
}
