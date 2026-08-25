//! Bounded static pickle opcode analysis.
//!
//! Layerfault never unpickles or executes pickle content. This module only
//! disassembles the documented protocol 0-5 opcode stream far enough to resolve
//! GLOBAL/STACK_GLOBAL references and dangerous construction primitives.

use crate::assurance::{parser_differential, AnalysisCompleteness};
use crate::finding_evidence::{
    byte_range_evidence, serialization_opcode, EvidenceSubject, FindingBuilder,
};
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use anyhow::{anyhow, bail, Context, Result};
use flate2::read::{GzDecoder, ZlibDecoder};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::Path;
use std::time::Instant;

const MAX_PICKLE_MEMBERS: usize = 256;
const MAX_JOBLIB_FRAME_CANDIDATES: usize = 4_096;
/// Caps how many `JoblibOpaqueRegion` diagnostic entries are retained per
/// stream, bounding memory for pathological inputs with many arrays; this
/// only limits diagnostic detail, not the completeness verdict itself.
const MAX_JOBLIB_OPAQUE_REGIONS_TRACKED: usize = 64;
const MAX_PICKLE_MEMBER_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TOTAL_PICKLE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_DIFFERENTIAL_BYTES: u64 = 32 * 1024 * 1024;
const MAX_PRIMARY_TRANSCRIPT_OPCODES: usize = 262_144;
const MAX_ARGUMENT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_TRACKED_STRING_BYTES: u64 = 1024 * 1024;
const MAX_OPCODES: usize = 2_000_000;
const MAX_STACK: usize = 262_144;
const MAX_MEMO: usize = 262_144;

const ALLOWLIST_PREFIXES: &[&str] = &[
    "torch._utils._rebuild_tensor",
    "torch._utils._rebuild_parameter",
    "torch.storage.",
    "torch.Tensor",
    "torch.nn.parameter.Parameter",
    "collections.OrderedDict",
    "numpy.core.multiarray.",
    "numpy._core.multiarray.",
    "numpy.dtype",
    "numpy.ndarray",
    "joblib.numpy_pickle.",
    "sklearn.utils._bunch.Bunch",
];

const SAFE_VALUE_CONSTRUCTORS: &[&str] = &[
    "_codecs.encode",
    "argparse.Namespace",
    "signal.Signals",
    "miles.utils.eval_config.EvalDatasetConfig",
    // These are data-only checkpoint constructors seen in standard PyTorch
    // and Transformers training artefacts. They are deliberately exact names;
    // arbitrary application classes and executable primitives remain unknown
    // or dangerous rather than being covered by a broad framework prefix.
    "torch.device",
    "torch.FloatStorage",
    "torch.nn.modules.activation.SiLU",
    "torch.nn.modules.activation.ReLU",
    "torch.nn.modules.batchnorm.BatchNorm2d",
    "torch.nn.modules.container.ModuleList",
    "torch.nn.modules.container.Sequential",
    "torch.nn.modules.conv.Conv2d",
    "torch.nn.modules.linear.Linear",
    "torch.nn.modules.pooling.MaxPool2d",
    "torch.nn.modules.upsampling.Upsample",
    "transformers.training_args.TrainingArguments",
    "transformers.training_args.OptimizerNames",
    "transformers.trainer_utils.IntervalStrategy",
    "transformers.trainer_utils.SchedulerType",
];

const SAFE_VALUE_CONSTRUCTOR_PREFIXES: &[&str] = &[
    "__torch__.",
    "megatron.core.enums.",
    "megatron.core.transformer.enums.",
    "peft.utils.peft_types.",
];

const SAFE_BUILTINS: &[&str] = &[
    "builtins.dict",
    "builtins.list",
    "builtins.tuple",
    "builtins.set",
    "builtins.frozenset",
    "builtins.int",
    "builtins.float",
    "builtins.str",
    "builtins.bytes",
    "builtins.bytearray",
    "builtins.bool",
    "__builtin__.dict",
    "__builtin__.list",
    "__builtin__.tuple",
    "__builtin__.set",
    "__builtin__.frozenset",
    "__builtin__.int",
    "__builtin__.float",
    "__builtin__.str",
    "__builtin__.bytes",
    "__builtin__.bytearray",
    "__builtin__.bool",
];

const DANGEROUS_EXACT: &[&str] = &[
    "builtins.eval",
    "builtins.exec",
    "builtins.compile",
    "builtins.__import__",
    "__builtin__.eval",
    "__builtin__.exec",
    "__builtin__.compile",
    "__builtin__.__import__",
    "os.system",
    "os.popen",
    "posix.system",
    "nt.system",
    "pty.spawn",
];

/// Maximum opcode sites retained as evidence from one stream.
const MAX_OPCODE_SITES: usize = 64;

/// Where in the opcode stream a security-relevant reference was resolved.
///
/// This comes solely from the bounded static disassembler. Layerfault never
/// deserializes the stream to obtain it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpcodeSite {
    /// The recorded entry, matching the corresponding `dangerous`/`globals` set item.
    pub entry: String,
    /// Mnemonic of the opcode that produced the entry.
    pub opcode: &'static str,
    /// 1-based index of that opcode within the stream.
    pub opcode_index: u64,
    /// Byte offset of that opcode within the stream.
    pub byte_offset: u64,
}

#[derive(Debug, Clone)]
pub struct PickleAnalysis {
    pub completeness: AnalysisCompleteness,
    pub unresolved_execution: Vec<UnresolvedExecutionPrimitive>,
    pub persistent_ids: Vec<OpcodeSite>,
    pub globals: BTreeSet<String>,
    pub unknown_globals: BTreeSet<String>,
    pub dangerous: BTreeSet<String>,
    pub opcode_count: usize,
    /// Bounded, ordered positions for the entries above.
    pub sites: Vec<OpcodeSite>,
    /// Joblib raw-array regions that could not be exactly sized and were
    /// instead resynchronized by heuristic FRAME search. Diagnostic detail
    /// for `LF-PICKLE-OPAQUE-COMPRESSED`, not itself a security signal.
    pub joblib_opaque_regions: Vec<JoblibOpaqueRegion>,
}

/// One raw-array region a Joblib pickle stream's exact-computation path
/// (`resolve_joblib_raw_array_region`)
/// declined, naming the byte offset and the construct/reason so the
/// resulting finding can point at exactly where and why coverage narrowed,
/// instead of a generic "could not be parsed completely".
#[derive(Debug, Clone)]
pub struct JoblibOpaqueRegion {
    pub byte_offset: u64,
    pub detail: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UnresolvedExecutionPrimitive {
    pub opcode: String,
    pub byte_offset: u64,
    pub reason: String,
}

impl Default for PickleAnalysis {
    fn default() -> Self {
        Self {
            completeness: AnalysisCompleteness::Complete,
            unresolved_execution: Vec::new(),
            persistent_ids: Vec::new(),
            globals: BTreeSet::new(),
            unknown_globals: BTreeSet::new(),
            dangerous: BTreeSet::new(),
            opcode_count: 0,
            sites: Vec::new(),
            joblib_opaque_regions: Vec::new(),
        }
    }
}

impl PickleAnalysis {
    /// The first recorded position for a set entry, if one was captured.
    pub fn site_for(&self, entry: &str) -> Option<&OpcodeSite> {
        self.sites.iter().find(|site| site.entry == entry)
    }
}

#[derive(Debug, Clone)]
enum StackValue {
    Str(String),
    Global(String),
    Constructed(String),
    Mark,
    Int(i64),
    Bool(bool),
    /// A small tuple whose elements are all simple scalars (no nesting).
    /// Only built for short tuples (protocol TUPLE1/2/3 or a small
    /// MARK-delimited TUPLE); used to recover Joblib NumPy array metadata
    /// (shape dims, dtype constructor args) without generally tracking
    /// arbitrary pickle container contents.
    SmallTuple(Vec<ScalarValue>),
    /// The result of a resolved `numpy.dtype(descr, ...)` REDUCE, carrying
    /// its descriptor string. Represented distinctly from `Constructed` (and
    /// not just discarded like other REDUCE args) specifically so the
    /// descriptor survives pickle memoization: Joblib memoizes a shared
    /// dtype object once and reuses it via GET across every array of that
    /// dtype, and since MEMOIZE/GET simply clone whichever `StackValue` was
    /// stored, cloning this variant carries the descriptor along for free.
    NumpyDtype(String),
    Other,
}

#[derive(Debug, Clone)]
enum ScalarValue {
    Str(String),
    Int(i64),
    /// The boolean's truth value isn't needed by any current caller — only
    /// that a tuple slot held a bool, so the tuple as a whole still
    /// qualifies as a `SmallTuple` (see `small_tuple_or_other`) instead of
    /// collapsing to `Other`.
    Bool,
}

impl ScalarValue {
    fn from_stack_value(value: &StackValue) -> Option<ScalarValue> {
        match value {
            StackValue::Str(s) => Some(ScalarValue::Str(s.clone())),
            StackValue::Int(n) => Some(ScalarValue::Int(*n)),
            StackValue::Bool(_) => Some(ScalarValue::Bool),
            _ => None,
        }
    }

    fn as_int(&self) -> Option<i64> {
        match self {
            ScalarValue::Int(n) => Some(*n),
            _ => None,
        }
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            ScalarValue::Str(s) => Some(s),
            _ => None,
        }
    }
}

/// Metadata recovered from a Joblib `NumpyArrayWrapper`'s pickled state
/// dict, sufficient to compute the exact byte extent of its raw array
/// region (which is written directly to the stream outside pickle opcodes,
/// see `resolve_joblib_raw_array_region`).
#[derive(Debug, Clone, Default)]
struct JoblibArrayMeta {
    shape: Option<Vec<i64>>,
    descr: Option<String>,
    allow_mmap: Option<bool>,
    alignment_bytes: Option<i64>,
}

pub fn scan(
    path: &Path,
    file: &File,
    size: u64,
    identity: &str,
    media: &str,
    budget: &crate::budget::ScanBudget,
) -> Result<Vec<LayerScanResult>> {
    let mut magic = [0u8; 4];
    let mut prefix = file.try_clone()?;
    prefix.seek(SeekFrom::Start(0))?;
    let count = prefix.read(&mut magic)?;
    if count >= 4 && magic == *b"PK\x03\x04" {
        return Ok(match scan_zip(path, file, identity, media, budget) {
            Ok(results) => results,
            Err(error) => vec![FindingBuilder::new(
                "LF-PICKLE-MALFORMED",
                CheckType::PickleStructure,
                ScanStatus::Fail,
            )
            .class(FindingClass::Structural)
            .confidence(Confidence::High)
            .digest(identity)
            .media_type(media)
            .subject(EvidenceSubject::identity(identity, media).with_sha256(Some(identity.to_owned())))
            .detail(format!("Malformed or unsafe pickle ZIP container: {error}"))
            .match_note(error.to_string())
            .evidence_unavailable(
                "the ZIP container could not be opened, so no member or byte offset could be attributed",
            )
            .finish()],
        });
    }
    if count >= 2 && magic[0] == 0x1f && magic[1] == 0x8b {
        return Ok(match scan_gzip(path, file, identity, media, budget) {
            Ok(results) => results,
            Err(error) => vec![FindingBuilder::new(
                "LF-PICKLE-MALFORMED",
                CheckType::PickleStructure,
                ScanStatus::Fail,
            )
            .class(FindingClass::Structural)
            .confidence(Confidence::High)
            .digest(identity)
            .media_type(media)
            .subject(EvidenceSubject::identity(identity, media).with_sha256(Some(identity.to_owned())))
            .detail(format!("Malformed or unsafe gzip-compressed pickle stream: {error}"))
            .match_note(error.to_string())
            .evidence_unavailable(
                "the gzip stream could not be decompressed, so no member or byte offset could be attributed",
            )
            .finish()],
        });
    }
    if count >= 2 && looks_like_zlib(&magic[..2]) {
        return Ok(match scan_zlib(path, file, identity, media, budget) {
            Ok(results) => results,
            Err(error) => vec![opaque_compressed_finding(
                identity,
                media,
                format!("raw zlib-compressed pickle stream could not be inspected: {error}"),
            )],
        });
    }
    let mut results = vec![scan_stream(
        file.try_clone()?,
        size,
        identity,
        media,
        None,
        budget,
    )];
    results.extend(parser_differential_scan(
        file, size, identity, media, budget,
    ));
    Ok(results)
}

/// A raw zlib-compressed pickle/joblib stream. Joblib's default compressor
/// writes this envelope directly (without a gzip header), so treating its
/// leading `0x78` byte as a pickle opcode produces a false malformed-stream
/// BLOCK. Decompress and analyze the actual opcode stream under the same
/// bounded resource accounting used for archive members.
fn scan_zlib(
    path: &Path,
    file: &File,
    identity: &str,
    media: &str,
    budget: &crate::budget::ScanBudget,
) -> Result<Vec<LayerScanResult>> {
    let compressed_len = file.metadata()?.len();
    if compressed_len < 6 {
        bail!("raw zlib stream is truncated before its checksum");
    }
    let mut trailer_reader = file.try_clone()?;
    trailer_reader.seek(SeekFrom::End(-4))?;
    let mut trailer = [0u8; 4];
    trailer_reader.read_exact(&mut trailer)?;

    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let bytes = read_bounded_decompressed(
        ZlibDecoder::new(reader),
        "raw zlib-compressed pickle stream",
    )?;
    let expected_checksum = u32::from_be_bytes(trailer);
    let actual_checksum = adler32(&bytes);
    if actual_checksum != expected_checksum {
        bail!(
            "raw zlib stream checksum mismatch (expected {expected_checksum:08x}, got {actual_checksum:08x})"
        );
    }
    scan_decompressed_pickle(
        bytes,
        identity,
        media,
        budget,
        "raw zlib-compressed pickle stream",
        is_joblib_path(path),
    )
}

fn adler32(bytes: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65_521;
    let mut a = 1u32;
    let mut b = 0u32;
    for chunk in bytes.chunks(5_552) {
        for byte in chunk {
            a += u32::from(*byte);
            b += a;
        }
        a %= MOD_ADLER;
        b %= MOD_ADLER;
    }
    (b << 16) | a
}

fn scan_decompressed_pickle(
    bytes: Vec<u8>,
    identity: &str,
    media: &str,
    budget: &crate::budget::ScanBudget,
    operation: &str,
    joblib_framing: bool,
) -> Result<Vec<LayerScanResult>> {
    budget
        .consume(
            crate::budget::BudgetDimension::DecompressedBytes,
            bytes.len() as u64,
            operation,
        )
        .map_err(|error| anyhow!("decompressed-bytes budget exhausted: {error}"))?;
    let len = bytes.len() as u64;
    let mut results = if joblib_framing {
        scan_joblib_stream(&bytes, identity, media, budget)
    } else {
        vec![scan_stream(
            Cursor::new(bytes.as_slice()),
            len,
            identity,
            media,
            None,
            budget,
        )]
    };
    if !joblib_framing {
        results.extend(parser_differential_bytes(
            &bytes, identity, media, None, budget,
        ));
    }
    Ok(results)
}

fn is_joblib_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.to_ascii_lowercase().contains(".joblib"))
}

fn scan_joblib_stream(
    bytes: &[u8],
    identity: &str,
    media: &str,
    budget: &crate::budget::ScanBudget,
) -> Vec<LayerScanResult> {
    let subject = pickle_subject(identity, media, None);
    let started = Instant::now();
    match analyze_reader_inner(
        Cursor::new(bytes),
        bytes.len() as u64,
        Some(budget),
        None,
        true,
    ) {
        Ok(analysis) => {
            let partial = analysis.completeness == AnalysisCompleteness::Partial;
            let opaque_regions = analysis.joblib_opaque_regions.clone();
            let mut results = vec![finding_from_analysis(
                analysis,
                identity,
                media,
                "joblib pickle stream",
                subject,
                started,
            )];
            if partial {
                results.push(opaque_joblib_regions_finding(
                    identity,
                    media,
                    &opaque_regions,
                ));
            }
            results
        }
        Err(error) => vec![malformed_pickle_finding(
            identity,
            media,
            "joblib pickle stream",
            subject,
            error,
            started,
        )],
    }
}

fn opaque_joblib_regions_finding(
    identity: &str,
    media: &str,
    regions: &[JoblibOpaqueRegion],
) -> LayerScanResult {
    let detail = match regions {
        [] => {
            // Defensive fallback: completeness was marked Partial by some
            // path that didn't record a region (shouldn't happen for the
            // joblib array-region resync path, which always records one).
            "Joblib opcode segments were analyzed, but embedded NumPy array regions are data-framed outside the pickle opcode stream".to_owned()
        }
        [one] => one.detail.clone(),
        many => format!(
            "{} joblib raw NumPy array regions could not be exactly sized and were resynchronized via heuristic FRAME search: {}",
            many.len(),
            many.iter()
                .map(|region| format!("byte offset {}", region.byte_offset))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    };
    let match_note = regions
        .first()
        .map(|region| region.detail.clone())
        .unwrap_or_else(|| {
            "joblib NumPy array data regions required bounded frame resynchronization".to_owned()
        });

    FindingBuilder::new(
        "LF-PICKLE-OPAQUE-COMPRESSED",
        CheckType::PickleStructure,
        ScanStatus::Warn,
    )
    .class(FindingClass::Compatibility)
    .confidence(Confidence::High)
    .digest(identity)
    .media_type(media)
    .subject(EvidenceSubject::identity(identity, media).with_sha256(Some(identity.to_owned())))
    .detail(detail)
    .match_note(match_note)
    .evidence_unavailable(
        "the opaque regions are raw array data rather than pickle opcodes; surrounding opcode segments were still analyzed",
    )
    .finish()
}

fn opaque_compressed_finding(identity: &str, media: &str, reason: String) -> LayerScanResult {
    FindingBuilder::new(
        "LF-PICKLE-OPAQUE-COMPRESSED",
        CheckType::PickleStructure,
        ScanStatus::Warn,
    )
    .class(FindingClass::Compatibility)
    .confidence(Confidence::High)
    .digest(identity)
    .media_type(media)
    .subject(EvidenceSubject::identity(identity, media).with_sha256(Some(identity.to_owned())))
    .detail(format!(
        "Compressed pickle/joblib content could not be inspected safely: {reason}"
    ))
    .match_note(reason)
    .evidence_unavailable(
        "the compressed stream could not be decoded within the configured bounds, so no pickle opcode could be attributed",
    )
    .finish()
}

/// A gzip-compressed pickle/joblib stream. Some producers use gzip directly,
/// and legacy/nested packages can additionally wrap zlib underneath (for
/// example `gzip(zlib(pickle))`). Decompress transparently, bounded by
/// [`MAX_PICKLE_MEMBER_BYTES`], so real pickle opcode evidence is produced
/// instead of failing to parse compressed bytes as if they were raw pickle.
fn scan_gzip(
    path: &Path,
    file: &File,
    identity: &str,
    media: &str,
    budget: &crate::budget::ScanBudget,
) -> Result<Vec<LayerScanResult>> {
    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let decompressed =
        read_bounded_decompressed(GzDecoder::new(reader), "gzip-compressed pickle stream")?;
    let bytes = if decompressed.len() >= 2 && looks_like_zlib(&decompressed[..2]) {
        read_bounded_decompressed(
            ZlibDecoder::new(Cursor::new(decompressed)),
            "zlib-compressed pickle stream",
        )?
    } else {
        decompressed
    };
    scan_decompressed_pickle(
        bytes,
        identity,
        media,
        budget,
        "gzip-compressed pickle stream",
        is_joblib_path(path),
    )
}

fn looks_like_zlib(head: &[u8]) -> bool {
    head.len() == 2
        && head[0] & 0x0f == 8
        && (u16::from(head[0]) * 256 + u16::from(head[1])) % 31 == 0
}

fn read_bounded_decompressed<R: Read>(mut reader: R, label: &str) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() as u64 > MAX_PICKLE_MEMBER_BYTES {
            bail!("{label} exceeds the {MAX_PICKLE_MEMBER_BYTES} byte decompression bound");
        }
    }
    Ok(buf)
}

/// Run the parser differential over a plain (non-ZIP) pickle stream and
/// return a finding if the outcome is security-relevant. Bounded by the same
/// total-size cap as the rest of this module; streams beyond that cap are
/// reported as assurance-incomplete rather than silently skipped, so a
/// coverage gap remains visible rather than disappearing.
fn parser_differential_scan(
    file: &File,
    size: u64,
    identity: &str,
    media: &str,
    budget: &crate::budget::ScanBudget,
) -> Option<LayerScanResult> {
    let subject = pickle_subject(identity, media, None);
    if size > MAX_DIFFERENTIAL_BYTES {
        return Some(assurance_incomplete_finding(
            subject,
            None,
            "stream exceeds the parser differential's bounded analysis size".to_owned(),
        ));
    }
    let bytes = match crate::safeio::read_all_from_file(file, MAX_DIFFERENTIAL_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            return Some(assurance_incomplete_finding(
                subject,
                None,
                format!("the stream could not be read for differential analysis: {error}"),
            ))
        }
    };
    parser_differential_bytes(&bytes, identity, media, None, budget)
}

fn parser_differential_bytes(
    bytes: &[u8],
    identity: &str,
    media: &str,
    member: Option<&str>,
    budget: &crate::budget::ScanBudget,
) -> Option<LayerScanResult> {
    let subject = pickle_subject(identity, media, member);
    if bytes.len() as u64 > MAX_DIFFERENTIAL_BYTES {
        return Some(assurance_incomplete_finding(
            subject,
            None,
            "stream exceeds the parser differential's bounded analysis size".to_owned(),
        ));
    }
    let outcome = parser_differential_outcome(bytes, Some(budget));
    parser_differential_finding(outcome, subject)
}

pub fn analyze_bytes(bytes: &[u8]) -> Result<PickleAnalysis> {
    let cursor = Cursor::new(bytes);
    analyze_reader(cursor, bytes.len() as u64, None)
}

fn scan_stream<R: Read + Seek>(
    reader: R,
    len: u64,
    identity: &str,
    media: &str,
    member: Option<&str>,
    budget: &crate::budget::ScanBudget,
) -> LayerScanResult {
    let started = Instant::now();
    let label = member
        .map(|name| format!("pickle member '{name}'"))
        .unwrap_or_else(|| "pickle stream".to_owned());
    let subject = pickle_subject(identity, media, member);
    match analyze_reader(reader, len, Some(budget)) {
        Ok(analysis) => finding_from_analysis(analysis, identity, media, &label, subject, started),
        Err(error) => malformed_pickle_finding(identity, media, &label, subject, error, started),
    }
}

fn malformed_pickle_finding(
    identity: &str,
    media: &str,
    label: &str,
    subject: EvidenceSubject,
    error: anyhow::Error,
    started: Instant,
) -> LayerScanResult {
    let offset = pickle_error_offset(&error);
    let mut builder = FindingBuilder::new(
        "LF-PICKLE-MALFORMED",
        CheckType::PickleStructure,
        ScanStatus::Fail,
    )
    .class(FindingClass::Structural)
    .confidence(Confidence::High)
    .digest(identity)
    .media_type(media)
    .subject(subject.clone())
    .detail(format!("Malformed or unsafe {label}: {error}"))
    .match_note(format!("bounded pickle opcode parsing failed for {label}"))
    .started(started);
    builder = match offset {
        Some(offset) => builder.evidence(byte_range_evidence(
            subject,
            offset,
            1,
            "Parsing failed at this byte offset in the opcode stream",
        )),
        None => builder.evidence_unavailable(
            "the parser rejected the stream before a specific byte offset could be attributed",
        ),
    };
    builder.finish()
}

/// Best-effort extraction of the byte offset embedded in a parser error
/// message, so `LF-PICKLE-MALFORMED` can report where parsing stopped without
/// plumbing a typed offset through every one of the disassembler's `bail!`s.
fn pickle_error_offset(error: &anyhow::Error) -> Option<u64> {
    let text = error.to_string();
    let marker = "at offset ";
    let start = text.find(marker)? + marker.len();
    let digits: String = text[start..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

fn pickle_subject(identity: &str, media: &str, member: Option<&str>) -> EvidenceSubject {
    let mut subject =
        EvidenceSubject::identity(identity, media).with_sha256(Some(identity.to_owned()));
    if let Some(name) = member {
        subject.package_relative_path = Some(name.to_owned());
    }
    subject
}

fn finding_from_analysis(
    analysis: PickleAnalysis,
    identity: &str,
    media: &str,
    label: &str,
    subject: EvidenceSubject,
    started: Instant,
) -> LayerScanResult {
    let globals = analysis.globals.iter().cloned().collect::<Vec<_>>();
    let dangerous = analysis.dangerous.iter().cloned().collect::<Vec<_>>();
    let unknown = analysis.unknown_globals.iter().cloned().collect::<Vec<_>>();
    if !dangerous.is_empty() {
        let mut builder = FindingBuilder::new(
            "LF-PICKLE-DANGEROUS-GLOBAL",
            CheckType::PickleStructure,
            ScanStatus::Fail,
        )
        .class(FindingClass::ContentIndicator)
        .confidence(Confidence::High)
        .digest(identity)
        .media_type(media)
        .subject(subject.clone())
        .detail(format!(
            "{label} references dangerous or untrusted callable(s): {}",
            dangerous.join(", ")
        ))
        .match_note(dangerous.first().cloned().unwrap_or_default())
        .started(started);
        for value in &dangerous {
            builder = builder.evidence(opcode_evidence(&subject, &analysis, value));
        }
        return builder.finish();
    }
    if !analysis.persistent_ids.is_empty() {
        let first_entry = analysis.persistent_ids[0].entry.clone();
        let mut builder = FindingBuilder::new(
            "LF-PICKLE-PERSISTENT-ID",
            CheckType::ScannerAssurance,
            ScanStatus::Warn,
        )
        .class(FindingClass::Structural)
        .confidence(Confidence::High)
        .digest(identity)
        .media_type(media)
        .subject(subject.clone())
        .detail(format!(
            "{label} contains persistent ID opcode(s) (PERSID/BINPERSID); persistent ID resolution is application-defined and requires resolver-aware review"
        ))
        .match_note(format!("persistent ID opcode observed: {first_entry}"))
        .started(started);
        for site in &analysis.persistent_ids {
            builder = builder.evidence(serialization_opcode(
                subject.clone(),
                site.opcode_index,
                site.byte_offset,
                serde_json::json!({
                    "opcode": site.opcode,
                    "entry": site.entry,
                }),
            ));
        }
        return builder.finish();
    }
    if !analysis.unresolved_execution.is_empty() {
        return FindingBuilder::new(
            "LF-ASSURANCE-PICKLE-UNRESOLVED-EXECUTION",
            CheckType::ScannerAssurance,
            ScanStatus::Fail,
        )
        .class(FindingClass::Structural)
        .confidence(Confidence::High)
        .digest(identity)
        .media_type(media)
        .subject(subject)
        .detail(format!(
            "{label} contains execution-capable pickle primitives that could not be fully resolved"
        ))
        .match_note(analysis.unresolved_execution[0].reason.clone())
        .started(started)
        .finish();
    }
    if !unknown.is_empty() {
        let mut builder = FindingBuilder::new(
            "LF-PICKLE-UNKNOWN-GLOBAL",
            CheckType::PickleStructure,
            ScanStatus::Warn,
        )
        .class(FindingClass::ContentIndicator)
        .confidence(Confidence::High)
        .digest(identity)
        .media_type(media)
        .subject(subject.clone())
        .detail(format!(
            "{label} contains unrecognized pickle global(s); review before trusting: {}",
            unknown.join(", ")
        ))
        .match_note(unknown.first().cloned().unwrap_or_default())
        .started(started);
        for value in &unknown {
            builder = builder.evidence(opcode_evidence(&subject, &analysis, value));
        }
        return builder.finish();
    }
    FindingBuilder::new(
        "LF-PICKLE-SAFE-GLOBALS",
        CheckType::PickleStructure,
        ScanStatus::Pass,
    )
    .class(FindingClass::Structural)
    .confidence(Confidence::High)
    .digest(identity)
    .media_type(media)
    .subject(subject)
    .detail(format!(
        "{label} opcode stream validated; {} opcode(s), allowlisted globals: {}",
        analysis.opcode_count,
        if globals.is_empty() {
            "none".to_owned()
        } else {
            globals.join(", ")
        }
    ))
    .match_note(if globals.is_empty() {
        "no GLOBAL/STACK_GLOBAL references".to_owned()
    } else {
        globals.join(", ")
    })
    .evidence_not_applicable()
    .started(started)
    .finish()
}

/// Build the static-opcode evidence record for one resolved global/callable.
///
/// Falls back to an explicit unavailable reason if a position was not
/// captured for the entry (e.g. the bounded site table was already full for
/// this stream) rather than fabricating one.
fn opcode_evidence(
    subject: &EvidenceSubject,
    analysis: &PickleAnalysis,
    entry: &str,
) -> crate::finding_evidence::FindingEvidence {
    match analysis.site_for(entry) {
        Some(site) => serialization_opcode(
            subject.clone(),
            site.opcode_index,
            site.byte_offset,
            serde_json::json!({
                "global": entry,
                "opcode": site.opcode,
            }),
        ),
        None => crate::finding_evidence::FindingEvidence::new(
            crate::finding_evidence::EvidenceKind::SerializationOpcode,
            subject.clone(),
            "Static opcode analysis resolved this reference, but its exact position was not retained",
        )
        .structured(serde_json::json!({ "global": entry })),
    }
}

fn scan_zip(
    path: &Path,
    file: &File,
    identity: &str,
    media: &str,
    budget: &crate::budget::ScanBudget,
) -> Result<Vec<LayerScanResult>> {
    let started = Instant::now();
    let mut archive =
        zip::ZipArchive::new(file.try_clone()?).context("invalid PyTorch/joblib ZIP container")?;
    if archive.len() > 16_384 {
        bail!("pickle ZIP container has too many members");
    }
    let mut results = Vec::new();
    let mut total = 0u64;
    let mut pickle_members = 0usize;
    for index in 0..archive.len() {
        budget
            .check()
            .map_err(|error| anyhow!("global scan budget exhausted: {error}"))?;
        let mut member = archive.by_index(index)?;
        let name = member.name().replace('\\', "/");
        validate_zip_member_name(&name)?;
        if member
            .unix_mode()
            .is_some_and(|mode| mode & 0o170000 == 0o120000)
        {
            bail!("pickle ZIP container contains symlink member '{name}'");
        }
        if !name.to_ascii_lowercase().ends_with(".pkl") {
            continue;
        }
        pickle_members = pickle_members.saturating_add(1);
        if pickle_members > MAX_PICKLE_MEMBERS {
            bail!("pickle ZIP container exceeds member analysis cap");
        }
        let len = member.size();
        if len > MAX_PICKLE_MEMBER_BYTES {
            bail!("pickle member '{name}' exceeds bounded decompressed-size cap");
        }
        total = total
            .checked_add(len)
            .ok_or_else(|| anyhow!("pickle ZIP decompressed-size overflow"))?;
        if total > MAX_TOTAL_PICKLE_BYTES {
            bail!("pickle ZIP exceeds total decompressed pickle-byte cap");
        }
        budget
            .consume(
                crate::budget::BudgetDimension::DecompressedBytes,
                len,
                &format!("pickle member '{name}'"),
            )
            .map_err(|error| {
                anyhow!("pickle member '{name}' would exceed decompressed-bytes budget: {error}")
            })?;
        let capacity = usize::try_from(len).context("pickle member size does not fit usize")?;
        let mut bytes = Vec::with_capacity(capacity);
        member
            .by_ref()
            .take(len.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 != len {
            bail!("pickle ZIP member '{name}' changed/truncated while reading");
        }
        results.push(scan_stream(
            Cursor::new(bytes.as_slice()),
            len,
            identity,
            media,
            Some(&name),
            budget,
        ));
        results.extend(parser_differential_bytes(
            &bytes,
            identity,
            media,
            Some(&name),
            budget,
        ));
    }
    if results.is_empty() {
        results.push(
            FindingBuilder::new(
                "LF-PICKLE-OPAQUE-CONTAINER",
                CheckType::PickleStructure,
                ScanStatus::Warn,
            )
            .class(FindingClass::Compatibility)
            .confidence(Confidence::High)
            .digest(identity)
            .media_type(media)
            .subject(
                EvidenceSubject::identity(identity, media).with_sha256(Some(identity.to_owned())),
            )
            .detail(format!(
                "PyTorch-style ZIP '{}' contains no .pkl member that Layerfault can opcode-analyze",
                path.display()
            ))
            .match_note(
                "ZIP serialization container contains no analyzable pickle member".to_owned(),
            )
            .evidence_unavailable(
                "opacity is the finding: no .pkl member exists to attribute evidence to",
            )
            .started(started)
            .finish(),
        );
    }
    Ok(results)
}

fn validate_zip_member_name(name: &str) -> Result<()> {
    crate::safeio::validated_relative_path(name, false)
        .map_err(|_| anyhow::anyhow!("unsafe pickle ZIP member path '{name}'"))?;
    Ok(())
}

/// Human-readable mnemonic for an opcode byte, used only as evidence labelling.
fn opcode_mnemonic(opcode: u8) -> &'static str {
    match opcode {
        b'c' => "GLOBAL",
        b'i' => "INST",
        0x93 => "STACK_GLOBAL",
        b'R' => "REDUCE",
        b'b' => "BUILD",
        b'o' => "OBJ",
        0x81 => "NEWOBJ",
        0x92 => "NEWOBJ_EX",
        0x80 => "PROTO",
        0x95 => "FRAME",
        _ => "OPCODE",
    }
}

pub(crate) fn analyze_reader<R: Read + Seek>(
    reader: R,
    len: u64,
    budget: Option<&crate::budget::ScanBudget>,
) -> Result<PickleAnalysis> {
    analyze_reader_inner(reader, len, budget, None, false)
}

/// Core decode loop shared by every caller of `analyze_reader`. `transcript`,
/// when `Some`, additionally captures a canonical structural transcript
/// entry for every opcode processed (including STOP), for parser-
/// differential comparison in `crate::assurance::parser_differential`. This
/// is a localized addition to the existing loop: normal scan callers pass
/// `None` and see no behavior change.
fn analyze_reader_inner<R: Read + Seek>(
    mut reader: R,
    len: u64,
    budget: Option<&crate::budget::ScanBudget>,
    mut transcript: Option<&mut Vec<parser_differential::TranscriptEntry>>,
    joblib_framing: bool,
) -> Result<PickleAnalysis> {
    if len == 0 {
        bail!("empty pickle stream");
    }
    reader.seek(SeekFrom::Start(0))?;
    let mut state = ParserState::default();
    let mut pos = 0u64;
    let mut saw_stop = false;
    while pos < len {
        state.analysis.opcode_count = state.analysis.opcode_count.saturating_add(1);
        if state.analysis.opcode_count > MAX_OPCODES {
            bail!("pickle opcode count exceeds safety cap");
        }
        if state.analysis.opcode_count % 256 == 0 {
            if let Some(budget) = budget {
                budget
                    .check()
                    .map_err(|error| anyhow!("global scan budget exhausted: {error}"))?;
            }
        }
        // Record where this opcode starts before consuming its byte, so any
        // dangerous/unknown entry it produces can be attributed to this exact
        // position rather than wherever the cursor ends up after its operands.
        state.current_offset = pos;
        if joblib_framing
            && matches!(
                state.stack.last(),
                Some(StackValue::Constructed(name))
                    if name == "joblib.numpy_pickle.NumpyArrayWrapper"
            )
        {
            // A joblib `NumpyArrayWrapper` is immediately followed by raw
            // array bytes written outside the pickle opcode stream, not by
            // another opcode. Those bytes commonly start with `\x93NUMPY`,
            // whose first byte is indistinguishable from the STACK_GLOBAL
            // opcode; checked structurally here, before ordinary opcode
            // dispatch would misinterpret it.
            let meta = state.last_array_meta.take();
            let region_end = match meta {
                Some(meta) => resolve_joblib_raw_array_region(&meta, &mut reader, pos, len)?,
                None => None,
            };
            if let Some(region_end) = region_end {
                state.pop();
                state.push(StackValue::Other)?;
                reader.seek(SeekFrom::Start(region_end))?;
                pos = region_end;
                continue;
            }
        }
        let opcode = read_u8(&mut reader, &mut pos, len)?;
        state.current_opcode = opcode_mnemonic(opcode);
        match opcode {
            b'I' | b'L' | b'F' => {
                skip_line(&mut reader, &mut pos, len, MAX_TRACKED_STRING_BYTES)?;
                state.push(StackValue::Other)?;
            }
            b'J' => {
                let value = read_i32(&mut reader, &mut pos, len)?;
                state.push(StackValue::Int(i64::from(value)))?;
            }
            b'K' => {
                let value = read_u8(&mut reader, &mut pos, len)?;
                state.push(StackValue::Int(i64::from(value)))?;
            }
            b'M' => {
                let mut bytes = [0u8; 2];
                require_remaining(pos, len, bytes.len() as u64)?;
                reader.read_exact(&mut bytes)?;
                pos += bytes.len() as u64;
                state.push(StackValue::Int(i64::from(u16::from_le_bytes(bytes))))?;
            }
            0x8a => {
                let n = u64::from(read_u8(&mut reader, &mut pos, len)?);
                let value = read_small_signed_long(&mut reader, &mut pos, len, n)?;
                state.push(value.map(StackValue::Int).unwrap_or(StackValue::Other))?;
            }
            0x8b => {
                let n = u64::from(read_u32(&mut reader, &mut pos, len)?);
                let value = read_small_signed_long(&mut reader, &mut pos, len, n)?;
                state.push(value.map(StackValue::Int).unwrap_or(StackValue::Other))?;
            }
            b'S' | b'V' => {
                let value = read_line_string(&mut reader, &mut pos, len)?;
                state.push(StackValue::Str(unquote_protocol0(value)))?;
            }
            b'T' | b'B' | b'X' => {
                let n = u64::from(read_u32(&mut reader, &mut pos, len)?);
                let value = read_tracked_string(&mut reader, &mut pos, len, n)?;
                state.push(value.map(StackValue::Str).unwrap_or(StackValue::Other))?;
            }
            b'U' | b'C' | 0x8c => {
                let n = u64::from(read_u8(&mut reader, &mut pos, len)?);
                let value = read_tracked_string(&mut reader, &mut pos, len, n)?;
                state.push(value.map(StackValue::Str).unwrap_or(StackValue::Other))?;
            }
            0x8d | 0x8e | 0x96 => {
                let n = read_u64(&mut reader, &mut pos, len)?;
                let value = if opcode == 0x8d {
                    read_tracked_string(&mut reader, &mut pos, len, n)?
                } else {
                    skip_argument(&mut reader, &mut pos, len, n)?;
                    None
                };
                state.push(value.map(StackValue::Str).unwrap_or(StackValue::Other))?;
            }
            b'G' => {
                skip_fixed(&mut reader, &mut pos, len, 8)?;
                state.push(StackValue::Other)?;
            }
            b'N' | b']' | b')' | b'}' | 0x8f | 0x97 => state.push(StackValue::Other)?,
            0x88 => state.push(StackValue::Bool(true))?,
            0x89 => state.push(StackValue::Bool(false))?,
            0x98 => {}
            b'(' => state.push(StackValue::Mark)?,
            b'0' => {
                state.pop();
            }
            b'2' => {
                let value = state.stack.last().cloned().unwrap_or(StackValue::Other);
                state.push(value)?;
            }
            b'1' => state.pop_to_mark(None)?,
            b'a' => {
                state.pop();
            }
            // APPENDS mutates the list below MARK; it does not push a new
            // stack value after consuming the marked items.
            b'e' => state.pop_to_mark(None)?,
            b'l' | b'd' | 0x91 => state.pop_to_mark(Some(StackValue::Other))?,
            b't' => {
                let items = state.take_since_mark()?;
                state.push(small_tuple_or_other(items))?;
            }
            0x85 => {
                let a = state.pop();
                state.push(small_tuple_or_other(vec![a]))?;
            }
            0x86 => {
                let b = state.pop();
                let a = state.pop();
                state.push(small_tuple_or_other(vec![a, b]))?;
            }
            0x87 => {
                let c = state.pop();
                let b = state.pop();
                let a = state.pop();
                state.push(small_tuple_or_other(vec![a, b, c]))?;
            }
            b's' => {
                let value = state.pop();
                let key = state.pop();
                state.record_dict_entry(&key, &value);
            }
            // SETITEMS mutates the dict below MARK with key/value pairs and
            // leaves that existing dict on the stack.
            b'u' => {
                let items = state.take_since_mark()?;
                for pair in items.chunks(2) {
                    if let [key, value] = pair {
                        state.record_dict_entry(key, value);
                    }
                }
            }
            // ADDITEMS mutates the set below MARK; it has no key/value
            // semantic, unlike SETITEMS.
            0x90 => state.pop_to_mark(None)?,
            b'g' => {
                let index = parse_decimal_index(&read_line_string(&mut reader, &mut pos, len)?)?;
                state.push_memo(index)?;
            }
            b'h' => {
                let index = usize::from(read_u8(&mut reader, &mut pos, len)?);
                state.push_memo(index)?;
            }
            b'j' => {
                let index = usize::try_from(read_u32(&mut reader, &mut pos, len)?)
                    .context("pickle memo index does not fit usize")?;
                state.push_memo(index)?;
            }
            b'p' => {
                let index = parse_decimal_index(&read_line_string(&mut reader, &mut pos, len)?)?;
                state.store_memo(index)?;
            }
            b'q' => {
                let index = usize::from(read_u8(&mut reader, &mut pos, len)?);
                state.store_memo(index)?;
            }
            b'r' => {
                let index = usize::try_from(read_u32(&mut reader, &mut pos, len)?)
                    .context("pickle memo index does not fit usize")?;
                state.store_memo(index)?;
            }
            0x94 => state.memoize()?,
            0x82 => {
                let code = u32::from(read_u8(&mut reader, &mut pos, len)?);
                state.record_extension(code);
                state.push(StackValue::Other)?;
            }
            0x83 => {
                let mut bytes = [0u8; 2];
                require_remaining(pos, len, bytes.len() as u64)?;
                reader.read_exact(&mut bytes)?;
                pos += bytes.len() as u64;
                state.record_extension(u32::from(u16::from_le_bytes(bytes)));
                state.push(StackValue::Other)?;
            }
            0x84 => {
                let code = read_u32(&mut reader, &mut pos, len)?;
                state.record_extension(code);
                state.push(StackValue::Other)?;
            }
            b'c' | b'i' => {
                let module = read_line_string(&mut reader, &mut pos, len)?;
                let name = read_line_string(&mut reader, &mut pos, len)?;
                let global = format!("{}.{}", module.trim(), name.trim());
                state.record_global(&global);
                if opcode == b'i' {
                    state.mark_dangerous(format!("{global} via legacy INST opcode"));
                    state.pop_to_mark(None)?;
                }
                state.push(StackValue::Global(global))?;
            }
            0x93 => {
                let name = state
                    .pop_string()
                    .ok_or_else(|| anyhow!("STACK_GLOBAL name is not a bounded string"))?;
                let module = state
                    .pop_string()
                    .ok_or_else(|| anyhow!("STACK_GLOBAL module is not a bounded string"))?;
                let global = format!("{module}.{name}");
                state.record_global(&global);
                state.push(StackValue::Global(global))?;
            }
            b'R' => {
                let args = state.pop(); // args tuple
                let callable = state.pop();
                let name = callable_name(&callable);
                if let Some(name) = name.as_deref() {
                    state.record_constructor(Some(name), "REDUCE");
                    // `numpy.dtype(descr, ...)` supplies the descriptor a
                    // Joblib NumpyArrayWrapper's raw array region needs to
                    // compute its exact byte extent; represented distinctly
                    // (see `StackValue::NumpyDtype`) so the descriptor
                    // survives memoized reuse of the dtype object.
                    let dtype_descr = (name == "numpy.dtype" || name.ends_with(".dtype"))
                        .then(|| match &args {
                            StackValue::SmallTuple(items) => {
                                items.first().and_then(ScalarValue::as_str)
                            }
                            _ => None,
                        })
                        .flatten();
                    match dtype_descr {
                        Some(descr) => state.push(StackValue::NumpyDtype(descr.to_owned()))?,
                        None => state.push(StackValue::Constructed(name.to_owned()))?,
                    }
                } else {
                    state.record_unresolved("REDUCE", "callable could not be resolved statically");
                    state.push(StackValue::Other)?;
                }
            }
            b'b' => {
                state.pop(); // state
                let instance = state.pop();
                if let Some(name) = callable_name(&instance) {
                    state.record_constructor(Some(&name), "BUILD");
                    if joblib_framing && name == "joblib.numpy_pickle.NumpyArrayWrapper" {
                        state.last_array_meta = state.pending_array_meta.take();
                    }
                    state.push(StackValue::Constructed(name.to_owned()))?;
                } else {
                    state.push(instance)?;
                }
            }
            b'o' => {
                // OBJ takes MARK, class object, args. Legacy class construction is
                // not expected in a plain tensor checkpoint and is an execution primitive.
                let values = state.take_since_mark()?;
                let class = values.first().and_then(callable_name);
                state.mark_dangerous(match class {
                    Some(name) => format!("{name} via legacy OBJ opcode"),
                    None => "legacy OBJ class-instantiation opcode".to_owned(),
                });
                state.push(StackValue::Other)?;
            }
            0x81 => {
                state.pop(); // args
                let class = state.pop();
                let name = callable_name(&class);
                state.record_constructor(name.as_deref(), "NEWOBJ");
                if joblib_framing
                    && name.as_deref() == Some("joblib.numpy_pickle.NumpyArrayWrapper")
                {
                    state.pending_array_meta = Some(JoblibArrayMeta::default());
                }
                state.push(
                    name.map(StackValue::Constructed)
                        .unwrap_or(StackValue::Other),
                )?;
            }
            0x92 => {
                state.pop();
                state.pop(); // kwargs, args
                let class = state.pop();
                let name = callable_name(&class);
                state.record_constructor(name.as_deref(), "NEWOBJ_EX");
                state.push(
                    name.map(StackValue::Constructed)
                        .unwrap_or(StackValue::Other),
                )?;
            }
            0x80 => {
                let protocol = read_u8(&mut reader, &mut pos, len)?;
                if protocol > 5 {
                    bail!("unsupported pickle protocol {protocol}; supported protocols are 0-5");
                }
            }
            0x95 => {
                let frame = read_u64(&mut reader, &mut pos, len)?;
                if frame > len.saturating_sub(pos) {
                    bail!("pickle FRAME extends beyond end of stream");
                }
            }
            b'P' => {
                state.record_persistent_id("PERSID");
                skip_line(&mut reader, &mut pos, len, MAX_TRACKED_STRING_BYTES)?;
                state.push(StackValue::Other)?;
            }
            b'Q' => {
                state.record_persistent_id("BINPERSID");
                state.pop();
                state.push(StackValue::Other)?;
            }
            b'.' => {
                saw_stop = true;
            }
            other => {
                if joblib_framing
                    && matches!(
                        state.stack.last(),
                        Some(StackValue::Constructed(name))
                            if name == "joblib.numpy_pickle.NumpyArrayWrapper"
                    )
                {
                    if let Some(frame_offset) =
                        find_next_plausible_pickle_frame(&mut reader, pos, len)?
                    {
                        state.analysis.completeness = AnalysisCompleteness::Partial;
                        if state.analysis.joblib_opaque_regions.len()
                            < MAX_JOBLIB_OPAQUE_REGIONS_TRACKED
                        {
                            state.analysis.joblib_opaque_regions.push(JoblibOpaqueRegion {
                                byte_offset: state.current_offset,
                                detail: format!(
                                    "joblib.numpy_pickle.NumpyArrayWrapper raw array region at byte offset {} could not be exactly sized (dtype/shape/allow_mmap metadata was not fully recoverable from the pickle opcode stream); resynchronized via heuristic FRAME search to byte offset {frame_offset}",
                                    state.current_offset
                                ),
                            });
                        }
                        state.pop();
                        state.push(StackValue::Other)?;
                        pos = frame_offset;
                        continue;
                    }
                }
                bail!(
                    "unknown pickle opcode 0x{other:02x} at offset {}",
                    pos.saturating_sub(1)
                )
            }
        }
        if let Some(transcript) = transcript.as_deref_mut() {
            if transcript.len() >= MAX_PRIMARY_TRANSCRIPT_OPCODES {
                bail!("primary parser differential transcript opcode cap exceeded");
            }
            let argument_start = state.current_offset + 1;
            transcript.push(parser_differential::TranscriptEntry {
                offset: state.current_offset,
                opcode,
                opcode_class: parser_differential::opcode_class(opcode),
                argument_start,
                declared_argument_length: pos.saturating_sub(argument_start),
                frame_boundary: opcode == 0x95,
                memo_operation: parser_differential::memo_operation(opcode),
                stack_effect_class: parser_differential::stack_effect_class(opcode),
                execution_capable: parser_differential::execution_capable(opcode),
            });
        }
        if saw_stop {
            break;
        }
    }
    if !saw_stop {
        bail!("pickle stream ended without STOP opcode");
    }
    Ok(state.analysis)
}

/// Resolve a joblib raw array from trusted wrapper metadata and framing.
fn resolve_joblib_raw_array_region<R: Read + Seek>(
    meta: &JoblibArrayMeta,
    reader: &mut R,
    start: u64,
    len: u64,
) -> Result<Option<u64>> {
    let (Some(shape), Some(descr)) = (meta.shape.as_ref(), meta.descr.as_deref()) else {
        return Ok(None);
    };
    let Some(item_size) = crate::formats::npy::simple_dtype_item_size(descr) else {
        return Ok(None);
    };

    let mut total_elements: u64 = 1;
    for &dim in shape {
        let Ok(dim) = u64::try_from(dim) else {
            return Ok(None);
        };
        total_elements = match total_elements.checked_mul(dim) {
            Some(value) => value,
            None => return Ok(None),
        };
    }
    let payload_bytes = match total_elements.checked_mul(item_size) {
        Some(value) => value,
        None => return Ok(None),
    };

    let data_start = match meta.alignment_bytes {
        Some(alignment) if (1..=255).contains(&alignment) => {
            let alignment = alignment as u64;
            let Some(pos_after_marker) = start.checked_add(1) else {
                return Ok(None);
            };
            // Joblib emits a full padding cycle when the marker ends aligned.
            let expected_padding = alignment - (pos_after_marker % alignment);

            if start >= len {
                return Ok(None);
            }
            let mut marker = [0u8; 1];
            reader.seek(SeekFrom::Start(start))?;
            reader.read_exact(&mut marker)?;
            if u64::from(marker[0]) != expected_padding {
                reader.seek(SeekFrom::Start(start))?;
                return Ok(None);
            }
            match pos_after_marker.checked_add(expected_padding) {
                Some(value) => value,
                None => return Ok(None),
            }
        }
        // Present-but-implausible or absent alignment metadata: no padding
        // marker was written, so the raw data starts immediately.
        _ => start,
    };

    let region_end = match data_start.checked_add(payload_bytes) {
        Some(value) if value <= len => value,
        _ => {
            reader.seek(SeekFrom::Start(start))?;
            return Ok(None);
        }
    };
    Ok(Some(region_end))
}

/// Locate the next protocol-4/5 FRAME boundary after a joblib raw-array
/// region. A candidate is accepted only when its declared frame length fits
/// entirely within the remaining bounded stream; a random `0x95` byte inside
/// array data is overwhelmingly likely to fail that 64-bit length check.
/// Resynchronized scans are still explicitly marked partial.
fn find_next_plausible_pickle_frame<R: Read + Seek>(
    reader: &mut R,
    start: u64,
    len: u64,
) -> Result<Option<u64>> {
    let mut candidate = start;
    let mut candidate_count = 0usize;
    let mut marker = [0u8; 1];
    let mut declared = [0u8; 8];
    while candidate.saturating_add(9) <= len {
        reader.seek(SeekFrom::Start(candidate))?;
        reader.read_exact(&mut marker)?;
        if marker[0] == 0x95 {
            candidate_count = candidate_count.saturating_add(1);
            if candidate_count > MAX_JOBLIB_FRAME_CANDIDATES {
                return Ok(None);
            }
            reader.read_exact(&mut declared)?;
            let frame_len = u64::from_le_bytes(declared);
            if frame_len > 0
                && frame_len <= MAX_DIFFERENTIAL_BYTES
                && frame_len <= len.saturating_sub(candidate + 9)
            {
                let capacity = usize::try_from(frame_len)
                    .context("joblib pickle frame length does not fit usize")?;
                let mut payload = vec![0u8; capacity];
                reader.read_exact(&mut payload)?;
                if parser_differential::structurally_valid_opcode_region(&payload) {
                    reader.seek(SeekFrom::Start(candidate))?;
                    return Ok(Some(candidate));
                }
            }
        }
        candidate = candidate.saturating_add(1);
    }
    Ok(None)
}

/// Message substrings that indicate the primary parser fully understood the
/// construct it encountered and determined the byte stream is structurally
/// invalid. Anything else is a coverage/budget/implementation limitation of
/// this parser, not evidence about the artifact, and is classified as
/// `Incomplete` rather than `Rejected`. See the module-level rationale in
/// `crate::assurance::parser_differential`.
const PRIMARY_REJECTED_MESSAGE_PATTERNS: &[&str] = &[
    "unknown pickle opcode",
    "pickle stream ended without STOP opcode",
    "truncated pickle opcode argument",
    "pickle line argument is not UTF-8",
    "invalid pickle memo index",
    "pickle FRAME extends beyond end of stream",
    "empty pickle stream",
    "pickle stack operation requires missing MARK",
];

fn classify_primary_error(
    error: &anyhow::Error,
    last_transcript_offset: Option<u64>,
) -> parser_differential::ReaderOutcome {
    let text = error.to_string();
    let at_offset = pickle_error_offset(error).or(last_transcript_offset);
    if PRIMARY_REJECTED_MESSAGE_PATTERNS
        .iter()
        .any(|pattern| text.contains(pattern))
    {
        parser_differential::ReaderOutcome::Rejected {
            at_offset,
            reason: text,
        }
    } else {
        parser_differential::ReaderOutcome::Incomplete {
            at_offset,
            reason: text,
        }
    }
}

/// Run the primary parser's real decode loop to produce a `ReaderOutcome`
/// for differential comparison. This drives `analyze_reader_inner` with
/// transcript capture enabled, so the differential's primary side is
/// byte-for-byte the same decode path used by real scans; only the terminal
/// classification (accepted / structurally rejected / assurance-incomplete)
/// differs from `analyze_reader`'s plain `anyhow::Result`.
pub(crate) fn primary_reader_outcome(
    bytes: &[u8],
    budget: Option<&crate::budget::ScanBudget>,
) -> parser_differential::ReaderOutcome {
    let mut transcript = Vec::new();
    let cursor = Cursor::new(bytes);
    match analyze_reader_inner(
        cursor,
        bytes.len() as u64,
        budget,
        Some(&mut transcript),
        false,
    ) {
        Ok(_) => parser_differential::ReaderOutcome::Accepted(transcript),
        Err(error) => classify_primary_error(&error, transcript.last().map(|entry| entry.offset)),
    }
}

/// Run the primary parser and the independent structural reader as two
/// separate bounded analyses over the same bytes, and compare their
/// outcomes. See `crate::assurance::parser_differential` for the comparison
/// semantics.
pub(crate) fn parser_differential_outcome(
    bytes: &[u8],
    budget: Option<&crate::budget::ScanBudget>,
) -> parser_differential::ParserDifferentialOutcome {
    let primary = primary_reader_outcome(bytes, budget);
    let secondary = parser_differential::secondary_reader_outcome(bytes, budget);
    parser_differential::compare(primary, secondary)
}

/// Build a finding for a parser-differential outcome, if the outcome is
/// security-relevant. `Agreement` produces no finding (a clean pass needs no
/// extra evidence). `BothRejected` also produces no finding here: the
/// primary's own independent re-parse in `scan_stream` already reports
/// `LF-PICKLE-MALFORMED` for the same rejection, so a second finding would
/// be redundant rather than additive.
fn parser_differential_finding(
    outcome: parser_differential::ParserDifferentialOutcome,
    subject: EvidenceSubject,
) -> Option<LayerScanResult> {
    use parser_differential::ParserDifferentialOutcome as Outcome;
    match outcome {
        Outcome::Agreement | Outcome::BothRejected { .. } => None,
        Outcome::Disagreement {
            first_divergence, ..
        } => Some(
            FindingBuilder::new(
                "LF-PICKLE-PARSER-DISAGREEMENT",
                CheckType::PickleStructure,
                ScanStatus::Warn,
            )
            .class(FindingClass::Structural)
            .confidence(Confidence::Medium)
            .subject(subject.clone())
            .detail(format!(
                "The primary pickle parser and an independent structural reader produced different results for the same byte stream, first diverging at offset {first_divergence}"
            ))
            .evidence(byte_range_evidence(
                subject,
                first_divergence,
                1,
                "The two independent readers first diverge at this byte offset",
            ))
            .finish(),
        ),
        Outcome::SecondaryAssuranceIncomplete { at_offset, reason }
        | Outcome::PrimaryAssuranceIncomplete { at_offset, reason } => {
            Some(assurance_incomplete_finding(subject, at_offset, reason))
        }
        Outcome::AssuranceIncomplete {
            primary_reason,
            secondary_reason,
        } => Some(assurance_incomplete_finding(
            subject,
            None,
            format!("primary: {primary_reason}; secondary: {secondary_reason}"),
        )),
    }
}

/// Build the assurance-incomplete finding. This describes a limitation of
/// Layerfault's own parser-differential coverage, not a property of the
/// artifact: it uses `ScanStatus::Pass` so it does not by itself escalate
/// the security verdict, and its wording must never suggest the artifact is
/// malformed, evasive, or unsafe. Policy may separately require complete
/// differential assurance and act on incomplete coverage.
fn assurance_incomplete_finding(
    subject: EvidenceSubject,
    at_offset: Option<u64>,
    reason: String,
) -> LayerScanResult {
    let builder = FindingBuilder::new(
        "LF-PICKLE-PARSER-ASSURANCE-INCOMPLETE",
        CheckType::PickleStructure,
        ScanStatus::Pass,
    )
    .class(FindingClass::Informational)
    .confidence(Confidence::High)
    .subject(subject.clone())
    .detail(format!(
        "Parser-differential assurance for this pickle stream is incomplete: {reason}"
    ));
    match at_offset {
        Some(offset) => builder
            .evidence(byte_range_evidence(
                subject,
                offset,
                1,
                "Assurance coverage ended at this byte offset",
            ))
            .finish(),
        None => builder
            .evidence_unavailable("the assurance gap is not attributable to a specific byte offset")
            .finish(),
    }
}

#[derive(Default)]
struct ParserState {
    stack: Vec<StackValue>,
    memo: BTreeMap<usize, StackValue>,
    next_memo: usize,
    analysis: PickleAnalysis,
    /// Byte offset of the opcode currently being interpreted, so any entry it
    /// produces can be attributed to an exact position.
    current_offset: u64,
    current_opcode: &'static str,
    /// Accumulates a Joblib `NumpyArrayWrapper`'s state-dict fields while its
    /// constructor (NEWOBJ..BUILD) is being interpreted. `None` outside that
    /// window.
    pending_array_meta: Option<JoblibArrayMeta>,
    /// The most recently finalized `NumpyArrayWrapper` metadata, set when its
    /// BUILD opcode completes and consumed by the raw-array-region resolver.
    last_array_meta: Option<JoblibArrayMeta>,
}

impl ParserState {
    fn push(&mut self, value: StackValue) -> Result<()> {
        if self.stack.len() >= MAX_STACK {
            bail!("pickle stack exceeds safety cap");
        }
        self.stack.push(value);
        Ok(())
    }
    fn pop(&mut self) -> StackValue {
        self.stack.pop().unwrap_or(StackValue::Other)
    }
    fn pop_string(&mut self) -> Option<String> {
        match self.pop() {
            StackValue::Str(value) => Some(value),
            _ => None,
        }
    }
    /// Record a `dict[key] = value` assignment (from SETITEM/SETITEMS) into
    /// `pending_array_meta`, when one is active and the key is a whitelisted
    /// Joblib NumPy array-wrapper field. A no-op the rest of the time, so
    /// this never grows into general pickle dict tracking.
    fn record_dict_entry(&mut self, key: &StackValue, value: &StackValue) {
        let Some(meta) = self.pending_array_meta.as_mut() else {
            return;
        };
        let StackValue::Str(key) = key else {
            return;
        };
        match key.as_str() {
            "shape" => {
                if let StackValue::SmallTuple(items) = value {
                    let mut dims = Vec::with_capacity(items.len());
                    for item in items {
                        match item.as_int() {
                            Some(n) => dims.push(n),
                            None => return,
                        }
                    }
                    meta.shape = Some(dims);
                }
            }
            "allow_mmap" => {
                if let StackValue::Bool(b) = value {
                    meta.allow_mmap = Some(*b);
                }
            }
            "numpy_array_alignment_bytes" => {
                if let StackValue::Int(n) = value {
                    meta.alignment_bytes = Some(*n);
                }
            }
            "dtype" => {
                if let StackValue::NumpyDtype(descr) = value {
                    meta.descr = Some(descr.clone());
                }
            }
            _ => {}
        }
    }
    fn take_since_mark(&mut self) -> Result<Vec<StackValue>> {
        let Some(index) = self
            .stack
            .iter()
            .rposition(|value| matches!(value, StackValue::Mark))
        else {
            bail!("pickle stack operation requires missing MARK");
        };
        let values = self.stack.split_off(index + 1);
        self.stack.pop();
        Ok(values)
    }
    fn pop_to_mark(&mut self, replacement: Option<StackValue>) -> Result<()> {
        self.take_since_mark()?;
        if let Some(value) = replacement {
            self.push(value)?;
        }
        Ok(())
    }
    fn store_memo(&mut self, index: usize) -> Result<()> {
        if index >= MAX_MEMO || self.memo.len() >= MAX_MEMO {
            bail!("pickle memo exceeds safety cap");
        }
        let value = self.stack.last().cloned().unwrap_or(StackValue::Other);
        self.memo.insert(index, value);
        self.next_memo = self.next_memo.max(index.saturating_add(1));
        Ok(())
    }
    fn memoize(&mut self) -> Result<()> {
        let index = self.next_memo;
        self.store_memo(index)
    }
    fn push_memo(&mut self, index: usize) -> Result<()> {
        let value = self.memo.get(&index).cloned().unwrap_or(StackValue::Other);
        self.push(value)
    }
    /// Record where the current opcode produced `entry`.
    ///
    /// Bounded and first-write-wins so a hostile stream repeating one construct
    /// millions of times cannot grow the evidence set.
    fn note_site(&mut self, entry: &str) {
        if self.analysis.sites.len() >= MAX_OPCODE_SITES {
            return;
        }
        if self.analysis.sites.iter().any(|site| site.entry == entry) {
            return;
        }
        self.analysis.sites.push(OpcodeSite {
            entry: entry.to_owned(),
            opcode: self.current_opcode,
            opcode_index: self.analysis.opcode_count as u64,
            byte_offset: self.current_offset,
        });
    }

    /// Insert a dangerous entry and record where it was resolved.
    fn mark_dangerous(&mut self, entry: String) {
        self.note_site(&entry);
        self.analysis.dangerous.insert(entry);
    }

    fn record_global(&mut self, value: &str) {
        self.analysis.globals.insert(value.to_owned());
        if is_allowlisted(value) {
            return;
        }
        if is_explicit_danger(value) {
            self.mark_dangerous(value.to_owned());
        } else {
            self.note_site(value);
            self.analysis.unknown_globals.insert(value.to_owned());
        }
    }
    fn record_persistent_id(&mut self, opcode: &'static str) {
        let site = OpcodeSite {
            entry: opcode.to_owned(),
            opcode,
            opcode_index: self.analysis.opcode_count as u64,
            byte_offset: self.current_offset,
        };
        if self.analysis.persistent_ids.len() < MAX_OPCODE_SITES {
            self.analysis.persistent_ids.push(site.clone());
        }
        if self.analysis.sites.len() < MAX_OPCODE_SITES {
            self.analysis.sites.push(site);
        }
    }
    fn record_extension(&mut self, code: u32) {
        self.record_unresolved(
            "EXT",
            &format!("extension registry code {code} requires environment-dependent resolution"),
        );
        self.mark_dangerous(format!(
            "unresolved pickle extension code {code}; EXT registry resolution is environment-dependent"
        ));
    }
    fn record_unresolved(&mut self, opcode: &str, reason: &str) {
        self.analysis.completeness = AnalysisCompleteness::Partial;
        if self.analysis.unresolved_execution.len() < MAX_OPCODE_SITES {
            self.analysis
                .unresolved_execution
                .push(UnresolvedExecutionPrimitive {
                    opcode: opcode.to_owned(),
                    byte_offset: self.current_offset,
                    reason: reason.to_owned(),
                });
        }
    }
    fn record_constructor(&mut self, name: Option<&str>, opcode: &str) {
        match name {
            Some(name) if is_allowlisted(name) => {}
            // A GLOBAL is already classified when resolved. Reconstructing an
            // unfamiliar class is not by itself proof of code execution:
            // common framework checkpoints contain their own module classes.
            // Keep such names as reviewable unknown globals; only an explicit
            // execution primitive is allowed to produce the blocking rule.
            Some(name) if is_explicit_danger(name) => {
                self.mark_dangerous(format!("{name} used by {opcode}"))
            }
            Some(_) => {}
            None => {
                self.record_unresolved(opcode, "constructor could not be resolved statically");
            }
        }
    }
}

fn callable_name(value: &StackValue) -> Option<String> {
    match value {
        StackValue::Global(name) | StackValue::Constructed(name) => Some(name.clone()),
        _ => None,
    }
}

fn is_allowlisted(value: &str) -> bool {
    SAFE_BUILTINS.contains(&value)
        || SAFE_VALUE_CONSTRUCTORS.contains(&value)
        || SAFE_VALUE_CONSTRUCTOR_PREFIXES
            .iter()
            .any(|prefix| value.starts_with(prefix))
        || ALLOWLIST_PREFIXES
            .iter()
            .any(|prefix| value.starts_with(prefix))
        || matches!(
            value,
            "sklearn.pipeline.Pipeline"
                | "sklearn.utils._bunch.Bunch"
                | "scipy.sparse._csr.csr_matrix"
                | "scipy.sparse._csc.csc_matrix"
        )
}

fn is_explicit_danger(value: &str) -> bool {
    DANGEROUS_EXACT.contains(&value)
        || value.starts_with("subprocess.")
        || value.contains(".__reduce__")
        || value.contains(".__setstate__")
        || value
            .split('.')
            // These are ordinary Python module names, not user-defined dunder
            // methods. Their explicitly dangerous members remain covered by
            // the exact-danger list above.
            .any(|part| {
                !matches!(part, "__builtin__" | "__main__" | "__mp_main__")
                    && part.starts_with("__")
                    && part.ends_with("__")
            })
}

/// Build a `StackValue::SmallTuple` from popped tuple elements when every
/// element is a simple scalar and the tuple is short; otherwise `Other`,
/// matching prior behavior for tuples this module doesn't need to inspect.
fn small_tuple_or_other(items: Vec<StackValue>) -> StackValue {
    if items.len() > 8 {
        return StackValue::Other;
    }
    let mut scalars = Vec::with_capacity(items.len());
    for item in &items {
        match ScalarValue::from_stack_value(item) {
            Some(scalar) => scalars.push(scalar),
            None => return StackValue::Other,
        }
    }
    StackValue::SmallTuple(scalars)
}

fn read_u8<R: Read>(reader: &mut R, pos: &mut u64, len: u64) -> Result<u8> {
    require_remaining(*pos, len, 1)?;
    let mut byte = [0u8; 1];
    reader.read_exact(&mut byte)?;
    *pos += 1;
    Ok(byte[0])
}
fn read_u32<R: Read>(reader: &mut R, pos: &mut u64, len: u64) -> Result<u32> {
    require_remaining(*pos, len, 4)?;
    let mut bytes = [0u8; 4];
    reader.read_exact(&mut bytes)?;
    *pos += 4;
    Ok(u32::from_le_bytes(bytes))
}
fn read_u64<R: Read>(reader: &mut R, pos: &mut u64, len: u64) -> Result<u64> {
    require_remaining(*pos, len, 8)?;
    let mut bytes = [0u8; 8];
    reader.read_exact(&mut bytes)?;
    *pos += 8;
    Ok(u64::from_le_bytes(bytes))
}
fn read_i32<R: Read>(reader: &mut R, pos: &mut u64, len: u64) -> Result<i32> {
    require_remaining(*pos, len, 4)?;
    let mut bytes = [0u8; 4];
    reader.read_exact(&mut bytes)?;
    *pos += 4;
    Ok(i32::from_le_bytes(bytes))
}
/// Read a pickle LONG1/LONG4 little-endian two's-complement integer of `n`
/// bytes, returning `None` (without discarding the safety cap on `n`) when
/// it doesn't fit an `i64` — such values are never plausible array metadata
/// (shape dims, alignment bytes), so callers fall back to `StackValue::Other`.
fn read_small_signed_long<R: Read + Seek>(
    reader: &mut R,
    pos: &mut u64,
    len: u64,
    n: u64,
) -> Result<Option<i64>> {
    if n == 0 {
        return Ok(Some(0));
    }
    if n > 8 {
        skip_argument(reader, pos, len, n)?;
        return Ok(None);
    }
    require_remaining(*pos, len, n)?;
    let count = n as usize;
    let mut bytes = [0u8; 8];
    reader.read_exact(&mut bytes[..count])?;
    *pos += n;
    let negative = bytes[count - 1] & 0x80 != 0;
    if negative {
        for byte in bytes.iter_mut().skip(count) {
            *byte = 0xff;
        }
    }
    Ok(Some(i64::from_le_bytes(bytes)))
}
fn skip_fixed<R: Read + Seek>(reader: &mut R, pos: &mut u64, len: u64, count: u64) -> Result<()> {
    skip_argument(reader, pos, len, count)
}
fn skip_argument<R: Read + Seek>(
    reader: &mut R,
    pos: &mut u64,
    len: u64,
    count: u64,
) -> Result<()> {
    if count > MAX_ARGUMENT_BYTES {
        bail!("pickle opcode argument exceeds safety cap");
    }
    require_remaining(*pos, len, count)?;
    let offset = i64::try_from(count).context("pickle argument length does not fit seek offset")?;
    reader.seek(SeekFrom::Current(offset))?;
    *pos = (*pos)
        .checked_add(count)
        .ok_or_else(|| anyhow!("pickle cursor overflow"))?;
    Ok(())
}
fn read_tracked_string<R: Read + Seek>(
    reader: &mut R,
    pos: &mut u64,
    len: u64,
    count: u64,
) -> Result<Option<String>> {
    if count > MAX_ARGUMENT_BYTES {
        bail!("pickle string argument exceeds safety cap");
    }
    require_remaining(*pos, len, count)?;
    if count > MAX_TRACKED_STRING_BYTES {
        skip_argument(reader, pos, len, count)?;
        return Ok(None);
    }
    let n = usize::try_from(count).context("pickle string length does not fit usize")?;
    let mut bytes = vec![0u8; n];
    reader.read_exact(&mut bytes)?;
    *pos += count;
    Ok(String::from_utf8(bytes).ok())
}
fn read_line_string<R: Read>(reader: &mut R, pos: &mut u64, len: u64) -> Result<String> {
    let mut out = Vec::new();
    loop {
        let byte = read_u8(reader, pos, len)?;
        if byte == b'\n' {
            break;
        }
        if out.len() as u64 >= MAX_TRACKED_STRING_BYTES {
            bail!("pickle line argument exceeds safety cap");
        }
        out.push(byte);
    }
    String::from_utf8(out).context("pickle line argument is not UTF-8")
}
fn skip_line<R: Read>(reader: &mut R, pos: &mut u64, len: u64, cap: u64) -> Result<()> {
    let mut count = 0u64;
    loop {
        let byte = read_u8(reader, pos, len)?;
        if byte == b'\n' {
            return Ok(());
        }
        count += 1;
        if count > cap {
            bail!("pickle line argument exceeds safety cap");
        }
    }
}
fn require_remaining(pos: u64, len: u64, count: u64) -> Result<()> {
    if count > len.saturating_sub(pos) {
        bail!("truncated pickle opcode argument");
    }
    Ok(())
}
fn parse_decimal_index(value: &str) -> Result<usize> {
    let index = value
        .trim()
        .parse::<usize>()
        .context("invalid pickle memo index")?;
    if index >= MAX_MEMO {
        bail!("pickle memo index exceeds safety cap");
    }
    Ok(index)
}
fn unquote_protocol0(mut value: String) -> String {
    if value.len() >= 2 {
        let first = value.as_bytes()[0];
        let last = *value.as_bytes().last().unwrap_or(&0);
        if (first == b'\'' && last == b'\'') || (first == b'"' && last == b'"') {
            value.remove(0);
            value.pop();
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zlib_bytes(bytes: &[u8]) -> Vec<u8> {
        use flate2::write::ZlibEncoder;
        use flate2::Compression;
        use std::io::Write;

        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(bytes).expect("compress pickle fixture");
        encoder.finish().expect("finish pickle fixture")
    }

    fn scan_zlib_bytes(
        bytes: &[u8],
        budget: &crate::budget::ScanBudget,
    ) -> Result<Vec<LayerScanResult>> {
        scan_named_zlib_bytes(bytes, ".pkl", budget)
    }

    fn scan_named_zlib_bytes(
        bytes: &[u8],
        suffix: &str,
        budget: &crate::budget::ScanBudget,
    ) -> Result<Vec<LayerScanResult>> {
        use std::io::Write;

        let mut file = tempfile::Builder::new().suffix(suffix).tempfile()?;
        file.write_all(bytes)?;
        scan(
            file.path(),
            file.as_file(),
            file.as_file().metadata()?.len(),
            "sha256:zlib-test",
            "application/x-python-pickle",
            budget,
        )
    }

    fn framed_joblib_stream(after_array: &[u8]) -> Vec<u8> {
        let module = b"joblib.numpy_pickle";
        let class = b"NumpyArrayWrapper";
        let mut bytes = vec![0x80, 0x05, 0x8c, module.len() as u8];
        bytes.extend_from_slice(module);
        bytes.extend_from_slice(&[0x8c, class.len() as u8]);
        bytes.extend_from_slice(class);
        bytes.extend_from_slice(&[0x93, b')', 0x81, b'}', b'b']);
        bytes.extend_from_slice(&[0x0e; 32]);
        bytes.push(0x95);
        bytes.extend_from_slice(&(after_array.len() as u64).to_le_bytes());
        bytes.extend_from_slice(after_array);
        bytes
    }

    fn global(module: &str, name: &str) -> Vec<u8> {
        format!("c{module}\n{name}\n.").into_bytes()
    }

    fn short_binunicode(s: &str) -> Vec<u8> {
        assert!(s.len() <= 255);
        let mut out = vec![0x8c, s.len() as u8];
        out.extend_from_slice(s.as_bytes());
        out
    }

    /// Builds the prefix (through BUILD) plus the computed padding/payload
    /// lengths for [`real_joblib_array_stream`], so callers that need to
    /// locate or corrupt the padding-marker byte (at `prefix.len()`) don't
    /// have to reimplement the layout.
    fn real_joblib_array_stream_parts(descr: &str, dim: u8, alignment: u8) -> (Vec<u8>, u64, u64) {
        let module = "joblib.numpy_pickle";
        let class = "NumpyArrayWrapper";

        let mut prefix = vec![0x80, 0x05]; // PROTO 5
        prefix.extend(short_binunicode(module));
        prefix.extend(short_binunicode(class));
        prefix.push(0x93); // STACK_GLOBAL
        prefix.push(b')'); // EMPTY_TUPLE
        prefix.push(0x81); // NEWOBJ
        prefix.push(b'}'); // EMPTY_DICT
        prefix.push(b'('); // MARK

        prefix.extend(short_binunicode("shape"));
        prefix.push(b'K'); // BININT1
        prefix.push(dim);
        prefix.push(0x85); // TUPLE1

        prefix.extend(short_binunicode("dtype"));
        prefix.extend(short_binunicode("numpy"));
        prefix.extend(short_binunicode("dtype"));
        prefix.push(0x93); // STACK_GLOBAL -> Global("numpy.dtype")
        prefix.extend(short_binunicode(descr));
        prefix.push(0x89); // NEWFALSE
        prefix.push(0x88); // NEWTRUE
        prefix.push(0x87); // TUPLE3
        prefix.push(b'R'); // REDUCE -> NumpyDtype(descr)

        prefix.extend(short_binunicode("allow_mmap"));
        prefix.push(0x88); // NEWTRUE

        prefix.extend(short_binunicode("numpy_array_alignment_bytes"));
        prefix.push(b'K'); // BININT1
        prefix.push(alignment);

        prefix.push(b'u'); // SETITEMS
        prefix.push(b'b'); // BUILD

        let alignment = u64::from(alignment);
        let pos_after_marker = prefix.len() as u64 + 1;
        let padding_length = alignment - (pos_after_marker % alignment);

        let item_size = crate::formats::npy::simple_dtype_item_size(descr).expect("test descr");
        let payload_bytes = u64::from(dim) * item_size;

        (prefix, padding_length, payload_bytes)
    }

    /// A joblib pickle stream matching the real on-disk layout: a
    /// `NumpyArrayWrapper` constructed via NEWOBJ/BUILD with a state dict
    /// (`shape`, `dtype`, `allow_mmap`, `numpy_array_alignment_bytes`),
    /// immediately followed by the raw array region joblib actually writes
    /// for `allow_mmap=True` arrays: a single padding-length marker byte,
    /// that many `0xff` bytes, then the contiguous raw payload — no `.npy`
    /// magic header. `shape` must be a single dimension fitting `BININT1`
    /// (0..=255).
    fn real_joblib_array_stream(
        descr: &str,
        dim: u8,
        alignment: u8,
        after_array: &[u8],
    ) -> Vec<u8> {
        let (prefix, padding_length, payload_bytes) =
            real_joblib_array_stream_parts(descr, dim, alignment);
        let mut out = prefix;
        out.push(padding_length as u8);
        out.extend(std::iter::repeat_n(0xffu8, padding_length as usize));
        out.extend(std::iter::repeat_n(0u8, payload_bytes as usize));
        out.extend_from_slice(after_array);
        out
    }

    #[test]
    fn allowlisted_ordered_dict_passes() -> Result<()> {
        let analysis = analyze_bytes(&global("collections", "OrderedDict"))?;
        assert!(analysis.dangerous.is_empty());
        assert!(analysis.unknown_globals.is_empty());
        assert!(analysis.globals.contains("collections.OrderedDict"));
        Ok(())
    }

    #[test]
    fn os_system_reduce_is_dangerous() -> Result<()> {
        let bytes = b"cos\nsystem\n)R.";
        let analysis = analyze_bytes(bytes)?;
        assert!(analysis
            .dangerous
            .iter()
            .any(|value| value.contains("os.system")));
        Ok(())
    }

    #[test]
    fn raw_zlib_joblib_is_opcode_analyzed() -> Result<()> {
        let budget =
            crate::budget::ScanBudget::new(crate::budget::ScanBudgetProfile::Default.limits())?;
        let results = scan_zlib_bytes(&zlib_bytes(b"\x80\x02N."), &budget)?;
        assert!(!results.iter().any(|finding| {
            matches!(
                crate::policy::rule_id(finding).as_str(),
                "LF-PICKLE-MALFORMED" | "LF-PICKLE-OPAQUE-COMPRESSED"
            )
        }));
        Ok(())
    }

    #[test]
    fn raw_zlib_joblib_preserves_dangerous_global_block() -> Result<()> {
        let budget =
            crate::budget::ScanBudget::new(crate::budget::ScanBudgetProfile::Default.limits())?;
        let results = scan_zlib_bytes(&zlib_bytes(b"cos\nsystem\n)R."), &budget)?;
        assert!(results.iter().any(|finding| {
            crate::policy::rule_id(finding) == "LF-PICKLE-DANGEROUS-GLOBAL"
                && finding.status == ScanStatus::Fail
        }));
        Ok(())
    }

    #[test]
    fn raw_zlib_joblib_resynchronizes_after_array_regions() -> Result<()> {
        let budget =
            crate::budget::ScanBudget::new(crate::budget::ScanBudgetProfile::Default.limits())?;
        let stream = framed_joblib_stream(b"N.");
        let results = scan_named_zlib_bytes(&zlib_bytes(&stream), ".joblib", &budget)?;
        assert!(results.iter().any(|finding| {
            crate::policy::rule_id(finding) == "LF-PICKLE-OPAQUE-COMPRESSED"
                && finding.status == ScanStatus::Warn
        }));
        assert!(!results
            .iter()
            .any(|finding| crate::policy::rule_id(finding) == "LF-PICKLE-MALFORMED"));
        Ok(())
    }

    #[test]
    fn joblib_opaque_finding_names_the_byte_offset_and_construct() -> Result<()> {
        let budget =
            crate::budget::ScanBudget::new(crate::budget::ScanBudgetProfile::Default.limits())?;
        let stream = framed_joblib_stream(b"N.");
        let results = scan_named_zlib_bytes(&zlib_bytes(&stream), ".joblib", &budget)?;
        let opaque = results
            .iter()
            .find(|finding| crate::policy::rule_id(finding) == "LF-PICKLE-OPAQUE-COMPRESSED")
            .expect("opaque finding");
        let detail = opaque.detail.as_deref().unwrap_or_default();
        assert!(
            detail.contains("byte offset"),
            "diagnostic detail should name a byte offset, not just say parsing was incomplete: {detail:?}"
        );
        assert!(
            detail.contains("NumpyArrayWrapper"),
            "diagnostic detail should name the joblib construct that triggered the fallback: {detail:?}"
        );
        Ok(())
    }

    #[test]
    fn raw_zlib_joblib_scans_dangerous_globals_after_array_regions() -> Result<()> {
        let budget =
            crate::budget::ScanBudget::new(crate::budget::ScanBudgetProfile::Default.limits())?;
        let stream = framed_joblib_stream(b"cos\nsystem\n)R.");
        let results = scan_named_zlib_bytes(&zlib_bytes(&stream), ".joblib", &budget)?;
        assert!(results.iter().any(|finding| {
            crate::policy::rule_id(finding) == "LF-PICKLE-DANGEROUS-GLOBAL"
                && finding.status == ScanStatus::Fail
        }));
        assert!(results.iter().any(|finding| {
            crate::policy::rule_id(finding) == "LF-PICKLE-OPAQUE-COMPRESSED"
                && finding.status == ScanStatus::Warn
        }));
        Ok(())
    }

    #[test]
    fn raw_zlib_joblib_real_padded_array_region_completes() -> Result<()> {
        let budget =
            crate::budget::ScanBudget::new(crate::budget::ScanBudgetProfile::Default.limits())?;
        let stream = real_joblib_array_stream("f4", 6, 16, b"N.");
        let results = scan_named_zlib_bytes(&zlib_bytes(&stream), ".joblib", &budget)?;
        // The array region was fully accounted for by exact padding/shape/
        // dtype validation, not heuristic resynchronization, so no
        // coverage-gap WARN should be raised for it.
        assert!(!results
            .iter()
            .any(|finding| crate::policy::rule_id(finding) == "LF-PICKLE-OPAQUE-COMPRESSED"));
        assert!(!results
            .iter()
            .any(|finding| crate::policy::rule_id(finding) == "LF-PICKLE-MALFORMED"));
        Ok(())
    }

    #[test]
    fn raw_zlib_joblib_accepts_full_cycle_alignment_padding() -> Result<()> {
        let budget =
            crate::budget::ScanBudget::new(crate::budget::ScanBudgetProfile::Default.limits())?;
        let stream = real_joblib_array_stream("f4", 6, 1, b"N.");
        let results = scan_named_zlib_bytes(&zlib_bytes(&stream), ".joblib", &budget)?;
        assert!(!results.iter().any(|finding| {
            let rule_id = crate::policy::rule_id(finding);
            rule_id == "LF-PICKLE-OPAQUE-COMPRESSED" || rule_id == "LF-PICKLE-MALFORMED"
        }));
        Ok(())
    }

    #[test]
    fn raw_zlib_joblib_detects_dangerous_global_after_real_padded_array_region() -> Result<()> {
        let budget =
            crate::budget::ScanBudget::new(crate::budget::ScanBudgetProfile::Default.limits())?;
        let stream = real_joblib_array_stream("i8", 4, 16, b"cos\nsystem\n)R.");
        let results = scan_named_zlib_bytes(&zlib_bytes(&stream), ".joblib", &budget)?;
        assert!(results.iter().any(|finding| {
            crate::policy::rule_id(finding) == "LF-PICKLE-DANGEROUS-GLOBAL"
                && finding.status == ScanStatus::Fail
        }));
        assert!(!results
            .iter()
            .any(|finding| crate::policy::rule_id(finding) == "LF-PICKLE-OPAQUE-COMPRESSED"));
        Ok(())
    }

    #[test]
    fn raw_zlib_joblib_corrupted_padding_marker_falls_back_to_incomplete_not_malformed(
    ) -> Result<()> {
        let budget =
            crate::budget::ScanBudget::new(crate::budget::ScanBudgetProfile::Default.limits())?;
        // Real metadata (shape/dtype/allow_mmap/alignment) is present, but
        // the on-disk marker byte doesn't match what that metadata implies
        // — the exact-computation path must reject it rather than trust a
        // mismatched byte, and fall back to heuristic resynchronization
        // (still a coverage-gap WARN, never silently PASS or a hard
        // failure). A framed continuation gives it a plausible resync
        // target, isolating "declined an unverifiable region" from "there
        // was nothing to resync to".
        let (prefix, padding_length, payload_bytes) = real_joblib_array_stream_parts("f4", 6, 16);
        let mut stream = prefix;
        stream.push(0xff); // wrong marker: real padding_length is `padding_length`, not 0xff
        stream.extend(std::iter::repeat_n(0xffu8, padding_length as usize));
        stream.extend(std::iter::repeat_n(0u8, payload_bytes as usize));
        stream.push(0x95);
        stream.extend_from_slice(&(2u64).to_le_bytes());
        stream.extend_from_slice(b"N.");

        let results = scan_named_zlib_bytes(&zlib_bytes(&stream), ".joblib", &budget)?;
        assert!(results.iter().any(|finding| {
            crate::policy::rule_id(finding) == "LF-PICKLE-OPAQUE-COMPRESSED"
                && finding.status == ScanStatus::Warn
        }));
        assert!(!results
            .iter()
            .any(|finding| crate::policy::rule_id(finding) == "LF-PICKLE-MALFORMED"));
        Ok(())
    }

    #[test]
    fn corrupt_raw_zlib_joblib_is_opaque_not_malformed() -> Result<()> {
        let budget =
            crate::budget::ScanBudget::new(crate::budget::ScanBudgetProfile::Default.limits())?;
        let results = scan_zlib_bytes(&[0x78, 0x9c, 0x00], &budget)?;
        assert!(results.iter().any(|finding| {
            crate::policy::rule_id(finding) == "LF-PICKLE-OPAQUE-COMPRESSED"
                && finding.status == ScanStatus::Warn
        }));
        assert!(!results
            .iter()
            .any(|finding| crate::policy::rule_id(finding) == "LF-PICKLE-MALFORMED"));
        Ok(())
    }

    #[test]
    fn raw_zlib_joblib_over_budget_is_opaque_not_malformed() -> Result<()> {
        let mut limits = crate::budget::ScanBudgetProfile::Constrained.limits();
        limits.decompressed_bytes = 128;
        let budget = crate::budget::ScanBudget::new(limits)?;
        let results = scan_zlib_bytes(&zlib_bytes(&vec![b'N'; 1024]), &budget)?;
        assert!(results.iter().any(|finding| {
            crate::policy::rule_id(finding) == "LF-PICKLE-OPAQUE-COMPRESSED"
                && finding.status == ScanStatus::Warn
                && finding
                    .detail
                    .as_deref()
                    .is_some_and(|detail| detail.contains("decompressed-bytes budget"))
        }));
        assert!(!results
            .iter()
            .any(|finding| crate::policy::rule_id(finding) == "LF-PICKLE-MALFORMED"));
        Ok(())
    }

    #[test]
    fn dangerous_global_records_opcode_and_offset() -> Result<()> {
        // GLOBAL at offset 0, REDUCE consuming it a few bytes later.
        let bytes = b"cos\nsystem\n)R.";
        let analysis = analyze_bytes(bytes)?;
        let entry = analysis
            .dangerous
            .iter()
            .find(|value| value.contains("os.system"))
            .expect("dangerous entry");
        let site = analysis.site_for(entry).expect("recorded site");
        assert_eq!(site.byte_offset, 0, "GLOBAL opcode starts at offset 0");
        assert_eq!(site.opcode_index, 1);
        assert_eq!(site.opcode, "GLOBAL");
        Ok(())
    }

    #[test]
    fn finding_from_analysis_attaches_serialization_opcode_evidence() {
        let bytes = b"cos\nsystem\n)R.";
        let subject = EvidenceSubject::identity("sha256:abcd", "application/octet-stream")
            .with_sha256(Some("sha256:abcd".to_owned()));
        let analysis = analyze_bytes(bytes).expect("analysis");
        let finding = finding_from_analysis(
            analysis,
            "sha256:abcd",
            "application/octet-stream",
            "pickle stream",
            subject,
            Instant::now(),
        );
        assert_eq!(
            crate::policy::rule_id(&finding),
            "LF-PICKLE-DANGEROUS-GLOBAL"
        );
        let record = finding.evidence.first().expect("evidence record");
        assert_eq!(
            record.kind,
            crate::finding_evidence::EvidenceKind::SerializationOpcode
        );
        match &record.location {
            Some(crate::finding_evidence::EvidenceLocation::Serialization {
                opcode_index,
                byte_offset,
            }) => {
                assert_eq!(*opcode_index, 1);
                assert_eq!(*byte_offset, 0);
            }
            other => panic!("expected serialization location, got {other:?}"),
        }
        assert_eq!(
            finding.evidence_state,
            Some(crate::finding_evidence::EvidenceState::Available)
        );
    }

    #[test]
    fn malformed_stream_reports_available_byte_offset() {
        let bytes = b"\x80\x04cfoo\nbar";
        let budget =
            crate::budget::ScanBudget::new(crate::budget::ScanBudgetProfile::Default.limits())
                .expect("budget");
        let finding = scan_stream(
            std::io::Cursor::new(bytes.to_vec()),
            bytes.len() as u64,
            "sha256:abcd",
            "application/octet-stream",
            None,
            &budget,
        );
        assert_eq!(crate::policy::rule_id(&finding), "LF-PICKLE-MALFORMED");
        assert!(matches!(
            finding.evidence_state,
            Some(crate::finding_evidence::EvidenceState::Available)
                | Some(crate::finding_evidence::EvidenceState::Unavailable)
        ));
    }

    #[test]
    fn custom_class_is_unknown() -> Result<()> {
        let analysis = analyze_bytes(&global("acme.model", "CustomTensor"))?;
        assert!(analysis.unknown_globals.contains("acme.model.CustomTensor"));
        Ok(())
    }

    #[test]
    fn main_module_custom_class_is_unknown_not_explicit_execution() -> Result<()> {
        let analysis = analyze_bytes(&global("__main__", "Policy"))?;
        assert!(analysis.dangerous.is_empty());
        assert!(analysis.unknown_globals.contains("__main__.Policy"));
        Ok(())
    }

    #[test]
    fn explicit_dunder_callable_remains_dangerous() -> Result<()> {
        let analysis = analyze_bytes(&global("acme.model", "__reduce__"))?;
        assert!(analysis.dangerous.contains("acme.model.__reduce__"));
        Ok(())
    }

    #[test]
    fn persistent_id_persid_emits_rule() {
        let bytes = b"Pexternal_ref\n.";
        let subject = EvidenceSubject::identity("sha256:abcd", "application/octet-stream");
        let analysis = analyze_bytes(bytes).expect("analysis");
        assert_eq!(analysis.persistent_ids.len(), 1);
        assert_eq!(analysis.persistent_ids[0].entry, "PERSID");

        let finding = finding_from_analysis(
            analysis,
            "sha256:abcd",
            "application/octet-stream",
            "pickle stream",
            subject,
            Instant::now(),
        );
        assert_eq!(crate::policy::rule_id(&finding), "LF-PICKLE-PERSISTENT-ID");
        assert_eq!(finding.status, ScanStatus::Warn);
    }

    #[test]
    fn persistent_id_binpersid_emits_rule() {
        let bytes = b"\x80\x02X\x04\x00\x00\x00dataQ.";
        let subject = EvidenceSubject::identity("sha256:abcd", "application/octet-stream");
        let analysis = analyze_bytes(bytes).expect("analysis");
        assert_eq!(analysis.persistent_ids.len(), 1);
        assert_eq!(analysis.persistent_ids[0].entry, "BINPERSID");

        let finding = finding_from_analysis(
            analysis,
            "sha256:abcd",
            "application/octet-stream",
            "pickle stream",
            subject,
            Instant::now(),
        );
        assert_eq!(crate::policy::rule_id(&finding), "LF-PICKLE-PERSISTENT-ID");
        assert_eq!(finding.status, ScanStatus::Warn);
    }

    #[test]
    fn truncated_stream_fails_cleanly() {
        assert!(analyze_bytes(b"\x80\x04cfoo\nbar").is_err());
    }

    #[test]
    fn extension_registry_opcode_never_passes_cleanly() -> Result<()> {
        let analysis = analyze_bytes(b"\x80\x02\x82\x01.")?;
        assert!(analysis
            .dangerous
            .iter()
            .any(|value| value.contains("extension code 1")));
        Ok(())
    }

    #[test]
    fn non_allowlisted_newobj_remains_an_unknown_global() -> Result<()> {
        let analysis = analyze_bytes(b"\x80\x02cacme.model\nCustomTensor\n)\x81.")?;
        assert!(analysis.dangerous.is_empty());
        assert!(analysis.unknown_globals.contains("acme.model.CustomTensor"));
        Ok(())
    }

    #[test]
    fn legacy_builtin_getattr_is_unknown_not_an_explicit_execution_primitive() -> Result<()> {
        let analysis = analyze_bytes(b"c__builtin__\ngetattr\n)R.")?;
        assert!(analysis.dangerous.is_empty());
        assert!(analysis.unknown_globals.contains("__builtin__.getattr"));
        Ok(())
    }

    #[test]
    fn unresolved_newobj_is_an_assurance_failure_not_a_dangerous_global() -> Result<()> {
        let analysis = analyze_bytes(b"\x80\x02N)\x81.")?;
        assert!(analysis.dangerous.is_empty());
        assert_eq!(analysis.unresolved_execution.len(), 1);
        assert_eq!(analysis.unresolved_execution[0].opcode, "NEWOBJ");
        Ok(())
    }

    #[test]
    fn routine_value_constructors_do_not_become_dangerous_globals() -> Result<()> {
        for (module, name) in [
            ("_codecs", "encode"),
            ("argparse", "Namespace"),
            ("signal", "Signals"),
            ("torch", "FloatStorage"),
            ("torch.nn.modules.activation", "ReLU"),
            ("torch.nn.modules.linear", "Linear"),
        ] {
            let bytes = format!("c{module}\n{name}\n)R.");
            let analysis = analyze_bytes(bytes.as_bytes())?;
            assert!(analysis.dangerous.is_empty(), "{module}.{name}");
            assert!(analysis.unknown_globals.is_empty(), "{module}.{name}");
        }
        Ok(())
    }

    #[test]
    fn torchscript_local_class_is_allowlisted_for_value_construction() -> Result<()> {
        let analysis = analyze_bytes(&global("__torch__.eddie_model", "Attention"))?;
        assert!(analysis.dangerous.is_empty());
        assert!(analysis.unknown_globals.is_empty());
        Ok(())
    }

    #[test]
    fn framework_enum_and_config_constructors_are_allowlisted() -> Result<()> {
        for (module, name) in [
            ("megatron.core.transformer.enums", "AttnBackend"),
            ("megatron.core.enums", "ModelType"),
            ("peft.utils.peft_types", "PeftType"),
            ("miles.utils.eval_config", "EvalDatasetConfig"),
        ] {
            let bytes = format!("c{module}\n{name}\n)R.");
            let analysis = analyze_bytes(bytes.as_bytes())?;
            assert!(analysis.dangerous.is_empty(), "{module}.{name}");
            assert!(analysis.unknown_globals.is_empty(), "{module}.{name}");
        }
        Ok(())
    }

    #[test]
    fn common_torch_and_transformers_checkpoint_constructors_are_allowlisted() -> Result<()> {
        for (module, name) in [
            ("torch", "device"),
            ("torch.nn.modules.activation", "SiLU"),
            ("torch.nn.modules.batchnorm", "BatchNorm2d"),
            ("torch.nn.modules.container", "ModuleList"),
            ("torch.nn.modules.container", "Sequential"),
            ("torch.nn.modules.conv", "Conv2d"),
            ("torch.nn.modules.pooling", "MaxPool2d"),
            ("torch.nn.modules.upsampling", "Upsample"),
            ("transformers.training_args", "TrainingArguments"),
            ("transformers.training_args", "OptimizerNames"),
            ("transformers.trainer_utils", "IntervalStrategy"),
            ("transformers.trainer_utils", "SchedulerType"),
        ] {
            let bytes = format!("c{module}\n{name}\n)R.");
            let analysis = analyze_bytes(bytes.as_bytes())?;
            assert!(analysis.dangerous.is_empty(), "{module}.{name}");
            assert!(analysis.unknown_globals.is_empty(), "{module}.{name}");
        }
        Ok(())
    }

    // --- Parser differential wiring ---
    //
    // These tests exercise the real primary decode path
    // (`primary_reader_outcome`) and the full orchestration
    // (`parser_differential_outcome`) together, complementing the
    // hand-constructed `ReaderOutcome` unit tests in
    // `crate::assurance::parser_differential`.

    #[test]
    fn primary_accepts_and_agrees_with_secondary_on_a_valid_stream() {
        let bytes = b"\x80\x02N.";
        let outcome = parser_differential_outcome(bytes, None);
        matches!(
            outcome,
            parser_differential::ParserDifferentialOutcome::Agreement
        )
        .then_some(())
        .unwrap_or_else(|| panic!("expected Agreement, got {outcome:?}"));
    }

    #[test]
    fn primary_rejects_unknown_opcode() {
        // 0xFF is not a documented pickle opcode.
        match primary_reader_outcome(b"\x80\x02\xffN.", None) {
            parser_differential::ReaderOutcome::Rejected { reason, .. } => {
                assert!(reason.contains("unknown pickle opcode"));
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[test]
    fn primary_reports_unsupported_protocol_as_incomplete_not_rejected() {
        // Protocol byte 6 is beyond the 0-5 range this parser implements.
        match primary_reader_outcome(b"\x80\x06N.", None) {
            parser_differential::ReaderOutcome::Incomplete { reason, .. } => {
                assert!(reason.contains("unsupported pickle protocol"));
            }
            other => panic!("expected Incomplete, got {other:?}"),
        }
    }

    #[test]
    fn unknown_opcode_yields_assurance_incomplete_not_disagreement() {
        // Fixture required by the parser-differential correctness work: an
        // opcode the primary rejects outright must not be reported as a
        // structural disagreement when the independent reader's honest
        // response is "I don't understand this construct either."
        let outcome = parser_differential_outcome(b"\x80\x02\xffN.", None);
        matches!(
            outcome,
            parser_differential::ParserDifferentialOutcome::AssuranceIncomplete { .. }
        )
        .then_some(())
        .unwrap_or_else(|| panic!("expected AssuranceIncomplete, got {outcome:?}"));
    }

    #[test]
    fn truncated_stream_is_rejected_by_both_readers() {
        let outcome = parser_differential_outcome(b"\x80", None);
        matches!(
            outcome,
            parser_differential::ParserDifferentialOutcome::BothRejected { .. }
        )
        .then_some(())
        .unwrap_or_else(|| panic!("expected BothRejected, got {outcome:?}"));
    }

    #[test]
    fn empty_stream_is_genuinely_both_rejected() {
        let outcome = parser_differential_outcome(b"", None);
        matches!(
            outcome,
            parser_differential::ParserDifferentialOutcome::BothRejected { .. }
        )
        .then_some(())
        .unwrap_or_else(|| panic!("expected BothRejected, got {outcome:?}"));
    }

    #[test]
    fn scan_reaches_disagreement_finding() {
        // Hand-construct a Disagreement outcome (equal-length, divergent
        // transcripts) to verify the finding built from it carries the
        // registered rule id, a Warn status, and byte-offset evidence —
        // without depending on being able to provoke an actual primary/
        // secondary bug from real bytes.
        use parser_differential::{MemoOperation, OpcodeClass, StackEffectClass, TranscriptEntry};
        let entry = |offset: u64, opcode: u8| TranscriptEntry {
            offset,
            opcode,
            opcode_class: OpcodeClass::Other,
            argument_start: offset + 1,
            declared_argument_length: 0,
            frame_boundary: false,
            memo_operation: MemoOperation::None,
            stack_effect_class: StackEffectClass::Push,
            execution_capable: false,
        };
        let outcome = parser_differential::compare(
            parser_differential::ReaderOutcome::Accepted(vec![entry(0, b'N')]),
            parser_differential::ReaderOutcome::Accepted(vec![entry(0, b'S')]),
        );
        let subject = EvidenceSubject::identity("sha256:abcd", "application/octet-stream");
        let finding = parser_differential_finding(outcome, subject).expect("finding expected");
        assert_eq!(
            crate::policy::rule_id(&finding),
            "LF-PICKLE-PARSER-DISAGREEMENT"
        );
        assert_eq!(finding.status, ScanStatus::Warn);
    }

    #[test]
    fn scan_reaches_assurance_incomplete_finding_without_escalating_verdict() {
        let subject = EvidenceSubject::identity("sha256:abcd", "application/octet-stream");
        let outcome =
            parser_differential::ParserDifferentialOutcome::SecondaryAssuranceIncomplete {
                at_offset: Some(3),
                reason: "opcode not understood".to_owned(),
            };
        let finding = parser_differential_finding(outcome, subject).expect("finding expected");
        assert_eq!(
            crate::policy::rule_id(&finding),
            "LF-PICKLE-PARSER-ASSURANCE-INCOMPLETE"
        );
        assert_eq!(
            finding.status,
            ScanStatus::Pass,
            "assurance-incomplete must not escalate the verdict by itself"
        );
        assert!(!finding
            .detail
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase()
            .contains("malicious"));
    }

    #[test]
    fn agreement_and_both_rejected_produce_no_finding() {
        let subject = EvidenceSubject::identity("sha256:abcd", "application/octet-stream");
        assert!(parser_differential_finding(
            parser_differential::ParserDifferentialOutcome::Agreement,
            subject.clone(),
        )
        .is_none());
        assert!(parser_differential_finding(
            parser_differential::ParserDifferentialOutcome::BothRejected {
                primary_reason: "unknown pickle opcode".to_owned(),
                secondary_reason: "unknown pickle opcode".to_owned(),
            },
            subject,
        )
        .is_none());
    }

    #[test]
    fn scan_wires_differential_findings_into_the_pickle_scan_path() -> Result<()> {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        file.write_all(b"\x80\x02N.").expect("write pickle bytes");
        let budget =
            crate::budget::ScanBudget::new(crate::budget::ScanBudgetProfile::Default.limits())?;
        let results = scan(
            file.path(),
            file.as_file(),
            file.as_file().metadata()?.len(),
            "sha256:test",
            "application/octet-stream",
            &budget,
        )?;
        // A clean, agreeing stream must not carry a parser-differential
        // finding at all (Agreement produces no finding).
        assert!(!results
            .iter()
            .any(|finding| crate::policy::rule_id(finding) == "LF-PICKLE-PARSER-DISAGREEMENT"));
        Ok(())
    }

    #[test]
    fn zip_members_receive_parser_differential_assurance() -> Result<()> {
        use std::io::Write;

        let dir = tempfile::tempdir()?;
        let path = dir.path().join("model.pt");
        let file = File::create(&path)?;
        let mut archive = zip::ZipWriter::new(file);
        archive.start_file("archive/data.pkl", zip::write::SimpleFileOptions::default())?;
        archive.write_all(b"\x80\x02\xffN.")?;
        archive.finish()?;

        let file = File::open(&path)?;
        let budget =
            crate::budget::ScanBudget::new(crate::budget::ScanBudgetProfile::Default.limits())?;
        let results = scan(
            &path,
            &file,
            file.metadata()?.len(),
            "sha256:test",
            "application/zip",
            &budget,
        )?;
        let finding = results
            .iter()
            .find(|finding| {
                crate::policy::rule_id(finding) == "LF-PICKLE-PARSER-ASSURANCE-INCOMPLETE"
            })
            .expect("ZIP pickle member must receive differential assurance");
        assert_eq!(
            finding
                .subject
                .as_ref()
                .and_then(|subject| subject.package_relative_path.as_deref()),
            Some("archive/data.pkl")
        );
        Ok(())
    }

    #[test]
    fn primary_differential_transcript_has_an_independent_memory_cap() {
        let mut bytes = vec![0x98; MAX_PRIMARY_TRANSCRIPT_OPCODES + 1];
        bytes.push(b'.');
        match primary_reader_outcome(&bytes, None) {
            parser_differential::ReaderOutcome::Incomplete { reason, .. } => {
                assert!(reason.contains("transcript opcode cap exceeded"));
            }
            other => panic!("expected transcript-cap incompleteness, got {other:?}"),
        }
    }

    #[test]
    fn zip_member_decompression_is_charged_against_the_shared_scan_budget() -> Result<()> {
        // A ZIP-contained pickle member must consume the same
        // ScanBudget::DecompressedBytes dimension every other decompressed
        // layer draws from, not a private counter local to this parser —
        // otherwise a nested/compressed payload could sidestep the global
        // scan-budget ceiling that bounds every other format's expansion.
        use std::io::Write;

        let dir = tempfile::tempdir()?;
        let path = dir.path().join("model.pt");
        let file = File::create(&path)?;
        let mut archive = zip::ZipWriter::new(file);
        let payload = vec![b'A'; 4096];
        archive.start_file("archive/data.pkl", zip::write::SimpleFileOptions::default())?;
        archive.write_all(&payload)?;
        archive.finish()?;

        let file = File::open(&path)?;

        // A budget whose DecompressedBytes ceiling is far smaller than the
        // member's decompressed size must reject the member rather than
        // silently accepting content beyond the shared budget.
        let mut tight_limits = crate::budget::ScanBudgetProfile::Constrained.limits();
        tight_limits.decompressed_bytes = 128;
        let tight_budget = crate::budget::ScanBudget::new(tight_limits)?;
        let results = scan(
            &path,
            &file,
            file.metadata()?.len(),
            "sha256:test",
            "application/zip",
            &tight_budget,
        )?;
        assert!(
            results.iter().any(|result| {
                result.status == ScanStatus::Fail
                    && result
                        .detail
                        .as_deref()
                        .unwrap_or_default()
                        .contains("decompressed-bytes budget")
            }),
            "a ZIP pickle member exceeding the decompressed-bytes budget must be rejected, not silently scanned: {results:?}"
        );

        // The same file with an ordinary budget must scan without error,
        // confirming the rejection above was budget-driven, not a general
        // parse failure.
        let file = File::open(&path)?;
        let ample_budget =
            crate::budget::ScanBudget::new(crate::budget::ScanBudgetProfile::Default.limits())?;
        scan(
            &path,
            &file,
            file.metadata()?.len(),
            "sha256:test",
            "application/zip",
            &ample_budget,
        )?;
        Ok(())
    }

    #[test]
    fn truncated_nested_zip_member_fails_safely_without_panicking() -> Result<()> {
        // A ZIP member whose local header claims a `.pkl` name and a size
        // but whose actual compressed bytes are corrupt/truncated must
        // surface as a bounded error, never a panic, even under repeated
        // scanning.
        use std::io::Write;

        let dir = tempfile::tempdir()?;
        let path = dir.path().join("truncated.pt");
        {
            let file = File::create(&path)?;
            let mut archive = zip::ZipWriter::new(file);
            archive.start_file("archive/data.pkl", zip::write::SimpleFileOptions::default())?;
            archive.write_all(&[0x80, 0x02, 0x4e, 0x2e])?;
            archive.finish()?;
        }
        // Truncate the file after it was written as a valid ZIP so the
        // local/central directory disagree about available bytes.
        let full_len = std::fs::metadata(&path)?.len();
        let truncated = crate::safeio::open_readonly_nofollow(&path)?
            .metadata()?
            .len()
            .min(full_len.saturating_sub(8));
        let file = std::fs::OpenOptions::new().write(true).open(&path)?;
        file.set_len(truncated)?;
        drop(file);

        let file = File::open(&path)?;
        let budget =
            crate::budget::ScanBudget::new(crate::budget::ScanBudgetProfile::Default.limits())?;
        // Either a bounded error or a bounded result is acceptable; a panic
        // is not. Calling this at all is the assertion.
        let _ = scan(
            &path,
            &file,
            file.metadata()?.len(),
            "sha256:test",
            "application/zip",
            &budget,
        );
        Ok(())
    }
}
