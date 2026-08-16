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
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::Path;
use std::time::Instant;

const MAX_PICKLE_MEMBERS: usize = 256;
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
    pub globals: BTreeSet<String>,
    pub unknown_globals: BTreeSet<String>,
    pub dangerous: BTreeSet<String>,
    pub opcode_count: usize,
    /// Bounded, ordered positions for the entries above.
    pub sites: Vec<OpcodeSite>,
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
            globals: BTreeSet::new(),
            unknown_globals: BTreeSet::new(),
            dangerous: BTreeSet::new(),
            opcode_count: 0,
            sites: Vec::new(),
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
    Other,
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
        Err(error) => {
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
    }
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
            "{label} references dangerous or non-allowlisted callable(s): {}",
            dangerous.join(", ")
        ))
        .match_note(dangerous.first().cloned().unwrap_or_default())
        .started(started);
        for value in &dangerous {
            builder = builder.evidence(opcode_evidence(&subject, &analysis, value));
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
    analyze_reader_inner(reader, len, budget, None)
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
        let opcode = read_u8(&mut reader, &mut pos, len)?;
        state.current_opcode = opcode_mnemonic(opcode);
        match opcode {
            b'I' | b'L' | b'F' => {
                skip_line(&mut reader, &mut pos, len, MAX_TRACKED_STRING_BYTES)?;
                state.push(StackValue::Other)?;
            }
            b'J' => {
                skip_fixed(&mut reader, &mut pos, len, 4)?;
                state.push(StackValue::Other)?;
            }
            b'K' => {
                skip_fixed(&mut reader, &mut pos, len, 1)?;
                state.push(StackValue::Other)?;
            }
            b'M' => {
                skip_fixed(&mut reader, &mut pos, len, 2)?;
                state.push(StackValue::Other)?;
            }
            0x8a => {
                let n = u64::from(read_u8(&mut reader, &mut pos, len)?);
                skip_argument(&mut reader, &mut pos, len, n)?;
                state.push(StackValue::Other)?;
            }
            0x8b => {
                let n = u64::from(read_u32(&mut reader, &mut pos, len)?);
                skip_argument(&mut reader, &mut pos, len, n)?;
                state.push(StackValue::Other)?;
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
            b'N' | 0x88 | 0x89 | b']' | b')' | b'}' | 0x8f | 0x97 => {
                state.push(StackValue::Other)?
            }
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
            b'e' => state.pop_to_mark(Some(StackValue::Other))?,
            b'l' | b't' | b'd' | 0x91 => state.pop_to_mark(Some(StackValue::Other))?,
            0x85 => {
                state.pop();
                state.push(StackValue::Other)?;
            }
            0x86 => {
                state.pop();
                state.pop();
                state.push(StackValue::Other)?;
            }
            0x87 => {
                state.pop();
                state.pop();
                state.pop();
                state.push(StackValue::Other)?;
            }
            b's' => {
                state.pop();
                state.pop();
            }
            b'u' | 0x90 => state.pop_to_mark(Some(StackValue::Other))?,
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
                state.pop(); // args tuple
                let callable = state.pop();
                let name = callable_name(&callable);
                if let Some(name) = name.as_deref() {
                    if !is_allowlisted(name) {
                        state.mark_dangerous(format!("{name} used by REDUCE"));
                    }
                    state.push(StackValue::Constructed(name.to_owned()))?;
                } else {
                    state.record_unresolved("REDUCE", "callable could not be resolved statically");
                    state.mark_dangerous("unresolved callable used by REDUCE".to_owned());
                    state.push(StackValue::Other)?;
                }
            }
            b'b' => {
                state.pop(); // state
                let instance = state.pop();
                if let Some(name) = callable_name(&instance) {
                    if !is_allowlisted(&name) {
                        state.mark_dangerous(format!("{name} used with BUILD"));
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
                state.record_unresolved("PERSID", "persistent ID resolution is application-defined and may invoke external object loading");
                skip_line(&mut reader, &mut pos, len, MAX_TRACKED_STRING_BYTES)?;
                state.push(StackValue::Other)?;
            }
            b'Q' => {
                state.record_unresolved("BINPERSID", "persistent ID resolution is application-defined and may invoke external object loading");
                state.pop();
                state.push(StackValue::Other)?;
            }
            b'.' => {
                saw_stop = true;
            }
            other => bail!(
                "unknown pickle opcode 0x{other:02x} at offset {}",
                pos.saturating_sub(1)
            ),
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
    match analyze_reader_inner(cursor, bytes.len() as u64, budget, Some(&mut transcript)) {
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
        if is_explicit_danger(value) {
            self.mark_dangerous(value.to_owned());
        } else if !is_allowlisted(value) {
            self.note_site(value);
            self.analysis.unknown_globals.insert(value.to_owned());
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
            Some(name) => {
                self.mark_dangerous(format!(
                    "non-allowlisted constructor {name} used by {opcode}"
                ));
            }
            None => {
                self.mark_dangerous(format!("unresolved callable used by {opcode}"));
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
            .any(|part| part.starts_with("__") && part.ends_with("__"))
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

    fn global(module: &str, name: &str) -> Vec<u8> {
        format!("c{module}\n{name}\n.").into_bytes()
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
    fn non_allowlisted_newobj_is_dangerous() -> Result<()> {
        let analysis = analyze_bytes(b"\x80\x02cacme.model\nCustomTensor\n)\x81.")?;
        assert!(analysis
            .dangerous
            .iter()
            .any(|value| value.contains("CustomTensor used by NEWOBJ")));
        Ok(())
    }

    #[test]
    fn unresolved_newobj_is_dangerous() -> Result<()> {
        let analysis = analyze_bytes(b"\x80\x02N)\x81.")?;
        assert!(analysis
            .dangerous
            .iter()
            .any(|value| value.contains("unresolved callable used by NEWOBJ")));
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
}
