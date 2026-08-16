//! Independent structural parser differential for pickle byte streams.
//!
//! This module runs a second, independently authored structural reader over
//! the same bytes the primary pickle disassembler (`crate::formats::pickle`)
//! parses, and compares the two outcomes entry by entry. The primary and
//! secondary readers are run as two separate bounded analyses (see
//! `crate::formats::pickle::primary_reader_outcome` and
//! `secondary_reader_outcome` below); this module only compares the two
//! outcomes it is handed (`compare`) and does not itself decode any bytes.
//!
//! Independence requirement: the byte-walk in `secondary_reader_outcome`
//! (opcode widths, argument-length arithmetic, truncation/overflow
//! detection) is authored from scratch against the documented pickle
//! protocol 0-5 opcode set and must never call into
//! `crate::formats::pickle`'s decode helpers (`read_u8`, `read_u32`,
//! `skip_argument`, `read_tracked_string`, `read_line_string`, ...) or reuse
//! its width/argument-length tables. Sharing that logic would make both
//! readers fail identically on the same malformed input, which would make
//! the differential structurally incapable of detecting the class of bug it
//! exists to catch. The small `opcode_class`/`memo_operation`/
//! `stack_effect_class`/`execution_capable` label functions below are the
//! one exception: they are pure, static lookups on a raw opcode byte (no
//! argument bytes consumed, no stream position advanced) shared by both
//! readers so their transcript entries use a common vocabulary for
//! comparison. Labeling a byte is not decoding it.
//!
//! Rejection and incompleteness are distinct outcomes, not degrees of the
//! same thing. `Rejected` means the reader fully understood the construct it
//! encountered and concluded the byte stream is structurally invalid.
//! `Incomplete` means the reader could not reach a verdict because of its
//! own bound, missing protocol-version coverage, an exhausted resource
//! budget, or an opcode it does not implement — a limitation of this
//! assurance pass, not a property of the artifact. Conflating the two would
//! let an artifact-directed finding fire because Layerfault's own secondary
//! reader has a coverage gap, which is exactly the failure mode this module
//! exists to avoid.

use serde::{Deserialize, Serialize};

/// Opcode cap for the independent structural reader. This is deliberately
/// lower than the primary parser's normal scan cap because a differential
/// retains two structural transcripts concurrently.
pub const MAX_SKELETON_OPCODES: usize = 262_144;
const MAX_SKELETON_ARGUMENT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_SKELETON_LINE_BYTES: u64 = 1024 * 1024;

/// Coarse structural category of an opcode byte. A pure label, not a
/// decoding result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpcodeClass {
    /// Resolves a module/class reference (GLOBAL, INST, STACK_GLOBAL).
    Global,
    /// Constructs or invokes a resolved callable (REDUCE, OBJ, NEWOBJ,
    /// NEWOBJ_EX).
    Execute,
    /// Application-defined persistent-object resolution (PERSID,
    /// BINPERSID).
    PersistentId,
    /// Registered-extension opcodes (EXT1/EXT2/EXT4).
    Extension,
    /// The STOP opcode.
    Stop,
    Other,
}

/// Whether an opcode stores into or reads from the memo table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoOperation {
    Store,
    Get,
    None,
}

/// Coarse value-stack effect of an opcode. Advisory only: it labels the
/// opcode byte itself, not the runtime stack state, so it does not require
/// tracking a stack to compute and cannot itself disagree between two
/// correct readers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StackEffectClass {
    Push,
    Pop,
    PopToMark,
    DupTop,
    Replace,
    None,
}

/// Static classification of a raw pickle opcode byte. Shared by both
/// readers; see the module-level independence note for why this sharing is
/// safe.
pub fn opcode_class(op: u8) -> OpcodeClass {
    match op {
        b'c' | b'i' | 0x93 => OpcodeClass::Global,
        b'R' | b'o' | 0x81 | 0x92 => OpcodeClass::Execute,
        b'P' | b'Q' => OpcodeClass::PersistentId,
        0x82..=0x84 => OpcodeClass::Extension,
        b'.' => OpcodeClass::Stop,
        _ => OpcodeClass::Other,
    }
}

pub fn memo_operation(op: u8) -> MemoOperation {
    match op {
        b'p' | b'q' | b'r' | 0x94 => MemoOperation::Store,
        b'g' | b'h' | b'j' => MemoOperation::Get,
        _ => MemoOperation::None,
    }
}

pub fn stack_effect_class(op: u8) -> StackEffectClass {
    match op {
        b'0' | b'a' | b's' => StackEffectClass::Pop,
        b'1' | b'e' | b'l' | b't' | b'd' | 0x91 | b'u' | 0x90 => StackEffectClass::PopToMark,
        b'2' => StackEffectClass::DupTop,
        b'R' | b'b' | 0x81 | 0x92 | b'o' | 0x85 | 0x86 | 0x87 => StackEffectClass::Replace,
        b'(' | 0x80 | 0x95 | 0x98 | b'.' | b'p' | b'q' | b'r' | 0x94 => StackEffectClass::None,
        _ => StackEffectClass::Push,
    }
}

/// Whether this opcode class is capable of resolving or invoking a callable.
pub fn execution_capable(op: u8) -> bool {
    matches!(opcode_class(op), OpcodeClass::Global | OpcodeClass::Execute)
}

/// One opcode occurrence in a canonical structural transcript, as produced
/// independently by the primary parser and by `secondary_reader_outcome`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptEntry {
    /// Byte offset where this opcode starts.
    pub offset: u64,
    pub opcode: u8,
    pub opcode_class: OpcodeClass,
    /// Byte offset immediately after the opcode byte, where its argument (if
    /// any) begins.
    pub argument_start: u64,
    /// Total bytes consumed by this opcode's argument, including any
    /// length-prefix bytes.
    pub declared_argument_length: u64,
    /// Whether this entry is a FRAME opcode, marking the start of a new
    /// frame region.
    pub frame_boundary: bool,
    pub memo_operation: MemoOperation,
    pub stack_effect_class: StackEffectClass,
    pub execution_capable: bool,
}

/// The result of running one structural reader (primary or secondary) to
/// completion over a byte stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReaderOutcome {
    /// The reader reached STOP and produced a complete transcript.
    Accepted(Vec<TranscriptEntry>),
    /// The reader fully understood the construct it encountered and
    /// determined the byte stream is structurally invalid.
    Rejected {
        at_offset: Option<u64>,
        reason: String,
    },
    /// The reader could not reach a verdict: an unsupported construct, an
    /// unsupported protocol version, an exhausted analysis budget, a
    /// configured limit, or missing implementation coverage. This describes
    /// a limitation of this assurance pass, not a property of the artifact.
    Incomplete {
        at_offset: Option<u64>,
        reason: String,
    },
}

impl ReaderOutcome {
    fn describe(&self) -> String {
        match self {
            ReaderOutcome::Accepted(entries) => {
                format!("accepted ({} opcodes)", entries.len())
            }
            ReaderOutcome::Rejected { at_offset, reason } => match at_offset {
                Some(offset) => format!("rejected at offset {offset}: {reason}"),
                None => format!("rejected: {reason}"),
            },
            ReaderOutcome::Incomplete { at_offset, reason } => match at_offset {
                Some(offset) => format!("incomplete at offset {offset}: {reason}"),
                None => format!("incomplete: {reason}"),
            },
        }
    }
}

/// One side of a reported divergence between the two readers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DivergenceSide {
    /// This reader produced a transcript entry at the divergence offset.
    Entry(TranscriptEntry),
    /// This reader rejected the stream at (or before) the divergence
    /// offset.
    Rejected(String),
    /// This reader's transcript has no entry here (it ended earlier than
    /// the other reader's).
    Missing,
}

/// The result of comparing two independent `ReaderOutcome`s for the same
/// byte stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ParserDifferentialOutcome {
    /// Both readers accepted the stream and produced identical transcripts.
    Agreement,
    /// The two readers produced different structural understandings of the
    /// same byte stream: one accepted where the other rejected, or their
    /// accepted transcripts diverge. This is a genuine disagreement, not an
    /// assurance gap.
    Disagreement {
        first_divergence: u64,
        primary: DivergenceSide,
        secondary: DivergenceSide,
    },
    /// The primary parser accepted the stream; the secondary reader could
    /// not reach a verdict. Not evidence against the primary.
    SecondaryAssuranceIncomplete {
        at_offset: Option<u64>,
        reason: String,
    },
    /// The secondary reader accepted the stream; the primary parser could
    /// not reach a verdict.
    PrimaryAssuranceIncomplete {
        at_offset: Option<u64>,
        reason: String,
    },
    /// At least one side is `Incomplete` and the other did not accept
    /// (either also `Incomplete`, or `Rejected`). Any combination touching a
    /// coverage/budget limitation is assurance-incomplete, never a
    /// structural disagreement or a joint rejection.
    AssuranceIncomplete {
        primary_reason: String,
        secondary_reason: String,
    },
    /// Both readers independently determined the stream is structurally
    /// invalid. This is a rejection outcome, not agreement.
    BothRejected {
        primary_reason: String,
        secondary_reason: String,
    },
}

fn diff_transcripts(
    primary: &[TranscriptEntry],
    secondary: &[TranscriptEntry],
) -> ParserDifferentialOutcome {
    let max_len = primary.len().max(secondary.len());
    for index in 0..max_len {
        match (primary.get(index), secondary.get(index)) {
            (Some(p), Some(s)) if p == s => continue,
            (Some(p), Some(s)) => {
                return ParserDifferentialOutcome::Disagreement {
                    first_divergence: p.offset,
                    primary: DivergenceSide::Entry(p.clone()),
                    secondary: DivergenceSide::Entry(s.clone()),
                }
            }
            (Some(p), None) => {
                return ParserDifferentialOutcome::Disagreement {
                    first_divergence: p.offset,
                    primary: DivergenceSide::Entry(p.clone()),
                    secondary: DivergenceSide::Missing,
                }
            }
            (None, Some(s)) => {
                return ParserDifferentialOutcome::Disagreement {
                    first_divergence: s.offset,
                    primary: DivergenceSide::Missing,
                    secondary: DivergenceSide::Entry(s.clone()),
                }
            }
            (None, None) => unreachable!("index bounded by max_len"),
        }
    }
    ParserDifferentialOutcome::Agreement
}

fn disagreement_secondary_rejected(
    primary: &[TranscriptEntry],
    at_offset: Option<u64>,
    reason: String,
) -> ParserDifferentialOutcome {
    let offset = at_offset.unwrap_or(0);
    let entry = primary.iter().find(|entry| entry.offset == offset).cloned();
    ParserDifferentialOutcome::Disagreement {
        first_divergence: offset,
        primary: entry
            .map(DivergenceSide::Entry)
            .unwrap_or(DivergenceSide::Missing),
        secondary: DivergenceSide::Rejected(reason),
    }
}

fn disagreement_primary_rejected(
    secondary: &[TranscriptEntry],
    at_offset: Option<u64>,
    reason: String,
) -> ParserDifferentialOutcome {
    let offset = at_offset.unwrap_or(0);
    let entry = secondary
        .iter()
        .find(|entry| entry.offset == offset)
        .cloned();
    ParserDifferentialOutcome::Disagreement {
        first_divergence: offset,
        primary: DivergenceSide::Rejected(reason),
        secondary: entry
            .map(DivergenceSide::Entry)
            .unwrap_or(DivergenceSide::Missing),
    }
}

/// Compare two independently produced `ReaderOutcome`s. This function does
/// not decode any bytes; it only classifies the relationship between two
/// outcomes that were each computed as a separate bounded analysis.
///
/// | primary    | secondary  | outcome                        |
/// |------------|------------|---------------------------------|
/// | accepted   | accepted   | `Agreement` / `Disagreement`    |
/// | accepted   | incomplete | `SecondaryAssuranceIncomplete`  |
/// | incomplete | accepted   | `PrimaryAssuranceIncomplete`    |
/// | rejected   | accepted   | `Disagreement`                  |
/// | accepted   | rejected   | `Disagreement`                  |
/// | rejected   | rejected   | `BothRejected`                  |
/// | otherwise (any remaining combination touching `incomplete`) | `AssuranceIncomplete` |
pub fn compare(primary: ReaderOutcome, secondary: ReaderOutcome) -> ParserDifferentialOutcome {
    match (primary, secondary) {
        (ReaderOutcome::Accepted(p), ReaderOutcome::Accepted(s)) => diff_transcripts(&p, &s),
        (ReaderOutcome::Accepted(p), ReaderOutcome::Rejected { at_offset, reason }) => {
            disagreement_secondary_rejected(&p, at_offset, reason)
        }
        (ReaderOutcome::Rejected { at_offset, reason }, ReaderOutcome::Accepted(s)) => {
            disagreement_primary_rejected(&s, at_offset, reason)
        }
        (ReaderOutcome::Accepted(_), ReaderOutcome::Incomplete { at_offset, reason }) => {
            ParserDifferentialOutcome::SecondaryAssuranceIncomplete { at_offset, reason }
        }
        (ReaderOutcome::Incomplete { at_offset, reason }, ReaderOutcome::Accepted(_)) => {
            ParserDifferentialOutcome::PrimaryAssuranceIncomplete { at_offset, reason }
        }
        (
            ReaderOutcome::Rejected { reason: pr, .. },
            ReaderOutcome::Rejected { reason: sr, .. },
        ) => ParserDifferentialOutcome::BothRejected {
            primary_reason: pr,
            secondary_reason: sr,
        },
        (primary, secondary) => ParserDifferentialOutcome::AssuranceIncomplete {
            primary_reason: primary.describe(),
            secondary_reason: secondary.describe(),
        },
    }
}

fn advance_by(
    bytes_len: usize,
    position: usize,
    declared_length: u64,
    start: u64,
) -> Result<usize, ReaderOutcome> {
    let length = usize::try_from(declared_length).map_err(|_| ReaderOutcome::Incomplete {
        at_offset: Some(start),
        reason: "declared argument length exceeds addressable range".to_owned(),
    })?;
    let end = position
        .checked_add(length)
        .ok_or(ReaderOutcome::Incomplete {
            at_offset: Some(start),
            reason: "declared argument length arithmetic overflow".to_owned(),
        })?;
    if end > bytes_len {
        return Err(ReaderOutcome::Rejected {
            at_offset: Some(start),
            reason: "truncated argument: insufficient bytes remaining".to_owned(),
        });
    }
    Ok(end)
}

fn consume_argument(
    bytes: &[u8],
    position: usize,
    start: u64,
    declared_length: u64,
) -> Result<usize, ReaderOutcome> {
    if declared_length > MAX_SKELETON_ARGUMENT_BYTES {
        return Err(ReaderOutcome::Incomplete {
            at_offset: Some(start),
            reason: "argument length exceeds the independent reader's bounded cap".to_owned(),
        });
    }
    advance_by(bytes.len(), position, declared_length, start)
}

fn read_u8_at(bytes: &[u8], position: usize) -> Result<u8, ReaderOutcome> {
    bytes.get(position).copied().ok_or(ReaderOutcome::Rejected {
        at_offset: Some(position as u64),
        reason: "truncated argument: insufficient bytes remaining".to_owned(),
    })
}

fn read_u32_at(bytes: &[u8], position: usize) -> Result<u32, ReaderOutcome> {
    let slice = bytes
        .get(position..position + 4)
        .ok_or(ReaderOutcome::Rejected {
            at_offset: Some(position as u64),
            reason: "truncated argument: insufficient bytes remaining".to_owned(),
        })?;
    Ok(u32::from_le_bytes(slice.try_into().expect("checked width")))
}

fn read_u64_at(bytes: &[u8], position: usize) -> Result<u64, ReaderOutcome> {
    let slice = bytes
        .get(position..position + 8)
        .ok_or(ReaderOutcome::Rejected {
            at_offset: Some(position as u64),
            reason: "truncated argument: insufficient bytes remaining".to_owned(),
        })?;
    Ok(u64::from_le_bytes(slice.try_into().expect("checked width")))
}

/// Scan forward from `position` for a `\n` line terminator, returning the
/// position immediately after it.
fn scan_line(bytes: &[u8], position: usize, start: u64) -> Result<usize, ReaderOutcome> {
    let rest = &bytes[position..];
    match rest.iter().position(|byte| *byte == b'\n') {
        Some(offset) => {
            if offset as u64 > MAX_SKELETON_LINE_BYTES {
                return Err(ReaderOutcome::Incomplete {
                    at_offset: Some(start),
                    reason: "line argument exceeds the independent reader's bounded cap".to_owned(),
                });
            }
            Ok(position + offset + 1)
        }
        None => Err(ReaderOutcome::Rejected {
            at_offset: Some(start),
            reason: "truncated argument: no line terminator before end of stream".to_owned(),
        }),
    }
}

/// Opcodes with no stream-level argument bytes: their operands (if any) come
/// from the value stack, not from new bytes in the stream.
fn is_zero_argument_opcode(op: u8) -> bool {
    matches!(
        op,
        b'N' | 0x88
            | 0x89
            | b']'
            | b')'
            | b'}'
            | 0x8f
            | 0x97
            | 0x98
            | b'('
            | b'0'
            | b'2'
            | b'1'
            | b'a'
            | b'e'
            | b'l'
            | b't'
            | b'd'
            | 0x91
            | 0x85
            | 0x86
            | 0x87
            | b's'
            | b'u'
            | 0x90
            | 0x94
            | 0x93
            | b'R'
            | b'b'
            | b'o'
            | 0x81
            | 0x92
            | b'Q'
    )
}

/// Advance past one opcode's argument bytes (if any), returning the new
/// stream position. `position` is the byte offset immediately after the
/// opcode byte itself.
fn consume_opcode_argument(
    bytes: &[u8],
    position: usize,
    start: u64,
    op: u8,
) -> Result<usize, ReaderOutcome> {
    if is_zero_argument_opcode(op) {
        return Ok(position);
    }
    match op {
        b'J' => advance_by(bytes.len(), position, 4, start),
        b'K' => advance_by(bytes.len(), position, 1, start),
        b'M' => advance_by(bytes.len(), position, 2, start),
        b'G' => advance_by(bytes.len(), position, 8, start),
        b'h' => advance_by(bytes.len(), position, 1, start),
        b'j' => advance_by(bytes.len(), position, 4, start),
        b'q' => advance_by(bytes.len(), position, 1, start),
        b'r' => advance_by(bytes.len(), position, 4, start),
        0x80 => advance_by(bytes.len(), position, 1, start),
        0x82 => advance_by(bytes.len(), position, 1, start),
        0x83 => advance_by(bytes.len(), position, 2, start),
        0x84 => advance_by(bytes.len(), position, 4, start),
        0x95 => advance_by(bytes.len(), position, 8, start),
        b'I' | b'L' | b'F' | b'S' | b'V' | b'p' | b'g' | b'P' => scan_line(bytes, position, start),
        b'c' | b'i' => {
            let after_module = scan_line(bytes, position, start)?;
            scan_line(bytes, after_module, start)
        }
        b'T' | b'B' | b'X' => {
            let length = u64::from(read_u32_at(bytes, position)?);
            consume_argument(bytes, position + 4, start, length)
        }
        b'U' | b'C' | 0x8c => {
            let length = u64::from(read_u8_at(bytes, position)?);
            consume_argument(bytes, position + 1, start, length)
        }
        0x8d | 0x8e | 0x96 => {
            let length = read_u64_at(bytes, position)?;
            consume_argument(bytes, position + 8, start, length)
        }
        0x8a => {
            let length = u64::from(read_u8_at(bytes, position)?);
            consume_argument(bytes, position + 1, start, length)
        }
        0x8b => {
            let length = u64::from(read_u32_at(bytes, position)?);
            consume_argument(bytes, position + 4, start, length)
        }
        b'.' => Ok(position),
        _ => Err(ReaderOutcome::Incomplete {
            at_offset: Some(start),
            reason: format!(
                "opcode 0x{op:02x} is not understood by the independent structural reader"
            ),
        }),
    }
}

/// Independently authored structural reader used only as a disagreement
/// detector. It deliberately does not resolve stack semantics or declare a
/// pickle safe; it only walks the byte stream and reports what it finds.
/// See the module-level documentation for the independence requirement this
/// function exists to satisfy.
pub fn secondary_reader_outcome(
    bytes: &[u8],
    budget: Option<&crate::budget::ScanBudget>,
) -> ReaderOutcome {
    let mut entries = Vec::new();
    let mut position = 0usize;
    let mut opcode_index = 0u64;
    while position < bytes.len() {
        if entries.len() >= MAX_SKELETON_OPCODES {
            return ReaderOutcome::Incomplete {
                at_offset: Some(position as u64),
                reason: "independent structural reader opcode cap exceeded".to_owned(),
            };
        }
        opcode_index = opcode_index.saturating_add(1);
        if opcode_index.is_multiple_of(256) {
            if let Some(budget) = budget {
                if let Err(error) = budget.check() {
                    return ReaderOutcome::Incomplete {
                        at_offset: Some(position as u64),
                        reason: format!("independent structural reader budget exhausted: {error}"),
                    };
                }
            }
        }
        let start = position as u64;
        let op = bytes[position];
        position += 1;
        let argument_start = position as u64;
        position = match consume_opcode_argument(bytes, position, start, op) {
            Ok(next) => next,
            Err(outcome) => return outcome,
        };
        let declared_argument_length = position as u64 - argument_start;
        entries.push(TranscriptEntry {
            offset: start,
            opcode: op,
            opcode_class: opcode_class(op),
            argument_start,
            declared_argument_length,
            frame_boundary: op == 0x95,
            memo_operation: memo_operation(op),
            stack_effect_class: stack_effect_class(op),
            execution_capable: execution_capable(op),
        });
        if op == b'.' {
            return ReaderOutcome::Accepted(entries);
        }
    }
    ReaderOutcome::Rejected {
        at_offset: entries.last().map(|entry| entry.offset),
        reason: "independent structural reader reached end of stream without a STOP opcode"
            .to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accepted_entries(outcome: ReaderOutcome) -> Vec<TranscriptEntry> {
        match outcome {
            ReaderOutcome::Accepted(entries) => entries,
            other => panic!("expected Accepted, got {other:?}"),
        }
    }

    #[test]
    fn accepts_minimal_valid_stream() {
        // PROTO 2, NONE, STOP.
        let bytes = b"\x80\x02N.";
        let entries = accepted_entries(secondary_reader_outcome(bytes, None));
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].opcode, 0x80);
        assert_eq!(entries[0].declared_argument_length, 1);
        assert_eq!(entries[1].opcode, b'N');
        assert_eq!(entries[1].declared_argument_length, 0);
        assert_eq!(entries[2].opcode, b'.');
        assert_eq!(entries[2].opcode_class, OpcodeClass::Stop);
    }

    #[test]
    fn binput_is_one_byte_not_four() {
        // PROTO 2, NONE, BINPUT 0, STOP. If BINPUT ('q') were misread as a
        // 4-byte argument, this stream would be misparsed as truncated
        // (only one memo-index byte follows before STOP).
        let bytes = b"\x80\x02Nq\x00.";
        let entries = accepted_entries(secondary_reader_outcome(bytes, None));
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[2].opcode, b'q');
        assert_eq!(entries[2].declared_argument_length, 1);
        assert_eq!(entries[3].opcode, b'.');
    }

    #[test]
    fn truncated_stream_is_rejected() {
        // PROTO opcode declares a 1-byte argument but the stream ends first.
        let bytes = b"\x80";
        match secondary_reader_outcome(bytes, None) {
            ReaderOutcome::Rejected { .. } => {}
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[test]
    fn stream_without_stop_is_rejected() {
        let bytes = b"\x80\x02N";
        match secondary_reader_outcome(bytes, None) {
            ReaderOutcome::Rejected { .. } => {}
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[test]
    fn unknown_opcode_is_incomplete_not_rejected() {
        // 0xFF is not a documented pickle opcode.
        let bytes = b"\x80\x02\xffN.";
        match secondary_reader_outcome(bytes, None) {
            ReaderOutcome::Incomplete { at_offset, .. } => assert_eq!(at_offset, Some(2)),
            other => panic!("expected Incomplete, got {other:?}"),
        }
    }

    #[test]
    fn empty_stream_is_rejected() {
        match secondary_reader_outcome(b"", None) {
            ReaderOutcome::Rejected { at_offset, .. } => assert_eq!(at_offset, None),
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    fn entry(offset: u64) -> TranscriptEntry {
        TranscriptEntry {
            offset,
            opcode: b'N',
            opcode_class: OpcodeClass::Other,
            argument_start: offset + 1,
            declared_argument_length: 0,
            frame_boundary: false,
            memo_operation: MemoOperation::None,
            stack_effect_class: StackEffectClass::Push,
            execution_capable: false,
        }
    }

    #[test]
    fn identical_transcripts_agree() {
        let a = vec![entry(0), entry(1)];
        let b = vec![entry(0), entry(1)];
        matches!(
            compare(ReaderOutcome::Accepted(a), ReaderOutcome::Accepted(b)),
            ParserDifferentialOutcome::Agreement
        )
        .then_some(())
        .expect("agreement expected");
    }

    #[test]
    fn divergent_transcripts_with_equal_length_disagree() {
        let a = vec![entry(0), entry(1)];
        let mut b = vec![entry(0), entry(1)];
        b[1].opcode = b'S';
        match compare(ReaderOutcome::Accepted(a), ReaderOutcome::Accepted(b)) {
            ParserDifferentialOutcome::Disagreement {
                first_divergence, ..
            } => {
                assert_eq!(first_divergence, 1);
            }
            other => panic!("expected Disagreement, got {other:?}"),
        }
    }

    #[test]
    fn secondary_incomplete_does_not_report_disagreement() {
        let outcome = compare(
            ReaderOutcome::Accepted(vec![entry(0)]),
            ReaderOutcome::Incomplete {
                at_offset: Some(4),
                reason: "opcode not understood".to_owned(),
            },
        );
        match outcome {
            ParserDifferentialOutcome::SecondaryAssuranceIncomplete { at_offset, .. } => {
                assert_eq!(at_offset, Some(4));
            }
            other => panic!("expected SecondaryAssuranceIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn primary_incomplete_does_not_report_disagreement() {
        let outcome = compare(
            ReaderOutcome::Incomplete {
                at_offset: Some(2),
                reason: "unsupported protocol".to_owned(),
            },
            ReaderOutcome::Accepted(vec![entry(0)]),
        );
        match outcome {
            ParserDifferentialOutcome::PrimaryAssuranceIncomplete { at_offset, .. } => {
                assert_eq!(at_offset, Some(2));
            }
            other => panic!("expected PrimaryAssuranceIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn mutual_budget_exhaustion_is_not_both_rejected() {
        let outcome = compare(
            ReaderOutcome::Incomplete {
                at_offset: Some(1),
                reason: "global scan budget exhausted".to_owned(),
            },
            ReaderOutcome::Incomplete {
                at_offset: Some(1),
                reason: "independent structural reader budget exhausted".to_owned(),
            },
        );
        matches!(
            outcome,
            ParserDifferentialOutcome::AssuranceIncomplete { .. }
        )
        .then_some(())
        .expect("assurance-incomplete expected, not BothRejected");
    }

    #[test]
    fn incomplete_and_rejected_is_not_both_rejected() {
        let outcome = compare(
            ReaderOutcome::Incomplete {
                at_offset: Some(1),
                reason: "unsupported protocol".to_owned(),
            },
            ReaderOutcome::Rejected {
                at_offset: Some(1),
                reason: "truncated".to_owned(),
            },
        );
        matches!(
            outcome,
            ParserDifferentialOutcome::AssuranceIncomplete { .. }
        )
        .then_some(())
        .expect("assurance-incomplete expected, not BothRejected");
    }

    #[test]
    fn both_genuinely_rejected_is_both_rejected() {
        let outcome = compare(
            ReaderOutcome::Rejected {
                at_offset: Some(1),
                reason: "unknown pickle opcode".to_owned(),
            },
            ReaderOutcome::Rejected {
                at_offset: Some(1),
                reason: "truncated argument".to_owned(),
            },
        );
        matches!(outcome, ParserDifferentialOutcome::BothRejected { .. })
            .then_some(())
            .expect("BothRejected expected");
    }

    #[test]
    fn one_sided_rejection_is_disagreement() {
        let accepted = vec![entry(0)];
        let outcome = compare(
            ReaderOutcome::Accepted(accepted),
            ReaderOutcome::Rejected {
                at_offset: Some(0),
                reason: "truncated argument".to_owned(),
            },
        );
        match outcome {
            ParserDifferentialOutcome::Disagreement { secondary, .. } => {
                matches!(secondary, DivergenceSide::Rejected(_))
                    .then_some(())
                    .expect("secondary side should be Rejected");
            }
            other => panic!("expected Disagreement, got {other:?}"),
        }
    }
}
