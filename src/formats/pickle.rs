//! Bounded static pickle opcode analysis.
//!
//! Layerfault never unpickles or executes pickle content. This module only
//! disassembles the documented protocol 0-5 opcode stream far enough to resolve
//! GLOBAL/STACK_GLOBAL references and dangerous construction primitives.

use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use anyhow::{anyhow, bail, Context, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::{Component, Path};
use std::time::Instant;

const MAX_PICKLE_MEMBERS: usize = 256;
const MAX_PICKLE_MEMBER_BYTES: u64 = 64 * 1024 * 1024;
const MAX_TOTAL_PICKLE_BYTES: u64 = 256 * 1024 * 1024;
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

#[derive(Debug, Clone, Default)]
pub struct PickleAnalysis {
    pub globals: BTreeSet<String>,
    pub unknown_globals: BTreeSet<String>,
    pub dangerous: BTreeSet<String>,
    pub opcode_count: usize,
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
) -> Result<Vec<LayerScanResult>> {
    let mut magic = [0u8; 4];
    let mut prefix = file.try_clone()?;
    prefix.seek(SeekFrom::Start(0))?;
    let count = prefix.read(&mut magic)?;
    if count >= 4 && magic == *b"PK\x03\x04" {
        return Ok(match scan_zip(path, file, identity, media) {
            Ok(results) => results,
            Err(error) => vec![LayerScanResult {
                layer_digest: identity.to_owned(),
                media_type: media.to_owned(),
                check_type: CheckType::PickleStructure,
                status: ScanStatus::Fail,
                finding_class: FindingClass::Structural,
                confidence: Confidence::High,
                detail: Some(format!("Malformed or unsafe pickle ZIP container: {error}")),
                matches: vec![format!("[LF-PICKLE-MALFORMED] {error}")],
                duration_ms: 0,
            }],
        });
    }
    Ok(vec![scan_stream(
        file.try_clone()?,
        size,
        identity,
        media,
        None,
    )])
}

pub fn analyze_bytes(bytes: &[u8]) -> Result<PickleAnalysis> {
    let cursor = Cursor::new(bytes);
    analyze_reader(cursor, bytes.len() as u64)
}

fn scan_stream<R: Read + Seek>(
    reader: R,
    len: u64,
    identity: &str,
    media: &str,
    member: Option<&str>,
) -> LayerScanResult {
    let started = Instant::now();
    let label = member
        .map(|name| format!("pickle member '{name}'"))
        .unwrap_or_else(|| "pickle stream".to_owned());
    match analyze_reader(reader, len) {
        Ok(analysis) => finding_from_analysis(analysis, identity, media, &label, started),
        Err(error) => LayerScanResult {
            layer_digest: identity.to_owned(),
            media_type: media.to_owned(),
            check_type: CheckType::PickleStructure,
            status: ScanStatus::Fail,
            finding_class: FindingClass::Structural,
            confidence: Confidence::High,
            detail: Some(format!("Malformed or unsafe {label}: {error}")),
            matches: vec![format!(
                "[LF-PICKLE-MALFORMED] bounded pickle opcode parsing failed for {label}"
            )],
            duration_ms: elapsed(started),
        },
    }
}

fn finding_from_analysis(
    analysis: PickleAnalysis,
    identity: &str,
    media: &str,
    label: &str,
    started: Instant,
) -> LayerScanResult {
    let globals = analysis.globals.iter().cloned().collect::<Vec<_>>();
    let dangerous = analysis.dangerous.iter().cloned().collect::<Vec<_>>();
    let unknown = analysis.unknown_globals.iter().cloned().collect::<Vec<_>>();
    if !dangerous.is_empty() {
        return LayerScanResult {
            layer_digest: identity.to_owned(),
            media_type: media.to_owned(),
            check_type: CheckType::PickleStructure,
            status: ScanStatus::Fail,
            finding_class: FindingClass::ContentIndicator,
            confidence: Confidence::High,
            detail: Some(format!(
                "{label} references dangerous or non-allowlisted callable(s): {}",
                dangerous.join(", ")
            )),
            matches: dangerous
                .iter()
                .map(|value| format!("[LF-PICKLE-DANGEROUS-GLOBAL] {value}"))
                .collect(),
            duration_ms: elapsed(started),
        };
    }
    if !unknown.is_empty() {
        return LayerScanResult {
            layer_digest: identity.to_owned(),
            media_type: media.to_owned(),
            check_type: CheckType::PickleStructure,
            status: ScanStatus::Warn,
            finding_class: FindingClass::ContentIndicator,
            confidence: Confidence::High,
            detail: Some(format!(
                "{label} contains unrecognized pickle global(s); review before trusting: {}",
                unknown.join(", ")
            )),
            matches: unknown
                .iter()
                .map(|value| format!("[LF-PICKLE-UNKNOWN-GLOBAL] {value}"))
                .collect(),
            duration_ms: elapsed(started),
        };
    }
    LayerScanResult {
        layer_digest: identity.to_owned(),
        media_type: media.to_owned(),
        check_type: CheckType::PickleStructure,
        status: ScanStatus::Pass,
        finding_class: FindingClass::Structural,
        confidence: Confidence::High,
        detail: Some(format!(
            "{label} opcode stream validated; {} opcode(s), allowlisted globals: {}",
            analysis.opcode_count,
            if globals.is_empty() {
                "none".to_owned()
            } else {
                globals.join(", ")
            }
        )),
        matches: vec![format!(
            "[LF-PICKLE-SAFE-GLOBALS] {}",
            if globals.is_empty() {
                "no GLOBAL/STACK_GLOBAL references".to_owned()
            } else {
                globals.join(", ")
            }
        )],
        duration_ms: elapsed(started),
    }
}

fn scan_zip(path: &Path, file: &File, identity: &str, media: &str) -> Result<Vec<LayerScanResult>> {
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
            Cursor::new(bytes),
            len,
            identity,
            media,
            Some(&name),
        ));
    }
    if results.is_empty() {
        results.push(LayerScanResult {
            layer_digest: identity.to_owned(),
            media_type: media.to_owned(),
            check_type: CheckType::PickleStructure,
            status: ScanStatus::Warn,
            finding_class: FindingClass::Compatibility,
            confidence: Confidence::High,
            detail: Some(format!(
                "PyTorch-style ZIP '{}' contains no .pkl member that Layerfault can opcode-analyze",
                path.display()
            )),
            matches: vec![
                "[LF-PICKLE-OPAQUE-CONTAINER] ZIP serialization container contains no analyzable pickle member"
                    .to_owned(),
            ],
            duration_ms: elapsed(started),
        });
    }
    Ok(results)
}

fn validate_zip_member_name(name: &str) -> Result<()> {
    let path = Path::new(name);
    if name.is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        bail!("unsafe pickle ZIP member path '{name}'");
    }
    Ok(())
}

fn analyze_reader<R: Read + Seek>(mut reader: R, len: u64) -> Result<PickleAnalysis> {
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
        let opcode = read_u8(&mut reader, &mut pos, len)?;
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
                    state
                        .analysis
                        .dangerous
                        .insert(format!("{global} via legacy INST opcode"));
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
                        state
                            .analysis
                            .dangerous
                            .insert(format!("{name} used by REDUCE"));
                    }
                    state.push(StackValue::Constructed(name.to_owned()))?;
                } else {
                    state
                        .analysis
                        .dangerous
                        .insert("unresolved callable used by REDUCE".to_owned());
                    state.push(StackValue::Other)?;
                }
            }
            b'b' => {
                state.pop(); // state
                let instance = state.pop();
                if let Some(name) = callable_name(&instance) {
                    if !is_allowlisted(&name) {
                        state
                            .analysis
                            .dangerous
                            .insert(format!("{name} used with BUILD"));
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
                state.analysis.dangerous.insert(match class {
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
                skip_line(&mut reader, &mut pos, len, MAX_TRACKED_STRING_BYTES)?;
                state.push(StackValue::Other)?;
            }
            b'Q' => {
                state.pop();
                state.push(StackValue::Other)?;
            }
            b'.' => {
                saw_stop = true;
                break;
            }
            other => bail!(
                "unknown pickle opcode 0x{other:02x} at offset {}",
                pos.saturating_sub(1)
            ),
        }
    }
    if !saw_stop {
        bail!("pickle stream ended without STOP opcode");
    }
    Ok(state.analysis)
}

#[derive(Default)]
struct ParserState {
    stack: Vec<StackValue>,
    memo: BTreeMap<usize, StackValue>,
    next_memo: usize,
    analysis: PickleAnalysis,
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
    fn record_global(&mut self, value: &str) {
        self.analysis.globals.insert(value.to_owned());
        if is_explicit_danger(value) {
            self.analysis.dangerous.insert(value.to_owned());
        } else if !is_allowlisted(value) {
            self.analysis.unknown_globals.insert(value.to_owned());
        }
    }
    fn record_extension(&mut self, code: u32) {
        self.analysis.dangerous.insert(format!(
            "unresolved pickle extension code {code}; EXT registry resolution is environment-dependent"
        ));
    }
    fn record_constructor(&mut self, name: Option<&str>, opcode: &str) {
        match name {
            Some(name) if is_allowlisted(name) => {}
            Some(name) => {
                self.analysis.dangerous.insert(format!(
                    "non-allowlisted constructor {name} used by {opcode}"
                ));
            }
            None => {
                self.analysis
                    .dangerous
                    .insert(format!("unresolved callable used by {opcode}"));
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
fn elapsed(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
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
}
