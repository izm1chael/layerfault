//! Legacy Torch7 (`.th`/`.t7`) binary serialization inspector.
//!
//! Torch7's on-disk format (see `torch/torch7`'s `File.lua`, and the
//! `python-torchfile` project for an independently-authored reference
//! implementation) is a self-describing, tagged object-graph stream: every
//! value is prefixed with a 4-byte little-endian type tag, and tables/Torch
//! class instances/functions additionally carry a 4-byte object-reference
//! index used to deduplicate repeated references within the same file.
//!
//! The dangerous primitive is the function types (`TYPE_FUNCTION`,
//! `TYPE_RECUR_FUNCTION`, the legacy `TYPE_RECUR_FUNCTION`): each embeds a
//! raw Lua bytecode blob (`string.dump` output) that a real Torch7 loader
//! unconditionally passes to `loadstring`/`load` on deserialization — an
//! unconditional code-execution primitive, structurally analogous to
//! pickle's `GLOBAL`/`REDUCE` opcodes. This module performs a bounded,
//! pure-Rust static walk of the type-tag stream (no Lua bytecode is ever
//! executed or decoded) and flags any occurrence of a function type.
//!
//! Torch class instances (`TYPE_TORCH`) are more structurally ambiguous:
//! the handful of built-in Tensor/Storage classes have fixed, non-generic
//! binary layouts baked into Torch7's C read routines, while every other
//! class (including every `nn.Module`-style class — exactly the shape an
//! attacker-crafted object graph would use to carry a function value) falls
//! back to a generic table read. Known Tensor/Storage class names are
//! parsed structurally so the walk can continue past their payload; any
//! other class name is walked as a generic table, since that is what a
//! real Torch7 loader does for it.

use crate::finding_evidence::{byte_range_evidence, EvidenceSubject, FindingBuilder};
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use anyhow::{anyhow, bail, Context, Result};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

const MAX_DEPTH: usize = 64;
const MAX_NODES: usize = 200_000;
const MAX_TRACKED_INDICES: usize = 200_000;
const MAX_STRING_BYTES: i64 = 16 * 1024 * 1024;
const MAX_ARRAY_ELEMENTS: i64 = 1_000_000;
const MAX_TABLE_ENTRIES: i64 = 1_000_000;
const MAX_DANGEROUS_FINDINGS: usize = 8;
const MAX_BYTECODE_EXCERPT: usize = 64;

const TYPE_NIL: i32 = 0;
const TYPE_NUMBER: i32 = 1;
const TYPE_STRING: i32 = 2;
const TYPE_TABLE: i32 = 3;
const TYPE_TORCH: i32 = 4;
const TYPE_BOOLEAN: i32 = 5;
const TYPE_FUNCTION: i32 = 6;
const LEGACY_TYPE_RECUR_FUNCTION: i32 = 7;
const TYPE_RECUR_FUNCTION: i32 = 8;

/// Built-in Torch Tensor classes: fixed layout `ndim:long, size:long[ndim],
/// stride:long[ndim], storage_offset:long, storage:object`.
const TENSOR_CLASSES: &[&str] = &[
    "torch.ByteTensor",
    "torch.CharTensor",
    "torch.ShortTensor",
    "torch.IntTensor",
    "torch.LongTensor",
    "torch.FloatTensor",
    "torch.DoubleTensor",
    "torch.HalfTensor",
    "torch.CudaTensor",
    "torch.CudaByteTensor",
    "torch.CudaCharTensor",
    "torch.CudaShortTensor",
    "torch.CudaIntTensor",
    "torch.CudaDoubleTensor",
    "torch.CudaHalfTensor",
];

/// Built-in Torch Storage classes: fixed layout `size:long` followed by
/// `size * element_bytes` bytes of raw inline data (no further objects).
const STORAGE_CLASSES: &[(&str, i64)] = &[
    ("torch.ByteStorage", 1),
    ("torch.CharStorage", 1),
    ("torch.ShortStorage", 2),
    ("torch.IntStorage", 4),
    ("torch.LongStorage", 8),
    ("torch.FloatStorage", 4),
    ("torch.DoubleStorage", 8),
    ("torch.HalfStorage", 2),
    ("torch.CudaStorage", 4),
    ("torch.CudaByteStorage", 1),
    ("torch.CudaCharStorage", 1),
    ("torch.CudaShortStorage", 2),
    ("torch.CudaIntStorage", 4),
    ("torch.CudaDoubleStorage", 8),
    ("torch.CudaHalfStorage", 2),
];

struct DangerousFunction {
    kind: &'static str,
    byte_offset: u64,
    bytecode_len: i64,
    excerpt: Vec<u8>,
}

struct Reader<'a> {
    file: &'a File,
    pos: u64,
    len: u64,
    nodes_visited: usize,
    seen_indices: std::collections::BTreeSet<i32>,
    dangerous: Vec<DangerousFunction>,
}

impl<'a> Reader<'a> {
    fn remaining(&self) -> u64 {
        self.len.saturating_sub(self.pos)
    }

    fn read_exact_tracked(&mut self, n: usize) -> Result<Vec<u8>> {
        if (n as u64) > self.remaining() {
            bail!(
                "read of {n} byte(s) at offset {} exceeds file length {}",
                self.pos,
                self.len
            );
        }
        let mut cloned = self.file.try_clone()?;
        cloned.seek(SeekFrom::Start(self.pos))?;
        let mut buf = vec![0u8; n];
        cloned.read_exact(&mut buf)?;
        self.pos += n as u64;
        Ok(buf)
    }

    fn skip(&mut self, n: u64) -> Result<()> {
        if n > self.remaining() {
            bail!(
                "skip of {n} byte(s) at offset {} exceeds file length {}",
                self.pos,
                self.len
            );
        }
        self.pos += n;
        Ok(())
    }

    fn read_i32(&mut self) -> Result<i32> {
        let bytes = self.read_exact_tracked(4)?;
        Ok(i32::from_le_bytes(bytes.try_into().expect("4 bytes")))
    }

    fn read_i64(&mut self) -> Result<i64> {
        let bytes = self.read_exact_tracked(8)?;
        Ok(i64::from_le_bytes(bytes.try_into().expect("8 bytes")))
    }

    fn read_f64(&mut self) -> Result<f64> {
        let bytes = self.read_exact_tracked(8)?;
        Ok(f64::from_le_bytes(bytes.try_into().expect("8 bytes")))
    }

    /// A Lua-string field: a 4-byte length prefix followed by raw bytes
    /// (not necessarily UTF-8 — Torch7/Lua strings are byte strings).
    fn read_lua_string(&mut self, max_len: i64) -> Result<Vec<u8>> {
        let size = self.read_i32()? as i64;
        if !(0..=max_len).contains(&size) {
            bail!("string length {size} outside 0..={max_len}");
        }
        self.read_exact_tracked(size as usize)
    }

    fn read_class_name_string(&mut self) -> Result<String> {
        let bytes = self.read_lua_string(4096)?;
        String::from_utf8(bytes).context("Torch class name is not valid UTF-8")
    }

    fn enter_node(&mut self, depth: usize) -> Result<()> {
        if depth > MAX_DEPTH {
            bail!("object graph exceeds maximum nesting depth {MAX_DEPTH}");
        }
        self.nodes_visited += 1;
        if self.nodes_visited > MAX_NODES {
            bail!("object graph exceeds maximum node count {MAX_NODES}");
        }
        Ok(())
    }

    /// Read one object-reference index shared by TABLE/TORCH/FUNCTION
    /// variants. Returns `true` if this index was already seen (a
    /// back-reference — no further payload bytes follow for this node).
    fn read_reference_index(&mut self) -> Result<bool> {
        let index = self.read_i32()?;
        if self.seen_indices.contains(&index) {
            return Ok(true);
        }
        if self.seen_indices.len() >= MAX_TRACKED_INDICES {
            bail!("object graph references more than {MAX_TRACKED_INDICES} distinct objects");
        }
        self.seen_indices.insert(index);
        Ok(false)
    }

    fn read_long_array(&mut self, n: i64) -> Result<()> {
        if !(0..=MAX_ARRAY_ELEMENTS).contains(&n) {
            bail!("array length {n} outside 0..={MAX_ARRAY_ELEMENTS}");
        }
        self.skip((n as u64).saturating_mul(8))
    }

    fn read_object(&mut self, depth: usize) -> Result<()> {
        self.enter_node(depth)?;
        let start_offset = self.pos;
        let typeidx = self.read_i32()?;
        match typeidx {
            t if t == TYPE_NIL => Ok(()),
            t if t == TYPE_NUMBER => {
                self.read_f64()?;
                Ok(())
            }
            t if t == TYPE_BOOLEAN => {
                self.read_i32()?;
                Ok(())
            }
            t if t == TYPE_STRING => {
                self.read_lua_string(MAX_STRING_BYTES)?;
                Ok(())
            }
            t if t == TYPE_FUNCTION
                || t == TYPE_RECUR_FUNCTION
                || t == LEGACY_TYPE_RECUR_FUNCTION =>
            {
                if self.read_reference_index()? {
                    return Ok(());
                }
                let bytecode_len = self.read_i32()? as i64;
                if !(0..=MAX_STRING_BYTES).contains(&bytecode_len) {
                    bail!("function bytecode length {bytecode_len} outside 0..={MAX_STRING_BYTES}");
                }
                let excerpt_len = (bytecode_len as usize).min(MAX_BYTECODE_EXCERPT);
                let bytecode_offset = self.pos;
                let excerpt = if excerpt_len > 0 {
                    let bytes = self.read_exact_tracked(excerpt_len)?;
                    self.skip((bytecode_len as u64).saturating_sub(excerpt_len as u64))?;
                    bytes
                } else {
                    Vec::new()
                };
                if self.dangerous.len() < MAX_DANGEROUS_FINDINGS {
                    self.dangerous.push(DangerousFunction {
                        kind: if t == TYPE_FUNCTION {
                            "TYPE_FUNCTION"
                        } else {
                            "TYPE_RECUR_FUNCTION"
                        },
                        byte_offset: bytecode_offset,
                        bytecode_len,
                        excerpt,
                    });
                }
                // Upvalues: a nested object (a table in modern writers, a
                // bare array in the legacy variant) — walk it the same way
                // as any other object so parsing can continue past it.
                self.read_object(depth + 1)
            }
            t if t == TYPE_TABLE => {
                if self.read_reference_index()? {
                    return Ok(());
                }
                self.read_table_entries(depth)
            }
            t if t == TYPE_TORCH => {
                if self.read_reference_index()? {
                    return Ok(());
                }
                let version = self.read_lua_string(4096)?;
                let class_name = if version.starts_with(b"V ") {
                    self.read_class_name_string()?
                } else {
                    String::from_utf8(version)
                        .context("Torch legacy class name is not valid UTF-8")?
                };
                if TENSOR_CLASSES.contains(&class_name.as_str()) {
                    let ndim = self.read_i64()?;
                    self.read_long_array(ndim)?; // size
                    self.read_long_array(ndim)?; // stride
                    self.read_i64()?; // storage_offset
                    self.read_object(depth + 1) // nested storage reference
                } else if let Some((_, elem_bytes)) =
                    STORAGE_CLASSES.iter().find(|(name, _)| *name == class_name)
                {
                    let count = self.read_i64()?;
                    if !(0..=MAX_ARRAY_ELEMENTS).contains(&count) {
                        bail!("storage element count {count} outside 0..={MAX_ARRAY_ELEMENTS}");
                    }
                    self.skip((count as u64).saturating_mul(*elem_bytes as u64))
                } else {
                    // Unrecognized class: a real Torch7 loader falls back to
                    // a generic table read for any class without a custom
                    // `write`/`read` metamethod — exactly the shape used by
                    // `nn.Module`-style classes, which is also where an
                    // attacker-crafted object graph would carry a function.
                    self.read_object(depth + 1)
                }
            }
            other => Err(anyhow!(
                "unrecognized Torch7 type tag {other} at byte offset {start_offset}"
            )),
        }
    }

    fn read_table_entries(&mut self, depth: usize) -> Result<()> {
        let size = self.read_i32()? as i64;
        if !(0..=MAX_TABLE_ENTRIES).contains(&size) {
            bail!("table entry count {size} outside 0..={MAX_TABLE_ENTRIES}");
        }
        for _ in 0..size {
            self.read_object(depth + 1)?; // key
            self.read_object(depth + 1)?; // value
        }
        Ok(())
    }
}

/// Bounded static scan for legacy Torch7 (`.th`/`.t7`) serialized streams.
pub fn scan(
    path: &Path,
    file: &File,
    size: u64,
    identity: &str,
    media: &str,
) -> Result<Vec<LayerScanResult>> {
    let subject = EvidenceSubject::member(&path.display().to_string())
        .with_sha256(Some(identity.to_owned()))
        .with_media_type(media);

    let mut prefix = [0u8; 3];
    let mut probe = file.try_clone()?;
    probe.seek(SeekFrom::Start(0))?;
    let probed = probe.read(&mut prefix).unwrap_or(0);
    if probed >= 3 && &prefix == b"BZh" {
        return Ok(vec![FindingBuilder::new(
            "LF-TORCH7-OPAQUE-COMPRESSED",
            CheckType::LayerPolicy,
            ScanStatus::Warn,
        )
        .class(FindingClass::Compatibility)
        .confidence(Confidence::High)
        .digest(identity)
        .media_type(media)
        .subject(subject.clone())
        .detail("Torch7 stream is BZip2-compressed; this is not part of the standard on-disk format and this build does not decompress it, so the object graph could not be inspected".to_owned())
        .finish()]);
    }

    let mut reader = Reader {
        file,
        pos: 0,
        len: size,
        nodes_visited: 0,
        seen_indices: std::collections::BTreeSet::new(),
        dangerous: Vec::new(),
    };

    match reader.read_object(0) {
        Ok(()) => {
            let mut results = Vec::new();
            for finding in &reader.dangerous {
                results.push(
                    FindingBuilder::new(
                        "LF-TORCH7-DANGEROUS-FUNCTION",
                        CheckType::LayerPolicy,
                        ScanStatus::Fail,
                    )
                    .class(FindingClass::ContentIndicator)
                    .confidence(Confidence::High)
                    .digest(identity)
                    .media_type(media)
                    .subject(subject.clone())
                    .detail(format!(
                        "Torch7 stream contains a {} entry ({} byte(s) of embedded Lua bytecode) that a real Torch7 loader unconditionally passes to loadstring() on deserialization",
                        finding.kind, finding.bytecode_len
                    ))
                    .evidence(byte_range_evidence(
                        subject.clone(),
                        finding.byte_offset,
                        finding.byte_offset.saturating_add(finding.excerpt.len() as u64),
                        "embedded Lua bytecode blob (code-execution primitive on deserialization)",
                    ))
                    .finish(),
                );
            }
            if results.is_empty() {
                results.push(
                    FindingBuilder::new(
                        "LF-TORCH7-STRUCT-VALID",
                        CheckType::LayerPolicy,
                        ScanStatus::Pass,
                    )
                    .class(FindingClass::Structural)
                    .confidence(Confidence::High)
                    .digest(identity)
                    .media_type(media)
                    .subject(subject)
                    .detail("Torch7 object graph parsed statically; no embedded function/bytecode entries found".to_owned())
                    .finish(),
                );
            }
            Ok(results)
        }
        Err(error) => Ok(vec![FindingBuilder::new(
            "LF-TORCH7-MALFORMED",
            CheckType::LayerPolicy,
            ScanStatus::Fail,
        )
        .class(FindingClass::Structural)
        .confidence(Confidence::High)
        .digest(identity)
        .media_type(media)
        .subject(subject)
        .detail(format!(
            "Torch7 object graph could not be safely parsed: {error}"
        ))
        .finish()]),
    }
}
