//! Bounded static NumPy `.npy` header and payload scanner.
//!
//! Layerfault never executes NumPy, Python `ast.literal_eval`, or unpickles content.
//! This module parses NPY version magic and headers, computes array sizes with
//! checked arithmetic, and analyzes object-dtype arrays using Layerfault's
//! existing bounded Pickle opcode disassembler.

use crate::finding_evidence::{
    byte_range_evidence, structural_invariant, EvidenceSubject, FindingBuilder,
};
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use anyhow::{anyhow, Result};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::time::Instant;

const NPY_MAGIC: &[u8] = b"\x93NUMPY";
const MAX_HEADER_BYTES: usize = 65536;
const MAX_SHAPE_DIMS: usize = 32;
const MAX_RECURSION_DEPTH: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpyHeader {
    pub major: u8,
    pub minor: u8,
    pub header_len: usize,
    pub data_offset: u64,
    pub descr_raw: String,
    pub fortran_order: bool,
    pub shape: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DtypeAnalysis {
    FixedSize { item_size: u64 },
    Object,
    Structured { item_size: u64, has_object: bool },
    Unsupported { reason: String },
}

pub fn scan(
    path: &Path,
    file: &File,
    size: u64,
    identity: &str,
    media: &str,
    budget: &crate::budget::ScanBudget,
) -> Result<Vec<LayerScanResult>> {
    let started = Instant::now();
    let mut results = Vec::new();
    let rel_path = path.display().to_string();
    let mut subject =
        EvidenceSubject::identity(identity, media).with_sha256(Some(identity.to_owned()));
    subject.package_relative_path = Some(rel_path.clone());

    // 1. Read header magic & version
    let mut header_buf = [0u8; 12];
    let mut file_ref = file.try_clone()?;
    file_ref.seek(SeekFrom::Start(0))?;
    let n = file_ref.read(&mut header_buf)?;

    if n < 10 || !header_buf.starts_with(NPY_MAGIC) {
        results.push(
            FindingBuilder::new("LF-NPY-STRUCT", CheckType::NpyStructure, ScanStatus::Fail)
                .class(FindingClass::Structural)
                .confidence(Confidence::High)
                .digest(identity)
                .media_type(media)
                .subject(subject.clone())
                .detail("Invalid NPY magic signature".to_owned())
                .evidence(byte_range_evidence(
                    subject.clone(),
                    0,
                    n.min(6) as u64,
                    "File header does not match \\x93NUMPY magic",
                ))
                .started(started)
                .finish(),
        );
        return Ok(results);
    }

    let major = header_buf[6];
    let minor = header_buf[7];

    let (prefix_len, header_len) = match major {
        1 => {
            let hlen = u16::from_le_bytes([header_buf[8], header_buf[9]]) as usize;
            (10usize, hlen)
        }
        2 | 3 => {
            if n < 12 {
                results.push(
                    FindingBuilder::new("LF-NPY-STRUCT", CheckType::NpyStructure, ScanStatus::Fail)
                        .class(FindingClass::Structural)
                        .confidence(Confidence::High)
                        .digest(identity)
                        .media_type(media)
                        .subject(subject.clone())
                        .detail("Truncated NPY v2/v3 header length".to_owned())
                        .started(started)
                        .finish(),
                );
                return Ok(results);
            }
            let hlen =
                u32::from_le_bytes([header_buf[8], header_buf[9], header_buf[10], header_buf[11]])
                    as usize;
            (12usize, hlen)
        }
        _ => {
            results.push(
                FindingBuilder::new("LF-NPY-STRUCT", CheckType::NpyStructure, ScanStatus::Fail)
                    .class(FindingClass::Structural)
                    .confidence(Confidence::High)
                    .digest(identity)
                    .media_type(media)
                    .subject(subject.clone())
                    .detail(format!("Unsupported NPY major version: {major}"))
                    .started(started)
                    .finish(),
            );
            return Ok(results);
        }
    };

    if header_len > MAX_HEADER_BYTES {
        results.push(
            FindingBuilder::new("LF-NPY-STRUCT", CheckType::NpyStructure, ScanStatus::Fail)
                .class(FindingClass::Structural)
                .confidence(Confidence::High)
                .digest(identity)
                .media_type(media)
                .subject(subject.clone())
                .detail(format!(
                    "NPY header length ({header_len} bytes) exceeds safety cap ({MAX_HEADER_BYTES} bytes)"
                ))
                .started(started)
                .finish(),
        );
        return Ok(results);
    }

    let data_offset = (prefix_len + header_len) as u64;
    if size < data_offset {
        results.push(
            FindingBuilder::new("LF-NPY-STRUCT", CheckType::NpyStructure, ScanStatus::Fail)
                .class(FindingClass::Structural)
                .confidence(Confidence::High)
                .digest(identity)
                .media_type(media)
                .subject(subject.clone())
                .detail(format!(
                    "File size ({size} bytes) is smaller than NPY header extent ({data_offset} bytes)"
                ))
                .started(started)
                .finish(),
        );
        return Ok(results);
    }

    // 2. Read dictionary header string
    let mut header_str_bytes = vec![0u8; header_len];
    file_ref.seek(SeekFrom::Start(prefix_len as u64))?;
    file_ref.read_exact(&mut header_str_bytes)?;

    let header_str = match std::str::from_utf8(&header_str_bytes) {
        Ok(s) => s,
        Err(_) => {
            results.push(
                FindingBuilder::new("LF-NPY-STRUCT", CheckType::NpyStructure, ScanStatus::Fail)
                    .class(FindingClass::Structural)
                    .confidence(Confidence::High)
                    .digest(identity)
                    .media_type(media)
                    .subject(subject.clone())
                    .detail("NPY header is not valid UTF-8/ASCII".to_owned())
                    .started(started)
                    .finish(),
            );
            return Ok(results);
        }
    };

    // 3. Parse header dictionary
    let header = match parse_header_dict(header_str, major, minor, header_len, data_offset) {
        Ok(h) => h,
        Err(err) => {
            results.push(
                FindingBuilder::new("LF-NPY-STRUCT", CheckType::NpyStructure, ScanStatus::Fail)
                    .class(FindingClass::Structural)
                    .confidence(Confidence::High)
                    .digest(identity)
                    .media_type(media)
                    .subject(subject.clone())
                    .detail(format!("Malformed NPY header dictionary: {err}"))
                    .started(started)
                    .finish(),
            );
            return Ok(results);
        }
    };

    // 4. Analyze Dtype
    let dtype_analysis = analyze_descr(&header.descr_raw);

    // Calculate total elements with checked arithmetic
    let mut total_elements: u64 = 1;
    let mut shape_overflow = false;
    for &dim in &header.shape {
        match total_elements.checked_mul(dim) {
            Some(prod) => total_elements = prod,
            None => {
                shape_overflow = true;
                break;
            }
        }
    }

    if shape_overflow {
        results.push(
            FindingBuilder::new("LF-NPY-STRUCT", CheckType::NpyStructure, ScanStatus::Fail)
                .class(FindingClass::Structural)
                .confidence(Confidence::High)
                .digest(identity)
                .media_type(media)
                .subject(subject.clone())
                .detail("NPY shape total element calculation overflowed u64".to_owned())
                .started(started)
                .finish(),
        );
        return Ok(results);
    }

    // 5. Handle dtype cases & validate payload length
    let actual_payload_bytes = size - data_offset;
    match dtype_analysis {
        DtypeAnalysis::FixedSize { item_size }
        | DtypeAnalysis::Structured {
            item_size,
            has_object: false,
        } => {
            let expected_bytes = match total_elements.checked_mul(item_size) {
                Some(bytes) => bytes,
                None => {
                    results.push(
                        FindingBuilder::new(
                            "LF-NPY-STRUCT",
                            CheckType::NpyStructure,
                            ScanStatus::Fail,
                        )
                        .class(FindingClass::Structural)
                        .confidence(Confidence::High)
                        .digest(identity)
                        .media_type(media)
                        .subject(subject.clone())
                        .detail("NPY array total byte size calculation overflowed u64".to_owned())
                        .started(started)
                        .finish(),
                    );
                    return Ok(results);
                }
            };

            if actual_payload_bytes < expected_bytes {
                results.push(
                    FindingBuilder::new(
                        "LF-NPY-STRUCT",
                        CheckType::NpyStructure,
                        ScanStatus::Fail,
                    )
                    .class(FindingClass::Structural)
                    .confidence(Confidence::High)
                    .digest(identity)
                    .media_type(media)
                    .subject(subject.clone())
                    .detail(format!(
                        "NPY file truncated: expected {expected_bytes} data bytes, found {actual_payload_bytes} bytes"
                    ))
                    .started(started)
                    .finish(),
                );
                return Ok(results);
            }
            if actual_payload_bytes > expected_bytes {
                results.push(
                    FindingBuilder::new("LF-NPY-STRUCT", CheckType::NpyStructure, ScanStatus::Fail)
                        .class(FindingClass::Structural)
                        .confidence(Confidence::High)
                        .digest(identity)
                        .media_type(media)
                        .subject(subject.clone())
                        .detail(format!(
                            "NPY file has {} unexplained trailing payload bytes",
                            actual_payload_bytes - expected_bytes
                        ))
                        .started(started)
                        .finish(),
                );
                return Ok(results);
            }
        }
        DtypeAnalysis::Unsupported { reason } => {
            results.push(
                FindingBuilder::new(
                    "LF-NPY-DTYPE-UNSUPPORTED",
                    CheckType::NpyStructure,
                    ScanStatus::Warn,
                )
                .class(FindingClass::Compatibility)
                .confidence(Confidence::High)
                .digest(identity)
                .media_type(media)
                .subject(subject.clone())
                .detail(format!(
                    "NPY array has unsupported or complex dtype descriptor '{}': {reason}",
                    header.descr_raw
                ))
                .started(started)
                .finish(),
            );
        }
        DtypeAnalysis::Object
        | DtypeAnalysis::Structured {
            has_object: true, ..
        } => {
            // Object dtype present! Record code-capable serialization risk
            results.push(
                FindingBuilder::new(
                    "LF-NPY-OBJECT-DTYPE",
                    CheckType::NpyStructure,
                    ScanStatus::Warn,
                )
                .class(FindingClass::ContentIndicator)
                .confidence(Confidence::High)
                .digest(identity)
                .media_type(media)
                .subject(subject.clone())
                .detail(format!(
                    "NPY array contains object dtype ('{}'); requires allow_pickle=True to deserialize",
                    header.descr_raw
                ))
                .evidence(structural_invariant(
                    subject.clone(),
                    "NPY header metadata",
                    serde_json::json!({
                        "version": format!("{}.{}", header.major, header.minor),
                        "header_length": header.header_len,
                        "descr": header.descr_raw,
                        "shape": header.shape,
                        "fortran_order": header.fortran_order,
                        "data_offset": header.data_offset,
                        "object_dtype": true
                    }),
                ))
                .started(started)
                .finish(),
            );

            // Hand remaining payload to bounded static Pickle opcode analyzer
            if actual_payload_bytes > 0 {
                let mut payload_reader = file.try_clone()?;
                payload_reader.seek(SeekFrom::Start(data_offset))?;
                let to_read = actual_payload_bytes.min(64 * 1024 * 1024) as usize;
                budget
                    .consume(
                        crate::budget::BudgetDimension::ParserWorkUnits,
                        to_read as u64,
                        "NumPy object-array Pickle analysis",
                    )
                    .map_err(|error| anyhow!("global scan budget exhausted: {error}"))?;
                let mut payload_buf = vec![0u8; to_read];
                if payload_reader.read_exact(&mut payload_buf).is_ok() {
                    match crate::formats::pickle::analyze_bytes(&payload_buf) {
                        Ok(analysis) => {
                            let dangerous: Vec<String> =
                                analysis.dangerous.iter().cloned().collect();
                            if !dangerous.is_empty() {
                                results.push(
                                    FindingBuilder::new(
                                        "LF-NPY-PICKLE",
                                        CheckType::NpyStructure,
                                        ScanStatus::Fail,
                                    )
                                    .class(FindingClass::ContentIndicator)
                                    .confidence(Confidence::High)
                                    .digest(identity)
                                    .media_type(media)
                                    .subject(subject.clone())
                                    .detail(format!(
                                        "NumPy object array payload contains dangerous Pickle callable(s): {}",
                                        dangerous.join(", ")
                                    ))
                                    .match_note(dangerous.first().cloned().unwrap_or_default())
                                    .evidence(structural_invariant(
                                        subject.clone(),
                                        "NumPy object array Pickle opcodes",
                                        serde_json::json!({
                                            "dangerous_callables": dangerous,
                                            "opcode_sites": analysis.sites.iter().map(|s| {
                                                serde_json::json!({
                                                    "entry": s.entry,
                                                    "opcode": s.opcode,
                                                    "byte_offset": data_offset + s.byte_offset
                                                })
                                            }).collect::<Vec<_>>()
                                        }),
                                    ))
                                    .started(started)
                                    .finish(),
                                );
                            }
                        }
                        Err(err) => {
                            results.push(
                                FindingBuilder::new(
                                    "LF-NPY-STRUCT",
                                    CheckType::NpyStructure,
                                    ScanStatus::Warn,
                                )
                                .class(FindingClass::Structural)
                                .confidence(Confidence::Medium)
                                .digest(identity)
                                .media_type(media)
                                .subject(subject.clone())
                                .detail(format!(
                                    "Could not analyze Pickle payload in object array: {err}"
                                ))
                                .started(started)
                                .finish(),
                            );
                        }
                    }
                }
            }
        }
    }

    if results.is_empty() {
        results.push(
            FindingBuilder::new("LF-NPY-STRUCT", CheckType::NpyStructure, ScanStatus::Pass)
                .class(FindingClass::Structural)
                .confidence(Confidence::High)
                .digest(identity)
                .media_type(media)
                .subject(subject.clone())
                .detail(format!(
                    "Valid NPY v{}.{} array, shape {:?}",
                    header.major, header.minor, header.shape
                ))
                .evidence(structural_invariant(
                    subject,
                    "NPY header metadata",
                    serde_json::json!({
                        "version": format!("{}.{}", header.major, header.minor),
                        "header_length": header.header_len,
                        "descr": header.descr_raw,
                        "shape": header.shape,
                        "fortran_order": header.fortran_order,
                        "data_offset": header.data_offset,
                        "actual_data_bytes": actual_payload_bytes
                    }),
                ))
                .started(started)
                .finish(),
        );
    }

    Ok(results)
}

fn parse_header_dict(
    header_str: &str,
    major: u8,
    minor: u8,
    header_len: usize,
    data_offset: u64,
) -> Result<NpyHeader> {
    let mut parser = ValueParser::new(header_str);
    let dict_val = parser.parse_value(0)?;
    parser.skip_whitespace();
    if parser.pos != parser.chars.len() {
        return Err(anyhow!(
            "unexpected trailing content after header dictionary"
        ));
    }

    let (descr_raw, fortran_order, shape) = match dict_val {
        DictValue::Dict(entries) => {
            let mut descr = None;
            let mut fortran = None;
            let mut shp = None;

            for (k, v) in entries {
                match k.as_str() {
                    "descr" => {
                        descr = Some(v.to_raw_repr());
                    }
                    "fortran_order" => match v {
                        DictValue::Bool(b) => fortran = Some(b),
                        _ => return Err(anyhow!("fortran_order must be boolean")),
                    },
                    "shape" => match v {
                        DictValue::Tuple(dims) | DictValue::List(dims) => {
                            if dims.len() > MAX_SHAPE_DIMS {
                                return Err(anyhow!(
                                    "shape exceeds max dimensions ({MAX_SHAPE_DIMS})"
                                ));
                            }
                            let mut shape_vec = Vec::new();
                            for dim in dims {
                                match dim {
                                    DictValue::Int(n) => shape_vec.push(n),
                                    _ => {
                                        return Err(anyhow!(
                                            "shape dimensions must be non-negative integers"
                                        ))
                                    }
                                }
                            }
                            shp = Some(shape_vec);
                        }
                        _ => return Err(anyhow!("shape must be a tuple or list")),
                    },
                    _ => {} // Ignore unexpected extra keys or preserve safely
                }
            }

            let descr_raw = descr.ok_or_else(|| anyhow!("missing 'descr' in header"))?;
            let fortran_order =
                fortran.ok_or_else(|| anyhow!("missing 'fortran_order' in header"))?;
            let shape = shp.ok_or_else(|| anyhow!("missing 'shape' in header"))?;

            (descr_raw, fortran_order, shape)
        }
        _ => return Err(anyhow!("NPY header must be a Python dictionary literal")),
    };

    Ok(NpyHeader {
        major,
        minor,
        header_len,
        data_offset,
        descr_raw,
        fortran_order,
        shape,
    })
}

fn analyze_descr(raw: &str) -> DtypeAnalysis {
    let clean = raw.trim();
    if clean == "'O'"
        || clean == "\"O\""
        || clean == "'|O'"
        || clean == "\"|O\""
        || clean == "'<O'"
        || clean == "'>O'"
    {
        return DtypeAnalysis::Object;
    }

    if (clean.starts_with('\'') && clean.ends_with('\''))
        || (clean.starts_with('"') && clean.ends_with('"'))
    {
        let inner = &clean[1..clean.len() - 1];
        if let Some(size) = parse_simple_dtype(inner) {
            return DtypeAnalysis::FixedSize { item_size: size };
        }
        if inner == "O" || inner == "|O" || inner == "<O" || inner == ">O" {
            return DtypeAnalysis::Object;
        }
        return DtypeAnalysis::Unsupported {
            reason: format!("unrecognized simple dtype string '{inner}'"),
        };
    }

    if clean.starts_with('[') && clean.ends_with(']') {
        return parse_structured_dtype(clean);
    }

    DtypeAnalysis::Unsupported {
        reason: format!("unhandled descriptor syntax '{clean}'"),
    }
}

fn parse_simple_dtype(s: &str) -> Option<u64> {
    let trimmed = s.trim_start_matches(['<', '>', '|', '=', '\\']);
    if trimmed.is_empty() {
        return None;
    }

    let kind = trimmed.chars().next()?;
    let num_str = &trimmed[kind.len_utf8()..];

    match kind {
        'b' | 'B' => {
            let n: u64 = if num_str.is_empty() {
                1
            } else {
                num_str.parse().ok()?
            };
            Some(n)
        }
        'i' | 'u' | 'f' | 'c' | 'm' | 'M' => {
            let bytes: u64 = num_str.parse().ok()?;
            Some(bytes)
        }
        'S' | 'a' | 'V' => {
            let bytes: u64 = if num_str.is_empty() {
                1
            } else {
                num_str.parse().ok()?
            };
            Some(bytes)
        }
        'U' => {
            let chars: u64 = if num_str.is_empty() {
                1
            } else {
                num_str.parse().ok()?
            };
            chars.checked_mul(4)
        }
        _ => None,
    }
}

fn parse_structured_dtype(raw: &str) -> DtypeAnalysis {
    let mut parser = ValueParser::new(raw);
    let val = match parser.parse_value(0) {
        Ok(v) => v,
        Err(err) => {
            return DtypeAnalysis::Unsupported {
                reason: format!("structured dtype parse error: {err}"),
            }
        }
    };

    let items = match val {
        DictValue::List(l) => l,
        _ => {
            return DtypeAnalysis::Unsupported {
                reason: "structured dtype must be a list".to_owned(),
            }
        }
    };

    let mut total_item_size: u64 = 0;
    let mut has_object = false;

    for item in items {
        match item {
            DictValue::Tuple(fields) => {
                if fields.len() < 2 {
                    return DtypeAnalysis::Unsupported {
                        reason: "structured field tuple must have at least (name, dtype)"
                            .to_owned(),
                    };
                }
                let dtype_val = &fields[1];
                let field_descr = dtype_val.to_raw_repr();
                let field_analysis = analyze_descr(&field_descr);

                let field_size = match field_analysis {
                    DtypeAnalysis::FixedSize { item_size } => item_size,
                    DtypeAnalysis::Object => {
                        has_object = true;
                        8 // 64-bit object reference size estimate
                    }
                    DtypeAnalysis::Structured {
                        item_size,
                        has_object: sub_obj,
                    } => {
                        if sub_obj {
                            has_object = true;
                        }
                        item_size
                    }
                    DtypeAnalysis::Unsupported { reason } => {
                        return DtypeAnalysis::Unsupported {
                            reason: format!("field dtype unsupported: {reason}"),
                        };
                    }
                };

                let mut field_multiplier: u64 = 1;
                if fields.len() >= 3 {
                    match &fields[2] {
                        DictValue::Tuple(shape) | DictValue::List(shape) => {
                            for dim in shape {
                                if let DictValue::Int(d) = dim {
                                    field_multiplier = match field_multiplier.checked_mul(*d) {
                                        Some(product) => product,
                                        None => {
                                            return DtypeAnalysis::Unsupported {
                                                reason: "structured field shape overflow"
                                                    .to_owned(),
                                            }
                                        }
                                    };
                                }
                            }
                        }
                        DictValue::Int(d) => field_multiplier = *d,
                        _ => {}
                    }
                }

                let field_total = match field_size.checked_mul(field_multiplier) {
                    Some(product) => product,
                    None => {
                        return DtypeAnalysis::Unsupported {
                            reason: "structured field item size overflow".to_owned(),
                        }
                    }
                };
                total_item_size = match total_item_size.checked_add(field_total) {
                    Some(sum) => sum,
                    None => {
                        return DtypeAnalysis::Unsupported {
                            reason: "structured field item size overflow".to_owned(),
                        }
                    }
                };
            }
            _ => {
                return DtypeAnalysis::Unsupported {
                    reason: "structured dtype fields must be tuples".to_owned(),
                }
            }
        }
    }

    DtypeAnalysis::Structured {
        item_size: total_item_size,
        has_object,
    }
}

// Bounded AST-like Python value representation for NPY dictionary header
#[derive(Debug, Clone, PartialEq, Eq)]
enum DictValue {
    Dict(Vec<(String, DictValue)>),
    List(Vec<DictValue>),
    Tuple(Vec<DictValue>),
    Str(String),
    Int(u64),
    Bool(bool),
}

impl DictValue {
    fn to_raw_repr(&self) -> String {
        match self {
            DictValue::Str(s) => format!("'{s}'"),
            DictValue::Int(n) => n.to_string(),
            DictValue::Bool(b) => {
                if *b {
                    "True".to_owned()
                } else {
                    "False".to_owned()
                }
            }
            DictValue::Tuple(items) => {
                let inner: Vec<String> = items.iter().map(|i| i.to_raw_repr()).collect();
                if items.len() == 1 {
                    format!("({},)", inner[0])
                } else {
                    format!("({})", inner.join(", "))
                }
            }
            DictValue::List(items) => {
                let inner: Vec<String> = items.iter().map(|i| i.to_raw_repr()).collect();
                format!("[{}]", inner.join(", "))
            }
            DictValue::Dict(kvs) => {
                let inner: Vec<String> = kvs
                    .iter()
                    .map(|(k, v)| format!("'{k}': {}", v.to_raw_repr()))
                    .collect();
                format!("{{{}}}", inner.join(", "))
            }
        }
    }
}

struct ValueParser {
    chars: Vec<char>,
    pos: usize,
}

impl ValueParser {
    fn new(input: &str) -> Self {
        Self {
            chars: input.chars().collect(),
            pos: 0,
        }
    }

    fn skip_whitespace(&mut self) {
        while self.pos < self.chars.len() && self.chars[self.pos].is_whitespace() {
            self.pos += 1;
        }
    }

    fn parse_value(&mut self, depth: usize) -> Result<DictValue> {
        if depth > MAX_RECURSION_DEPTH {
            return Err(anyhow!("nesting depth limit exceeded"));
        }
        self.skip_whitespace();
        if self.pos >= self.chars.len() {
            return Err(anyhow!("unexpected EOF"));
        }

        let ch = self.chars[self.pos];
        match ch {
            '{' => self.parse_dict(depth),
            '[' => self.parse_list(depth),
            '(' => self.parse_tuple(depth),
            '\'' | '"' => self.parse_str(),
            'T' | 'F' | 't' | 'f' => self.parse_bool_or_name(),
            _ if ch.is_ascii_digit() || ch == '-' || ch == '+' => self.parse_int(),
            _ => Err(anyhow!(
                "unexpected character '{ch}' at position {}",
                self.pos
            )),
        }
    }

    fn parse_dict(&mut self, depth: usize) -> Result<DictValue> {
        self.pos += 1; // skip '{'
        let mut entries = Vec::new();

        loop {
            self.skip_whitespace();
            if self.pos >= self.chars.len() {
                return Err(anyhow!("unclosed dict"));
            }
            if self.chars[self.pos] == '}' {
                self.pos += 1;
                break;
            }

            let key_val = self.parse_value(depth + 1)?;
            let key_str = match key_val {
                DictValue::Str(s) => s,
                _ => return Err(anyhow!("dict keys must be strings")),
            };

            self.skip_whitespace();
            if self.pos >= self.chars.len() || self.chars[self.pos] != ':' {
                return Err(anyhow!("expected ':' after dict key"));
            }
            self.pos += 1; // skip ':'

            let val = self.parse_value(depth + 1)?;
            entries.push((key_str, val));

            self.skip_whitespace();
            if self.pos < self.chars.len() && self.chars[self.pos] == ',' {
                self.pos += 1;
            }
        }

        Ok(DictValue::Dict(entries))
    }

    fn parse_list(&mut self, depth: usize) -> Result<DictValue> {
        self.pos += 1; // skip '['
        let mut items = Vec::new();

        loop {
            self.skip_whitespace();
            if self.pos >= self.chars.len() {
                return Err(anyhow!("unclosed list"));
            }
            if self.chars[self.pos] == ']' {
                self.pos += 1;
                break;
            }

            let val = self.parse_value(depth + 1)?;
            items.push(val);

            self.skip_whitespace();
            if self.pos < self.chars.len() && self.chars[self.pos] == ',' {
                self.pos += 1;
            }
        }

        Ok(DictValue::List(items))
    }

    fn parse_tuple(&mut self, depth: usize) -> Result<DictValue> {
        self.pos += 1; // skip '('
        let mut items = Vec::new();

        loop {
            self.skip_whitespace();
            if self.pos >= self.chars.len() {
                return Err(anyhow!("unclosed tuple"));
            }
            if self.chars[self.pos] == ')' {
                self.pos += 1;
                break;
            }

            let val = self.parse_value(depth + 1)?;
            items.push(val);

            self.skip_whitespace();
            if self.pos < self.chars.len() && self.chars[self.pos] == ',' {
                self.pos += 1;
            }
        }

        Ok(DictValue::Tuple(items))
    }

    fn parse_str(&mut self) -> Result<DictValue> {
        let quote = self.chars[self.pos];
        self.pos += 1;
        let mut out = String::new();

        while self.pos < self.chars.len() {
            let ch = self.chars[self.pos];
            if ch == quote {
                self.pos += 1;
                return Ok(DictValue::Str(out));
            }
            if ch == '\\' && self.pos + 1 < self.chars.len() {
                self.pos += 1;
                let escaped = self.chars[self.pos];
                out.push(escaped);
            } else {
                out.push(ch);
            }
            self.pos += 1;
        }

        Err(anyhow!("unclosed string literal"))
    }

    fn parse_int(&mut self) -> Result<DictValue> {
        let start = self.pos;
        if self.pos < self.chars.len()
            && (self.chars[self.pos] == '-' || self.chars[self.pos] == '+')
        {
            self.pos += 1;
        }
        while self.pos < self.chars.len() && self.chars[self.pos].is_ascii_digit() {
            self.pos += 1;
        }
        let s: String = self.chars[start..self.pos].iter().collect();
        let n: u64 = s.parse().map_err(|_| anyhow!("invalid integer '{s}'"))?;
        Ok(DictValue::Int(n))
    }

    fn parse_bool_or_name(&mut self) -> Result<DictValue> {
        let start = self.pos;
        while self.pos < self.chars.len()
            && (self.chars[self.pos].is_ascii_alphanumeric() || self.chars[self.pos] == '_')
        {
            self.pos += 1;
        }
        let word: String = self.chars[start..self.pos].iter().collect();
        match word.as_str() {
            "True" | "true" => Ok(DictValue::Bool(true)),
            "False" | "false" => Ok(DictValue::Bool(false)),
            _ => Ok(DictValue::Str(word)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_npy_header() {
        let header_str = "{'descr': '<f8', 'fortran_order': False, 'shape': (10, 20), }";
        let parsed = parse_header_dict(header_str, 1, 0, 64, 128).unwrap();
        assert_eq!(parsed.major, 1);
        assert!(!parsed.fortran_order);
        assert_eq!(parsed.shape, vec![10, 20]);
    }

    #[test]
    fn dtype_simple_and_object_detection() {
        assert_eq!(
            analyze_descr("'<f8'"),
            DtypeAnalysis::FixedSize { item_size: 8 }
        );
        assert_eq!(
            analyze_descr("'>i4'"),
            DtypeAnalysis::FixedSize { item_size: 4 }
        );
        assert_eq!(
            analyze_descr("'|b1'"),
            DtypeAnalysis::FixedSize { item_size: 1 }
        );
        assert_eq!(
            analyze_descr("'<U10'"),
            DtypeAnalysis::FixedSize { item_size: 40 }
        );
        assert_eq!(analyze_descr("'O'"), DtypeAnalysis::Object);
        assert_eq!(analyze_descr("'|O'"), DtypeAnalysis::Object);
    }

    #[test]
    fn structured_dtype_parsing() {
        let descr = "[('a', '<f8'), ('b', '<i4')]";
        let res = parse_structured_dtype(descr);
        assert_eq!(
            res,
            DtypeAnalysis::Structured {
                item_size: 12,
                has_object: false
            }
        );
    }
}
