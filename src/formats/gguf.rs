//! Reusable bounded GGUF parser and inventory.
//!
//! This is the single authoritative GGUF structural parser. Scanner, model
//! snapshot, lineage, derivation and weight-analysis code all consume this
//! inventory rather than reparsing attacker-controlled bytes independently.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::Path;

pub const MAX_HEADER_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_METADATA_FIELDS: u64 = 1_000_000;
pub const MAX_TENSORS: u64 = 1_000_000;
pub const MAX_ARRAY_ITEMS: u64 = 10_000_000;
pub const MAX_STRING_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_COLLECTED_TEXT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_ARRAY_DEPTH: usize = 8;
pub const DEFAULT_ALIGNMENT: u64 = 32;
const MAX_CAPTURED_STRING_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Endian {
    Little,
    Big,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GgufMetadataEntry {
    pub value_type: u32,
    pub digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub string_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsigned_value: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_value: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub float_value: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bool_value: Option<bool>,
}

impl GgufMetadataEntry {
    pub fn as_str(&self) -> Option<&str> {
        self.string_value.as_deref()
    }

    pub fn as_u64(&self) -> Option<u64> {
        self.unsigned_value.or_else(|| self.signed_value.and_then(|v| u64::try_from(v).ok()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GgufTensor {
    pub name: String,
    pub dimensions: Vec<u64>,
    pub tensor_type: u32,
    pub offset: u64,
    pub byte_len: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GgufInventory {
    pub version: u32,
    pub endian: Endian,
    pub tensor_count: u64,
    pub metadata_count: u64,
    pub alignment: u64,
    pub tensor_data_start: u64,
    pub metadata: BTreeMap<String, GgufMetadataEntry>,
    pub tensors: Vec<GgufTensor>,
    pub collected_text: String,
    pub warnings: Vec<String>,
}

pub fn parse_path(path: &Path) -> Result<GgufInventory> {
    let file = crate::safeio::open_readonly_nofollow(path)?;
    let len = file.metadata()?.len();
    parse_file(&file, len)
}

pub fn parse_file(file: &File, file_len: u64) -> Result<GgufInventory> {
    let mut cloned = file.try_clone()?;
    cloned.seek(SeekFrom::Start(0))?;
    parse_reader(cloned, file_len)
}

pub fn validate_gguf_bytes(bytes: &[u8]) -> Result<()> {
    let len = u64::try_from(bytes.len()).context("GGUF input length does not fit u64")?;
    parse_reader(Cursor::new(bytes), len).map(|_| ())
}

struct GgufReader<R: Read + Seek> {
    file: R,
    endian: Endian,
    version: u32,
}

impl<R: Read + Seek> GgufReader<R> {
    fn position(&mut self) -> Result<u64> {
        Ok(self.file.stream_position()?)
    }

    fn ensure_header_budget(&mut self, additional: u64) -> Result<()> {
        let pos = self.position()?;
        if pos.checked_add(additional).is_none_or(|end| end > MAX_HEADER_BYTES) {
            bail!("GGUF header/metadata exceeds {MAX_HEADER_BYTES} byte safety budget");
        }
        Ok(())
    }

    fn read_exact_vec(&mut self, len: usize) -> Result<Vec<u8>> {
        self.ensure_header_budget(len as u64)?;
        let mut bytes = vec![0_u8; len];
        self.file.read_exact(&mut bytes)?;
        Ok(bytes)
    }

    fn read_u8(&mut self) -> Result<u8> { Ok(self.read_exact_vec(1)?[0]) }
    fn read_i8(&mut self) -> Result<i8> { Ok(self.read_u8()? as i8) }

    fn read_u16(&mut self) -> Result<u16> {
        let bytes: [u8; 2] = self.read_exact_vec(2)?.try_into().expect("fixed length");
        Ok(match self.endian { Endian::Little => u16::from_le_bytes(bytes), Endian::Big => u16::from_be_bytes(bytes) })
    }
    fn read_i16(&mut self) -> Result<i16> {
        let bytes: [u8; 2] = self.read_exact_vec(2)?.try_into().expect("fixed length");
        Ok(match self.endian { Endian::Little => i16::from_le_bytes(bytes), Endian::Big => i16::from_be_bytes(bytes) })
    }
    fn read_u32(&mut self) -> Result<u32> {
        let bytes: [u8; 4] = self.read_exact_vec(4)?.try_into().expect("fixed length");
        Ok(match self.endian { Endian::Little => u32::from_le_bytes(bytes), Endian::Big => u32::from_be_bytes(bytes) })
    }
    fn read_i32(&mut self) -> Result<i32> {
        let bytes: [u8; 4] = self.read_exact_vec(4)?.try_into().expect("fixed length");
        Ok(match self.endian { Endian::Little => i32::from_le_bytes(bytes), Endian::Big => i32::from_be_bytes(bytes) })
    }
    fn read_f32(&mut self) -> Result<f32> {
        let bits = self.read_u32()?;
        Ok(f32::from_bits(bits))
    }
    fn read_u64(&mut self) -> Result<u64> {
        let bytes: [u8; 8] = self.read_exact_vec(8)?.try_into().expect("fixed length");
        Ok(match self.endian { Endian::Little => u64::from_le_bytes(bytes), Endian::Big => u64::from_be_bytes(bytes) })
    }
    fn read_i64(&mut self) -> Result<i64> {
        let bytes: [u8; 8] = self.read_exact_vec(8)?.try_into().expect("fixed length");
        Ok(match self.endian { Endian::Little => i64::from_le_bytes(bytes), Endian::Big => i64::from_be_bytes(bytes) })
    }
    fn read_f64(&mut self) -> Result<f64> {
        let bits = self.read_u64()?;
        Ok(f64::from_bits(bits))
    }

    fn read_count(&mut self) -> Result<u64> {
        if self.version == 1 { Ok(self.read_u32()? as u64) } else { self.read_u64() }
    }

    fn read_string_bytes(&mut self, max_len: u64) -> Result<Vec<u8>> {
        let len = self.read_count()?;
        if len > max_len { bail!("GGUF string length {len} exceeds safety limit {max_len}"); }
        let len = usize::try_from(len).context("GGUF string length does not fit usize")?;
        self.read_exact_vec(len)
    }

    fn read_string(&mut self, max_len: u64) -> Result<String> {
        String::from_utf8(self.read_string_bytes(max_len)?).context("GGUF string is not valid UTF-8")
    }
}

#[derive(Default)]
struct CapturedValue {
    string_value: Option<String>,
    unsigned_value: Option<u64>,
    signed_value: Option<i64>,
    float_value: Option<f64>,
    bool_value: Option<bool>,
}

fn parse_reader<R: Read + Seek>(mut raw: R, file_len: u64) -> Result<GgufInventory> {
    if file_len < 8 { bail!("file is too small to contain GGUF magic and version"); }
    raw.seek(SeekFrom::Start(0))?;
    let mut prefix = [0_u8; 8];
    raw.read_exact(&mut prefix)?;
    if &prefix[..4] != b"GGUF" { bail!("missing GGUF magic"); }

    let le_version = u32::from_le_bytes(prefix[4..8].try_into().expect("fixed slice"));
    let be_version = u32::from_be_bytes(prefix[4..8].try_into().expect("fixed slice"));
    let (version, endian) = if (1..=3).contains(&le_version) {
        (le_version, Endian::Little)
    } else if be_version == 3 {
        (be_version, Endian::Big)
    } else {
        bail!("unsupported GGUF version/endianness encoding ({le_version}/{be_version})");
    };

    let minimum_header = if version == 1 { 16 } else { 24 };
    if file_len < minimum_header { bail!("file is too small for a GGUF v{version} header"); }

    let mut reader = GgufReader { file: raw, endian, version };
    let tensor_count = reader.read_count()?;
    let metadata_count = reader.read_count()?;
    if tensor_count > MAX_TENSORS { bail!("tensor count {tensor_count} exceeds safety cap {MAX_TENSORS}"); }
    if metadata_count > MAX_METADATA_FIELDS { bail!("metadata count {metadata_count} exceeds safety cap {MAX_METADATA_FIELDS}"); }

    let mut metadata = BTreeMap::new();
    let mut collected_text = String::new();
    let mut alignment = DEFAULT_ALIGNMENT;

    for _ in 0..metadata_count {
        let key = reader.read_string(65_535)?;
        validate_metadata_key(&key)?;
        if metadata.contains_key(&key) { bail!("duplicate GGUF metadata key '{key}'"); }
        let value_type = reader.read_u32()?;
        let mut hasher = Sha256::new();
        hasher.update(value_type.to_le_bytes());
        let capture = read_metadata_value(
            &mut reader,
            value_type,
            0,
            should_collect_metadata(&key),
            &mut collected_text,
            &mut hasher,
        )?;
        if key == "general.alignment" {
            if let Some(value) = capture.unsigned_value { alignment = value; }
        }
        metadata.insert(key, GgufMetadataEntry {
            value_type,
            digest: format!("sha256:{}", hex::encode(hasher.finalize())),
            string_value: capture.string_value,
            unsigned_value: capture.unsigned_value,
            signed_value: capture.signed_value,
            float_value: capture.float_value,
            bool_value: capture.bool_value,
        });
    }

    if alignment < 8 || !alignment.is_multiple_of(8) || alignment > 1024 * 1024 {
        bail!("general.alignment {alignment} is invalid (must be a reasonable multiple of 8)");
    }

    let mut tensors = Vec::with_capacity(usize::try_from(tensor_count.min(100_000)).unwrap_or(0));
    let mut tensor_names = BTreeSet::new();
    for _ in 0..tensor_count {
        let name = reader.read_string(16 * 1024)?;
        if name.is_empty() { bail!("tensor name must not be empty"); }
        if !tensor_names.insert(name.clone()) { bail!("duplicate GGUF tensor name '{name}'"); }
        let n_dimensions = reader.read_u32()?;
        if n_dimensions == 0 || n_dimensions > 4 { bail!("tensor '{name}' has invalid dimension count {n_dimensions}"); }
        let mut dimensions = Vec::with_capacity(n_dimensions as usize);
        for _ in 0..n_dimensions {
            let dimension = reader.read_u64()?;
            if dimension == 0 { bail!("tensor '{name}' contains a zero dimension"); }
            dimensions.push(dimension);
        }
        let tensor_type = reader.read_u32()?;
        if matches!(tensor_type, 4 | 5 | 31 | 32 | 33 | 36 | 37 | 38) {
            bail!("tensor '{name}' uses removed GGML type {tensor_type}");
        }
        let offset = reader.read_u64()?;
        if offset % alignment != 0 { bail!("tensor '{name}' offset {offset} is not aligned to {alignment}"); }
        let elements = dimensions.iter().try_fold(1_u64, |acc, v| acc.checked_mul(*v))
            .ok_or_else(|| anyhow!("tensor '{name}' dimension product overflows u64"))?;
        let byte_len = match tensor_layout(tensor_type) {
            Some((block_elements, block_bytes)) => {
                let first_dimension = dimensions[0];
                if first_dimension % block_elements != 0 {
                    bail!("tensor '{name}' first dimension {first_dimension} is not divisible by block size {block_elements} for type {tensor_type}");
                }
                if elements % block_elements != 0 {
                    bail!("tensor '{name}' element count {elements} is not divisible by block size {block_elements} for type {tensor_type}");
                }
                let blocks = elements / block_elements;
                let bytes = blocks.checked_mul(block_bytes)
                    .ok_or_else(|| anyhow!("tensor '{name}' byte-size calculation overflows u64"))?;
                Some(bytes)
            }
            None => None,
        };
        tensors.push(GgufTensor { name, dimensions, tensor_type, offset, byte_len });
    }

    let descriptor_end = reader.position()?;
    let tensor_data_start = align_up(descriptor_end, alignment)?;
    if tensor_data_start > file_len { bail!("aligned tensor-data start {tensor_data_start} is beyond file length {file_len}"); }
    validate_padding(&mut reader.file, descriptor_end, tensor_data_start)?;
    let tensor_data_len = file_len - tensor_data_start;
    if !tensors.is_empty() && tensor_data_len == 0 { bail!("GGUF declares tensors but contains no tensor data"); }
    let mut warnings = Vec::new();
    validate_tensor_ranges(&tensors, tensor_data_len, &mut warnings)?;

    Ok(GgufInventory {
        version,
        endian,
        tensor_count,
        metadata_count,
        alignment,
        tensor_data_start,
        metadata,
        tensors,
        collected_text,
        warnings,
    })
}

fn validate_metadata_key(key: &str) -> Result<()> {
    if key.is_empty() || !key.is_ascii() || key.bytes().any(|byte| byte.is_ascii_control()) {
        bail!("metadata key is empty, non-ASCII, or contains control characters");
    }
    Ok(())
}

fn should_collect_metadata(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("template") || key.contains("prompt") || key.contains("system")
        || key.starts_with("general.") || key.contains("license") || key.contains("description")
}

fn read_metadata_value<R: Read + Seek>(
    reader: &mut GgufReader<R>,
    value_type: u32,
    depth: usize,
    collect_strings: bool,
    collected: &mut String,
    hasher: &mut Sha256,
) -> Result<CapturedValue> {
    if depth > MAX_ARRAY_DEPTH { bail!("nested GGUF metadata array exceeds depth cap {MAX_ARRAY_DEPTH}"); }
    let mut out = CapturedValue::default();
    match value_type {
        0 => { let v = reader.read_u8()?; hasher.update([v]); out.unsigned_value = Some(v as u64); }
        1 => { let v = reader.read_i8()?; hasher.update(v.to_le_bytes()); out.signed_value = Some(v as i64); }
        2 => { let v = reader.read_u16()?; hasher.update(v.to_le_bytes()); out.unsigned_value = Some(v as u64); }
        3 => { let v = reader.read_i16()?; hasher.update(v.to_le_bytes()); out.signed_value = Some(v as i64); }
        4 => { let v = reader.read_u32()?; hasher.update(v.to_le_bytes()); out.unsigned_value = Some(v as u64); }
        5 => { let v = reader.read_i32()?; hasher.update(v.to_le_bytes()); out.signed_value = Some(v as i64); }
        6 => { let v = reader.read_f32()?; hasher.update(v.to_bits().to_le_bytes()); out.float_value = Some(v as f64); }
        7 => {
            let v = reader.read_u8()?;
            if v > 1 { bail!("GGUF boolean value must be 0 or 1, got {v}"); }
            hasher.update([v]); out.bool_value = Some(v == 1);
        }
        8 => {
            let bytes = reader.read_string_bytes(MAX_STRING_BYTES)?;
            hasher.update((bytes.len() as u64).to_le_bytes());
            hasher.update(&bytes);
            let value = String::from_utf8(bytes).context("GGUF string is not valid UTF-8")?;
            if collect_strings { append_collected_text(collected, &value); }
            if value.len() <= MAX_CAPTURED_STRING_BYTES { out.string_value = Some(value); }
        }
        9 => {
            let element_type = reader.read_u32()?;
            if element_type > 12 { bail!("unknown GGUF array element type {element_type}"); }
            let count = reader.read_count()?;
            if count > MAX_ARRAY_ITEMS { bail!("GGUF array count {count} exceeds safety cap {MAX_ARRAY_ITEMS}"); }
            hasher.update(element_type.to_le_bytes());
            hasher.update(count.to_le_bytes());
            for _ in 0..count {
                let mut child = Sha256::new();
                child.update(element_type.to_le_bytes());
                let _ = read_metadata_value(reader, element_type, depth + 1, collect_strings, collected, &mut child)?;
                hasher.update(child.finalize());
            }
        }
        10 => { let v = reader.read_u64()?; hasher.update(v.to_le_bytes()); out.unsigned_value = Some(v); }
        11 => { let v = reader.read_i64()?; hasher.update(v.to_le_bytes()); out.signed_value = Some(v); }
        12 => { let v = reader.read_f64()?; hasher.update(v.to_bits().to_le_bytes()); out.float_value = Some(v); }
        other => bail!("unknown GGUF metadata value type {other}"),
    }
    Ok(out)
}

fn append_collected_text(output: &mut String, value: &str) {
    if output.len() >= MAX_COLLECTED_TEXT_BYTES { return; }
    let remaining = MAX_COLLECTED_TEXT_BYTES - output.len();
    if !output.is_empty() && remaining > 0 { output.push('\n'); }
    let allowed = remaining.saturating_sub(1);
    if value.len() <= allowed { output.push_str(value); return; }
    let mut end = allowed.min(value.len());
    while end > 0 && !value.is_char_boundary(end) { end -= 1; }
    output.push_str(&value[..end]);
}

fn align_up(value: u64, alignment: u64) -> Result<u64> {
    let remainder = value % alignment;
    if remainder == 0 { return Ok(value); }
    value.checked_add(alignment - remainder).ok_or_else(|| anyhow!("alignment calculation overflow"))
}

fn validate_padding<R: Read + Seek>(file: &mut R, start: u64, end: u64) -> Result<()> {
    if end <= start { return Ok(()); }
    file.seek(SeekFrom::Start(start))?;
    let mut padding = vec![0_u8; usize::try_from(end - start)?];
    file.read_exact(&mut padding)?;
    if padding.iter().any(|byte| *byte != 0) { bail!("GGUF alignment padding contains non-zero bytes"); }
    Ok(())
}

fn validate_tensor_ranges(tensors: &[GgufTensor], tensor_data_len: u64, warnings: &mut Vec<String>) -> Result<()> {
    let mut ordered: Vec<&GgufTensor> = tensors.iter().collect();
    ordered.sort_by_key(|tensor| tensor.offset);
    let mut unknown_types = BTreeSet::new();
    for (index, tensor) in ordered.iter().enumerate() {
        if tensor.offset >= tensor_data_len && tensor_data_len != 0 {
            bail!("tensor '{}' begins at relative offset {} beyond tensor-data length {}", tensor.name, tensor.offset, tensor_data_len);
        }
        let next_offset = ordered.get(index + 1).map(|next| next.offset);
        if next_offset.is_some_and(|next| next <= tensor.offset) {
            bail!("tensor '{}' overlaps another tensor at offset {}", tensor.name, tensor.offset);
        }
        if let Some(bytes) = tensor.byte_len {
            let end = tensor.offset.checked_add(bytes).ok_or_else(|| anyhow!("tensor '{}' end offset overflows u64", tensor.name))?;
            if end > tensor_data_len { bail!("tensor '{}' range {}..{} exceeds tensor-data length {}", tensor.name, tensor.offset, end, tensor_data_len); }
            if let Some(next) = next_offset { if end > next { bail!("tensor '{}' calculated range ends at {}, overlapping next tensor at {}", tensor.name, end, next); } }
        } else {
            unknown_types.insert(tensor.tensor_type);
        }
    }
    if !unknown_types.is_empty() {
        warnings.push(format!("[GGUF-COMPAT] Tensor type(s) {} are structurally bounded by offsets but lack exact byte-size validation in this Layerfault build", unknown_types.into_iter().map(|v| v.to_string()).collect::<Vec<_>>().join(", ")));
    }
    Ok(())
}

/// (elements per block, bytes per block) for common/current ggml types.
pub fn tensor_layout(tensor_type: u32) -> Option<(u64, u64)> {
    match tensor_type {
        0 => Some((1, 4)), 1 => Some((1, 2)), 2 => Some((32, 18)), 3 => Some((32, 20)),
        6 => Some((32, 22)), 7 => Some((32, 24)), 8 => Some((32, 34)), 9 => Some((32, 36)),
        10 => Some((256, 84)), 11 => Some((256, 110)), 12 => Some((256, 144)), 13 => Some((256, 176)),
        14 => Some((256, 210)), 15 => Some((256, 292)), 16 => Some((256, 66)), 17 => Some((256, 74)),
        18 => Some((256, 98)), 19 => Some((256, 50)), 20 => Some((32, 18)), 21 => Some((256, 110)),
        22 => Some((256, 82)), 23 => Some((256, 136)), 24 => Some((1, 1)), 25 => Some((1, 2)),
        26 => Some((1, 4)), 27 => Some((1, 8)), 28 => Some((1, 8)), 29 => Some((256, 56)),
        30 => Some((1, 2)), 34 => Some((256, 54)), 35 => Some((256, 66)), 39 => Some((32, 17)),
        40 => Some((64, 36)), 41 => Some((128, 18)), 42 => Some((64, 18)), _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncated_is_rejected() {
        assert!(validate_gguf_bytes(b"GGUF\x03\x00\x00\x00").is_err());
    }

    #[test]
    fn current_layouts_are_known() {
        assert_eq!(tensor_layout(39), Some((32, 17)));
        assert_eq!(tensor_layout(42), Some((64, 18)));
    }

    /// Builds a minimal single-tensor GGUF byte stream. The parser bails out while
    /// reading the tensor descriptor for a known-but-invalid layout, so no tensor
    /// data body is required for these fixtures.
    fn single_tensor_gguf(name: &str, dimensions: &[u64], tensor_type: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"GGUF");
        bytes.extend_from_slice(&3_u32.to_le_bytes());
        bytes.extend_from_slice(&1_u64.to_le_bytes()); // tensor count
        bytes.extend_from_slice(&0_u64.to_le_bytes()); // metadata count
        bytes.extend_from_slice(&(name.len() as u64).to_le_bytes());
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(&(dimensions.len() as u32).to_le_bytes());
        for dimension in dimensions {
            bytes.extend_from_slice(&dimension.to_le_bytes());
        }
        bytes.extend_from_slice(&tensor_type.to_le_bytes());
        bytes.extend_from_slice(&0_u64.to_le_bytes()); // offset
        bytes
    }

    /// Regression for corpus case 08-gguf-integer-overflow: a known tensor layout
    /// (type 6, block size 32) whose first dimension is not divisible by the block
    /// size must be a hard structural failure, not a silently downgraded warning.
    #[test]
    fn known_layout_indivisible_first_dimension_is_a_structural_failure() {
        assert_eq!(tensor_layout(6), Some((32, 22)));
        let bytes = single_tensor_gguf("overflow_tensor", &[4_611_686_018_427_387_905], 6);
        let err = validate_gguf_bytes(&bytes).expect_err("indivisible first dimension must fail");
        let message = err.to_string();
        assert!(message.contains("overflow_tensor"), "{message}");
        assert!(message.contains("first dimension 4611686018427387905"), "{message}");
        assert!(message.contains("is not divisible by block size 32 for type 6"), "{message}");
    }

    /// Regression for corpus case 10-gguf-stride-overflow: a known tensor layout
    /// whose element/byte-size arithmetic overflows u64 must be a hard structural
    /// failure, not a silently downgraded warning.
    #[test]
    fn known_layout_byte_size_overflow_is_a_structural_failure() {
        assert_eq!(tensor_layout(0), Some((1, 4)));
        let bytes = single_tensor_gguf("exploit", &[4_611_686_018_427_387_904], 0);
        let err = validate_gguf_bytes(&bytes).expect_err("byte-size overflow must fail");
        let message = err.to_string();
        assert!(message.contains("exploit"), "{message}");
        assert!(message.contains("byte-size calculation overflows u64"), "{message}");
    }

    /// A genuinely unsupported tensor layout, with an offset/range that is still
    /// safely bounded within the tensor-data section, must parse successfully (as a
    /// bounded compatibility warning upstream) rather than hard-fail.
    #[test]
    fn unknown_layout_with_bounded_offset_is_not_a_structural_failure() {
        assert_eq!(tensor_layout(1_000), None);
        let mut bytes = single_tensor_gguf("unknown_layout", &[1], 1_000);
        while !bytes.len().is_multiple_of(DEFAULT_ALIGNMENT as usize) {
            bytes.push(0);
        }
        bytes.extend_from_slice(&[0_u8; 8]); // bounded, arbitrary tensor-data body
        assert!(validate_gguf_bytes(&bytes).is_ok());
    }
}
