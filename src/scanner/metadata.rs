use crate::scanner::{
    duration_ms, CheckType, Confidence, FindingClass, HeuristicsScanner, LayerScanResult,
    ScanStatus,
};
use anyhow::{anyhow, bail, Context, Result};
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::time::Instant;

const MAX_HEADER_BYTES: u64 = 128 * 1024 * 1024;
const MAX_METADATA_FIELDS: u64 = 1_000_000;
const MAX_TENSORS: u64 = 1_000_000;
const MAX_ARRAY_ITEMS: u64 = 10_000_000;
const MAX_STRING_BYTES: u64 = 16 * 1024 * 1024;
const MAX_COLLECTED_TEXT_BYTES: usize = 8 * 1024 * 1024;
const MAX_ARRAY_DEPTH: usize = 8;
const DEFAULT_ALIGNMENT: u64 = 32;

pub struct MetadataScanner;

impl MetadataScanner {
    pub fn scan_file(
        file: &File,
        file_len: u64,
        layer_digest: &str,
        media_type: &str,
    ) -> Result<LayerScanResult> {
        Ok(Self::scan_file_results(file, file_len, layer_digest, media_type)?.remove(0))
    }

    pub fn scan_file_results(
        file: &File,
        file_len: u64,
        layer_digest: &str,
        media_type: &str,
    ) -> Result<Vec<LayerScanResult>> {
        let started = Instant::now();
        let parsed = match (|| -> Result<ParsedGguf> {
            let mut cloned = file.try_clone()?;
            cloned.seek(SeekFrom::Start(0))?;
            parse_gguf(cloned, file_len)
        })() {
            Ok(parsed) => parsed,
            Err(error) => {
                return Ok(vec![LayerScanResult {
                    layer_digest: layer_digest.to_owned(),
                    media_type: media_type.to_owned(),
                    check_type: CheckType::GGUFMetadata,
                    status: ScanStatus::Fail,
                    finding_class: FindingClass::Structural,
                    confidence: Confidence::High,
                    detail: Some(format!("Invalid or unsafe GGUF structure: {error}")),
                    matches: vec!["[T15-STRUCT] GGUF structural validation failed".to_owned()],
                    duration_ms: duration_ms(started),
                }]);
            }
        };

        let status = if parsed.warnings.is_empty() {
            ScanStatus::Pass
        } else {
            ScanStatus::Warn
        };
        let class = if parsed.warnings.is_empty() {
            FindingClass::Structural
        } else {
            FindingClass::Compatibility
        };
        let confidence = Confidence::High;
        let matches = parsed.warnings.clone();
        let detail = Some(format!(
            "GGUF v{} {}-endian structure validated: {} tensor(s), {} metadata field(s), alignment {}",
            parsed.version,
            if parsed.endian == Endian::Little { "little" } else { "big" },
            parsed.tensor_count,
            parsed.metadata_count,
            parsed.alignment
        ));

        let structural_result = LayerScanResult {
            layer_digest: layer_digest.to_owned(),
            media_type: media_type.to_owned(),
            check_type: CheckType::GGUFMetadata,
            status,
            finding_class: class,
            confidence,
            detail,
            matches,
            duration_ms: duration_ms(started),
        };

        let mut results = vec![structural_result];
        if !parsed.text.is_empty() {
            let heuristic = HeuristicsScanner::scan_content_for_media(
                &parsed.text,
                layer_digest,
                media_type,
                duration_ms(started),
            )?;
            results.push(heuristic);
        }

        Ok(results)
    }
}

/// Validate GGUF structure directly from bytes. This calls the same bounded
/// parser used by the production file scanner and is intentionally public for
/// fuzz/property testing.
pub fn validate_gguf_bytes(bytes: &[u8]) -> Result<()> {
    let len = u64::try_from(bytes.len()).context("GGUF input length does not fit u64")?;
    parse_gguf(Cursor::new(bytes), len).map(|_| ())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Endian {
    Little,
    Big,
}

struct ParsedGguf {
    version: u32,
    endian: Endian,
    tensor_count: u64,
    metadata_count: u64,
    alignment: u64,
    text: String,
    warnings: Vec<String>,
}

#[derive(Debug)]
struct TensorInfo {
    name: String,
    dimensions: Vec<u64>,
    tensor_type: u32,
    offset: u64,
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
        if pos
            .checked_add(additional)
            .is_none_or(|end| end > MAX_HEADER_BYTES)
        {
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

    fn read_u8(&mut self) -> Result<u8> {
        Ok(self.read_exact_vec(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16> {
        let bytes: [u8; 2] = self.read_exact_vec(2)?.try_into().expect("fixed length");
        Ok(match self.endian {
            Endian::Little => u16::from_le_bytes(bytes),
            Endian::Big => u16::from_be_bytes(bytes),
        })
    }

    fn read_u32(&mut self) -> Result<u32> {
        let bytes: [u8; 4] = self.read_exact_vec(4)?.try_into().expect("fixed length");
        Ok(match self.endian {
            Endian::Little => u32::from_le_bytes(bytes),
            Endian::Big => u32::from_be_bytes(bytes),
        })
    }

    fn read_u64(&mut self) -> Result<u64> {
        let bytes: [u8; 8] = self.read_exact_vec(8)?.try_into().expect("fixed length");
        Ok(match self.endian {
            Endian::Little => u64::from_le_bytes(bytes),
            Endian::Big => u64::from_be_bytes(bytes),
        })
    }

    fn read_count(&mut self) -> Result<u64> {
        if self.version == 1 {
            Ok(self.read_u32()? as u64)
        } else {
            self.read_u64()
        }
    }

    fn read_string(&mut self, max_len: u64) -> Result<String> {
        let len = self.read_count()?;
        if len > max_len {
            bail!("GGUF string length {len} exceeds safety limit {max_len}");
        }
        let len_usize = usize::try_from(len).context("GGUF string length does not fit usize")?;
        let bytes = self.read_exact_vec(len_usize)?;
        String::from_utf8(bytes).context("GGUF string is not valid UTF-8")
    }

    fn skip(&mut self, bytes: u64) -> Result<()> {
        self.ensure_header_budget(bytes)?;
        let delta = i64::try_from(bytes).context("skip length too large")?;
        self.file.seek(SeekFrom::Current(delta))?;
        Ok(())
    }
}

fn parse_gguf<R: Read + Seek>(mut raw: R, file_len: u64) -> Result<ParsedGguf> {
    if file_len < 8 {
        bail!("file is too small to contain GGUF magic and version");
    }

    raw.seek(SeekFrom::Start(0))?;
    let mut prefix = [0_u8; 8];
    raw.read_exact(&mut prefix)?;
    if &prefix[..4] != b"GGUF" {
        bail!("missing GGUF magic");
    }

    let le_version = u32::from_le_bytes(prefix[4..8].try_into().expect("fixed slice"));
    let be_version = u32::from_be_bytes(prefix[4..8].try_into().expect("fixed slice"));
    let (version, endian) = if (1..=3).contains(&le_version) {
        (le_version, Endian::Little)
    } else if be_version == 3 {
        // GGUF v3 introduced explicit big-endian support. Accepting a
        // big-endian encoding for v1/v2 would bless a non-standard layout.
        (be_version, Endian::Big)
    } else {
        bail!("unsupported GGUF version/endianness encoding ({le_version}/{be_version})");
    };

    let minimum_header = if version == 1 { 16 } else { 24 };
    if file_len < minimum_header {
        bail!(
            "file is too small for a GGUF v{version} header (need at least {minimum_header} bytes)"
        );
    }

    let mut reader = GgufReader {
        file: raw,
        endian,
        version,
    };

    // The v1 historical width changed in v2. Most surviving v1 files use
    // 32-bit countables; support that layout while v2/v3 use 64-bit values.
    let tensor_count = reader.read_count()?;
    let metadata_count = reader.read_count()?;
    if tensor_count > MAX_TENSORS {
        bail!("tensor count {tensor_count} exceeds safety cap {MAX_TENSORS}");
    }
    if metadata_count > MAX_METADATA_FIELDS {
        bail!("metadata count {metadata_count} exceeds safety cap {MAX_METADATA_FIELDS}");
    }

    let mut collected = String::new();
    let mut alignment = DEFAULT_ALIGNMENT;
    for _ in 0..metadata_count {
        let key = reader.read_string(65_535)?;
        validate_metadata_key(&key)?;
        let value_type = reader.read_u32()?;
        let scalar = read_metadata_value(
            &mut reader,
            value_type,
            0,
            should_collect_metadata(&key),
            &mut collected,
        )?;
        if key == "general.alignment" {
            if let Some(value) = scalar {
                alignment = value;
            }
        }
    }

    if alignment < 8 || !alignment.is_multiple_of(8) || alignment > 1024 * 1024 {
        bail!("general.alignment {alignment} is invalid (must be a reasonable multiple of 8)");
    }

    let mut tensors = Vec::with_capacity(usize::try_from(tensor_count.min(100_000)).unwrap_or(0));
    for _ in 0..tensor_count {
        let name = reader.read_string(64)?;
        if name.is_empty() {
            bail!("tensor name must not be empty");
        }
        let n_dimensions = reader.read_u32()?;
        if n_dimensions == 0 || n_dimensions > 4 {
            bail!("tensor '{name}' has invalid dimension count {n_dimensions}");
        }
        let mut dimensions = Vec::with_capacity(n_dimensions as usize);
        for _ in 0..n_dimensions {
            // GGUF tensor dimensions remain u64 in v1; only header counts and
            // string lengths use the historical 32-bit width.
            let dimension = reader.read_u64()?;
            if dimension == 0 {
                bail!("tensor '{name}' contains a zero dimension");
            }
            dimensions.push(dimension);
        }
        let tensor_type = reader.read_u32()?;
        if matches!(tensor_type, 4 | 5 | 31 | 32 | 33 | 36 | 37 | 38) {
            bail!("tensor '{name}' uses removed GGML type {tensor_type}");
        }
        let offset = reader.read_u64()?;
        if offset % alignment != 0 {
            bail!("tensor '{name}' offset {offset} is not aligned to {alignment}");
        }
        tensors.push(TensorInfo {
            name,
            dimensions,
            tensor_type,
            offset,
        });
    }

    let descriptor_end = reader.position()?;
    let tensor_data_start = align_up(descriptor_end, alignment)?;
    if tensor_data_start > file_len {
        bail!("aligned tensor-data start {tensor_data_start} is beyond file length {file_len}");
    }
    validate_padding(&mut reader.file, descriptor_end, tensor_data_start)?;
    let tensor_data_len = file_len - tensor_data_start;

    if !tensors.is_empty() && tensor_data_len == 0 {
        bail!("GGUF declares tensors but contains no tensor data");
    }

    let mut warnings = Vec::new();
    validate_tensor_ranges(&tensors, tensor_data_len, &mut warnings)?;

    Ok(ParsedGguf {
        version,
        endian,
        tensor_count,
        metadata_count,
        alignment,
        text: collected,
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
    key.contains("template")
        || key.contains("prompt")
        || key.contains("system")
        || key.starts_with("general.")
        || key.contains("license")
        || key.contains("description")
}

fn read_metadata_value<R: Read + Seek>(
    reader: &mut GgufReader<R>,
    value_type: u32,
    depth: usize,
    collect_strings: bool,
    collected: &mut String,
) -> Result<Option<u64>> {
    if depth > MAX_ARRAY_DEPTH {
        bail!("nested GGUF metadata array exceeds depth cap {MAX_ARRAY_DEPTH}");
    }

    match value_type {
        0 | 1 => {
            let value = reader.read_u8()?;
            Ok((value_type == 0).then_some(value as u64))
        }
        2 | 3 => {
            let value = reader.read_u16()?;
            Ok((value_type == 2).then_some(value as u64))
        }
        4 => Ok(Some(reader.read_u32()? as u64)),
        5 | 6 => {
            reader.skip(4)?;
            Ok(None)
        }
        7 => {
            let value = reader.read_u8()?;
            if value > 1 {
                bail!("GGUF boolean value must be 0 or 1, got {value}");
            }
            Ok(Some(value as u64))
        }
        8 => {
            let value = reader.read_string(MAX_STRING_BYTES)?;
            if collect_strings {
                append_collected_text(collected, &value);
            }
            Ok(None)
        }
        9 => {
            let element_type = reader.read_u32()?;
            if element_type > 12 {
                bail!("unknown GGUF array element type {element_type}");
            }
            let count = reader.read_count()?;
            if count > MAX_ARRAY_ITEMS {
                bail!("GGUF array count {count} exceeds safety cap {MAX_ARRAY_ITEMS}");
            }
            for _ in 0..count {
                read_metadata_value(reader, element_type, depth + 1, collect_strings, collected)?;
            }
            Ok(None)
        }
        10 => Ok(Some(reader.read_u64()?)),
        11 | 12 => {
            reader.skip(8)?;
            Ok(None)
        }
        other => bail!("unknown GGUF metadata value type {other}"),
    }
}

fn append_collected_text(output: &mut String, value: &str) {
    if output.len() >= MAX_COLLECTED_TEXT_BYTES {
        return;
    }
    let remaining = MAX_COLLECTED_TEXT_BYTES - output.len();
    if !output.is_empty() && remaining > 0 {
        output.push('\n');
    }
    let allowed = remaining.saturating_sub(1);
    if value.len() <= allowed {
        output.push_str(value);
        return;
    }
    let mut end = allowed.min(value.len());
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    output.push_str(&value[..end]);
}

fn align_up(value: u64, alignment: u64) -> Result<u64> {
    let remainder = value % alignment;
    if remainder == 0 {
        return Ok(value);
    }
    value
        .checked_add(alignment - remainder)
        .ok_or_else(|| anyhow!("alignment calculation overflow"))
}

fn validate_padding<R: Read + Seek>(file: &mut R, start: u64, end: u64) -> Result<()> {
    if end <= start {
        return Ok(());
    }
    file.seek(SeekFrom::Start(start))?;
    let mut padding = vec![0_u8; usize::try_from(end - start)?];
    file.read_exact(&mut padding)?;
    if padding.iter().any(|byte| *byte != 0) {
        bail!("GGUF alignment padding contains non-zero bytes");
    }
    Ok(())
}

fn validate_tensor_ranges(
    tensors: &[TensorInfo],
    tensor_data_len: u64,
    warnings: &mut Vec<String>,
) -> Result<()> {
    let mut ordered: Vec<&TensorInfo> = tensors.iter().collect();
    ordered.sort_by_key(|tensor| tensor.offset);
    let mut unknown_types = std::collections::BTreeSet::new();

    for (index, tensor) in ordered.iter().enumerate() {
        if tensor.offset >= tensor_data_len && tensor_data_len != 0 {
            bail!(
                "tensor '{}' begins at relative offset {} beyond tensor-data length {}",
                tensor.name,
                tensor.offset,
                tensor_data_len
            );
        }

        let elements = tensor
            .dimensions
            .iter()
            .try_fold(1_u64, |acc, dimension| acc.checked_mul(*dimension))
            .ok_or_else(|| anyhow!("tensor '{}' dimension product overflows u64", tensor.name))?;
        if elements == 0 {
            bail!("tensor '{}' has zero elements", tensor.name);
        }

        let next_offset = ordered.get(index + 1).map(|next| next.offset);
        if next_offset.is_some_and(|next| next <= tensor.offset) {
            bail!(
                "tensor '{}' overlaps another tensor at offset {}",
                tensor.name,
                tensor.offset
            );
        }

        match tensor_layout(tensor.tensor_type) {
            Some((block_elements, block_bytes)) => {
                let first_dimension = tensor.dimensions[0];
                if first_dimension % block_elements != 0 {
                    bail!(
                        "tensor '{}' first dimension {} is not divisible by block size {} for type {}",
                        tensor.name,
                        first_dimension,
                        block_elements,
                        tensor.tensor_type
                    );
                }
                if elements % block_elements != 0 {
                    bail!(
                        "tensor '{}' element count is incompatible with its GGML type",
                        tensor.name
                    );
                }
                let blocks = elements / block_elements;
                let bytes = blocks.checked_mul(block_bytes).ok_or_else(|| {
                    anyhow!(
                        "tensor '{}' byte-size calculation overflows u64",
                        tensor.name
                    )
                })?;
                let end = tensor
                    .offset
                    .checked_add(bytes)
                    .ok_or_else(|| anyhow!("tensor '{}' end offset overflows u64", tensor.name))?;
                if end > tensor_data_len {
                    bail!(
                        "tensor '{}' range {}..{} exceeds tensor-data length {}",
                        tensor.name,
                        tensor.offset,
                        end,
                        tensor_data_len
                    );
                }
                if let Some(next) = next_offset {
                    if end > next {
                        bail!(
                            "tensor '{}' calculated range ends at {}, overlapping next tensor at {}",
                            tensor.name,
                            end,
                            next
                        );
                    }
                }
            }
            None => {
                unknown_types.insert(tensor.tensor_type);
            }
        }
    }

    if !unknown_types.is_empty() {
        warnings.push(format!(
            "[GGUF-COMPAT] Tensor type(s) {} are structurally bounded by offsets but lack exact byte-size validation in this Layerfault build",
            unknown_types
                .into_iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    Ok(())
}

/// (elements per block, bytes per block). Values mirror current ggml layouts
/// for stable/common types. New encodings intentionally return None so future
/// GGUF files are reported as partially validated rather than falsely rejected.
fn tensor_layout(tensor_type: u32) -> Option<(u64, u64)> {
    match tensor_type {
        0 => Some((1, 4)),
        1 => Some((1, 2)),
        2 => Some((32, 18)),
        3 => Some((32, 20)),
        6 => Some((32, 22)),
        7 => Some((32, 24)),
        8 => Some((32, 34)),
        9 => Some((32, 36)),
        10 => Some((256, 84)),
        11 => Some((256, 110)),
        12 => Some((256, 144)),
        13 => Some((256, 176)),
        14 => Some((256, 210)),
        15 => Some((256, 292)),
        16 => Some((256, 66)),
        17 => Some((256, 74)),
        18 => Some((256, 98)),
        19 => Some((256, 50)),
        20 => Some((32, 18)),
        21 => Some((256, 110)),
        22 => Some((256, 82)),
        23 => Some((256, 136)),
        24 => Some((1, 1)),
        25 => Some((1, 2)),
        26 => Some((1, 4)),
        27 => Some((1, 8)),
        28 => Some((1, 8)),
        29 => Some((256, 56)),
        30 => Some((1, 2)),
        34 => Some((256, 54)),
        35 => Some((256, 66)),
        39 => Some((32, 17)),  // MXFP4
        40 => Some((64, 36)),  // NVFP4
        41 => Some((128, 18)), // Q1_0
        42 => Some((64, 18)),  // Q2_0
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write_u32(buf: &mut Vec<u8>, value: u32, endian: Endian) {
        let bytes = match endian {
            Endian::Little => value.to_le_bytes(),
            Endian::Big => value.to_be_bytes(),
        };
        buf.extend_from_slice(&bytes);
    }

    fn write_u64(buf: &mut Vec<u8>, value: u64, endian: Endian) {
        let bytes = match endian {
            Endian::Little => value.to_le_bytes(),
            Endian::Big => value.to_be_bytes(),
        };
        buf.extend_from_slice(&bytes);
    }

    fn write_string(buf: &mut Vec<u8>, value: &str, endian: Endian) {
        let len = value.len() as u64;
        write_u64(buf, len, endian);
        buf.extend_from_slice(value.as_bytes());
    }

    fn minimal_v3_tensor(
        endian: Endian,
        bad_offset: bool,
        tensor_type: u32,
        dim: u64,
        tensor_bytes: usize,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"GGUF");
        let version = 3_u32;
        write_u32(&mut buf, version, endian);
        let one = 1_u64;
        for value in [one, one] {
            write_u64(&mut buf, value, endian);
        }
        write_string(&mut buf, "general.name", endian);
        let string_type = 8_u32;
        write_u32(&mut buf, string_type, endian);
        write_string(&mut buf, "safe model", endian);
        write_string(&mut buf, "weight", endian);
        let dims = 1_u32;
        write_u32(&mut buf, dims, endian);
        write_u64(&mut buf, dim, endian);
        write_u32(&mut buf, tensor_type, endian);
        let offset = if bad_offset { 4096_u64 } else { 0_u64 };
        write_u64(&mut buf, offset, endian);
        while buf.len() % 32 != 0 {
            buf.push(0);
        }
        buf.extend_from_slice(&vec![0_u8; tensor_bytes]);
        buf
    }

    fn minimal_v3(endian: Endian, bad_offset: bool) -> Vec<u8> {
        minimal_v3_tensor(endian, bad_offset, 2, 32, 18)
    }

    fn with_temp_file(name: &str, bytes: &[u8], f: impl FnOnce(&File) -> Result<()>) -> Result<()> {
        let path = std::env::temp_dir().join(format!("layerfault_gguf_{name}"));
        fs::write(&path, bytes)?;
        let file = File::open(&path)?;
        f(&file)?;
        let _ = fs::remove_file(path);
        Ok(())
    }

    #[test]
    fn current_tensor_layouts_are_exactly_bounded() {
        assert_eq!(tensor_layout(39), Some((32, 17)));
        assert_eq!(tensor_layout(40), Some((64, 36)));
        assert_eq!(tensor_layout(41), Some((128, 18)));
        assert_eq!(tensor_layout(42), Some((64, 18)));
        assert_eq!(tensor_layout(43), None);
    }

    #[test]
    fn newest_known_tensor_types_receive_exact_range_validation() -> Result<()> {
        for (tensor_type, dim, bytes) in [(40_u32, 64_u64, 36_usize), (41, 128, 18), (42, 64, 18)] {
            let data = minimal_v3_tensor(Endian::Little, false, tensor_type, dim, bytes);
            validate_gguf_bytes(&data)?;

            let truncated = minimal_v3_tensor(Endian::Little, false, tensor_type, dim, bytes - 1);
            assert!(validate_gguf_bytes(&truncated).is_err());
        }
        Ok(())
    }

    #[test]
    fn valid_little_endian_v3_passes() -> Result<()> {
        let bytes = minimal_v3(Endian::Little, false);
        with_temp_file("le", &bytes, |file| {
            let parsed = parse_gguf(file.try_clone()?, bytes.len() as u64)?;
            assert_eq!(parsed.version, 3);
            assert_eq!(parsed.tensor_count, 1);
            Ok(())
        })
    }

    #[test]
    fn valid_big_endian_v3_passes() -> Result<()> {
        let bytes = minimal_v3(Endian::Big, false);
        with_temp_file("be", &bytes, |file| {
            let parsed = parse_gguf(file.try_clone()?, bytes.len() as u64)?;
            assert_eq!(parsed.endian, Endian::Big);
            Ok(())
        })
    }

    #[test]
    fn out_of_bounds_tensor_fails() -> Result<()> {
        let bytes = minimal_v3(Endian::Little, true);
        with_temp_file("bad_offset", &bytes, |file| {
            assert!(parse_gguf(file.try_clone()?, bytes.len() as u64).is_err());
            Ok(())
        })
    }

    #[test]
    fn truncated_gguf_fails_instead_of_passing() -> Result<()> {
        with_temp_file("truncated", b"GGUF\x03\x00\x00\x00", |file| {
            assert!(parse_gguf(file.try_clone()?, 8).is_err());
            Ok(())
        })
    }

    #[test]
    fn empty_metadata_key_fails_byte_and_file_paths() -> Result<()> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"GGUF");
        write_u32(&mut bytes, 3, Endian::Little);
        write_u64(&mut bytes, 0, Endian::Little);
        write_u64(&mut bytes, 1, Endian::Little);
        write_string(&mut bytes, "", Endian::Little);
        write_u32(&mut bytes, 8, Endian::Little);
        write_string(&mut bytes, "value", Endian::Little);

        assert!(validate_gguf_bytes(&bytes).is_err());
        with_temp_file("empty_metadata_key", &bytes, |file| {
            let results = MetadataScanner::scan_file_results(
                file,
                bytes.len() as u64,
                "sha256:fixture",
                "application/x-gguf",
            )?;
            assert_eq!(results.len(), 1);
            let finding = &results[0];
            assert_eq!(finding.status, ScanStatus::Fail);
            assert_eq!(finding.finding_class, FindingClass::Structural);
            assert!(finding
                .matches
                .iter()
                .any(|value| value.contains("T15-STRUCT")));
            Ok(())
        })
    }

    #[test]
    fn pre_v3_big_endian_version_is_rejected() {
        let mut bytes = vec![0_u8; 24];
        bytes[..4].copy_from_slice(b"GGUF");
        bytes[4..8].copy_from_slice(&2_u32.to_be_bytes());
        assert!(validate_gguf_bytes(&bytes).is_err());
    }

    #[test]
    fn v1_uses_shorter_count_header_width() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"GGUF");
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        // v1 uses 32-bit counts, so descriptors end at byte 16. Pad to the
        // default tensor-data alignment to keep the fixture structurally valid.
        bytes.resize(32, 0);
        assert!(validate_gguf_bytes(&bytes).is_ok());
    }

    #[test]
    fn nested_array_depth_is_bounded() {
        const { assert!(MAX_ARRAY_DEPTH < 64) };
    }
}
