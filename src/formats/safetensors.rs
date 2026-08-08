use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use anyhow::{anyhow, bail, Context, Result};
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Component, Path};
use std::time::Instant;

pub const MAX_HEADER_BYTES: u64 = 100 * 1024 * 1024;
pub const MAX_TENSORS: usize = 1_000_000;
pub const MAX_DIMENSIONS: usize = 32;

#[derive(Debug, Clone, serde::Serialize)]
pub struct SafetensorsSummary {
    pub tensor_count: usize,
    pub data_bytes: u64,
    pub header_bytes: u64,
    pub metadata_entries: usize,
    pub unknown_dtypes: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SafetensorsTensor {
    pub name: String,
    pub dtype: String,
    pub shape: Vec<u64>,
    pub start: u64,
    pub end: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SafetensorsInventory {
    pub summary: SafetensorsSummary,
    pub data_start: u64,
    pub metadata: BTreeMap<String, String>,
    pub tensors: Vec<SafetensorsTensor>,
}

#[derive(Debug, Clone)]
struct TensorSpec {
    dtype: String,
    shape: Vec<u64>,
    start: u64,
    end: u64,
}

struct UniqueObject(BTreeMap<String, Value>);

impl<'de> serde::Deserialize<'de> for UniqueObject {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct UniqueVisitor;
        impl<'de> Visitor<'de> for UniqueVisitor {
            type Value = UniqueObject;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON object with unique keys")
            }
            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut out = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, Value>()? {
                    if out.insert(key.clone(), value).is_some() {
                        return Err(serde::de::Error::custom(format!(
                            "duplicate safetensors header key '{key}'"
                        )));
                    }
                    if out.len() > MAX_TENSORS.saturating_add(1) {
                        return Err(serde::de::Error::custom(
                            "too many safetensors header entries",
                        ));
                    }
                }
                Ok(UniqueObject(out))
            }
        }
        deserializer.deserialize_map(UniqueVisitor)
    }
}

#[derive(Debug)]
struct UniqueStringMap(BTreeMap<String, String>);

impl<'de> serde::Deserialize<'de> for UniqueStringMap {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct UniqueStringMapVisitor;
        impl<'de> Visitor<'de> for UniqueStringMapVisitor {
            type Value = UniqueStringMap;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON string map with unique keys")
            }
            fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut out = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, String>()? {
                    if out.insert(key.clone(), value).is_some() {
                        return Err(serde::de::Error::custom(format!(
                            "duplicate Safetensors weight_map key '{key}'"
                        )));
                    }
                    if out.len() > MAX_TENSORS {
                        return Err(serde::de::Error::custom(
                            "too many Safetensors weight_map entries",
                        ));
                    }
                }
                Ok(UniqueStringMap(out))
            }
        }
        deserializer.deserialize_map(UniqueStringMapVisitor)
    }
}

#[derive(serde::Deserialize)]
struct SafetensorsIndexDocument {
    weight_map: UniqueStringMap,
}

pub(crate) fn parse_index_weight_map(bytes: &[u8]) -> Result<BTreeMap<String, String>> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let document =
        SafetensorsIndexDocument::deserialize(&mut de).context("invalid Safetensors index JSON")?;
    de.end()
        .context("trailing non-whitespace data in Safetensors index")?;
    Ok(document.weight_map.0)
}

pub fn scan_file(
    file: &File,
    file_len: u64,
    digest: &str,
    media_type: &str,
) -> Result<LayerScanResult> {
    let started = Instant::now();
    match validate_file(file, file_len) {
        Ok(summary) => {
            let mut matches = Vec::new();
            let (status, class, detail) = if summary.unknown_dtypes.is_empty() {
                (
                    ScanStatus::Pass,
                    FindingClass::Structural,
                    format!(
                        "Safetensors structure validated: {} tensor(s), {} data bytes, {} header bytes",
                        summary.tensor_count, summary.data_bytes, summary.header_bytes
                    ),
                )
            } else {
                matches.push(format!(
                    "[LF-SAFE-DTYPE] Exact tensor-byte validation skipped for unknown dtype(s): {}",
                    summary.unknown_dtypes.join(", ")
                ));
                (
                    ScanStatus::Warn,
                    FindingClass::Compatibility,
                    format!(
                        "Safetensors structure validated with {} unknown dtype(s)",
                        summary.unknown_dtypes.len()
                    ),
                )
            };
            Ok(LayerScanResult {
                layer_digest: digest.to_owned(),
                media_type: media_type.to_owned(),
                check_type: CheckType::SafetensorsStructure,
                status,
                finding_class: class,
                confidence: Confidence::High,
                detail: Some(detail),
                matches,
                duration_ms: elapsed(started),
            })
        }
        Err(error) => Ok(LayerScanResult {
            layer_digest: digest.to_owned(),
            media_type: media_type.to_owned(),
            check_type: CheckType::SafetensorsStructure,
            status: ScanStatus::Fail,
            finding_class: FindingClass::Structural,
            confidence: Confidence::High,
            detail: Some(format!("Invalid or unsafe Safetensors structure: {error}")),
            matches: vec!["[LF-SAFE-STRUCT] Safetensors structural validation failed".to_owned()],
            duration_ms: elapsed(started),
        }),
    }
}

pub fn scan_index(
    path: &Path,
    file: &File,
    file_len: u64,
    digest: &str,
    media_type: &str,
) -> Result<LayerScanResult> {
    let started = Instant::now();
    match validate_index(path, file, file_len) {
        Ok((tensors, shards)) => Ok(LayerScanResult {
            layer_digest: digest.to_owned(),
            media_type: media_type.to_owned(),
            check_type: CheckType::SafetensorsStructure,
            status: ScanStatus::Pass,
            finding_class: FindingClass::Structural,
            confidence: Confidence::High,
            detail: Some(format!("Safetensors sharded index validated: {tensors} tensor mapping(s), {shards} shard(s)")),
            matches: vec!["[LF-SAFE-INDEX] sharded Safetensors index validated".to_owned()],
            duration_ms: elapsed(started),
        }),
        Err(error) => Ok(LayerScanResult {
            layer_digest: digest.to_owned(),
            media_type: media_type.to_owned(),
            check_type: CheckType::SafetensorsStructure,
            status: ScanStatus::Fail,
            finding_class: FindingClass::Structural,
            confidence: Confidence::High,
            detail: Some(format!("Invalid or unsafe Safetensors sharded index: {error}")),
            matches: vec!["[LF-SAFE-INDEX-INVALID] Safetensors index validation failed".to_owned()],
            duration_ms: elapsed(started),
        }),
    }
}

pub fn validate_index(path: &Path, file: &File, file_len: u64) -> Result<(usize, usize)> {
    if file_len == 0 || file_len > MAX_HEADER_BYTES {
        bail!("index size {file_len} is outside the 1..={MAX_HEADER_BYTES} safety range");
    }
    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let mut bytes =
        Vec::with_capacity(usize::try_from(file_len).context("index size does not fit usize")?);
    reader
        .take(file_len.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != file_len {
        bail!("index changed while being read");
    }
    let map = parse_index_weight_map(&bytes)?;
    if map.is_empty() || map.len() > MAX_TENSORS {
        bail!("weight_map tensor count is outside the supported safety range");
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("index path has no parent directory"))?;
    let canonical_parent = std::fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
    let mut shards = BTreeSet::<String>::new();
    for (tensor, shard) in &map {
        if tensor.is_empty() || tensor.len() > 16 * 1024 {
            bail!("weight_map contains an invalid tensor name");
        }
        let relative = Path::new(shard); // nosemgrep: rust.actix.path-traversal.tainted-path.tainted-path -- immediately constrained to non-empty relative Normal components before any filesystem access
        if relative.as_os_str().is_empty()
            || relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            bail!("weight_map contains unsafe shard path '{shard}'");
        }
        if !shard.to_ascii_lowercase().ends_with(".safetensors") {
            bail!("weight_map references non-Safetensors shard '{shard}'");
        }
        shards.insert(shard.to_owned());
    }
    if shards.len() > 100_000 {
        bail!("index references too many shards");
    }
    for shard in &shards {
        let shard_path = parent.join(shard);
        let canonical = std::fs::canonicalize(&shard_path)
            .with_context(|| format!("referenced shard '{shard}' is missing or inaccessible"))?;
        if !canonical.starts_with(&canonical_parent) {
            bail!("referenced shard '{shard}' resolves outside the index directory");
        }
        let shard_file = crate::safeio::open_readonly_nofollow(&canonical)?;
        let shard_len = shard_file.metadata()?.len();
        validate_file(&shard_file, shard_len)
            .with_context(|| format!("referenced shard '{shard}' is structurally invalid"))?;
    }
    Ok((map.len(), shards.len()))
}

pub fn inventory_path(path: &Path) -> Result<SafetensorsInventory> {
    let file = crate::safeio::open_readonly_nofollow(path)?;
    let file_len = file.metadata()?.len();
    inventory_file(&file, file_len)
}

pub fn validate_file(file: &File, file_len: u64) -> Result<SafetensorsSummary> {
    Ok(inventory_file(file, file_len)?.summary)
}

pub fn inventory_file(file: &File, file_len: u64) -> Result<SafetensorsInventory> {
    if file_len < 10 {
        bail!("file is too small to contain a Safetensors header");
    }
    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let mut prefix = [0_u8; 8];
    reader.read_exact(&mut prefix)?;
    let header_len = u64::from_le_bytes(prefix);
    if header_len == 0 || header_len > MAX_HEADER_BYTES {
        bail!("header length {header_len} is outside the 1..={MAX_HEADER_BYTES} safety range");
    }
    let data_start = 8_u64
        .checked_add(header_len)
        .ok_or_else(|| anyhow!("header length overflow"))?;
    if data_start > file_len {
        bail!("header extends beyond end of file");
    }
    let header_usize = usize::try_from(header_len).context("header length does not fit usize")?;
    let mut header = vec![0_u8; header_usize];
    reader.read_exact(&mut header)?;
    if header.first().copied() != Some(b'{') {
        bail!("header does not begin with '{{'");
    }
    if std::str::from_utf8(&header).is_err() {
        bail!("header is not valid UTF-8");
    }
    let mut de = serde_json::Deserializer::from_slice(&header);
    let UniqueObject(entries) = <UniqueObject as serde::Deserialize>::deserialize(&mut de)
        .context("invalid Safetensors JSON header")?;
    de.end()
        .context("trailing non-whitespace data in Safetensors header")?;

    let data_bytes = file_len - data_start;
    let mut tensors = Vec::<SafetensorsTensor>::new();
    let mut metadata = BTreeMap::<String, String>::new();
    let mut unknown_dtypes = BTreeSet::new();
    for (name, value) in entries {
        if name == "__metadata__" {
            let object = value
                .as_object()
                .ok_or_else(|| anyhow!("__metadata__ must be an object"))?;
            if object.len() > 100_000 {
                bail!("__metadata__ contains too many entries");
            }
            for (key, value) in object {
                if key.is_empty() || key.len() > 4096 || !value.is_string() {
                    bail!("__metadata__ values must be bounded strings");
                }
                let value = value.as_str().unwrap_or_default();
                if value.len() > 64 * 1024 {
                    bail!("__metadata__ string value is too large");
                }
                metadata.insert(key.clone(), value.to_owned());
            }
            continue;
        }
        let spec = parse_tensor(&name, &value)?;
        if spec.end > data_bytes || spec.start > spec.end {
            bail!("tensor '{name}' data_offsets are outside the data buffer");
        }
        if let Some(bytes_per_element) = dtype_bytes(&spec.dtype) {
            let elements = checked_elements(&spec.shape)?;
            let expected = elements
                .checked_mul(bytes_per_element)
                .ok_or_else(|| anyhow!("tensor '{name}' byte size overflows u64"))?;
            let actual = spec.end - spec.start;
            if expected != actual {
                bail!("tensor '{name}' declares {actual} data bytes but shape/dtype require {expected}");
            }
        } else {
            unknown_dtypes.insert(spec.dtype.clone());
        }
        tensors.push(SafetensorsTensor {
            name,
            dtype: spec.dtype,
            shape: spec.shape,
            start: spec.start,
            end: spec.end,
        });
    }
    if tensors.len() > MAX_TENSORS {
        bail!("tensor count exceeds safety limit {MAX_TENSORS}");
    }

    tensors.sort_by_key(|spec| (spec.start, spec.end, spec.name.clone()));
    let mut cursor = 0_u64;
    for spec in &tensors {
        if spec.start == spec.end {
            continue;
        }
        if spec.start < cursor {
            bail!("tensor '{}' overlaps a prior tensor range", spec.name);
        }
        if spec.start != cursor {
            bail!(
                "unindexed hole in Safetensors data buffer from {cursor} to {}",
                spec.start
            );
        }
        cursor = spec.end;
    }
    if cursor != data_bytes {
        bail!(
            "Safetensors data buffer is not fully indexed: covered {cursor} of {data_bytes} bytes"
        );
    }

    tensors.sort_by(|a, b| a.name.cmp(&b.name));
    let summary = SafetensorsSummary {
        tensor_count: tensors.len(),
        data_bytes,
        header_bytes: header_len,
        metadata_entries: metadata.len(),
        unknown_dtypes: unknown_dtypes.into_iter().collect(),
    };
    Ok(SafetensorsInventory {
        summary,
        data_start,
        metadata,
        tensors,
    })
}

pub fn read_tensor_bytes(
    file: &File,
    inventory: &SafetensorsInventory,
    tensor: &SafetensorsTensor,
    max_bytes: u64,
) -> Result<Vec<u8>> {
    let len = tensor
        .end
        .checked_sub(tensor.start)
        .ok_or_else(|| anyhow!("invalid tensor range"))?;
    if len > max_bytes {
        bail!(
            "tensor '{}' is {len} bytes, above read cap {max_bytes}",
            tensor.name
        );
    }
    let absolute = inventory
        .data_start
        .checked_add(tensor.start)
        .ok_or_else(|| anyhow!("tensor offset overflow"))?;
    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(absolute))?;
    let mut bytes =
        vec![0_u8; usize::try_from(len).context("tensor byte length does not fit usize")?];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn parse_tensor(name: &str, value: &Value) -> Result<TensorSpec> {
    if name.is_empty() || name.len() > 16 * 1024 {
        bail!("tensor name is empty or too long");
    }
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("tensor '{name}' entry must be an object"))?;
    let dtype = object
        .get("dtype")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("tensor '{name}' is missing string dtype"))?
        .to_owned();
    let shape_value = object
        .get("shape")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("tensor '{name}' is missing shape array"))?;
    if shape_value.len() > MAX_DIMENSIONS {
        bail!("tensor '{name}' has too many dimensions");
    }
    let mut shape = Vec::with_capacity(shape_value.len());
    for dimension in shape_value {
        shape.push(dimension.as_u64().ok_or_else(|| {
            anyhow!("tensor '{name}' shape values must be non-negative integers")
        })?);
    }
    let offsets = object
        .get("data_offsets")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("tensor '{name}' is missing data_offsets array"))?;
    if offsets.len() != 2 {
        bail!("tensor '{name}' data_offsets must contain exactly two integers");
    }
    let start = offsets[0]
        .as_u64()
        .ok_or_else(|| anyhow!("tensor '{name}' start offset must be a non-negative integer"))?;
    let end = offsets[1]
        .as_u64()
        .ok_or_else(|| anyhow!("tensor '{name}' end offset must be a non-negative integer"))?;
    Ok(TensorSpec {
        dtype,
        shape,
        start,
        end,
    })
}

fn checked_elements(shape: &[u64]) -> Result<u64> {
    if shape.is_empty() {
        return Ok(1);
    }
    shape.iter().try_fold(1_u64, |acc, value| {
        acc.checked_mul(*value)
            .ok_or_else(|| anyhow!("tensor element count overflows u64"))
    })
}

fn dtype_bytes(dtype: &str) -> Option<u64> {
    match dtype.to_ascii_uppercase().as_str() {
        "BOOL" | "I8" | "U8" | "F8_E4M3" | "F8_E5M2" | "F8_E4M3FN" | "F8_E5M2FNUZ" => Some(1),
        "I16" | "U16" | "F16" | "BF16" => Some(2),
        "I32" | "U32" | "F32" => Some(4),
        "I64" | "U64" | "F64" => Some(8),
        _ => None,
    }
}

fn elapsed(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fixture(header: &str, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(header.len() as u64).to_le_bytes());
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(data);
        out
    }

    #[test]
    fn validates_simple_file() -> Result<()> {
        let bytes = fixture(
            r#"{"w":{"dtype":"F32","shape":[2],"data_offsets":[0,8]}}"#,
            &[0; 8],
        );
        let path = std::env::temp_dir().join("layerfault_safe_simple.safetensors");
        fs::write(&path, &bytes)?;
        let file = crate::safeio::open_readonly_nofollow(&path)?;
        let summary = validate_file(&file, bytes.len() as u64)?;
        assert_eq!(summary.tensor_count, 1);
        let _ = fs::remove_file(path);
        Ok(())
    }

    #[test]
    fn rejects_duplicate_index_tensor_keys() {
        let bytes = br#"{"weight_map":{"w":"one.safetensors","w":"two.safetensors"}}"#;
        assert!(parse_index_weight_map(bytes).is_err());
    }

    #[test]
    fn rejects_holes() -> Result<()> {
        let bytes = fixture(
            r#"{"w":{"dtype":"F32","shape":[1],"data_offsets":[4,8]}}"#,
            &[0; 8],
        );
        let path = std::env::temp_dir().join("layerfault_safe_hole.safetensors");
        fs::write(&path, &bytes)?;
        let file = crate::safeio::open_readonly_nofollow(&path)?;
        assert!(validate_file(&file, bytes.len() as u64).is_err());
        let _ = fs::remove_file(path);
        Ok(())
    }
}
