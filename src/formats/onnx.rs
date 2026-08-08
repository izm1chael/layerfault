//! Bounded non-executing ONNX ModelProto structural scanner.

use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

const MAX_FIELDS: u64 = 5_000_000;
const MAX_STRING: u64 = 4 * 1024 * 1024;
const MAX_DEPTH: usize = 32;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct OnnxExternalData {
    pub location: String,
    pub relative_path: String,
    pub offset: Option<u64>,
    pub length: Option<u64>,
    pub checksum: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OnnxSummary {
    pub ir_version: Option<u64>,
    pub producer_name: Option<String>,
    pub producer_version: Option<String>,
    pub domain: Option<String>,
    pub model_version: Option<u64>,
    pub graph_name: Option<String>,
    pub node_count: u64,
    pub initializer_count: u64,
    pub input_count: u64,
    pub output_count: u64,
    pub opsets: Vec<(String, u64)>,
    pub custom_domains: Vec<String>,
    pub external_data: Vec<OnnxExternalData>,
    pub training_info_count: u64,
}

pub fn inspect(file: &File, len: u64) -> Result<OnnxSummary> {
    let mut reader = Proto::new(file.try_clone()?, 0, len, 0)?;
    parse_model(&mut reader)
}

pub fn scan(
    path: &Path,
    file: &File,
    len: u64,
    digest: &str,
    media: &str,
) -> Result<(crate::scanner::LayerScanResult, Option<String>)> {
    let start = std::time::Instant::now();
    match inspect(file, len) {
        Ok(summary) => {
            let mut matches = Vec::new();
            let mut status = crate::scanner::ScanStatus::Pass;
            let mut class = crate::scanner::FindingClass::Structural;
            if !summary.custom_domains.is_empty() {
                status = crate::scanner::ScanStatus::Warn;
                class = crate::scanner::FindingClass::ContentIndicator;
                matches.push(format!(
                    "[LF-ONNX-CUSTOM-OP] custom operator domain(s): {}",
                    summary.custom_domains.join(", ")
                ));
            }
            let compound_identity = if summary.external_data.is_empty() {
                None
            } else {
                match bind_external_data(path, digest, &summary.external_data) {
                    Ok((identity, bound)) => {
                        matches.extend(bound);
                        Some(identity)
                    }
                    Err(error) => {
                        status = crate::scanner::ScanStatus::Fail;
                        class = crate::scanner::FindingClass::Integrity;
                        matches.push(format!(
                            "[LF-ONNX-EXTERNAL-INTEGRITY] external tensor data could not be integrity-bound: {error}"
                        ));
                        None
                    }
                }
            };
            let detail = if let Some(identity) = &compound_identity {
                format!(
                    "ONNX structure validated: {} node(s), {} initializer(s), IR {:?}; {} external tensor sidecar(s) integrity-bound as {}",
                    summary.node_count,
                    summary.initializer_count,
                    summary.ir_version,
                    summary.external_data.len(),
                    identity
                )
            } else {
                format!(
                    "ONNX structure validated: {} node(s), {} initializer(s), IR {:?}",
                    summary.node_count, summary.initializer_count, summary.ir_version
                )
            };
            Ok((
                result(digest, media, status, class, detail, matches, start),
                compound_identity,
            ))
        }
        Err(error) => Ok((
            result(
                digest,
                media,
                crate::scanner::ScanStatus::Fail,
                crate::scanner::FindingClass::Structural,
                format!("Invalid or unsafe ONNX structure: {error}"),
                vec!["[LF-ONNX-STRUCT] ONNX structural validation failed".to_owned()],
                start,
            ),
            None,
        )),
    }
}

struct BoundSidecar {
    path: PathBuf,
    file: File,
    identity: crate::hashcache::FileIdentity,
    len: u64,
    digest: String,
}

fn bind_external_data(
    model_path: &Path,
    model_digest: &str,
    external: &[OnnxExternalData],
) -> Result<(String, Vec<String>)> {
    let parent = model_path.parent().unwrap_or_else(|| Path::new("."));
    let parent = parent
        .canonicalize()
        .with_context(|| format!("unable to canonicalize ONNX parent '{}'", parent.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(b"layerfault-onnx-compound-identity\0");
    hasher.update(model_digest.as_bytes());
    hasher.update([0]);
    let mut matches = Vec::new();
    let mut sidecars = BTreeMap::<String, BoundSidecar>::new();

    for item in external {
        let relative = PathBuf::from(&item.relative_path);
        let candidate = parent.join(&relative);
        let metadata = std::fs::symlink_metadata(&candidate).with_context(|| {
            format!(
                "ONNX external tensor sidecar '{}' is missing or unreadable",
                item.relative_path
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!(
                "ONNX external tensor sidecar '{}' must be a regular non-symlink file",
                item.relative_path
            );
        }
        let canonical = candidate.canonicalize()?;
        if !canonical.starts_with(&parent) {
            bail!(
                "ONNX external tensor sidecar '{}' resolves outside the model directory",
                item.relative_path
            );
        }
        let cache_key = canonical.to_string_lossy().into_owned();
        if !sidecars.contains_key(&cache_key) {
            let sidecar = crate::safeio::open_readonly_nofollow(&canonical)?;
            let sidecar_len = sidecar.metadata()?.len();
            let outcome = crate::hashcache::sha256_prefixed(&canonical, &sidecar)?;
            if !crate::hashcache::identity_unchanged(&canonical, &sidecar, &outcome.identity)? {
                bail!(
                    "ONNX external tensor sidecar '{}' changed while being integrity-bound",
                    item.relative_path
                );
            }
            sidecars.insert(
                cache_key.clone(),
                BoundSidecar {
                    path: canonical.clone(),
                    file: sidecar,
                    identity: outcome.identity,
                    len: sidecar_len,
                    digest: outcome.sha256,
                },
            );
        }
        let bound = sidecars
            .get(&cache_key)
            .expect("sidecar inserted before lookup");
        let sidecar_len = bound.len;
        let sidecar_digest = bound.digest.clone();
        let offset = item.offset.unwrap_or(0);
        if offset > sidecar_len {
            bail!(
                "ONNX external tensor sidecar '{}' offset {} exceeds file length {}",
                item.relative_path,
                offset,
                sidecar_len
            );
        }
        if let Some(length) = item.length {
            let end = offset
                .checked_add(length)
                .ok_or_else(|| anyhow!("ONNX external tensor range overflows u64"))?;
            if end > sidecar_len {
                bail!(
                    "ONNX external tensor sidecar '{}' range {}..{} exceeds file length {}",
                    item.relative_path,
                    offset,
                    end,
                    sidecar_len
                );
            }
        }
        hasher.update(item.relative_path.as_bytes());
        hasher.update([0]);
        hasher.update(sidecar_len.to_le_bytes());
        hasher.update(sidecar_digest.as_bytes());
        hasher.update(offset.to_le_bytes());
        hasher.update(item.length.unwrap_or(u64::MAX).to_le_bytes());
        hasher.update([0xff]);
        matches.push(format!(
            "[LF-ONNX-EXTERNAL-DATA] '{}' {} bytes {} offset={} length={}",
            item.relative_path,
            sidecar_len,
            sidecar_digest,
            offset,
            item.length
                .map(|value| value.to_string())
                .unwrap_or_else(|| "to-eof".to_owned())
        ));
    }
    for bound in sidecars.values() {
        if !crate::hashcache::identity_unchanged(&bound.path, &bound.file, &bound.identity)? {
            bail!(
                "ONNX external tensor sidecar '{}' changed while compound identity was being computed",
                bound.path.display()
            );
        }
    }

    Ok((
        format!("lfonnx:sha256:{}", hex::encode(hasher.finalize())),
        matches,
    ))
}

fn parse_model(reader: &mut Proto) -> Result<OnnxSummary> {
    let mut out = OnnxSummary {
        ir_version: None,
        producer_name: None,
        producer_version: None,
        domain: None,
        model_version: None,
        graph_name: None,
        node_count: 0,
        initializer_count: 0,
        input_count: 0,
        output_count: 0,
        opsets: Vec::new(),
        custom_domains: Vec::new(),
        external_data: Vec::new(),
        training_info_count: 0,
    };

    while let Some(field) = reader.next()? {
        match (field.no, field.wire) {
            (1, 0) => out.ir_version = Some(reader.varint()?),
            (2, 2) => {
                out.producer_name = Some(
                    reader.string(
                        field
                            .len
                            .ok_or_else(|| anyhow!("missing protobuf length"))?,
                    )?,
                )
            }
            (3, 2) => {
                out.producer_version = Some(
                    reader.string(
                        field
                            .len
                            .ok_or_else(|| anyhow!("missing protobuf length"))?,
                    )?,
                )
            }
            (4, 2) => {
                out.domain = Some(
                    reader.string(
                        field
                            .len
                            .ok_or_else(|| anyhow!("missing protobuf length"))?,
                    )?,
                )
            }
            (5, 0) => out.model_version = Some(reader.varint()?),
            (7, 2) => parse_graph(
                &mut reader.sub(
                    field
                        .len
                        .ok_or_else(|| anyhow!("missing protobuf length"))?,
                )?,
                &mut out,
            )?,
            (8, 2) => out.opsets.push(parse_opset(
                &mut reader.sub(
                    field
                        .len
                        .ok_or_else(|| anyhow!("missing protobuf length"))?,
                )?,
            )?),
            (20, 2) => {
                out.training_info_count += 1;
                reader.skip_len(
                    field
                        .len
                        .ok_or_else(|| anyhow!("missing protobuf length"))?,
                )?;
            }
            _ => reader.skip(field)?,
        }
    }

    out.custom_domains.sort();
    out.custom_domains.dedup();
    out.external_data
        .sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    out.external_data.dedup_by(|a, b| a == b);
    Ok(out)
}

fn parse_opset(reader: &mut Proto) -> Result<(String, u64)> {
    let mut domain = String::new();
    let mut version = 0;
    while let Some(field) = reader.next()? {
        match (field.no, field.wire) {
            (1, 2) => {
                domain = reader.string(
                    field
                        .len
                        .ok_or_else(|| anyhow!("missing protobuf length"))?,
                )?
            }
            (2, 0) => version = reader.varint()?,
            _ => reader.skip(field)?,
        }
    }
    Ok((domain, version))
}

fn parse_graph(reader: &mut Proto, out: &mut OnnxSummary) -> Result<()> {
    while let Some(field) = reader.next()? {
        match (field.no, field.wire) {
            (1, 2) => {
                out.node_count += 1;
                parse_node(
                    &mut reader.sub(
                        field
                            .len
                            .ok_or_else(|| anyhow!("missing protobuf length"))?,
                    )?,
                    out,
                )?;
            }
            (2, 2) => {
                out.graph_name = Some(
                    reader.string(
                        field
                            .len
                            .ok_or_else(|| anyhow!("missing protobuf length"))?,
                    )?,
                )
            }
            (5, 2) => {
                out.initializer_count += 1;
                parse_tensor(
                    &mut reader.sub(
                        field
                            .len
                            .ok_or_else(|| anyhow!("missing protobuf length"))?,
                    )?,
                    out,
                )?;
            }
            (11, 2) => {
                out.input_count += 1;
                reader.skip_len(
                    field
                        .len
                        .ok_or_else(|| anyhow!("missing protobuf length"))?,
                )?;
            }
            (12, 2) => {
                out.output_count += 1;
                reader.skip_len(
                    field
                        .len
                        .ok_or_else(|| anyhow!("missing protobuf length"))?,
                )?;
            }
            _ => reader.skip(field)?,
        }
    }
    Ok(())
}

fn parse_node(reader: &mut Proto, out: &mut OnnxSummary) -> Result<()> {
    let mut op = String::new();
    let mut domain = String::new();
    while let Some(field) = reader.next()? {
        match (field.no, field.wire) {
            (4, 2) => {
                op = reader.string(
                    field
                        .len
                        .ok_or_else(|| anyhow!("missing protobuf length"))?,
                )?
            }
            (7, 2) => {
                domain = reader.string(
                    field
                        .len
                        .ok_or_else(|| anyhow!("missing protobuf length"))?,
                )?
            }
            _ => reader.skip(field)?,
        }
    }
    if !domain.is_empty() && domain != "ai.onnx" && domain != "ai.onnx.ml" {
        out.custom_domains.push(format!("{domain}:{op}"));
    }
    Ok(())
}

fn parse_tensor(reader: &mut Proto, out: &mut OnnxSummary) -> Result<()> {
    let mut external = BTreeMap::<String, String>::new();
    let mut data_location_external = false;
    while let Some(field) = reader.next()? {
        match (field.no, field.wire) {
            (13, 2) => {
                if let Some((key, value)) = parse_external_entry(
                    &mut reader.sub(
                        field
                            .len
                            .ok_or_else(|| anyhow!("missing protobuf length"))?,
                    )?,
                )? {
                    validate_external_entry(&key, &value)?;
                    if external.insert(key.clone(), value).is_some() {
                        bail!("duplicate ONNX external_data key '{key}'");
                    }
                }
            }
            (14, 0) => data_location_external = reader.varint()? == 1,
            (9, 2) => reader.skip_len(
                field
                    .len
                    .ok_or_else(|| anyhow!("missing protobuf length"))?,
            )?,
            _ => reader.skip(field)?,
        }
    }

    if data_location_external || !external.is_empty() {
        let location = external
            .get("location")
            .ok_or_else(|| anyhow!("ONNX external tensor data is missing location"))?
            .clone();
        validate_external_location(&location)?;
        let basepath = external.get("basepath").cloned().unwrap_or_default();
        if !basepath.is_empty() {
            validate_external_location(&basepath)?;
        }
        let relative_path = if basepath.is_empty() {
            location.clone()
        } else {
            Path::new(&basepath)
                .join(&location)
                .to_string_lossy()
                .replace('\\', "/")
        };
        validate_external_location(&relative_path)?;
        let offset = external
            .get("offset")
            .map(|value| value.parse::<u64>())
            .transpose()
            .context("ONNX external_data offset is invalid")?;
        let length = external
            .get("length")
            .map(|value| value.parse::<u64>())
            .transpose()
            .context("ONNX external_data length is invalid")?;
        out.external_data.push(OnnxExternalData {
            location,
            relative_path,
            offset,
            length,
            checksum: external.get("checksum").cloned(),
        });
    }
    Ok(())
}

fn parse_external_entry(reader: &mut Proto) -> Result<Option<(String, String)>> {
    let mut key = None;
    let mut value = None;
    while let Some(field) = reader.next()? {
        match (field.no, field.wire) {
            (1, 2) => {
                key = Some(
                    reader.string(
                        field
                            .len
                            .ok_or_else(|| anyhow!("missing protobuf length"))?,
                    )?,
                )
            }
            (2, 2) => {
                value = Some(
                    reader.string(
                        field
                            .len
                            .ok_or_else(|| anyhow!("missing protobuf length"))?,
                    )?,
                )
            }
            _ => reader.skip(field)?,
        }
    }
    Ok(match (key, value) {
        (Some(key), Some(value)) => Some((key, value)),
        (None, None) => None,
        _ => bail!("ONNX external_data entry is missing key or value"),
    })
}

fn validate_external_entry(key: &str, value: &str) -> Result<()> {
    match key {
        "location" | "checksum" | "basepath" => Ok(()),
        "offset" | "length" => {
            value.parse::<u64>().with_context(|| {
                format!("ONNX external_data {key} is not a non-negative integer")
            })?;
            Ok(())
        }
        other => bail!("unsupported ONNX external_data key '{other}'"),
    }
}

fn validate_external_location(path: &str) -> Result<()> {
    let parsed = std::path::Path::new(path);
    if path.is_empty() || path.len() > 16 * 1024 || parsed.is_absolute() || path.contains("://") {
        bail!("unsafe ONNX external_data location '{path}'");
    }
    let mut normal_components = 0usize;
    for component in parsed.components() {
        match component {
            std::path::Component::Normal(_) => normal_components += 1,
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir
            | std::path::Component::RootDir
            | std::path::Component::Prefix(_) => {
                bail!("unsafe ONNX external_data location '{path}'")
            }
        }
    }
    if normal_components == 0 {
        bail!("unsafe ONNX external_data location '{path}'");
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct Field {
    no: u32,
    wire: u8,
    len: Option<u64>,
}

struct Proto {
    file: File,
    pos: u64,
    end: u64,
    depth: usize,
    fields: u64,
}

impl Proto {
    fn new(file: File, start: u64, end: u64, depth: usize) -> Result<Self> {
        if depth > MAX_DEPTH {
            bail!("protobuf nesting exceeds {MAX_DEPTH}");
        }
        if start > end {
            bail!("protobuf reader start exceeds end");
        }
        Ok(Self {
            file,
            pos: start,
            end,
            depth,
            fields: 0,
        })
    }

    fn next(&mut self) -> Result<Option<Field>> {
        if self.pos >= self.end {
            return Ok(None);
        }
        self.fields += 1;
        if self.fields > MAX_FIELDS {
            bail!("protobuf field count exceeds safety cap");
        }
        let key = self.varint()?;
        let number = key >> 3;
        if number == 0 || number > u32::MAX as u64 {
            bail!("protobuf field number is invalid");
        }
        let wire = (key & 7) as u8;
        let len = if wire == 2 {
            Some(self.varint()?)
        } else {
            None
        };
        Ok(Some(Field {
            no: number as u32,
            wire,
            len,
        }))
    }

    fn varint(&mut self) -> Result<u64> {
        let mut out = 0u64;
        for index in 0..10u32 {
            let byte = self.byte()?;
            if index == 9 && byte > 1 {
                bail!("protobuf varint exceeds u64");
            }
            out |= ((byte & 0x7f) as u64) << (index * 7);
            if byte & 0x80 == 0 {
                return Ok(out);
            }
        }
        bail!("protobuf varint exceeds 10 bytes")
    }

    fn byte(&mut self) -> Result<u8> {
        if self.pos >= self.end {
            bail!("truncated protobuf");
        }
        self.file.seek(SeekFrom::Start(self.pos))?;
        let mut byte = [0u8; 1];
        self.file.read_exact(&mut byte)?;
        self.pos += 1;
        Ok(byte[0])
    }

    fn string(&mut self, len: u64) -> Result<String> {
        if len > MAX_STRING {
            bail!("protobuf string exceeds {MAX_STRING} byte cap");
        }
        let bytes = self.bytes(len)?;
        String::from_utf8(bytes).context("protobuf string is not UTF-8")
    }

    fn bytes(&mut self, len: u64) -> Result<Vec<u8>> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| anyhow!("protobuf length overflow"))?;
        if end > self.end {
            bail!("length-delimited protobuf field extends beyond message");
        }
        self.file.seek(SeekFrom::Start(self.pos))?;
        let mut bytes = vec![0u8; usize::try_from(len).context("protobuf field too large")?];
        self.file.read_exact(&mut bytes)?;
        self.pos = end;
        Ok(bytes)
    }

    fn sub(&mut self, len: u64) -> Result<Proto> {
        let start = self.pos;
        let end = start
            .checked_add(len)
            .ok_or_else(|| anyhow!("protobuf submessage overflow"))?;
        if end > self.end {
            bail!("protobuf submessage extends beyond parent");
        }
        let sub = Proto::new(self.file.try_clone()?, start, end, self.depth + 1)?;
        self.pos = end;
        Ok(sub)
    }

    fn skip_len(&mut self, len: u64) -> Result<()> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| anyhow!("protobuf skip overflow"))?;
        if end > self.end {
            bail!("protobuf field extends beyond message");
        }
        self.pos = end;
        Ok(())
    }

    fn skip(&mut self, field: Field) -> Result<()> {
        match field.wire {
            0 => {
                let _ = self.varint()?;
                Ok(())
            }
            1 => self.skip_len(8),
            2 => self.skip_len(
                field
                    .len
                    .ok_or_else(|| anyhow!("missing protobuf length"))?,
            ),
            5 => self.skip_len(4),
            other => bail!("unsupported protobuf wire type {other}"),
        }
    }
}

fn result(
    digest: &str,
    media: &str,
    status: crate::scanner::ScanStatus,
    class: crate::scanner::FindingClass,
    detail: String,
    matches: Vec<String>,
    started: std::time::Instant,
) -> crate::scanner::LayerScanResult {
    crate::scanner::LayerScanResult {
        layer_digest: digest.to_owned(),
        media_type: media.to_owned(),
        check_type: crate::scanner::CheckType::OnnxStructure,
        status,
        finding_class: class,
        confidence: crate::scanner::Confidence::High,
        detail: Some(detail),
        matches,
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn varint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                return out;
            }
        }
    }

    fn key(field: u32, wire: u8) -> Vec<u8> {
        varint(((field as u64) << 3) | wire as u64)
    }

    fn push_varint(out: &mut Vec<u8>, field: u32, value: u64) {
        out.extend_from_slice(&key(field, 0));
        out.extend_from_slice(&varint(value));
    }

    fn push_len(out: &mut Vec<u8>, field: u32, bytes: &[u8]) {
        out.extend_from_slice(&key(field, 2));
        out.extend_from_slice(&varint(bytes.len() as u64));
        out.extend_from_slice(bytes);
    }

    fn model_with_external(location: &str) -> Vec<u8> {
        let mut external = Vec::new();
        push_len(&mut external, 1, b"location");
        push_len(&mut external, 2, location.as_bytes());

        let mut tensor = Vec::new();
        push_varint(&mut tensor, 2, 2);
        push_len(&mut tensor, 8, b"weight");
        push_len(&mut tensor, 13, &external);
        push_varint(&mut tensor, 14, 1);

        let mut graph = Vec::new();
        push_len(&mut graph, 2, b"graph");
        push_len(&mut graph, 5, &tensor);

        let mut model = Vec::new();
        push_varint(&mut model, 1, 10);
        push_len(&mut model, 7, &graph);
        model
    }

    fn write_fixture(label: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("layerfault-onnx-{label}-{}", std::process::id()));
        fs::write(&path, bytes).expect("write ONNX fixture");
        path
    }

    #[test]
    fn nested_submessages_keep_independent_logical_offsets() {
        let bytes = model_with_external("data/weights.bin");
        let path = write_fixture("nested", &bytes);
        let file = File::open(&path).expect("open ONNX fixture");
        let summary = inspect(&file, bytes.len() as u64).expect("parse nested ONNX");
        assert_eq!(summary.graph_name.as_deref(), Some("graph"));
        assert_eq!(summary.initializer_count, 1);
        assert_eq!(summary.external_data[0].relative_path, "data/weights.bin");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn current_directory_external_reference_is_accepted() {
        let bytes = model_with_external("./weights.bin");
        let path = write_fixture("curdir", &bytes);
        let file = File::open(&path).expect("open ONNX fixture");
        let summary = inspect(&file, bytes.len() as u64).expect("parse ONNX");
        assert_eq!(summary.external_data[0].relative_path, "./weights.bin");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn traversal_external_reference_is_rejected() {
        let bytes = model_with_external("../outside.bin");
        let path = write_fixture("traversal", &bytes);
        let file = File::open(&path).expect("open ONNX fixture");
        let error = inspect(&file, bytes.len() as u64).expect_err("reject traversal");
        assert!(error
            .to_string()
            .contains("unsafe ONNX external_data location"));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn external_sidecar_is_integrity_bound() -> Result<()> {
        let root =
            std::env::temp_dir().join(format!("layerfault-onnx-sidecar-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("data"))?;
        let model = model_with_external("data/weights.bin");
        let model_path = root.join("model.onnx");
        fs::write(&model_path, &model)?;
        fs::write(root.join("data/weights.bin"), b"tensor-bytes")?;
        let file = File::open(&model_path)?;
        let (finding, compound) = scan(
            &model_path,
            &file,
            model.len() as u64,
            "sha256:model",
            "application/x-onnx",
        )?;
        assert_ne!(finding.status, crate::scanner::ScanStatus::Fail);
        assert!(compound
            .as_deref()
            .is_some_and(|value| value.starts_with("lfonnx:sha256:")));
        let _ = fs::remove_dir_all(root);
        Ok(())
    }

    #[test]
    fn missing_external_sidecar_prevents_clean_pass() -> Result<()> {
        let root = std::env::temp_dir().join(format!(
            "layerfault-onnx-missing-sidecar-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        let model = model_with_external("weights.bin");
        let model_path = root.join("model.onnx");
        fs::write(&model_path, &model)?;
        let file = File::open(&model_path)?;
        let (finding, compound) = scan(
            &model_path,
            &file,
            model.len() as u64,
            "sha256:model",
            "application/x-onnx",
        )?;
        assert_eq!(finding.status, crate::scanner::ScanStatus::Fail);
        assert!(compound.is_none());
        let _ = fs::remove_dir_all(root);
        Ok(())
    }
}
