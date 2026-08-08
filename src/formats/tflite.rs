//! Minimal bounded TensorFlow Lite FlatBuffer structural validation.
use anyhow::{bail, Result};
use serde::Serialize;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
const MAX_PREFIX: u64 = 32 * 1024 * 1024;
#[derive(Debug, Clone, Serialize)]
pub struct TfliteSummary {
    pub schema_version: u32,
    pub root_offset: u32,
    pub operator_code_count: Option<u32>,
    pub subgraph_count: Option<u32>,
    pub buffer_count: Option<u32>,
}
pub fn inspect(file: &File, len: u64) -> Result<TfliteSummary> {
    if len < 12 {
        bail!("TFLite file is too small");
    }
    let mut f = file.try_clone()?;
    f.seek(SeekFrom::Start(0))?;
    let mut h = [0u8; 12];
    f.read_exact(&mut h)?;
    if &h[4..8] != b"TFL3" {
        bail!("missing TFL3 FlatBuffer identifier");
    }
    let root = u32::from_le_bytes(h[0..4].try_into().unwrap_or([0; 4]));
    if root < 8 || u64::from(root) + 4 > len {
        bail!("invalid TFLite root table offset");
    }
    let read_len = len.min(MAX_PREFIX);
    let mut bytes = vec![0u8; usize::try_from(read_len).unwrap_or(0)];
    f.seek(SeekFrom::Start(0))?;
    f.read_exact(&mut bytes)?;
    let root_usize = root as usize;
    if root_usize >= bytes.len() {
        bail!("root table lies beyond bounded validation prefix");
    }
    let version = table_u32(&bytes, root_usize, 0)?
        .ok_or_else(|| anyhow::anyhow!("TFLite Model.version field missing"))?;
    let op = table_vector_len(&bytes, root_usize, 1)?;
    let sub = table_vector_len(&bytes, root_usize, 2)?;
    let buffers = table_vector_len(&bytes, root_usize, 4)?;
    Ok(TfliteSummary {
        schema_version: version,
        root_offset: root,
        operator_code_count: op,
        subgraph_count: sub,
        buffer_count: buffers,
    })
}
pub fn scan(
    file: &File,
    len: u64,
    digest: &str,
    media: &str,
) -> Result<crate::scanner::LayerScanResult> {
    let st = std::time::Instant::now();
    match inspect(file, len) {
        Ok(s) => Ok(mk(
            digest,
            media,
            crate::scanner::ScanStatus::Pass,
            format!(
                "TFLite FlatBuffer validated: schema {}, {:?} subgraph(s), {:?} operator code(s)",
                s.schema_version, s.subgraph_count, s.operator_code_count
            ),
            vec![],
            st,
        )),
        Err(e) => Ok(mk(
            digest,
            media,
            crate::scanner::ScanStatus::Fail,
            format!("Invalid or unsafe TFLite structure: {e}"),
            vec!["[LF-TFLITE-STRUCT] TFLite structural validation failed".to_owned()],
            st,
        )),
    }
}
fn table_field(buf: &[u8], table: usize, index: usize) -> Result<Option<usize>> {
    if table < 4 || table + 4 > buf.len() {
        bail!("invalid FlatBuffer table");
    }
    let back = i32::from_le_bytes(buf[table..table + 4].try_into().unwrap_or([0; 4]));
    if back <= 0 || usize::try_from(back).ok().is_none_or(|v| v > table) {
        bail!("invalid FlatBuffer vtable offset");
    }
    let vt = table - usize::try_from(back).unwrap_or(0);
    if vt + 4 > buf.len() {
        bail!("truncated FlatBuffer vtable");
    }
    let vt_len = u16::from_le_bytes(buf[vt..vt + 2].try_into().unwrap_or([0; 2])) as usize;
    let slot = vt + 4 + index * 2;
    if slot + 2 > vt + vt_len || slot + 2 > buf.len() {
        return Ok(None);
    }
    let off = u16::from_le_bytes(buf[slot..slot + 2].try_into().unwrap_or([0; 2])) as usize;
    if off == 0 {
        return Ok(None);
    }
    let pos = table
        .checked_add(off)
        .ok_or_else(|| anyhow::anyhow!("FlatBuffer field offset overflow"))?;
    if pos >= buf.len() {
        bail!("FlatBuffer field outside prefix");
    }
    Ok(Some(pos))
}
fn table_u32(buf: &[u8], table: usize, index: usize) -> Result<Option<u32>> {
    let Some(pos) = table_field(buf, table, index)? else {
        return Ok(None);
    };
    if pos + 4 > buf.len() {
        bail!("truncated FlatBuffer scalar");
    }
    Ok(Some(u32::from_le_bytes(
        buf[pos..pos + 4].try_into().unwrap_or([0; 4]),
    )))
}
fn table_vector_len(buf: &[u8], table: usize, index: usize) -> Result<Option<u32>> {
    let Some(pos) = table_field(buf, table, index)? else {
        return Ok(None);
    };
    if pos + 4 > buf.len() {
        bail!("truncated FlatBuffer vector offset");
    }
    let rel = u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap_or([0; 4])) as usize;
    let vector = pos
        .checked_add(rel)
        .ok_or_else(|| anyhow::anyhow!("FlatBuffer vector offset overflow"))?;
    if vector + 4 > buf.len() {
        return Ok(None);
    }
    Ok(Some(u32::from_le_bytes(
        buf[vector..vector + 4].try_into().unwrap_or([0; 4]),
    )))
}
fn mk(
    d: &str,
    m: &str,
    s: crate::scanner::ScanStatus,
    detail: String,
    matches: Vec<String>,
    st: std::time::Instant,
) -> crate::scanner::LayerScanResult {
    crate::scanner::LayerScanResult {
        layer_digest: d.into(),
        media_type: m.into(),
        check_type: crate::scanner::CheckType::TfliteStructure,
        status: s,
        finding_class: crate::scanner::FindingClass::Structural,
        confidence: crate::scanner::Confidence::High,
        detail: Some(detail),
        matches,
        duration_ms: u64::try_from(st.elapsed().as_millis()).unwrap_or(u64::MAX),
    }
}
