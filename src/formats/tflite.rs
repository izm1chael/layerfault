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
    pub associated_files: Vec<String>,
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
    let read_len = len.min(MAX_PREFIX);
    if root < 8 || u64::from(root) + 4 > read_len {
        bail!("invalid TFLite root table offset");
    }
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
    let associated_files = associated_file_names(&f, len)?;
    Ok(TfliteSummary {
        schema_version: version,
        root_offset: root,
        operator_code_count: op,
        subgraph_count: sub,
        buffer_count: buffers,
        associated_files,
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
        Ok(s) => {
            let associated = !s.associated_files.is_empty();
            Ok(mk(
            digest,
            media,
            if associated {
                crate::scanner::ScanStatus::Warn
            } else {
                crate::scanner::ScanStatus::Pass
            },
            format!(
                "TFLite FlatBuffer validated: schema {}, {:?} subgraph(s), {:?} operator code(s), associated files {:?}",
                s.schema_version, s.subgraph_count, s.operator_code_count, s.associated_files
            ),
            if associated {
                vec!["[LF-TFLITE-ASSOCIATED-FILE] TFLite carries ZIP-appended authority metadata that must be integrity-bound with the model".to_owned()]
            } else {
                vec![]
            },
            st,
        ))
        }
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

fn associated_file_names(file: &File, len: u64) -> Result<Vec<String>> {
    // TFLite Model Metadata stores associated files in a ZIP archive appended
    // to the FlatBuffer. Listing central-directory names does not decompress
    // attacker-controlled content.
    let mut probe = file.try_clone()?;
    let tail_len = len.min(128 * 1024);
    probe.seek(SeekFrom::Start(len.saturating_sub(tail_len)))?;
    let mut tail = vec![0; usize::try_from(tail_len).unwrap_or(0)];
    probe.read_exact(&mut tail)?;
    if !tail.windows(4).any(|window| window == b"PK\x05\x06") {
        return Ok(Vec::new());
    }
    let mut archive = zip::ZipArchive::new(file.try_clone()?)
        .map_err(|error| anyhow::anyhow!("invalid TFLite associated-file ZIP: {error}"))?;
    if archive.len() > 256 {
        bail!("TFLite associated-file ZIP contains too many entries");
    }
    let mut names = Vec::with_capacity(archive.len());
    for index in 0..archive.len() {
        let entry = archive.by_index(index)?;
        names.push(entry.name().chars().take(512).collect());
    }
    names.sort();
    Ok(names)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn root_offset_is_bounded_by_the_parsed_prefix() -> Result<()> {
        let mut file = tempfile::tempfile()?;
        let root = u32::try_from(MAX_PREFIX + 8)?;
        file.write_all(&root.to_le_bytes())?;
        file.write_all(b"TFL3")?;
        file.write_all(&[0; 4])?;
        file.set_len(MAX_PREFIX + 4096)?;
        file.seek(SeekFrom::Start(0))?;
        let error = inspect(&file, MAX_PREFIX + 4096).unwrap_err();
        assert!(error
            .to_string()
            .contains("invalid TFLite root table offset"));
        Ok(())
    }

    #[test]
    fn zip_appended_labels_are_reported_as_integrity_relevant() -> Result<()> {
        let mut file = tempfile::tempfile()?;
        let mut model = Vec::new();
        model.extend_from_slice(&16_u32.to_le_bytes());
        model.extend_from_slice(b"TFL3");
        model.extend_from_slice(&6_u16.to_le_bytes());
        model.extend_from_slice(&8_u16.to_le_bytes());
        model.extend_from_slice(&4_u16.to_le_bytes());
        model.extend_from_slice(&[0, 0]);
        model.extend_from_slice(&8_i32.to_le_bytes());
        model.extend_from_slice(&3_u32.to_le_bytes());
        file.write_all(&model)?;
        file.seek(SeekFrom::End(0))?;
        {
            let mut zip = zip::ZipWriter::new(file.try_clone()?);
            zip.start_file("labels.txt", zip::write::SimpleFileOptions::default())?;
            zip.write_all(b"safe\nunsafe\n")?;
            zip.finish()?;
        }
        let len = file.metadata()?.len();
        let summary = inspect(&file, len)?;
        assert_eq!(summary.associated_files, vec!["labels.txt"]);
        let result = scan(&file, len, "fixture", "application/tflite")?;
        assert_eq!(result.status, crate::scanner::ScanStatus::Warn);
        assert!(result
            .matches
            .iter()
            .any(|value| value.contains("LF-TFLITE-ASSOCIATED-FILE")));
        Ok(())
    }
}
