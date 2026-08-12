use super::types::{nearest_boundary, DatasetFormat, Record};
use anyhow::{bail, Context, Result};
use std::io::BufRead;
use std::path::Path;

const MAX_RECORD_BYTES: usize = 1024 * 1024;
/// Monolithic JSON needs an in-memory DOM in this build. Line-oriented formats
/// are streamed and are deliberately not subject to this byte limit.
pub(super) const MAX_JSON_BYTES_FOR_RECORD_PARSE: u64 = 256 * 1024 * 1024;

pub(super) fn parseable(format: DatasetFormat) -> bool {
    matches!(
        format,
        DatasetFormat::Json
            | DatasetFormat::Jsonl
            | DatasetFormat::Csv
            | DatasetFormat::Tsv
            | DatasetFormat::Text
    )
}

/// Stream records and invoke `visitor` in source order. `selected` is an
/// optional sorted list of record indexes. Parsers still validate every record
/// so malformed content cannot be hidden in an unselected region, but only
/// selected records are materialized into security-analysis text.
pub(super) fn visit_records<F>(
    path: &Path,
    format: DatasetFormat,
    selected: Option<&[usize]>,
    mut visitor: F,
) -> Result<()>
where
    F: FnMut(usize, Record) -> Result<()>,
{
    match format {
        DatasetFormat::Text => visit_text(path, selected, &mut visitor),
        DatasetFormat::Jsonl => visit_jsonl(path, selected, &mut visitor),
        DatasetFormat::Json => visit_json(path, selected, &mut visitor),
        DatasetFormat::Csv => visit_delimited(path, b',', selected, &mut visitor),
        DatasetFormat::Tsv => visit_delimited(path, b'\t', selected, &mut visitor),
        _ => Ok(()),
    }
}

fn wants(selected: Option<&[usize]>, position: &mut usize, index: usize) -> bool {
    let Some(selected) = selected else {
        return true;
    };
    while *position < selected.len() && selected[*position] < index {
        *position += 1;
    }
    *position < selected.len() && selected[*position] == index
}

fn visit_text<F>(path: &Path, selected: Option<&[usize]>, visitor: &mut F) -> Result<()>
where
    F: FnMut(usize, Record) -> Result<()>,
{
    let file = crate::safeio::open_readonly_nofollow(path)?;
    let mut reader = std::io::BufReader::new(file);
    let mut bytes = Vec::new();
    let mut index = 0_usize;
    let mut selected_position = 0_usize;
    loop {
        bytes.clear();
        let read = reader.read_until(b'\n', &mut bytes)?;
        if read == 0 {
            break;
        }
        trim_line_ending(&mut bytes);
        if bytes.is_empty() {
            continue;
        }
        if bytes.len() > MAX_RECORD_BYTES {
            bail!("text dataset record exceeds byte cap");
        }
        if wants(selected, &mut selected_position, index) {
            let text = String::from_utf8_lossy(&bytes).into_owned();
            visitor(index, Record { text, label: None })?;
        }
        index = index.saturating_add(1);
    }
    Ok(())
}

fn visit_jsonl<F>(path: &Path, selected: Option<&[usize]>, visitor: &mut F) -> Result<()>
where
    F: FnMut(usize, Record) -> Result<()>,
{
    let file = crate::safeio::open_readonly_nofollow(path)?;
    let mut reader = std::io::BufReader::new(file);
    let mut bytes = Vec::new();
    let mut index = 0_usize;
    let mut selected_position = 0_usize;
    loop {
        bytes.clear();
        let read = reader.read_until(b'\n', &mut bytes)?;
        if read == 0 {
            break;
        }
        trim_line_ending(&mut bytes);
        if bytes.iter().all(|byte| byte.is_ascii_whitespace()) {
            continue;
        }
        if bytes.len() > MAX_RECORD_BYTES {
            bail!("JSONL dataset record exceeds byte cap");
        }
        let value: serde_json::Value =
            serde_json::from_slice(&bytes).context("invalid JSONL record")?;
        if wants(selected, &mut selected_position, index) {
            visitor(index, record_from_json(&value))?;
        }
        index = index.saturating_add(1);
    }
    Ok(())
}

fn visit_json<F>(path: &Path, selected: Option<&[usize]>, visitor: &mut F) -> Result<()>
where
    F: FnMut(usize, Record) -> Result<()>,
{
    let file = crate::safeio::open_readonly_nofollow(path)?;
    let bytes = crate::safeio::read_all_from_file(&file, MAX_JSON_BYTES_FOR_RECORD_PARSE)?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).context("invalid JSON dataset")?;
    let mut selected_position = 0_usize;
    match value {
        serde_json::Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                if wants(selected, &mut selected_position, index) {
                    visitor(index, record_from_json(value))?;
                }
            }
        }
        other => {
            if wants(selected, &mut selected_position, 0) {
                visitor(0, record_from_json(&other))?;
            }
        }
    }
    Ok(())
}

fn visit_delimited<F>(
    path: &Path,
    delimiter: u8,
    selected: Option<&[usize]>,
    visitor: &mut F,
) -> Result<()>
where
    F: FnMut(usize, Record) -> Result<()>,
{
    let file = crate::safeio::open_readonly_nofollow(path)?;
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(delimiter)
        .flexible(true)
        .from_reader(file);
    let headers = reader.headers()?.clone();
    let text_columns: Vec<usize> = headers
        .iter()
        .enumerate()
        .filter_map(|(i, h)| {
            let h = h.to_ascii_lowercase();
            matches!(
                h.as_str(),
                "text"
                    | "prompt"
                    | "input"
                    | "instruction"
                    | "question"
                    | "response"
                    | "output"
                    | "completion"
                    | "content"
            )
            .then_some(i)
        })
        .collect();
    let label_column = headers.iter().position(|h| {
        matches!(
            h.to_ascii_lowercase().as_str(),
            "label" | "target" | "class" | "category"
        )
    });
    let mut selected_position = 0_usize;
    for (index, row) in reader.records().enumerate() {
        let row = row?;
        if !wants(selected, &mut selected_position, index) {
            continue;
        }
        let text = if text_columns.is_empty() {
            row.iter().take(64).collect::<Vec<_>>().join(" ")
        } else {
            text_columns
                .iter()
                .filter_map(|i| row.get(*i))
                .collect::<Vec<_>>()
                .join(" ")
        };
        if text.len() > MAX_RECORD_BYTES {
            bail!("delimited dataset record exceeds byte cap");
        }
        visitor(
            index,
            Record {
                text,
                label: label_column.and_then(|i| row.get(i)).map(str::to_owned),
            },
        )?;
    }
    Ok(())
}

fn trim_line_ending(bytes: &mut Vec<u8>) {
    while bytes
        .last()
        .is_some_and(|byte| matches!(*byte, b'\n' | b'\r'))
    {
        bytes.pop();
    }
}

fn record_from_json(value: &serde_json::Value) -> Record {
    let label = value.as_object().and_then(|object| {
        ["label", "target", "class", "category"]
            .iter()
            .find_map(|key| object.get(*key))
            .and_then(scalar_string)
    });
    let mut parts = Vec::new();
    collect_text(value, &mut parts, 0);
    let mut text = parts.join(" ");
    if text.len() > MAX_RECORD_BYTES {
        text.truncate(nearest_boundary(&text, MAX_RECORD_BYTES));
    }
    Record { text, label }
}

fn collect_text(value: &serde_json::Value, out: &mut Vec<String>, depth: usize) {
    if depth > 8 || out.len() > 128 {
        return;
    }
    match value {
        serde_json::Value::String(value) => out.push(value.clone()),
        serde_json::Value::Array(values) => {
            for value in values.iter().take(128) {
                collect_text(value, out, depth + 1);
            }
        }
        serde_json::Value::Object(object) => {
            for (key, value) in object.iter().take(128) {
                if !matches!(key.as_str(), "label" | "target" | "class" | "category") {
                    collect_text(value, out, depth + 1);
                }
            }
        }
        _ => {}
    }
}

fn scalar_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        serde_json::Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}
