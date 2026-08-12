use super::*;
pub fn discover_lmstudio() -> Result<Vec<SourceArtifact>> {
    let binary = find_executable("lms")
        .ok_or_else(|| anyhow!("LM Studio CLI 'lms' was not found in PATH"))?;
    let output = Command::new(&binary)
        .args(["ls", "--json", "--detailed"])
        .output()
        .context("Unable to execute 'lms ls --json --detailed'")?;
    if !output.status.success() {
        return Err(anyhow!(
            "lms ls failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let rows = parse_lmstudio_inventory_bytes(&output.stdout)?;
    if rows.is_empty() {
        return Err(anyhow!("LM Studio returned JSON but Layerfault could not identify any local model paths; use 'layerfault inspect <file>' for this LM Studio release"));
    }
    Ok(rows)
}

pub fn parse_lmstudio_inventory_bytes(bytes: &[u8]) -> Result<Vec<SourceArtifact>> {
    let value: Value = serde_json::from_slice(bytes).context("lms ls did not return valid JSON")?;
    let mut rows = Vec::new();
    collect_lms_objects(&value, &mut rows);
    rows.sort_by(|a, b| a.identity.cmp(&b.identity));
    rows.dedup_by(|a, b| a.identity == b.identity && a.path == b.path);
    Ok(rows)
}

fn collect_lms_objects(value: &Value, out: &mut Vec<SourceArtifact>) {
    match value {
        Value::Array(values) => values
            .iter()
            .for_each(|value| collect_lms_objects(value, out)),
        Value::Object(object) => {
            let path = ["path", "filePath", "file_path", "modelPath", "model_path"]
                .iter()
                .find_map(|key| object.get(*key).and_then(Value::as_str));
            if let Some(path) = path {
                let pathbuf = PathBuf::from(path);
                if pathbuf.is_file() {
                    let identity = [
                        "modelKey",
                        "model_key",
                        "key",
                        "identifier",
                        "name",
                        "displayName",
                    ]
                    .iter()
                    .find_map(|key| object.get(*key).and_then(Value::as_str))
                    .unwrap_or(path)
                    .to_owned();
                    let format = format_from_path(&pathbuf);
                    let size = fs::metadata(&pathbuf).map(|m| m.len()).unwrap_or(0);
                    let architecture = ["architecture", "arch"]
                        .iter()
                        .find_map(|key| object.get(*key).and_then(Value::as_str))
                        .map(ToOwned::to_owned);
                    let quantization = ["quantization", "quantizationType", "quantization_type"]
                        .iter()
                        .find_map(|key| object.get(*key).and_then(Value::as_str))
                        .map(ToOwned::to_owned);
                    out.push(SourceArtifact {
                        source: SourceKind::LmStudio,
                        identity,
                        path: pathbuf.clone(),
                        display_path: pathbuf.display().to_string(),
                        format,
                        size,
                        architecture,
                        quantization,
                    });
                }
            }
            object
                .values()
                .for_each(|value| collect_lms_objects(value, out));
        }
        _ => {}
    }
}
