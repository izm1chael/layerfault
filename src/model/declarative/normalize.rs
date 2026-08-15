use super::types::ConfigFact;
use anyhow::{bail, Result};
const MAX_CONFIG_BYTES: usize = 4 * 1024 * 1024;
const MAX_FACTS_PER_FILE: usize = 4096;
const MAX_LIST_VALUES: usize = 1024;
const MAX_DEPTH: usize = 32;

fn recognized(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    matches!(
        name.as_str(),
        "config.json"
            | "tokenizer_config.json"
            | "processor_config.json"
            | "preprocessor_config.json"
            | "generation_config.json"
            | "adapter_config.json"
    ) || (name.starts_with("sentence_") && name.ends_with(".json"))
}

pub fn normalized_config_facts(relative_path: &str, bytes: &[u8]) -> Result<Vec<ConfigFact>> {
    if !recognized(relative_path) {
        return Ok(Vec::new());
    }
    if bytes.len() > MAX_CONFIG_BYTES {
        bail!("configuration exceeds declarative analysis cap");
    }
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    let mut out = Vec::new();
    fn walk(
        member: &str,
        path: &str,
        v: &serde_json::Value,
        depth: usize,
        out: &mut Vec<ConfigFact>,
    ) {
        if depth > MAX_DEPTH || out.len() >= MAX_FACTS_PER_FILE {
            return;
        }
        match v {
            serde_json::Value::Object(map) => {
                for (k, v) in map.iter().take(MAX_FACTS_PER_FILE) {
                    let p = if path.is_empty() {
                        k.clone()
                    } else {
                        format!("{path}.{k}")
                    };
                    walk(member, &p, v, depth + 1, out);
                }
            }
            serde_json::Value::Array(values) => {
                let vals = values
                    .iter()
                    .take(MAX_LIST_VALUES)
                    .filter_map(scalar)
                    .collect::<Vec<_>>();
                if !vals.is_empty() {
                    out.push(ConfigFact {
                        member: member.into(),
                        field_path: path.into(),
                        values: vals,
                    });
                }
            }
            _ => {
                if let Some(value) = scalar(v) {
                    out.push(ConfigFact {
                        member: member.into(),
                        field_path: path.into(),
                        values: vec![value],
                    });
                }
            }
        }
    }
    fn scalar(v: &serde_json::Value) -> Option<String> {
        match v {
            serde_json::Value::String(s) => Some(s.chars().take(16 * 1024).collect()),
            serde_json::Value::Bool(b) => Some(b.to_string()),
            serde_json::Value::Number(n) => Some(n.to_string()),
            _ => None,
        }
    }
    walk(relative_path, "", &value, 0, &mut out);
    Ok(out)
}

pub fn normalize_qualified_target(value: &str) -> Option<String> {
    let v = value.trim();
    if v.is_empty()
        || v.len() > 4096
        || v.contains("..")
        || v.contains("://")
        || v.chars().any(|c| c.is_control() || c.is_whitespace())
        || v.contains([';', '|', '&', '$', '`', '\\', '/'])
    {
        return None;
    }
    if v.split('.').all(|part| {
        !part.is_empty()
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    }) {
        Some(v.into())
    } else {
        None
    }
}
