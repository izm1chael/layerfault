use super::SpecialTokenRecord;
const MAX_SPECIAL_TOKENS: usize = 16384;
pub fn from_json(path: &str, value: &serde_json::Value) -> Vec<SpecialTokenRecord> {
    let mut out = Vec::new();
    if let Some(map) = value.as_object() {
        for (key, v) in map {
            let role = canonical_role(key);
            match v {
                serde_json::Value::String(token) => {
                    push(&mut out, path, token, role.clone(), true, None)
                }
                serde_json::Value::Object(obj) => {
                    if let Some(token) = obj
                        .get("content")
                        .and_then(|v| v.as_str())
                        .or_else(|| obj.get("token").and_then(|v| v.as_str()))
                    {
                        push(
                            &mut out,
                            path,
                            token,
                            role.clone(),
                            obj.get("special")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(role.is_some()),
                            obj.get("id").and_then(|v| v.as_u64()),
                        )
                    }
                }
                serde_json::Value::Array(arr)
                    if key == "additional_special_tokens" || key == "added_tokens" =>
                {
                    for item in arr.iter().take(MAX_SPECIAL_TOKENS) {
                        match item {
                            serde_json::Value::String(t) => {
                                push(&mut out, path, t, None, true, None)
                            }
                            serde_json::Value::Object(obj) => {
                                if let Some(t) = obj.get("content").and_then(|v| v.as_str()) {
                                    push(
                                        &mut out,
                                        path,
                                        t,
                                        None,
                                        obj.get("special")
                                            .and_then(|v| v.as_bool())
                                            .unwrap_or(true),
                                        obj.get("id").and_then(|v| v.as_u64()),
                                    )
                                }
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
    }
    out.truncate(MAX_SPECIAL_TOKENS);
    out
}
fn canonical_role(key: &str) -> Option<String> {
    let k = key.to_ascii_lowercase();
    for role in [
        "bos",
        "eos",
        "unk",
        "pad",
        "system",
        "user",
        "assistant",
        "tool",
    ] {
        if k.contains(role) {
            return Some(role.into());
        }
    }
    None
}
fn push(
    out: &mut Vec<SpecialTokenRecord>,
    source: &str,
    token: &str,
    role: Option<String>,
    special: bool,
    id: Option<u64>,
) {
    if out.len() < MAX_SPECIAL_TOKENS && token.len() <= 8192 {
        out.push(SpecialTokenRecord {
            token: token.into(),
            role,
            special,
            id,
            source: source.into(),
        })
    }
}
