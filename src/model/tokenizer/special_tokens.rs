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
                                let role = canonical_role(t);
                                push(&mut out, path, t, role, true, None)
                            }
                            serde_json::Value::Object(obj) => {
                                if let Some(t) = obj.get("content").and_then(|v| v.as_str()) {
                                    let special = obj
                                        .get("special")
                                        .and_then(|v| v.as_bool())
                                        .unwrap_or(true);
                                    // Infer the role from the token content when
                                    // processing added_tokens (e.g. SmolLM2's
                                    // <|im_start|> declared only in tokenizer.json).
                                    let role = canonical_role(t);
                                    push(
                                        &mut out,
                                        path,
                                        t,
                                        role,
                                        special,
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
/// Map a tokenizer key name or token content to a canonical security role.
///
/// For `special_tokens_map.json` keys the role is determined from the
/// conventional field name (e.g. `bos_token` → `"bos"`).  For
/// `tokenizer.json` `added_tokens` entries the role is inferred from the
/// token content string itself (e.g. `<|im_start|>` → `"assistant"` via the
/// `im_start` / `im_end` pattern that marks ChatML role boundaries).
///
/// The function checks the lowercased input for known role substrings, but
/// only when the substring appears at a word boundary (or is the entire
/// input) so that e.g. `"toolkit"` does not falsely match `"tool"`.
fn canonical_role(key_or_token: &str) -> Option<String> {
    let k = key_or_token.to_ascii_lowercase();
    // Ordered so that longer, more-specific patterns match before shorter ones
    // that could be substrings of them.
    for role in [
        "assistant",
        "system",
        "user",
        "tool",
        "bos",
        "eos",
        "unk",
        "pad",
    ] {
        if word_match(&k, role) {
            return Some(role.into());
        }
    }
    // im_start / im_end are ChatML role-boundary tokens (used by SmolLM2,
    // Qwen, etc.).  They separate system/user/assistant turns but are not
    // themselves role-specific — the closest canonical security role is
    // "assistant" because that is the most-privileged role they gate.
    if word_match(&k, "im_start") || word_match(&k, "im_end") {
        return Some("assistant".into());
    }
    None
}
/// Returns true when `pattern` appears in `text` at a word boundary: either
/// the match starts at the beginning of `text` or after a non-alphanumeric
/// character, and ends at the end of `text` or before a non-alphanumeric
/// character.  This avoids false positives like `"toolkit"` matching `"tool"`.
fn word_match(text: &str, pattern: &str) -> bool {
    text.match_indices(pattern).any(|(start, _)| {
        let before = start == 0 || {
            let prev = text.as_bytes()[start - 1];
            !prev.is_ascii_alphanumeric()
        };
        let after = {
            let end = start + pattern.len();
            end >= text.len() || {
                let next = text.as_bytes()[end];
                !next.is_ascii_alphanumeric()
            }
        };
        before && after
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bos_token_key_gets_bos_role() {
        assert_eq!(canonical_role("bos_token"), Some("bos".into()));
    }

    #[test]
    fn eos_token_key_gets_eos_role() {
        assert_eq!(canonical_role("eos_token"), Some("eos".into()));
    }

    #[test]
    fn unk_token_key_gets_unk_role() {
        assert_eq!(canonical_role("unk_token"), Some("unk".into()));
    }

    #[test]
    fn pad_token_key_gets_pad_role() {
        assert_eq!(canonical_role("pad_token"), Some("pad".into()));
    }

    #[test]
    fn system_key_gets_system_role() {
        assert_eq!(canonical_role("system_message"), Some("system".into()));
    }

    #[test]
    fn user_key_gets_user_role() {
        assert_eq!(canonical_role("user_message"), Some("user".into()));
    }

    #[test]
    fn assistant_key_gets_assistant_role() {
        assert_eq!(
            canonical_role("assistant_message"),
            Some("assistant".into())
        );
    }

    #[test]
    fn tool_key_gets_tool_role() {
        assert_eq!(canonical_role("tool_message"), Some("tool".into()));
    }

    #[test]
    fn toolkit_does_not_falsely_match_tool() {
        // "toolkit" contains "tool" but not at a word boundary
        assert_eq!(canonical_role("toolkit"), None);
    }

    #[test]
    fn bosom_does_not_falsely_match_bos() {
        assert_eq!(canonical_role("bosom"), None);
    }

    #[test]
    fn im_start_token_gets_assistant_role() {
        // ChatML boundary token used by SmolLM2, Qwen, etc.
        assert_eq!(canonical_role("<|im_start|>"), Some("assistant".into()));
    }

    #[test]
    fn im_end_token_gets_assistant_role() {
        assert_eq!(canonical_role("<|im_end|>"), Some("assistant".into()));
    }

    #[test]
    fn unrelated_token_gets_no_role() {
        assert_eq!(canonical_role("hello"), None);
    }

    #[test]
    fn added_tokens_string_items_get_role_inference() {
        let value = serde_json::json!({
            "added_tokens": ["<|im_start|>", "<|im_end|>", "<s>", "</s>"]
        });
        let tokens = from_json("tokenizer.json", &value);
        // <|im_start|> → assistant, <|im_end|> → assistant
        // <s> and </s> contain no known role patterns at word boundaries
        let roles: Vec<Option<String>> = tokens.iter().map(|t| t.role.clone()).collect();
        assert!(
            roles.contains(&Some("assistant".into())),
            "im_start/im_end should get assistant role"
        );
    }

    #[test]
    fn added_tokens_object_items_get_role_inference() {
        let value = serde_json::json!({
            "added_tokens": [
                {"id": 0, "content": "<|im_start|>", "special": true},
                {"id": 1, "content": "<|im_end|>", "special": true},
                {"id": 2, "content": "hello", "special": false}
            ]
        });
        let tokens = from_json("tokenizer.json", &value);
        assert_eq!(tokens.len(), 3);
        // First two should have assistant role, last should have None
        assert_eq!(tokens[0].role, Some("assistant".into()));
        assert_eq!(tokens[1].role, Some("assistant".into()));
        assert_eq!(tokens[2].role, None);
    }

    #[test]
    fn special_tokens_map_still_uses_key_based_role() {
        // Keys in special_tokens_map.json get their role from the key name
        let value = serde_json::json!({
            "bos_token": "<s>",
            "eos_token": "</s>"
        });
        let tokens = from_json("special_tokens_map.json", &value);
        assert_eq!(tokens.len(), 2);
        assert_eq!(tokens[0].role, Some("bos".into()));
        assert_eq!(tokens[1].role, Some("eos".into()));
    }
}
