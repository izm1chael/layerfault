use super::{ChatTemplateSecurity, UnicodeControlRecord};
use sha2::{Digest, Sha256};
pub fn inspect(path: &str, text: &str) -> (ChatTemplateSecurity, Vec<UnicodeControlRecord>) {
    let normalized = text.replace("\r\n", "\n");
    let hash = |v: &[u8]| hex::encode(Sha256::digest(v));
    let roles = ["system", "user", "assistant", "tool"]
        .into_iter()
        .filter(|r| text.contains(r))
        .map(str::to_owned)
        .collect();
    let tools = ["tool_call", "tools", "function"]
        .into_iter()
        .filter(|t| text.contains(t))
        .map(str::to_owned)
        .collect();
    let hidden_literals = lines_hidden_literals(text);
    let controls = crate::model::tokenizer::unicode::scan_text(path, "chat_template", text, true);
    (
        ChatTemplateSecurity {
            source: path.into(),
            sha256: hash(text.as_bytes()),
            normalized_sha256: hash(normalized.as_bytes()),
            roles_referenced: roles,
            tool_constructs: tools,
            hidden_literals,
            static_analysis_complete: text.len() <= 4 * 1024 * 1024,
        },
        controls,
    )
}
fn lines_hidden_literals(text: &str) -> Vec<String> {
    text.lines()
        .filter(|line| {
            let l = line.trim();
            !l.is_empty()
                && !l.starts_with("{#")
                && !l.starts_with("{{")
                && !l.starts_with("{%")
                && (l.to_ascii_lowercase().contains("system")
                    || l.to_ascii_lowercase().contains("ignore previous"))
        })
        .take(32)
        .map(|s| s.chars().take(256).collect())
        .collect()
}
