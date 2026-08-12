use super::signatures::COMPILED_SIGNATURES;
use sha2::{Digest, Sha256};
pub(super) fn redacted_context_window(
    content: &str,
    match_start: usize,
    match_end: usize,
) -> String {
    let start = previous_char_boundary(content, match_start.saturating_sub(20));
    let end = next_char_boundary(content, (match_end + 40).min(content.len()));
    let window = &content[start..end];
    let mut replacements = Vec::new();
    for compiled in COMPILED_SIGNATURES.iter() {
        if !matches!(
            compiled.signature.category,
            "HardcodedSecrets" | "PIILeakage"
        ) {
            continue;
        }
        for matched in compiled.regex.find_iter(window) {
            let value = &window[matched.start()..matched.end()];
            let fingerprint = hex::encode(Sha256::digest(value.as_bytes()));
            replacements.push((
                matched.start(),
                matched.end(),
                format!("<redacted sha256:{}>", &fingerprint[..16]),
            ));
        }
    }
    replacements.sort_by_key(|(start, _, _)| *start);
    let mut rendered = String::with_capacity(window.len());
    let mut cursor = 0;
    for (replacement_start, replacement_end, replacement) in replacements {
        if replacement_start < cursor {
            continue;
        }
        rendered.push_str(&window[cursor..replacement_start]);
        rendered.push_str(&replacement);
        cursor = replacement_end;
    }
    rendered.push_str(&window[cursor..]);
    rendered
}

pub(super) fn previous_char_boundary(content: &str, mut index: usize) -> usize {
    while index > 0 && !content.is_char_boundary(index) {
        index -= 1;
    }
    index
}
pub(super) fn next_char_boundary(content: &str, mut index: usize) -> usize {
    while index < content.len() && !content.is_char_boundary(index) {
        index += 1;
    }
    index
}
