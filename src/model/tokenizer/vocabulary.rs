//! Bounded parsing of plain vocabulary files (`vocab.json`, `vocab.txt`).
//!
//! Unlike `special_tokens.rs`, which reads declared special-token records,
//! this reads the ordinary token strings a tokenizer can produce at all —
//! the surface `special_token_collisions` checks against for smuggled
//! role-boundary markers. Each entry carries the numeric id the vocabulary
//! assigns it (`vocab.json`'s value, or the line number for `vocab.txt`) so
//! that surface matches against declared special tokens can be checked for
//! id agreement rather than treated as inherently suspicious.

const MAX_VOCABULARY_ENTRIES: usize = 300_000;
const MAX_TOKEN_LEN: usize = 8192;

/// `vocab.json`: `{"token string": id, ...}`. The keys are the literal
/// token strings (for byte-level BPE tokenizers these already include the
/// byte-level encoding, e.g. `Ġthe`, which is the same surface form the
/// tokenizer would actually decode back to text).
pub fn from_json(value: &serde_json::Value) -> Vec<(String, Option<u64>)> {
    let Some(map) = value.as_object() else {
        return Vec::new();
    };
    map.iter()
        .filter(|(token, _)| token.len() <= MAX_TOKEN_LEN)
        .take(MAX_VOCABULARY_ENTRIES)
        .map(|(token, id)| (token.clone(), id.as_u64()))
        .collect()
}

/// `vocab.txt`: one token per line (the WordPiece/BERT-style convention).
/// The line number is the token's id under this format.
pub fn from_txt(text: &str) -> Vec<(String, Option<u64>)> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.is_empty() && line.len() <= MAX_TOKEN_LEN)
        .take(MAX_VOCABULARY_ENTRIES)
        .map(|(index, line)| (line.to_owned(), Some(index as u64)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_vocab_json_keys_and_ids() {
        let value = serde_json::json!({"hello": 0, "world": 1, "<|im_start|>": 2});
        let tokens = from_json(&value);
        assert_eq!(tokens.len(), 3);
        assert!(tokens.contains(&("<|im_start|>".to_owned(), Some(2))));
    }

    #[test]
    fn non_object_json_yields_no_tokens() {
        assert!(from_json(&serde_json::json!(["a", "b"])).is_empty());
    }

    #[test]
    fn parses_vocab_txt_lines_with_line_number_as_id() {
        let text = "hello\nworld\n<|im_start|>\n";
        let tokens = from_txt(text);
        assert_eq!(
            tokens,
            vec![
                ("hello".to_owned(), Some(0)),
                ("world".to_owned(), Some(1)),
                ("<|im_start|>".to_owned(), Some(2)),
            ]
        );
    }

    #[test]
    fn empty_lines_are_skipped() {
        let text = "hello\n\nworld\n";
        assert_eq!(
            from_txt(text),
            vec![("hello".to_owned(), Some(0)), ("world".to_owned(), Some(2))]
        );
    }

    #[test]
    fn oversized_tokens_are_rejected() {
        let oversized = "a".repeat(MAX_TOKEN_LEN + 1);
        let text = format!("hello\n{oversized}\nworld\n");
        assert_eq!(
            from_txt(&text),
            vec![("hello".to_owned(), Some(0)), ("world".to_owned(), Some(2))]
        );
    }
}
