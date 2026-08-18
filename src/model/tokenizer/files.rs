use super::*;
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::path::Path;
const MAX_FILES: usize = 128;
const MAX_TEXT: u64 = 256 * 1024 * 1024;
fn kind(path: &str) -> Option<TokenizerFileKind> {
    let n = path.rsplit('/').next()?.to_ascii_lowercase();
    Some(match n.as_str() {
        "tokenizer.json" => TokenizerFileKind::TokenizerJson,
        "tokenizer_config.json" => TokenizerFileKind::TokenizerConfig,
        "special_tokens_map.json" => TokenizerFileKind::SpecialTokensMap,
        "added_tokens.json" => TokenizerFileKind::AddedTokens,
        "spiece.model" | "tokenizer.model" => TokenizerFileKind::SentencePiece,
        "merges.txt" => TokenizerFileKind::BpeMerges,
        "vocab.json" | "vocab.txt" => TokenizerFileKind::Vocabulary,
        "chat_template.jinja" => TokenizerFileKind::ChatTemplate,
        "processor_config.json" | "preprocessor_config.json" => TokenizerFileKind::ProcessorConfig,
        _ => return None,
    })
}
pub fn inspect_package(
    root: &Path,
    relative_files: &[String],
    identity: &str,
) -> Result<TokenizerSecurityReport> {
    let subject = crate::finding_evidence::EvidenceSubject::identity(
        identity,
        "application/vnd.layerfault.tokenizer+json",
    );
    let mut report = TokenizerSecurityReport {
        subject,
        files: Vec::new(),
        special_tokens: Vec::new(),
        chat_template: None,
        unicode_controls: Vec::new(),
        special_token_collisions: Vec::new(),
        findings: Vec::new(),
        coverage: crate::coverage::Coverage::complete(0, 0),
    };
    let mut text_total = 0u64;
    let mut vocabulary_entries: Vec<(String, String, Option<u64>)> = Vec::new();
    for rel in relative_files
        .iter()
        .filter(|r| kind(r).is_some())
        .take(MAX_FILES)
    {
        let k = kind(rel).unwrap();
        let f = crate::safeio::open_readonly_nofollow(&root.join(rel))?;
        let size = f.metadata()?.len();
        let bytes =
            crate::safeio::read_all_from_file(&f, size.min(MAX_TEXT.saturating_sub(text_total)))?;
        let sha = hex::encode(Sha256::digest(&bytes));
        report.files.push(TokenizerFileSummary {
            relative_path: rel.clone(),
            size,
            sha256: sha,
            kind: k,
        });
        if matches!(k, TokenizerFileKind::SentencePiece) {
            continue;
        }
        text_total = text_total.saturating_add(bytes.len() as u64);
        if let Ok(text) = std::str::from_utf8(&bytes) {
            report
                .unicode_controls
                .extend(unicode::scan_text(rel, "file", text, false));
            if matches!(k, TokenizerFileKind::ChatTemplate) {
                let (t, c) = template::inspect(rel, text);
                report.chat_template = Some(t);
                report.unicode_controls.extend(c);
            }
            if rel.ends_with(".json") {
                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                    report
                        .special_tokens
                        .extend(special_tokens::from_json(rel, &v));
                    if let Some(t) = v.get("chat_template").and_then(|v| v.as_str()) {
                        let (sec, c) = template::inspect(rel, t);
                        report.chat_template = Some(sec);
                        report.unicode_controls.extend(c);
                    }
                    if matches!(k, TokenizerFileKind::Vocabulary) {
                        vocabulary_entries.extend(
                            vocabulary::from_json(&v)
                                .into_iter()
                                .map(|(token, id)| (rel.clone(), token, id)),
                        );
                    }
                }
            } else if matches!(k, TokenizerFileKind::Vocabulary) {
                vocabulary_entries.extend(
                    vocabulary::from_txt(text)
                        .into_iter()
                        .map(|(token, id)| (rel.clone(), token, id)),
                );
            }
        }
    }
    report.special_token_collisions =
        special_token_collisions(&report.special_tokens, &vocabulary_entries);
    report.coverage = crate::coverage::Coverage::complete(report.files.len() as u64, text_total);
    let clone = report.clone();
    report.findings = findings::build(&clone);
    Ok(report)
}

/// A plain vocabulary entry whose literal string matches a declared
/// role-boundary special token is normal and expected: a special token must
/// have a numeric id to be encodable at all, so complete tokenizers always
/// list it in `vocab.json`/`vocab.txt` alongside declaring it special
/// elsewhere. That duplication alone is not smuggling.
///
/// This only becomes a genuine "smuggled" collision — see
/// `TokenizerSecurityReport::special_token_collisions` — when the id the
/// vocabulary assigns the token string materially *contradicts* the id the
/// special-token declaration assigns it. Two different ids for what claims
/// to be the same control token is a real disagreement about what that
/// token resolves to; the same id from both sources is just the ordinary
/// registration of one token. When either side's id is unknown there is no
/// evidence of contradiction, so no finding is produced.
fn special_token_collisions(
    special_tokens: &[SpecialTokenRecord],
    vocabulary_entries: &[(String, String, Option<u64>)],
) -> Vec<SpecialTokenCollision> {
    let role_boundary: std::collections::HashMap<&str, (&str, Option<u64>)> = special_tokens
        .iter()
        .filter(|record| record.special && record.role.is_some())
        .map(|record| (record.token.as_str(), (record.source.as_str(), record.id)))
        .collect();
    if role_boundary.is_empty() {
        return Vec::new();
    }
    vocabulary_entries
        .iter()
        .filter_map(|(source, token, vocabulary_id)| {
            let (special_source, special_id) = role_boundary.get(token.as_str())?;
            let contradicts = match (special_id, vocabulary_id) {
                (Some(special_id), Some(vocabulary_id)) => special_id != vocabulary_id,
                _ => false,
            };
            contradicts.then(|| SpecialTokenCollision {
                token: token.clone(),
                special_source: (*special_source).to_owned(),
                vocabulary_source: source.clone(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn special(
        token: &str,
        role: &str,
        special: bool,
        source: &str,
        id: Option<u64>,
    ) -> SpecialTokenRecord {
        SpecialTokenRecord {
            token: token.to_owned(),
            role: Some(role.to_owned()),
            special,
            id,
            source: source.to_owned(),
        }
    }

    #[test]
    fn vocabulary_entry_with_conflicting_id_is_a_collision() {
        // The special-token declaration says <|im_start|> is id 0. The
        // vocabulary says the same literal string is id 1. Two different
        // ids for what claims to be the same control token is a genuine
        // contradiction about what that token resolves to.
        let specials = vec![special(
            "<|im_start|>",
            "system",
            true,
            "tokenizer_config.json",
            Some(0),
        )];
        let vocab = vec![("vocab.json".to_owned(), "<|im_start|>".to_owned(), Some(1))];
        let collisions = special_token_collisions(&specials, &vocab);
        assert_eq!(collisions.len(), 1);
        assert_eq!(collisions[0].token, "<|im_start|>");
        assert_eq!(collisions[0].special_source, "tokenizer_config.json");
        assert_eq!(collisions[0].vocabulary_source, "vocab.json");
    }

    #[test]
    fn vocabulary_entry_with_agreeing_id_is_not_a_collision() {
        // A complete tokenizer always lists its special tokens in the plain
        // vocabulary too, because a token needs a numeric id to be
        // encodable at all. Agreement on that id is normal registration,
        // not smuggling.
        let specials = vec![special(
            "<|im_start|>",
            "system",
            true,
            "tokenizer_config.json",
            Some(0),
        )];
        let vocab = vec![("vocab.json".to_owned(), "<|im_start|>".to_owned(), Some(0))];
        assert!(special_token_collisions(&specials, &vocab).is_empty());
    }

    #[test]
    fn vocabulary_entry_without_a_known_id_on_either_side_is_not_a_collision() {
        // Sources such as special_tokens_map.json declare a role-boundary
        // token by content only, without carrying an id. With no id on
        // either side there is no evidence of a contradiction.
        let specials = vec![special(
            "<|im_start|>",
            "system",
            true,
            "tokenizer_config.json",
            None,
        )];
        let vocab = vec![("vocab.json".to_owned(), "<|im_start|>".to_owned(), None)];
        assert!(special_token_collisions(&specials, &vocab).is_empty());
    }

    #[test]
    fn non_role_boundary_special_tokens_are_not_checked() {
        // `special: false` means it is not actually declared special — a
        // vocabulary entry matching it is not a smuggling risk, it is the
        // same ordinary token by definition.
        let specials = vec![special("hello", "system", false, "vocab.json", Some(0))];
        let vocab = vec![("vocab.json".to_owned(), "hello".to_owned(), Some(1))];
        assert!(special_token_collisions(&specials, &vocab).is_empty());
    }

    #[test]
    fn unrelated_vocabulary_entries_are_not_flagged() {
        let specials = vec![special(
            "<|im_start|>",
            "system",
            true,
            "tokenizer_config.json",
            Some(0),
        )];
        let vocab = vec![("vocab.json".to_owned(), "hello".to_owned(), Some(0))];
        assert!(special_token_collisions(&specials, &vocab).is_empty());
    }

    #[test]
    fn no_special_tokens_yields_no_collisions_without_scanning_vocabulary() {
        let vocab = vec![("vocab.json".to_owned(), "hello".to_owned(), Some(0))];
        assert!(special_token_collisions(&[], &vocab).is_empty());
    }

    #[test]
    fn inspect_package_detects_a_real_smuggled_token_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("special_tokens_map.json"),
            serde_json::json!({
                "bos_token": {"content": "<|im_start|>", "special": true, "id": 0}
            })
            .to_string(),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("vocab.json"),
            serde_json::json!({"hello": 0, "<|im_start|>": 1}).to_string(),
        )
        .unwrap();
        let report = inspect_package(
            dir.path(),
            &[
                "special_tokens_map.json".to_owned(),
                "vocab.json".to_owned(),
            ],
            "test-identity",
        )
        .expect("inspect package");
        assert_eq!(report.special_token_collisions.len(), 1);
        assert_eq!(report.special_token_collisions[0].token, "<|im_start|>");
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.rule_id.as_deref()
                == Some("LF-TOKENIZER-SPECIAL-TOKEN-SPOOFABLE")));
    }

    #[test]
    fn inspect_package_smollm2_style_consistent_declaration_does_not_collide() {
        // A known-good SmolLM2-style tokenizer: <|im_start|>/<|im_end|> are
        // declared special in tokenizer.json's added_tokens with explicit
        // ids, and those same ids are what vocab.json assigns the literal
        // strings. This is the normal shape of a complete tokenizer and
        // must not trigger the spoofing finding.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("tokenizer.json"),
            serde_json::json!({
                "added_tokens": [
                    {"id": 0, "content": "<|im_start|>", "special": true},
                    {"id": 1, "content": "<|im_end|>", "special": true}
                ]
            })
            .to_string(),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("vocab.json"),
            serde_json::json!({
                "hello": 2,
                "<|im_start|>": 0,
                "<|im_end|>": 1
            })
            .to_string(),
        )
        .unwrap();
        let report = inspect_package(
            dir.path(),
            &["tokenizer.json".to_owned(), "vocab.json".to_owned()],
            "test-identity",
        )
        .expect("inspect package");
        assert!(
            report.special_token_collisions.is_empty(),
            "consistent SmolLM2-style ids must not be reported as a collision: {:?}",
            report.special_token_collisions
        );
        assert!(!report
            .findings
            .iter()
            .any(|finding| finding.rule_id.as_deref()
                == Some("LF-TOKENIZER-SPECIAL-TOKEN-SPOOFABLE")));
    }

    #[test]
    fn inspect_package_detects_smuggled_token_from_added_tokens_in_tokenizer_json() {
        // Real SmolLM2 tokenizers declare <|im_start|> in tokenizer.json's
        // `added_tokens` array, not in special_tokens_map.json.  The role
        // must be inferred from the token content so collision detection
        // still works.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("tokenizer.json"),
            serde_json::json!({
                "added_tokens": [
                    {"id": 0, "content": "<|im_start|>", "special": true},
                    {"id": 1, "content": "<|im_end|>", "special": true}
                ]
            })
            .to_string(),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("vocab.json"),
            serde_json::json!({"hello": 0, "<|im_start|>": 1}).to_string(),
        )
        .unwrap();
        let report = inspect_package(
            dir.path(),
            &["tokenizer.json".to_owned(), "vocab.json".to_owned()],
            "test-identity",
        )
        .expect("inspect package");
        assert_eq!(
            report.special_token_collisions.len(),
            1,
            "<|im_start|> in tokenizer.json added_tokens should be detected as role-boundary"
        );
        assert_eq!(report.special_token_collisions[0].token, "<|im_start|>");
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.rule_id.as_deref()
                == Some("LF-TOKENIZER-SPECIAL-TOKEN-SPOOFABLE")));
    }
}
