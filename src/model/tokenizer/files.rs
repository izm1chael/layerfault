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
    let mut vocabulary_entries: Vec<(String, String)> = Vec::new();
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
                                .map(|token| (rel.clone(), token)),
                        );
                    }
                }
            } else if matches!(k, TokenizerFileKind::Vocabulary) {
                vocabulary_entries.extend(
                    vocabulary::from_txt(text)
                        .into_iter()
                        .map(|token| (rel.clone(), token)),
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

/// A plain vocabulary entry whose literal string exactly matches a declared
/// role-boundary special token is "smuggled" — see
/// `TokenizerSecurityReport::special_token_collisions` for what this means
/// and does not cover.
fn special_token_collisions(
    special_tokens: &[SpecialTokenRecord],
    vocabulary_entries: &[(String, String)],
) -> Vec<SpecialTokenCollision> {
    let role_boundary: std::collections::HashMap<&str, &str> = special_tokens
        .iter()
        .filter(|record| record.special && record.role.is_some())
        .map(|record| (record.token.as_str(), record.source.as_str()))
        .collect();
    if role_boundary.is_empty() {
        return Vec::new();
    }
    vocabulary_entries
        .iter()
        .filter_map(|(source, token)| {
            role_boundary
                .get(token.as_str())
                .map(|special_source| SpecialTokenCollision {
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

    fn special(token: &str, role: &str, special: bool, source: &str) -> SpecialTokenRecord {
        SpecialTokenRecord {
            token: token.to_owned(),
            role: Some(role.to_owned()),
            special,
            id: None,
            source: source.to_owned(),
        }
    }

    #[test]
    fn plain_vocabulary_entry_matching_a_role_boundary_token_is_a_collision() {
        let specials = vec![special(
            "<|im_start|>",
            "system",
            true,
            "tokenizer_config.json",
        )];
        let vocab = vec![("vocab.json".to_owned(), "<|im_start|>".to_owned())];
        let collisions = special_token_collisions(&specials, &vocab);
        assert_eq!(collisions.len(), 1);
        assert_eq!(collisions[0].token, "<|im_start|>");
        assert_eq!(collisions[0].special_source, "tokenizer_config.json");
        assert_eq!(collisions[0].vocabulary_source, "vocab.json");
    }

    #[test]
    fn non_role_boundary_special_tokens_are_not_checked() {
        // `special: false` means it is not actually declared special — a
        // vocabulary entry matching it is not a smuggling risk, it is the
        // same ordinary token by definition.
        let specials = vec![special("hello", "system", false, "vocab.json")];
        let vocab = vec![("vocab.json".to_owned(), "hello".to_owned())];
        assert!(special_token_collisions(&specials, &vocab).is_empty());
    }

    #[test]
    fn unrelated_vocabulary_entries_are_not_flagged() {
        let specials = vec![special(
            "<|im_start|>",
            "system",
            true,
            "tokenizer_config.json",
        )];
        let vocab = vec![("vocab.json".to_owned(), "hello".to_owned())];
        assert!(special_token_collisions(&specials, &vocab).is_empty());
    }

    #[test]
    fn no_special_tokens_yields_no_collisions_without_scanning_vocabulary() {
        let vocab = vec![("vocab.json".to_owned(), "hello".to_owned())];
        assert!(special_token_collisions(&[], &vocab).is_empty());
    }

    #[test]
    fn inspect_package_detects_a_real_smuggled_token_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("special_tokens_map.json"),
            serde_json::json!({
                "bos_token": {"content": "<|im_start|>", "special": true}
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
}
