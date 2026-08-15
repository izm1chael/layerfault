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
        findings: Vec::new(),
        coverage: crate::coverage::Coverage::complete(0, 0),
    };
    let mut text_total = 0u64;
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
                }
            }
        }
    }
    report.coverage = crate::coverage::Coverage::complete(report.files.len() as u64, text_total);
    let clone = report.clone();
    report.findings = findings::build(&clone);
    Ok(report)
}
