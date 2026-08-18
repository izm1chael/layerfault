use super::{
    SpecialTokenCollision, SpecialTokenRecord, TokenizerSecurityReport, UnicodeControlRecord,
};
use crate::finding_evidence::{EvidenceKind, FindingBuilder, FindingEvidence};
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use std::collections::BTreeMap;

/// Standard HF practice: models without a dedicated pad token commonly
/// reuse eos/bos/unk as pad (e.g. SmolLM2's `<|im_end|>` as both eos_token
/// and pad_token). Reusing a token for one of these known-safe role pairs
/// is not a conflict; genuine id/content contradictions are still caught
/// separately below.
const SAFE_ROLE_OVERLAP_PAIRS: &[(&str, &str)] = &[("eos", "pad"), ("bos", "pad"), ("unk", "pad")];

fn is_safe_role_overlap(a: &str, b: &str) -> bool {
    SAFE_ROLE_OVERLAP_PAIRS
        .iter()
        .any(|(x, y)| (*x == a && *y == b) || (*x == b && *y == a))
}

pub(crate) fn build(report: &TokenizerSecurityReport) -> Vec<LayerScanResult> {
    let mut out = Vec::new();
    for c in &report.unicode_controls {
        out.push(control(report, c));
    }
    conflicts(report, &report.special_tokens, &mut out);
    for collision in &report.special_token_collisions {
        out.push(collision_finding(report, collision));
    }
    if let Some(t) = &report.chat_template {
        if !t.hidden_literals.is_empty() {
            out.push(simple(
                report,
                "LF-TOKENIZER-HIDDEN-PROMPT",
                ScanStatus::Warn,
                "chat template contains a hard-coded privilege-relevant literal",
            ));
        }
        if !t.tool_constructs.is_empty() && !t.static_analysis_complete {
            out.push(simple(
                report,
                "LF-TOKENIZER-TOOL-TEMPLATE-RISK",
                ScanStatus::Warn,
                "tool-capable chat template could not be completely analyzed",
            ));
        }
    }
    out
}
fn simple(
    r: &TokenizerSecurityReport,
    id: &str,
    status: ScanStatus,
    detail: &str,
) -> LayerScanResult {
    FindingBuilder::new(id, CheckType::TokenizerSecurity, status)
        .class(FindingClass::ContentIndicator)
        .confidence(Confidence::High)
        .subject(r.subject.clone())
        .detail(detail)
        .evidence(FindingEvidence::new(
            EvidenceKind::TokenizerRecord,
            r.subject.clone(),
            detail,
        ))
        .finish()
}
fn control(r: &TokenizerSecurityReport, c: &UnicodeControlRecord) -> LayerScanResult {
    let (id, status) = if c.role_boundary {
        ("LF-TOKENIZER-ROLE-BOUNDARY-CONTROL", ScanStatus::Fail)
    } else {
        ("LF-TOKENIZER-UNICODE-CONTROL", ScanStatus::Warn)
    };
    FindingBuilder::new(id, CheckType::TokenizerSecurity, status)
        .class(FindingClass::ContentIndicator)
        .confidence(Confidence::High)
        .subject(r.subject.clone())
        .detail(format!(
            "{} contains {} at {}",
            c.relative_path, c.unicode_name_or_hex, c.field_path
        ))
        .evidence(
            FindingEvidence::new(
                EvidenceKind::TokenizerRecord,
                r.subject.clone(),
                "Unicode control in tokenizer content",
            )
            .structured(serde_json::json!(c)),
        )
        .finish()
}
fn collision_finding(
    r: &TokenizerSecurityReport,
    collision: &SpecialTokenCollision,
) -> LayerScanResult {
    FindingBuilder::new(
        "LF-TOKENIZER-SPECIAL-TOKEN-SPOOFABLE",
        CheckType::TokenizerSecurity,
        ScanStatus::Warn,
    )
    .class(FindingClass::ContentIndicator)
    .confidence(Confidence::High)
    .subject(r.subject.clone())
    .detail(format!(
        "plain vocabulary entry in {} matches the literal string of a role-boundary special token declared in {}",
        collision.vocabulary_source, collision.special_source
    ))
    .evidence(
        FindingEvidence::new(
            EvidenceKind::TokenizerRecord,
            r.subject.clone(),
            "Special token smuggling: plain vocabulary entry matches a role-boundary marker",
        )
        .structured(serde_json::json!(collision)),
    )
    .finish()
}

fn conflicts(
    r: &TokenizerSecurityReport,
    t: &[SpecialTokenRecord],
    out: &mut Vec<LayerScanResult>,
) {
    let mut by_token: BTreeMap<&str, &Option<String>> = BTreeMap::new();
    let mut by_id: BTreeMap<u64, &str> = BTreeMap::new();
    let mut by_token_id: BTreeMap<&str, u64> = BTreeMap::new();
    let mut by_role_token_special: BTreeMap<(&str, &str), bool> = BTreeMap::new();
    for x in t {
        if let Some(prev) = by_token.insert(&x.token, &x.role) {
            let is_safe_overlap = match (prev, &x.role) {
                (Some(prev_role), Some(new_role)) => is_safe_role_overlap(prev_role, new_role),
                _ => false,
            };
            if prev != &x.role && !is_safe_overlap {
                out.push(simple(
                    r,
                    "LF-TOKENIZER-SPECIAL-TOKEN-CONFLICT",
                    ScanStatus::Warn,
                    "same special token is assigned conflicting roles",
                ));
                break;
            }
        }
        if let Some(id) = x.id {
            if let Some(prev) = by_id.insert(id, &x.token) {
                if prev != x.token {
                    out.push(simple(
                        r,
                        "LF-TOKENIZER-SPECIAL-TOKEN-CONFLICT",
                        ScanStatus::Warn,
                        "same special-token id maps to different token strings",
                    ));
                    break;
                }
            }
            // A role-boundary token declared with two different ids is a
            // contradiction about what that control token actually
            // resolves to, even when the literal token string agrees.
            if let Some(prev_id) = by_token_id.insert(&x.token, id) {
                if prev_id != id {
                    out.push(simple(
                        r,
                        "LF-TOKENIZER-SPECIAL-TOKEN-CONFLICT",
                        ScanStatus::Warn,
                        "same special token is assigned conflicting ids",
                    ));
                    break;
                }
            }
        }
        // The same (role, token) pair registered as special in one source
        // and not-special in another changes whether it is actually
        // enforced as a control boundary.
        if let Some(role) = &x.role {
            if let Some(prev_special) =
                by_role_token_special.insert((role.as_str(), &x.token), x.special)
            {
                if prev_special != x.special {
                    out.push(simple(
                        r,
                        "LF-TOKENIZER-SPECIAL-TOKEN-CONFLICT",
                        ScanStatus::Warn,
                        "same role-boundary token has conflicting special registration",
                    ));
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod conflict_tests {
    use super::*;
    use crate::finding_evidence::EvidenceSubject;

    fn report() -> TokenizerSecurityReport {
        TokenizerSecurityReport {
            subject: EvidenceSubject::identity(
                "test-identity",
                "application/vnd.layerfault.tokenizer+json",
            ),
            files: Vec::new(),
            special_tokens: Vec::new(),
            chat_template: None,
            unicode_controls: Vec::new(),
            special_token_collisions: Vec::new(),
            findings: Vec::new(),
            coverage: crate::coverage::Coverage::complete(0, 0),
        }
    }

    fn record(
        token: &str,
        role: &str,
        special: bool,
        id: Option<u64>,
        source: &str,
    ) -> SpecialTokenRecord {
        SpecialTokenRecord {
            token: token.to_owned(),
            role: Some(role.to_owned()),
            special,
            id,
            source: source.to_owned(),
        }
    }

    fn conflict_ids(t: &[SpecialTokenRecord]) -> Vec<LayerScanResult> {
        let mut out = Vec::new();
        conflicts(&report(), t, &mut out);
        out
    }

    #[test]
    fn consistent_trusted_declaration_yields_no_conflict() {
        let tokens = vec![
            record("</s>", "eos", true, Some(1), "tokenizer_config.json"),
            record("</s>", "eos", true, Some(1), "special_tokens_map.json"),
            record("<|im_start|>", "assistant", true, Some(0), "tokenizer.json"),
        ];
        assert!(conflict_ids(&tokens).is_empty());
    }

    #[test]
    fn same_role_token_with_two_different_ids_conflicts() {
        // "EOS role assigned two incompatible IDs": same literal token,
        // same role, but the id disagrees between sources.
        let tokens = vec![
            record("</s>", "eos", true, Some(1), "tokenizer_config.json"),
            record("</s>", "eos", true, Some(2), "special_tokens_map.json"),
        ];
        let findings = conflict_ids(&tokens);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].rule_id.as_deref(),
            Some("LF-TOKENIZER-SPECIAL-TOKEN-CONFLICT")
        );
    }

    #[test]
    fn same_id_with_two_different_token_strings_conflicts() {
        // "same control token ID represented by different incompatible
        // content": id 5 claimed by two unrelated token strings.
        let tokens = vec![
            record("</s>", "eos", true, Some(5), "tokenizer_config.json"),
            record("<pad>", "pad", true, Some(5), "special_tokens_map.json"),
        ];
        let findings = conflict_ids(&tokens);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].rule_id.as_deref(),
            Some("LF-TOKENIZER-SPECIAL-TOKEN-CONFLICT")
        );
    }

    #[test]
    fn same_role_token_with_conflicting_special_flag_conflicts() {
        // "conflicting special flag/registration that changes semantics":
        // one source claims it is enforced as a control boundary, another
        // claims it is not.
        let tokens = vec![
            record("<|im_start|>", "assistant", true, Some(0), "tokenizer.json"),
            record(
                "<|im_start|>",
                "assistant",
                false,
                Some(0),
                "tokenizer_config.json",
            ),
        ];
        let findings = conflict_ids(&tokens);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].rule_id.as_deref(),
            Some("LF-TOKENIZER-SPECIAL-TOKEN-CONFLICT")
        );
    }

    #[test]
    fn eos_token_also_serving_as_pad_is_not_a_conflict() {
        // SmolLM2's special_tokens_map.json: <|im_end|> is both eos_token
        // and pad_token. Standard HF practice, not a conflict.
        let tokens = vec![
            record(
                "<|im_end|>",
                "eos",
                true,
                Some(2),
                "special_tokens_map.json",
            ),
            record(
                "<|im_end|>",
                "pad",
                true,
                Some(2),
                "special_tokens_map.json",
            ),
        ];
        assert!(conflict_ids(&tokens).is_empty());
    }

    #[test]
    fn bos_and_unk_token_also_serving_as_pad_is_not_a_conflict() {
        let bos_pad = vec![
            record("<s>", "bos", true, Some(0), "special_tokens_map.json"),
            record("<s>", "pad", true, Some(0), "special_tokens_map.json"),
        ];
        assert!(conflict_ids(&bos_pad).is_empty());

        let unk_pad = vec![
            record("<unk>", "unk", true, Some(3), "special_tokens_map.json"),
            record("<unk>", "pad", true, Some(3), "special_tokens_map.json"),
        ];
        assert!(conflict_ids(&unk_pad).is_empty());
    }

    #[test]
    fn eos_and_bos_role_overlap_on_the_same_token_still_conflicts() {
        // The allowlist only covers known-safe pairs; eos+bos on the same
        // token is not one of them and must still be flagged.
        let tokens = vec![
            record("<|im_end|>", "eos", true, Some(2), "tokenizer_config.json"),
            record(
                "<|im_end|>",
                "bos",
                true,
                Some(2),
                "special_tokens_map.json",
            ),
        ];
        let findings = conflict_ids(&tokens);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].rule_id.as_deref(),
            Some("LF-TOKENIZER-SPECIAL-TOKEN-CONFLICT")
        );
    }
}
