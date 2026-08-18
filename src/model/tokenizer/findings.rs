use super::{
    SpecialTokenCollision, SpecialTokenRecord, TokenizerSecurityReport, UnicodeControlRecord,
};
use crate::finding_evidence::{EvidenceKind, FindingBuilder, FindingEvidence};
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use std::collections::BTreeMap;
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
            if prev != &x.role {
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
}
