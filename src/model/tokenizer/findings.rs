use super::{SpecialTokenRecord, TokenizerSecurityReport, UnicodeControlRecord};
use crate::finding_evidence::{EvidenceKind, FindingBuilder, FindingEvidence};
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use std::collections::BTreeMap;
pub(crate) fn build(report: &TokenizerSecurityReport) -> Vec<LayerScanResult> {
    let mut out = Vec::new();
    for c in &report.unicode_controls {
        out.push(control(report, c));
    }
    conflicts(report, &report.special_tokens, &mut out);
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
fn conflicts(
    r: &TokenizerSecurityReport,
    t: &[SpecialTokenRecord],
    out: &mut Vec<LayerScanResult>,
) {
    let mut by_token: BTreeMap<&str, &Option<String>> = BTreeMap::new();
    let mut by_id: BTreeMap<u64, &str> = BTreeMap::new();
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
        }
    }
}
