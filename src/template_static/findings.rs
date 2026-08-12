//! Converts template analysis results into structured Layerfault scan findings and evidence.

use crate::finding_evidence::{
    ensure_finding_identity, EvidenceKind, EvidenceLocation, EvidenceSubject, FindingEvidence,
};
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use crate::template_static::analyzer::{TemplateAnalysisResult, TemplateFindingRule};

pub fn build_layer_scan_result(
    analysis: TemplateAnalysisResult,
    layer_digest: &str,
    media_type: &str,
    duration_ms: u64,
) -> LayerScanResult {
    let mut result = LayerScanResult {
        layer_digest: layer_digest.to_owned(),
        media_type: media_type.to_owned(),
        check_type: CheckType::HeuristicSignature,
        status: ScanStatus::Pass,
        finding_class: FindingClass::ContentIndicator,
        confidence: Confidence::High,
        detail: None,
        matches: Vec::new(),
        duration_ms,
        rule_id: None,
        subject: None,
        evidence: Vec::new(),
        evidence_state: None,
        evidence_reason: None,
        finding_id: None,
    };

    let subject = EvidenceSubject::identity(layer_digest, media_type)
        .with_sha256(Some(layer_digest.to_owned()));
    result.subject = Some(subject.clone());

    if analysis.findings.is_empty() {
        return result;
    }

    let primary = analysis
        .findings
        .iter()
        .find(|f| f.rule == TemplateFindingRule::Ssti)
        .or_else(|| {
            analysis
                .findings
                .iter()
                .find(|f| f.rule == TemplateFindingRule::DynamicInclude)
        })
        .unwrap_or(&analysis.findings[0]);

    match primary.rule {
        TemplateFindingRule::Ssti => {
            result.status = ScanStatus::Fail;
            result.rule_id = Some("LF-TEMPLATE-SSTI".to_owned());
        }
        TemplateFindingRule::Introspection => {
            result.status = ScanStatus::Warn;
            result.rule_id = Some("LF-TEMPLATE-INTROSPECTION".to_owned());
        }
        TemplateFindingRule::DynamicInclude => {
            result.status = ScanStatus::Warn;
            result.rule_id = Some("LF-TEMPLATE-DYNAMIC-INCLUDE".to_owned());
        }
    }

    let rule_id = result.rule_id.clone().unwrap_or_default();
    result.matches.push(format!(
        "[{}] {}: '{}'",
        rule_id, primary.detail, primary.excerpt
    ));

    let mut detail_msg = primary.detail.clone();
    if analysis.metrics.incomplete_coverage {
        detail_msg.push_str(" [incomplete semantic coverage: fallback text scanner active]");
    }
    result.detail = Some(detail_msg);

    for finding in &analysis.findings {
        let location = EvidenceLocation::ByteRange {
            offset: finding.span.offset,
            length: finding.span.length.max(1),
        };
        let desc = format!("{} matched in template content", finding.rule.rule_id());
        let ev = FindingEvidence::new(EvidenceKind::SourceExcerpt, subject.clone(), &desc)
            .at(location)
            .excerpt(&finding.excerpt);

        result.evidence.push(ev);
    }

    ensure_finding_identity(&mut result, &rule_id);
    result
}
