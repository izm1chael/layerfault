use crate::intelligence::{mapping_for_rule, IntelligencePack, ThreatMapping};
use crate::scanner::LayerScanResult;

#[derive(serde::Serialize)]
pub(super) struct MappedFinding<'a> {
    #[serde(flatten)]
    pub finding: &'a LayerScanResult,
    #[serde(rename = "framework_mappings", skip_serializing_if = "Option::is_none")]
    pub mapping: Option<ThreatMapping>,
}

#[allow(dead_code)]
pub(super) fn mapped_finding<'a>(
    finding: &'a LayerScanResult,
    pack: &IntelligencePack,
) -> MappedFinding<'a> {
    MappedFinding {
        mapping: mapping_for_rule(pack, &crate::policy::rule_id(finding)),
        finding,
    }
}

#[allow(dead_code)]
pub(super) fn mapped_findings<'a>(
    findings: &'a [LayerScanResult],
    pack: &IntelligencePack,
) -> Vec<MappedFinding<'a>> {
    findings
        .iter()
        .map(|finding| mapped_finding(finding, pack))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn enrichment_does_not_mutate_core_finding() {
        let finding = LayerScanResult {
            rule_id: Some("LF-NO-MAPPING".into()),
            finding_id: Some("finding-stable".into()),
            ..Default::default()
        };
        let before = serde_json::to_value(&finding).unwrap();
        let pack = crate::intelligence::builtin_pack().unwrap();
        let mapped = serde_json::to_value(mapped_finding(&finding, &pack)).unwrap();
        assert_eq!(before, serde_json::to_value(&finding).unwrap());
        assert_eq!(finding.finding_id.as_deref(), Some("finding-stable"));
        assert!(mapped.get("framework_mappings").is_none());
    }
}
