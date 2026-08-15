use super::{IntelligencePack, ThreatMapping};

/// Return the exact post-detection framework mapping for a Layerfault rule.
/// Intelligence validation guarantees at most one record per rule id; this
/// function only canonicalizes list order/deduplication for deterministic
/// reporting and never performs fuzzy matching.
pub fn mapping_for_rule(pack: &IntelligencePack, rule_id: &str) -> Option<ThreatMapping> {
    let mut mapping = pack
        .threat_mappings
        .iter()
        .find(|record| record.rule_id == rule_id)?
        .clone();
    mapping.canonicalize();
    Some(mapping)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_is_exact_and_deterministic() {
        let mut pack = crate::intelligence::builtin_pack().expect("builtin intelligence");
        pack.threat_mappings.push(ThreatMapping {
            rule_id: "LF-EXACT".to_owned(),
            cwe: vec!["CWE-94".to_owned(), "CWE-94".to_owned()],
            references: vec!["https://cwe.mitre.org/data/definitions/94.html".to_owned()],
            ..ThreatMapping::default()
        });
        let found = mapping_for_rule(&pack, "LF-EXACT").expect("mapping");
        assert_eq!(found.cwe, vec!["CWE-94"]);
        assert!(mapping_for_rule(&pack, "lf-exact").is_none());
    }
}
