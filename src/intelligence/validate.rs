use super::{IntelligencePack, ThreatMapping};
use anyhow::{anyhow, bail, Result};
use std::collections::BTreeSet;

pub const MAX_PACK_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_RECORDS_PER_SECTION: usize = 100_000;
pub const MAX_STRING_BYTES: usize = 16 * 1024;
pub const MAX_MAPPINGS_PER_RECORD: usize = 256;

fn bounded(label: &str, value: &str) -> Result<()> {
    if value.len() > MAX_STRING_BYTES {
        bail!("{label} exceeds {MAX_STRING_BYTES} bytes");
    }
    Ok(())
}

fn https_reference(label: &str, value: &str) -> Result<()> {
    bounded(label, value)?;
    if value.starts_with("file:") {
        bail!("{label} must not use file: references");
    }
    if !value.starts_with("https://") {
        bail!("{label} must be an HTTPS URL");
    }
    Ok(())
}

fn insert_unique(ids: &mut BTreeSet<String>, section: &str, id: &str) -> Result<()> {
    if id.trim().is_empty() {
        bail!("{section} contains an empty id");
    }
    bounded("record id", id)?;
    if !ids.insert(id.to_ascii_lowercase()) {
        bail!("{section} contains duplicate id '{id}'");
    }
    Ok(())
}

fn validate_mapping(mapping: &ThreatMapping) -> Result<()> {
    if mapping.rule_id.trim().is_empty() {
        bail!("threat mapping contains an empty rule_id");
    }
    bounded("threat mapping rule_id", &mapping.rule_id)?;
    for (name, values) in [
        ("cwe", &mapping.cwe),
        ("cve", &mapping.cve),
        ("ghsa", &mapping.ghsa),
        ("mitre_atlas", &mapping.mitre_atlas),
        ("owasp_genai", &mapping.owasp_genai),
        ("nist", &mapping.nist),
    ] {
        if values.len() > MAX_MAPPINGS_PER_RECORD {
            bail!("threat mapping {name} list exceeds {MAX_MAPPINGS_PER_RECORD} entries");
        }
        for value in values {
            bounded("threat mapping value", value)?;
        }
    }
    for value in &mapping.cwe {
        if !valid_cwe(value) {
            bail!("invalid CWE identifier '{value}'");
        }
    }
    for value in &mapping.cve {
        if !valid_cve(value) {
            bail!("invalid CVE identifier '{value}'");
        }
    }
    for value in &mapping.ghsa {
        if !valid_ghsa(value) {
            bail!("invalid GHSA identifier '{value}'");
        }
    }
    for reference in &mapping.references {
        https_reference("threat mapping reference", reference)?;
    }
    if (!mapping.owasp_genai.is_empty() || !mapping.nist.is_empty())
        && mapping.references.is_empty()
    {
        bail!("OWASP/NIST threat mappings require at least one HTTPS reference");
    }
    Ok(())
}

fn valid_cwe(value: &str) -> bool {
    value
        .strip_prefix("CWE-")
        .is_some_and(|tail| !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit()))
}
fn valid_cve(value: &str) -> bool {
    let Some(tail) = value.strip_prefix("CVE-") else {
        return false;
    };
    let Some((year, number)) = tail.split_once('-') else {
        return false;
    };
    year.len() == 4
        && year.bytes().all(|b| b.is_ascii_digit())
        && !number.is_empty()
        && number.bytes().all(|b| b.is_ascii_digit())
}
fn valid_ghsa(value: &str) -> bool {
    let Some(tail) = value.strip_prefix("GHSA-") else {
        return false;
    };
    let parts = tail.split('-').collect::<Vec<_>>();
    parts.len() == 3
        && parts.iter().all(|p| {
            p.len() == 4
                && p.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        })
}

pub fn validate(pack: &IntelligencePack) -> Result<()> {
    if pack.version != 1 {
        bail!("unsupported intelligence pack version {}", pack.version);
    }
    if pack.sequence == 0 {
        bail!("intelligence sequence must be greater than zero");
    }
    if pack.generated_unix == 0 {
        bail!("intelligence generated_unix must be greater than zero");
    }
    if pack
        .expires_unix
        .is_some_and(|expires| expires <= pack.generated_unix)
    {
        bail!("intelligence expiry must be later than generated_unix");
    }

    for (name, len) in [
        ("runtime_advisories", pack.runtime_advisories.len()),
        ("pickle_gadgets", pack.pickle_gadgets.len()),
        ("declarative_edges", pack.declarative_edges.len()),
        ("known_identities", pack.known_identities.len()),
        ("threat_mappings", pack.threat_mappings.len()),
    ] {
        if len > MAX_RECORDS_PER_SECTION {
            bail!("{name} exceeds {MAX_RECORDS_PER_SECTION} records");
        }
    }

    let mut ids = BTreeSet::new();
    for advisory in &pack.runtime_advisories {
        insert_unique(&mut ids, "runtime_advisories", &advisory.id)?;
        bounded("runtime advisory runtime", &advisory.runtime)?;
        bounded("runtime advisory title", &advisory.title)?;
        bounded("runtime advisory matcher scheme", &advisory.matcher.scheme)?;
        bounded("runtime advisory matcher fixed", &advisory.matcher.fixed)?;
        https_reference("runtime advisory reference", &advisory.reference)?;
    }

    ids.clear();
    for gadget in &pack.pickle_gadgets {
        insert_unique(&mut ids, "pickle_gadgets", &gadget.id)?;
        bounded("pickle gadget module", &gadget.module)?;
        bounded("pickle gadget callable", &gadget.callable)?;
        https_reference("pickle gadget reference", &gadget.reference)?;
    }

    ids.clear();
    for edge in &pack.declarative_edges {
        insert_unique(&mut ids, "declarative_edges", &edge.id)?;
        bounded("declarative framework", &edge.framework)?;
        bounded("declarative source_path", &edge.source_path)?;
        bounded("declarative field_path", &edge.field_path)?;
        if edge.source_path.split('/').any(|part| part == "..")
            || edge.field_path.split('.').any(|part| part == "..")
            || edge.source_path.contains("..")
            || edge.field_path.contains("..")
        {
            bail!("declarative path must not contain '..'");
        }
        for prefix in &edge.allowed_prefixes {
            bounded("declarative allowed prefix", prefix)?;
        }
        if let Some(runtime) = &edge.affected_runtime {
            bounded("declarative affected runtime", runtime)?;
        }
        https_reference("declarative edge reference", &edge.reference)?;
    }

    ids.clear();
    for identity in &pack.known_identities {
        insert_unique(&mut ids, "known_identities", &identity.id)?;
        if identity.value.trim().is_empty() {
            bail!("known identity '{}' has an empty value", identity.id);
        }
        for (label, value) in [
            ("known identity kind", Some(identity.identity_kind.as_str())),
            ("known identity value", Some(identity.value.as_str())),
            ("known identity subject", identity.subject.as_deref()),
            ("known identity parent", identity.parent.as_deref()),
        ] {
            if let Some(value) = value {
                bounded(label, value)?;
            }
        }
        if let Some(reference) = identity.reference.as_deref() {
            https_reference("known identity reference", reference)?;
        }
    }

    let mut rules = BTreeSet::new();
    for mapping in &pack.threat_mappings {
        validate_mapping(mapping)?;
        if !rules.insert(mapping.rule_id.clone()) {
            return Err(anyhow!(
                "duplicate threat mapping rule_id '{}'",
                mapping.rule_id
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod mapping_validation_tests {
    use super::*;
    #[test]
    fn rejects_invalid_cve_mapping() {
        let mut pack = crate::intelligence::builtin_pack().unwrap();
        pack.threat_mappings
            .push(crate::intelligence::ThreatMapping {
                rule_id: "LF-BAD-CVE".into(),
                cve: vec!["CVE-not-valid".into()],
                references: vec!["https://example.invalid/security".into()],
                ..Default::default()
            });
        assert!(validate(&pack).is_err());
    }
    #[test]
    fn rejects_duplicate_mapping_rule() {
        let mut pack = crate::intelligence::builtin_pack().unwrap();
        let mapping = crate::intelligence::ThreatMapping {
            rule_id: "LF-DUPLICATE".into(),
            ..Default::default()
        };
        pack.threat_mappings.extend([mapping.clone(), mapping]);
        assert!(validate(&pack).is_err());
    }
}
