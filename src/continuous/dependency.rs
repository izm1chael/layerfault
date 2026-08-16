use super::{EvidenceDomain, ExecutionSnapshot, InvalidationPlan, SecurityComponent};
use std::collections::BTreeSet;

pub fn default_dependencies(domain: EvidenceDomain) -> &'static [SecurityComponent] {
    use EvidenceDomain as E;
    use SecurityComponent as C;
    match domain {
        E::StaticModel => &[C::ModelArtifact, C::Ruleset],
        E::TensorForensics => &[C::ModelArtifact, C::Ruleset],
        E::TokenizerSecurity => &[C::Tokenizer, C::ChatTemplate, C::Ruleset],
        E::AdapterSecurity => &[
            C::ModelArtifact,
            C::AdapterSet,
            C::ModelComposition,
            C::Ruleset,
        ],
        E::RuntimePosture => &[C::RuntimeBinary, C::RuntimeConfiguration, C::Ruleset],
        E::Exploitability => &[
            C::ModelArtifact,
            C::ModelComposition,
            C::RuntimeBinary,
            C::RuntimeConfiguration,
            C::Intelligence,
            C::Ruleset,
        ],
        E::AgentCapability => &[
            C::AgentConfiguration,
            C::McpServers,
            C::ToolSchemas,
            C::Ruleset,
        ],
        E::Provenance => &[
            C::ModelArtifact,
            C::ModelComposition,
            C::Provenance,
            C::Ruleset,
        ],
        E::BehaviouralAssurance => &[
            C::ModelArtifact,
            C::ModelComposition,
            C::GenerationConfig,
            C::RuntimeBinary,
            C::RuntimeConfiguration,
            C::AgentConfiguration,
            C::McpServers,
            C::ToolSchemas,
            C::SandboxProfile,
            C::TelemetryConfiguration,
            C::ProbeSuite,
            C::SamplingConfiguration,
            C::BehaviourAffectingEnvironment,
            C::PlatformEnvironment,
            C::Ruleset,
        ],
        E::SecurityPassport => &[
            C::ModelArtifact,
            C::ModelComposition,
            C::Ruleset,
            C::Intelligence,
            C::Provenance,
            C::SecurityPassport,
        ],
        E::Admission => &[
            C::ModelArtifact,
            C::ModelComposition,
            C::GenerationConfig,
            C::RuntimeBinary,
            C::RuntimeConfiguration,
            C::AgentConfiguration,
            C::McpServers,
            C::ToolSchemas,
            C::Policy,
            C::Ruleset,
            C::Intelligence,
            C::Provenance,
            C::SecurityPassport,
            C::AdmissionReceipt,
        ],
    }
}

pub fn diff(previous: &ExecutionSnapshot, current: &ExecutionSnapshot) -> InvalidationPlan {
    let mut changed = BTreeSet::new();
    for component in previous.identities.keys().chain(current.identities.keys()) {
        if previous.identities.get(component) != current.identities.get(component) {
            changed.insert(*component);
        }
    }
    let mut invalidated = BTreeSet::new();
    let mut unchanged = BTreeSet::new();
    for domain in previous.evidence.keys().chain(current.evidence.keys()) {
        let dependencies = current
            .evidence
            .get(domain)
            .or_else(|| previous.evidence.get(domain))
            .map(|record| record.dependencies.as_slice())
            .filter(|dependencies| !dependencies.is_empty())
            .unwrap_or_else(|| default_dependencies(*domain));
        if dependencies
            .iter()
            .any(|component| changed.contains(component))
        {
            invalidated.insert(*domain);
        } else {
            unchanged.insert(*domain);
        }
    }
    InvalidationPlan {
        changed_components: changed.into_iter().collect(),
        invalidated_domains: invalidated.into_iter().collect(),
        unchanged_domains: unchanged.into_iter().collect(),
    }
}

pub fn apply(snapshot: &mut ExecutionSnapshot, plan: &InvalidationPlan, reason: &str) {
    for domain in &plan.invalidated_domains {
        if let Some(record) = snapshot.evidence.get_mut(domain) {
            record.stale = true;
            record.stale_reason = Some(reason.to_owned());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::continuous::{EvidenceRecord, TrustState};
    use std::collections::BTreeMap;

    fn snapshot(runtime: &str) -> ExecutionSnapshot {
        let mut identities = BTreeMap::new();
        identities.insert(SecurityComponent::RuntimeConfiguration, runtime.into());
        let mut evidence = BTreeMap::new();
        for domain in [
            EvidenceDomain::TensorForensics,
            EvidenceDomain::RuntimePosture,
            EvidenceDomain::Exploitability,
        ] {
            evidence.insert(
                domain,
                EvidenceRecord {
                    identity: format!("{domain:?}"),
                    generated_unix: 1,
                    dependencies: Vec::new(),
                    stale: false,
                    stale_reason: None,
                },
            );
        }
        ExecutionSnapshot {
            version: 1,
            captured_unix: 1,
            state: TrustState::Approved,
            identities,
            evidence,
        }
    }

    #[test]
    fn runtime_config_drift_does_not_invalidate_tensor_forensics() {
        let before = snapshot("a");
        let after = snapshot("b");
        let plan = diff(&before, &after);
        assert!(plan
            .invalidated_domains
            .contains(&EvidenceDomain::RuntimePosture));
        assert!(plan
            .invalidated_domains
            .contains(&EvidenceDomain::Exploitability));
        assert!(!plan
            .invalidated_domains
            .contains(&EvidenceDomain::TensorForensics));
    }

    #[test]
    fn model_artifact_drift_invalidates_portable_and_admission_evidence() {
        let mut before = snapshot("runtime-a");
        let mut after = before.clone();
        before
            .identities
            .insert(SecurityComponent::ModelArtifact, "model-a".into());
        after
            .identities
            .insert(SecurityComponent::ModelArtifact, "model-b".into());
        for domain in [EvidenceDomain::SecurityPassport, EvidenceDomain::Admission] {
            before.evidence.insert(
                domain,
                EvidenceRecord {
                    identity: format!("{domain:?}"),
                    generated_unix: 1,
                    dependencies: Vec::new(),
                    stale: false,
                    stale_reason: None,
                },
            );
        }
        after.evidence = before.evidence.clone();
        let plan = diff(&before, &after);
        assert!(plan
            .invalidated_domains
            .contains(&EvidenceDomain::SecurityPassport));
        assert!(plan
            .invalidated_domains
            .contains(&EvidenceDomain::Admission));
        assert!(!plan
            .invalidated_domains
            .contains(&EvidenceDomain::RuntimePosture));
    }

    #[test]
    fn generation_config_drift_invalidates_behavioural_and_admission_not_unrelated() {
        let mut before = snapshot("runtime-a");
        let mut after = before.clone();
        before
            .identities
            .insert(SecurityComponent::GenerationConfig, "gen-a".into());
        after
            .identities
            .insert(SecurityComponent::GenerationConfig, "gen-b".into());
        for domain in [
            EvidenceDomain::BehaviouralAssurance,
            EvidenceDomain::Admission,
            EvidenceDomain::TensorForensics,
        ] {
            before.evidence.insert(
                domain,
                EvidenceRecord {
                    identity: format!("{domain:?}"),
                    generated_unix: 1,
                    dependencies: Vec::new(),
                    stale: false,
                    stale_reason: None,
                },
            );
        }
        after.evidence = before.evidence.clone();
        let plan = diff(&before, &after);
        assert!(plan
            .invalidated_domains
            .contains(&EvidenceDomain::BehaviouralAssurance));
        assert!(plan
            .invalidated_domains
            .contains(&EvidenceDomain::Admission));
        assert!(!plan
            .invalidated_domains
            .contains(&EvidenceDomain::TensorForensics));
    }

    #[test]
    fn passport_drift_invalidates_passport_and_admission_only() {
        let mut before = snapshot("runtime-a");
        let mut after = before.clone();
        before
            .identities
            .insert(SecurityComponent::SecurityPassport, "passport-a".into());
        after
            .identities
            .insert(SecurityComponent::SecurityPassport, "passport-b".into());
        before.evidence.insert(
            EvidenceDomain::SecurityPassport,
            EvidenceRecord {
                identity: "passport-a".into(),
                generated_unix: 1,
                dependencies: Vec::new(),
                stale: false,
                stale_reason: None,
            },
        );
        before.evidence.insert(
            EvidenceDomain::Admission,
            EvidenceRecord {
                identity: "receipt-a".into(),
                generated_unix: 1,
                dependencies: Vec::new(),
                stale: false,
                stale_reason: None,
            },
        );
        after.evidence = before.evidence.clone();
        let plan = diff(&before, &after);
        assert!(plan
            .invalidated_domains
            .contains(&EvidenceDomain::SecurityPassport));
        assert!(plan
            .invalidated_domains
            .contains(&EvidenceDomain::Admission));
        assert!(!plan
            .invalidated_domains
            .contains(&EvidenceDomain::TensorForensics));
    }
}
