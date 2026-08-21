use super::{
    new_snapshot, record_evidence, set_identity, EvidenceDomain, ExecutionSnapshot,
    SecurityComponent, TrustState,
};
use anyhow::{anyhow, bail, Context, Result};
use std::path::{Path, PathBuf};

const MAX_BEHAVIOURAL_REPORT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ObservationInputs {
    pub state: TrustState,
    pub model_artifact: Option<PathBuf>,
    pub composition_manifest: Option<PathBuf>,
    pub agent_config: Option<PathBuf>,
    pub agent_name: String,
    pub runtime_binary: Option<PathBuf>,
    pub runtime_config: Option<PathBuf>,
    pub policy_file: Option<PathBuf>,
    pub intelligence_pack: Option<PathBuf>,
    pub provenance_chain: Option<PathBuf>,
    pub passport: Option<PathBuf>,
    pub receipt: Option<PathBuf>,
    /// A record of an actual behavioural run (`crate::behaviour::BehaviourReport`).
    /// `EvidenceDomain::BehaviouralAssurance` is populated only when this is
    /// present, loads, and binds to the execution context this observation
    /// otherwise records — never merely because that context can be
    /// fingerprinted. See `bind_behavioural_report`.
    pub behavioural_report: Option<PathBuf>,
    /// Operator-supplied description of behaviour-affecting environment
    /// variables/configuration for this run (`SecurityComponent::BehaviourAffectingEnvironment`).
    pub behaviour_affecting_environment: Option<PathBuf>,
    /// Operator-supplied description of the platform (OS/kernel/arch) this
    /// run executed on (`SecurityComponent::PlatformEnvironment`).
    pub platform_environment: Option<PathBuf>,
}

impl Default for ObservationInputs {
    fn default() -> Self {
        Self {
            state: TrustState::Unknown,
            model_artifact: None,
            composition_manifest: None,
            agent_config: None,
            agent_name: "agent".to_owned(),
            runtime_binary: None,
            runtime_config: None,
            policy_file: None,
            intelligence_pack: None,
            provenance_chain: None,
            passport: None,
            receipt: None,
            behavioural_report: None,
            behaviour_affecting_environment: None,
            platform_environment: None,
        }
    }
}

pub fn observe(inputs: &ObservationInputs) -> Result<ExecutionSnapshot> {
    let mut snapshot = new_snapshot(inputs.state);
    set_identity(
        &mut snapshot,
        SecurityComponent::Ruleset,
        crate::explain::ruleset_sha256(),
    );

    if let Some(path) = inputs.model_artifact.as_deref() {
        set_identity(
            &mut snapshot,
            SecurityComponent::ModelArtifact,
            file_identity(path)?,
        );
    }

    let composition = inputs
        .composition_manifest
        .as_deref()
        .map(crate::model::composition::resolve_manifest)
        .transpose()?;
    let composition_identity = composition
        .as_ref()
        .map(crate::model::composition::identity)
        .transpose()?;
    if let (Some(composition), Some(identity)) = (&composition, &composition_identity) {
        set_identity(
            &mut snapshot,
            SecurityComponent::ModelComposition,
            identity.value.clone(),
        );
        if inputs.model_artifact.is_none() {
            set_identity(
                &mut snapshot,
                SecurityComponent::ModelArtifact,
                composition.base_model.identity.clone(),
            );
        }
        set_identity(
            &mut snapshot,
            SecurityComponent::AdapterSet,
            crate::model::composition::adapter_set_identity(composition)?,
        );
        set_optional_component(
            &mut snapshot,
            SecurityComponent::Tokenizer,
            composition
                .tokenizer
                .as_ref()
                .map(|value| value.identity.as_str()),
        );
        set_optional_component(
            &mut snapshot,
            SecurityComponent::ChatTemplate,
            composition
                .chat_template
                .as_ref()
                .map(|value| value.identity.as_str()),
        );
        set_optional_component(
            &mut snapshot,
            SecurityComponent::GenerationConfig,
            composition
                .generation_config
                .as_ref()
                .map(|value| value.identity.as_str()),
        );
    }

    if let Some(config) = inputs.agent_config.as_deref() {
        set_identity(
            &mut snapshot,
            SecurityComponent::AgentConfiguration,
            file_identity(config)?,
        );
        let assessment = crate::agent_security::inspect_agent_config(
            &inputs.agent_name,
            config,
            composition_identity
                .as_ref()
                .map(|value| value.value.as_str()),
        )?;
        set_identity(
            &mut snapshot,
            SecurityComponent::McpServers,
            crate::agent_security::server_set_identity(&assessment.graph.servers)?,
        );
        set_identity(
            &mut snapshot,
            SecurityComponent::ToolSchemas,
            crate::agent_security::tool_schema_identity(&assessment.graph.servers)?,
        );
        record_evidence(
            &mut snapshot,
            EvidenceDomain::AgentCapability,
            assessment.graph.graph_identity,
            None,
        );
    }

    set_file_component(
        &mut snapshot,
        SecurityComponent::RuntimeBinary,
        inputs.runtime_binary.as_deref(),
    )?;
    set_file_component(
        &mut snapshot,
        SecurityComponent::RuntimeConfiguration,
        inputs.runtime_config.as_deref(),
    )?;
    set_file_component(
        &mut snapshot,
        SecurityComponent::Policy,
        inputs.policy_file.as_deref(),
    )?;
    set_file_component(
        &mut snapshot,
        SecurityComponent::Provenance,
        inputs.provenance_chain.as_deref(),
    )?;
    set_file_component(
        &mut snapshot,
        SecurityComponent::BehaviourAffectingEnvironment,
        inputs.behaviour_affecting_environment.as_deref(),
    )?;
    set_file_component(
        &mut snapshot,
        SecurityComponent::PlatformEnvironment,
        inputs.platform_environment.as_deref(),
    )?;

    if let Some(path) = inputs.intelligence_pack.as_deref() {
        let (pack, _) = crate::intelligence::load_pack(path)?;
        set_identity(
            &mut snapshot,
            SecurityComponent::Intelligence,
            format!(
                "{}:epoch:{}",
                file_identity(path)?,
                crate::intelligence::epoch(&pack)
            ),
        );
    }

    if let Some(path) = inputs.passport.as_deref() {
        let passport = crate::inventory::load_portable_passport(path)?;
        let passport_identity = crate::inventory::passport_sha256(&passport)?;
        set_identity(
            &mut snapshot,
            SecurityComponent::SecurityPassport,
            passport_identity.clone(),
        );
        record_evidence(
            &mut snapshot,
            EvidenceDomain::SecurityPassport,
            passport_identity,
            None,
        );
    }

    if let Some(path) = inputs.receipt.as_deref() {
        let _ = crate::evidence::load(path)?;
        let receipt_identity = file_identity(path)?;
        set_identity(
            &mut snapshot,
            SecurityComponent::AdmissionReceipt,
            receipt_identity.clone(),
        );
        record_evidence(
            &mut snapshot,
            EvidenceDomain::Admission,
            receipt_identity,
            None,
        );
    }

    if let Some(path) = inputs.behavioural_report.as_deref() {
        bind_behavioural_report(&mut snapshot, path)?;
    }

    Ok(snapshot)
}

/// Load a behavioural report and, only if it binds to the execution context
/// already captured in `snapshot`, record `EvidenceDomain::BehaviouralAssurance`.
///
/// `observe()` inspects identities; it does not run a model. Recording
/// behavioural evidence merely because an execution environment can be
/// fingerprinted would manufacture an evidence record for analysis that
/// never happened. A supplied report is therefore treated as a claim to be
/// checked, not as evidence on its own: this function sets the atomic
/// identities the report actually demonstrates (`ProbeSuite`,
/// `SamplingConfiguration`, `SandboxProfile`), then requires the report's
/// own runtime-binary identity to match the `RuntimeBinary` component
/// already observed in this snapshot before it will record evidence.
///
/// Binding is checked on `RuntimeBinary` because it is the one dimension
/// both sides express in the same identity scheme (`sha256:<hex>` of the
/// executable). `BehaviourReport.model_identity` is recorded by the
/// behaviour subsystem via a different canonical-identity scheme
/// (`crate::modelmeta`) than the plain file hash `observe()` uses for
/// `SecurityComponent::ModelArtifact`, so a direct string comparison there
/// would reject genuinely matching contexts as often as it caught mismatched
/// ones. Aligning those two schemes is out of scope here; until it happens,
/// this is a real but partial binding check, not a complete one — a
/// mismatched or unverifiable binding fails loudly rather than silently
/// producing no evidence, so an operator who explicitly supplied a report
/// is not left believing it was recorded when it was not.
fn bind_behavioural_report(snapshot: &mut ExecutionSnapshot, path: &Path) -> Result<()> {
    let report = load_behavioural_report(path)?;

    set_identity(
        snapshot,
        SecurityComponent::ProbeSuite,
        format!("{}:{}", report.probe_suite_id, report.probe_suite_version),
    );
    set_identity(
        snapshot,
        SecurityComponent::SamplingConfiguration,
        format!("seed:{}", report.seed),
    );
    set_identity(
        snapshot,
        SecurityComponent::SandboxProfile,
        sandbox_capabilities_identity(&report.runtime.sandbox)?,
    );

    let observed_runtime_binary = snapshot
        .identities
        .get(&SecurityComponent::RuntimeBinary)
        .cloned();
    let bound =
        observed_runtime_binary.as_deref() == Some(report.runtime.executable_sha256.as_str());
    if !bound {
        bail!(
            "behavioural report '{}' does not bind to this execution context: its runtime binary identity ('{}') does not match the observed RuntimeBinary component ({}); behavioural evidence was not recorded",
            path.display(),
            report.runtime.executable_sha256,
            observed_runtime_binary
                .as_deref()
                .map(|value| format!("'{value}'"))
                .unwrap_or_else(|| "none observed".to_owned())
        );
    }

    record_evidence(
        snapshot,
        EvidenceDomain::BehaviouralAssurance,
        behavioural_outcome_identity(&report)?,
        None,
    );
    Ok(())
}

fn load_behavioural_report(path: &Path) -> Result<crate::behaviour::BehaviourReport> {
    let file = crate::safeio::open_readonly_nofollow(path)?;
    let bytes = crate::safeio::read_all_from_file(&file, MAX_BEHAVIOURAL_REPORT_BYTES)?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("behavioural report '{}' is not valid JSON", path.display()))
}

fn sandbox_capabilities_identity(
    capabilities: &crate::behaviour::sandbox::SandboxCapabilities,
) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"layerfault:sandbox-profile:v1\0");
    hasher.update(serde_json::to_vec(capabilities)?);
    Ok(format!(
        "lfsandbox:v1:sha256:{}",
        hex::encode(hasher.finalize())
    ))
}

/// Identity of what the behavioural run actually observed: its executions,
/// findings and derived state. A report that "ran" but recorded nothing
/// still produces a different identity from one that recorded real
/// evidence, so a change in this identity is meaningful for invalidation.
fn behavioural_outcome_identity(report: &crate::behaviour::BehaviourReport) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"layerfault:behavioural-outcome:v1\0");
    hasher.update(serde_json::to_vec(report)?);
    Ok(format!(
        "lfbehaviouraloutcome:v1:sha256:{}",
        hex::encode(hasher.finalize())
    ))
}

fn set_optional_component(
    snapshot: &mut ExecutionSnapshot,
    component: SecurityComponent,
    identity: Option<&str>,
) {
    if let Some(identity) = identity {
        set_identity(snapshot, component, identity.to_owned());
    }
}

fn set_file_component(
    snapshot: &mut ExecutionSnapshot,
    component: SecurityComponent,
    path: Option<&Path>,
) -> Result<()> {
    if let Some(path) = path {
        set_identity(snapshot, component, file_identity(path)?);
    }
    Ok(())
}

fn file_identity(path: &Path) -> Result<String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| anyhow!("unable to inspect '{}': {error}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("identity input '{}' may not be a symlink", path.display());
    }
    if !metadata.is_file() {
        bail!("identity input '{}' must be a regular file", path.display());
    }
    crate::safeio::sha256_path(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::behaviour::sandbox::SandboxCapabilities;
    use crate::behaviour::{
        BehaviourLimits, BehaviourReport, DynamicObservationSummary, RuntimeIdentity,
    };
    use crate::transformation::BehaviourState;
    use std::io::Write;

    fn write_file(bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().expect("temp file");
        file.write_all(bytes).expect("write bytes");
        file
    }

    fn report_with_runtime_hash(executable_sha256: &str) -> BehaviourReport {
        BehaviourReport {
            schema_version: "1.1".to_owned(),
            model_identity: "sha256:test".to_owned(),
            model_path: "test".to_owned(),
            runtime: RuntimeIdentity {
                backend: "test".to_owned(),
                executable: "/runtime".to_owned(),
                executable_sha256: executable_sha256.to_owned(),
                version: None,
                sandbox: SandboxCapabilities::default(),
                closure: None,
            },
            probe_suite_id: "test-suite".to_owned(),
            probe_suite_version: 3,
            seed: 42,
            limits: BehaviourLimits::for_profile("quick").expect("profile"),
            executions: Vec::new(),
            dynamic_observations: DynamicObservationSummary::default(),
            state: BehaviourState::NoSuspiciousObserved,
            reason_code: None,
            detail: None,
            estimated_memory_bytes: None,
            available_budget_bytes: None,
            safe_memory_budget_bytes: None,
            findings: Vec::new(),
            boundary: "test".to_owned(),
        }
    }

    fn base_inputs() -> ObservationInputs {
        ObservationInputs {
            state: TrustState::Unknown,
            ..Default::default()
        }
    }

    #[test]
    fn no_report_means_no_behavioural_evidence() -> Result<()> {
        let snapshot = observe(&base_inputs())?;
        assert!(!snapshot
            .evidence
            .contains_key(&EvidenceDomain::BehaviouralAssurance));
        Ok(())
    }

    #[test]
    fn matching_runtime_binary_binds_report_and_records_evidence() -> Result<()> {
        let runtime_binary = write_file(b"fake-runtime-binary");
        let runtime_hash = crate::safeio::sha256_path(runtime_binary.path())?;
        let report_file = write_file(&serde_json::to_vec(&report_with_runtime_hash(
            &runtime_hash,
        ))?);

        let mut inputs = base_inputs();
        inputs.runtime_binary = Some(runtime_binary.path().to_path_buf());
        inputs.behavioural_report = Some(report_file.path().to_path_buf());

        let snapshot = observe(&inputs)?;
        assert!(snapshot
            .evidence
            .contains_key(&EvidenceDomain::BehaviouralAssurance));
        assert_eq!(
            snapshot
                .identities
                .get(&SecurityComponent::ProbeSuite)
                .map(String::as_str),
            Some("test-suite:3")
        );
        assert_eq!(
            snapshot
                .identities
                .get(&SecurityComponent::SamplingConfiguration)
                .map(String::as_str),
            Some("seed:42")
        );
        assert!(snapshot
            .identities
            .contains_key(&SecurityComponent::SandboxProfile));
        Ok(())
    }

    #[test]
    fn mismatched_runtime_binary_report_fails_loudly() -> Result<()> {
        let runtime_binary = write_file(b"fake-runtime-binary");
        let report_file = write_file(&serde_json::to_vec(&report_with_runtime_hash(
            "sha256:wrong",
        ))?);

        let mut inputs = base_inputs();
        inputs.runtime_binary = Some(runtime_binary.path().to_path_buf());
        inputs.behavioural_report = Some(report_file.path().to_path_buf());

        let error = observe(&inputs).expect_err("mismatched binding must fail");
        assert!(error.to_string().contains("does not bind"));
        Ok(())
    }

    #[test]
    fn report_without_observed_runtime_binary_fails_loudly() -> Result<()> {
        let report_file = write_file(&serde_json::to_vec(&report_with_runtime_hash(
            "sha256:anything",
        ))?);

        let mut inputs = base_inputs();
        inputs.behavioural_report = Some(report_file.path().to_path_buf());

        let error = observe(&inputs).expect_err("unverifiable binding must fail");
        assert!(error.to_string().contains("does not bind"));
        Ok(())
    }
}
