use super::{
    new_snapshot, record_evidence, set_identity, EvidenceDomain, ExecutionSnapshot,
    SecurityComponent, TrustState,
};
use anyhow::{anyhow, bail, Result};
use std::path::{Path, PathBuf};

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

    Ok(snapshot)
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
