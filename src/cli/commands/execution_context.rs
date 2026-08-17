use anyhow::{anyhow, Result};
use layerfault::assurance::AnalysisCompleteness;
use layerfault::scanner::LayerScanResult;
use std::path::Path;

#[derive(Debug, Default)]
pub(crate) struct ObservedExecutionContext {
    pub(crate) composition_identity: Option<String>,
    pub(crate) runtime_configuration_identity: Option<String>,
    pub(crate) agent_identity: Option<String>,
    pub(crate) capability_graph_identity: Option<String>,
    pub(crate) mcp_server_identities: Vec<String>,
    pub(crate) passport_sha256: Option<String>,
    pub(crate) composition_summary: Option<layerfault::inventory::PassportCompositionSummary>,
    pub(crate) agent_summary: Option<layerfault::inventory::PassportAgentSummary>,
    pub(crate) provenance_summary: Option<layerfault::inventory::PassportProvenanceSummary>,
    pub(crate) composition_complete: Option<bool>,
    pub(crate) adapters_independently_scanned: Option<bool>,
    pub(crate) unsigned_adapter_count: u32,
    pub(crate) adapter_identities: Vec<String>,
    pub(crate) provenance_verified: Option<bool>,
    pub(crate) builder_identities: Vec<String>,
    pub(crate) derived_model: Option<bool>,
    pub(crate) agent_capabilities_complete: Option<bool>,
    pub(crate) dangerous_capability_chains:
        Vec<layerfault::agent_security::DangerousCapabilityChain>,
    pub(crate) dangerous_capability_chain_ids: Vec<String>,
    pub(crate) findings: Vec<LayerScanResult>,
}

pub(crate) struct ObservationRequest<'a> {
    pub(crate) composition_manifest: Option<&'a Path>,
    pub(crate) runtime_config: Option<&'a Path>,
    pub(crate) agent_config: Option<&'a Path>,
    pub(crate) agent_name: &'a str,
    pub(crate) provenance_chain: Option<&'a Path>,
    pub(crate) passport: Option<&'a Path>,
    pub(crate) trust_store: &'a layerfault::trust::TrustStore,
}

impl ObservedExecutionContext {
    pub(crate) fn binding(&self) -> layerfault::admission::ExecutionContextBinding<'_> {
        layerfault::admission::ExecutionContextBinding {
            composition_identity: self.composition_identity.as_deref(),
            runtime_configuration_identity: self.runtime_configuration_identity.as_deref(),
            agent_identity: self.agent_identity.as_deref(),
            capability_graph_identity: self.capability_graph_identity.as_deref(),
            mcp_server_identities: self
                .mcp_server_identities
                .iter()
                .map(String::as_str)
                .collect(),
        }
    }

    pub(crate) fn expectation(&self) -> layerfault::admission::ExecutionContextExpectation<'_> {
        layerfault::admission::ExecutionContextExpectation {
            composition_identity: self.composition_identity.as_deref(),
            runtime_configuration_identity: self.runtime_configuration_identity.as_deref(),
            agent_identity: self.agent_identity.as_deref(),
            capability_graph_identity: self.capability_graph_identity.as_deref(),
            mcp_server_identities: self
                .mcp_server_identities
                .iter()
                .map(String::as_str)
                .collect(),
        }
    }

    pub(crate) fn apply_policy_context(&self, context: &mut layerfault::policy::PolicyContext) {
        context.composition_complete = self.composition_complete;
        context.adapters_independently_scanned = self.adapters_independently_scanned;
        context.unsigned_adapter_count = self.unsigned_adapter_count;
        context.provenance_verified = self.provenance_verified;
        context.derived_model = self.derived_model;
        if self.provenance_verified == Some(true) {
            context.lineage_consistency =
                Some(layerfault::model::lineage::LineageConsistency::Consistent);
        }
        context.agent_capabilities_complete = self.agent_capabilities_complete;
        context.dangerous_capability_chains = self.dangerous_capability_chains.clone();
        context.dangerous_capability_chain_ids = self.dangerous_capability_chain_ids.clone();
    }
}

pub(crate) fn observe(request: ObservationRequest<'_>) -> Result<ObservedExecutionContext> {
    let mut observed = ObservedExecutionContext::default();
    let mut composition = None;
    let mut manifest_root = None;

    if let Some(path) = request.composition_manifest {
        let manifest = layerfault::model::composition::load_manifest(path)?;
        let resolved = layerfault::model::composition::resolve_manifest(path)?;
        let assessment = layerfault::model::composition::assess(resolved)?;
        observed.composition_identity = Some(assessment.identity.value.clone());
        observed.composition_summary =
            Some(layerfault::inventory::PassportCompositionSummary::from_assessment(&assessment));
        observed.composition_complete =
            Some(assessment.identity.completeness == AnalysisCompleteness::Complete);
        observed.unsigned_adapter_count =
            u32::try_from(assessment.composition.adapters.len()).unwrap_or(u32::MAX);
        for adapter in &assessment.composition.adapters {
            observed.adapter_identities.push(adapter.identity.clone());
            if let Some(sha256) = &adapter.sha256 {
                observed.adapter_identities.push(sha256.clone());
            }
        }
        observed.adapter_identities.sort();
        observed.adapter_identities.dedup();
        observed.derived_model = Some(!assessment.composition.adapters.is_empty());
        observed.findings.extend(assessment.findings.clone());
        manifest_root = Some(
            path.parent()
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf(),
        );
        composition = Some((manifest, assessment));
    }

    if let Some((manifest, assessment)) = &composition {
        let subject = layerfault::finding_evidence::EvidenceSubject::identity(
            &assessment.identity.value,
            "application/vnd.layerfault.model-composition+json",
        );
        let root = manifest_root.as_deref().unwrap_or_else(|| Path::new("."));
        let expected_base = manifest
            .base_model
            .identity
            .as_deref()
            .unwrap_or(manifest.base_model.name.as_str());
        let mut all_scanned = true;
        for adapter_entry in &manifest.adapters {
            let Some(relative) = adapter_entry.path.as_deref() else {
                all_scanned = false;
                observed.findings.push(
                    layerfault::model::composition::adapter_analysis_incomplete(
                        &adapter_entry.name,
                        "adapter manifest entry has no local path for independent analysis",
                        &subject,
                    ),
                );
                continue;
            };
            let safe_relative = match layerfault::safeio::validated_relative_path(relative, true) {
                Ok(value) => value,
                Err(error) => {
                    all_scanned = false;
                    observed.findings.push(
                        layerfault::model::composition::adapter_analysis_incomplete(
                            &adapter_entry.name,
                            &error.to_string(),
                            &subject,
                        ),
                    );
                    continue;
                }
            };
            let adapter_path = root.join(safe_relative);
            match layerfault::model::composition::inspect_adapter(
                &adapter_path,
                Some(expected_base),
            ) {
                Ok(adapter) => {
                    observed
                        .findings
                        .extend(layerfault::model::composition::adapter_findings(
                            &adapter, &subject,
                        ))
                }
                Err(error) => {
                    all_scanned = false;
                    observed.findings.push(
                        layerfault::model::composition::adapter_analysis_incomplete(
                            &adapter_entry.name,
                            &error.to_string(),
                            &subject,
                        ),
                    );
                }
            }
        }
        observed.adapters_independently_scanned = Some(all_scanned);
    }

    if let Some(path) = request.runtime_config {
        observed.runtime_configuration_identity = Some(file_identity(path)?);
    }

    if let Some(path) = request.agent_config {
        let assessment = layerfault::agent_security::inspect_agent_config(
            request.agent_name,
            path,
            observed.composition_identity.as_deref(),
        )?;
        observed.agent_identity = Some(assessment.graph.agent.identity.clone());
        observed.agent_summary = Some(layerfault::inventory::PassportAgentSummary::from_graph(
            &assessment.graph,
        ));
        observed.capability_graph_identity = Some(assessment.graph.graph_identity.clone());
        observed.mcp_server_identities = assessment
            .graph
            .servers
            .iter()
            .map(|server| server.identity.clone())
            .collect();
        observed.mcp_server_identities.sort();
        observed.mcp_server_identities.dedup();
        observed.agent_capabilities_complete =
            Some(assessment.graph.completeness == AnalysisCompleteness::Complete);
        observed.dangerous_capability_chains = assessment.graph.dangerous_chains.clone();
        observed.dangerous_capability_chain_ids = assessment
            .graph
            .dangerous_chains
            .iter()
            .map(|chain| chain.id.clone())
            .collect();
        observed.findings.extend(assessment.findings);
    }

    if let Some(path) = request.provenance_chain {
        let verification =
            layerfault::model::transformation::verify_chain(path, request.trust_store)?;
        observed.provenance_verified =
            Some(verification.state == layerfault::model::transformation::LineageState::Verified);
        let chain = layerfault::model::transformation::load_chain(path)?;
        observed.builder_identities = chain
            .links
            .iter()
            .filter_map(|link| link.manifest.builder.as_ref())
            .map(|builder| builder.identity.clone())
            .collect();
        observed.builder_identities.sort();
        observed.builder_identities.dedup();
        let builder_identity = chain
            .links
            .last()
            .and_then(|link| link.manifest.builder.as_ref())
            .map(|builder| builder.identity.clone());
        observed.provenance_summary = Some(layerfault::inventory::PassportProvenanceSummary {
            transformation_chain_sha256: Some(layerfault::safeio::sha256_path(path)?),
            state: format!("{:?}", verification.state),
            builder_identity,
        });
    }

    if let Some(path) = request.passport {
        let passport = layerfault::inventory::load_portable_passport(path)?;
        let verification = layerfault::inventory::verify_passport(&passport)?;
        if !verification.valid {
            return Err(anyhow!("security passport validation failed"));
        }
        observed.passport_sha256 = Some(verification.sha256);
    }

    Ok(observed)
}

pub(crate) fn file_identity(path: &Path) -> Result<String> {
    layerfault::safeio::sha256_path(path)
}
