use super::{PostureState, RuntimeConfiguration, RuntimeInstallation, RuntimePosture};
use crate::coverage::Coverage;
use crate::finding_evidence::{EvidenceKind, EvidenceSubject, FindingBuilder, FindingEvidence};
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};

fn finding(
    rule: &str,
    status: ScanStatus,
    class: FindingClass,
    installation: &RuntimeInstallation,
    config: &RuntimeConfiguration,
    detail: &str,
) -> LayerScanResult {
    let identity = format!(
        "runtime:{}:{}",
        installation.runtime.as_str(),
        installation.executable.as_deref().unwrap_or("unknown")
    );
    let subject = EvidenceSubject::identity(&identity, "application/vnd.layerfault.runtime+json");
    FindingBuilder::new(rule, CheckType::RuntimePosture, status)
        .class(class)
        .confidence(Confidence::High)
        .subject(subject.clone())
        .detail(detail)
        .evidence(
            FindingEvidence::new(
                EvidenceKind::RuntimeConfiguration,
                subject,
                "Observed local AI runtime configuration",
            )
            .structured(serde_json::json!({
                "listen_addresses": config.listen_addresses,
                "listen_ports": config.listen_ports,
                "authentication": config.authentication,
                "tls": config.tls,
                "network_exposure": config.network_exposure,
                "python_optimized": config.python_optimized,
                "trust_remote_code": config.trust_remote_code,
                "custom_code_extension": config.custom_code_extension,
                "pickle_weight_loading": config.pickle_weight_loading,
                "cors_wildcard_origin": config.cors_wildcard_origin,
                "custom_chat_template": config.custom_chat_template,
                "revision_pinned": config.revision_pinned,
                "local_media_access": config.local_media_access,
                "cross_tenant_state_exposure": config.cross_tenant_state_exposure,
            })),
        )
        .finish()
}

pub fn evaluate_posture(
    installation: RuntimeInstallation,
    configuration: RuntimeConfiguration,
    coverage: Coverage,
) -> RuntimePosture {
    let mut findings = Vec::new();
    if configuration.network_exposure == PostureState::Enabled {
        findings.push(finding(
            "LF-RUNTIME-POSTURE-NETWORK-EXPOSED",
            ScanStatus::Warn,
            FindingClass::Operational,
            &installation,
            &configuration,
            "runtime is configured to listen on a non-loopback or wildcard address",
        ));
        if configuration.authentication == PostureState::Disabled {
            findings.push(finding(
                "LF-RUNTIME-POSTURE-AUTH-ABSENT",
                ScanStatus::Fail,
                FindingClass::Operational,
                &installation,
                &configuration,
                "network-exposed runtime has no observed authentication mechanism",
            ));
        }
        if configuration.tls == PostureState::Disabled {
            findings.push(finding(
                "LF-RUNTIME-POSTURE-TLS-ABSENT",
                ScanStatus::Warn,
                FindingClass::Operational,
                &installation,
                &configuration,
                "network-exposed runtime has no observed TLS configuration",
            ));
        }
    }
    if configuration.python_optimized == Some(true) {
        findings.push(finding(
            "LF-RUNTIME-POSTURE-PYTHON-OPTIMIZED",
            ScanStatus::Warn,
            FindingClass::Operational,
            &installation,
            &configuration,
            "Python optimization is enabled for this runtime context",
        ));
    }
    if configuration.custom_code_extension == Some(true) {
        findings.push(finding(
            "LF-RUNTIME-POSTURE-CUSTOM-CODE-EXTENSION",
            ScanStatus::Warn,
            FindingClass::Operational,
            &installation,
            &configuration,
            "runtime launch configuration loads an operator-supplied code extension (middleware or plugin) at startup",
        ));
    }
    if configuration.pickle_weight_loading == Some(true) {
        findings.push(finding(
            "LF-RUNTIME-POSTURE-PICKLE-WEIGHT-LOADING",
            ScanStatus::Warn,
            FindingClass::Operational,
            &installation,
            &configuration,
            "runtime is configured to load model weights through a pickle-based deserialization path",
        ));
    }
    if configuration.cors_wildcard_origin == Some(true)
        && configuration.network_exposure == PostureState::Enabled
    {
        findings.push(finding(
            "LF-RUNTIME-POSTURE-CORS-WILDCARD",
            ScanStatus::Warn,
            FindingClass::Operational,
            &installation,
            &configuration,
            "network-exposed runtime allows cross-origin requests from any origin",
        ));
    }
    if configuration.custom_chat_template == Some(true) {
        findings.push(finding(
            "LF-RUNTIME-POSTURE-CUSTOM-CHAT-TEMPLATE",
            ScanStatus::Pass,
            FindingClass::Informational,
            &installation,
            &configuration,
            "runtime is configured to use a chat template supplied outside the model's own bundled template",
        ));
    }
    if configuration.revision_pinned == Some(false) {
        findings.push(finding(
            "LF-RUNTIME-POSTURE-REVISION-UNPINNED",
            ScanStatus::Warn,
            FindingClass::Operational,
            &installation,
            &configuration,
            "runtime loads the model from a floating reference rather than a pinned, immutable revision",
        ));
    }
    if configuration.local_media_access == Some(true)
        && configuration.network_exposure == PostureState::Enabled
    {
        findings.push(finding(
            "LF-RUNTIME-POSTURE-LOCAL-MEDIA-ACCESS",
            ScanStatus::Warn,
            FindingClass::Operational,
            &installation,
            &configuration,
            "network-exposed runtime accepts local filesystem paths as media input",
        ));
    }
    if configuration.cross_tenant_state_exposure == Some(true)
        && configuration.network_exposure == PostureState::Enabled
    {
        findings.push(finding(
            "LF-RUNTIME-POSTURE-CROSS-TENANT-STATE-EXPOSURE",
            ScanStatus::Warn,
            FindingClass::Operational,
            &installation,
            &configuration,
            "network-exposed runtime has an endpoint enabled that exposes per-request internal state across clients sharing this server",
        ));
    }
    if !coverage.complete {
        findings.push(finding(
            "LF-RUNTIME-POSTURE-INCOMPLETE",
            ScanStatus::Warn,
            FindingClass::Informational,
            &installation,
            &configuration,
            &coverage.reasons.join("; "),
        ));
    }
    RuntimePosture {
        installation,
        configuration,
        coverage,
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_security::{RuntimeDiscoveryMethod, RuntimeKind};

    fn installation() -> RuntimeInstallation {
        RuntimeInstallation {
            runtime: RuntimeKind::Vllm,
            executable: Some("vllm".to_owned()),
            executable_sha256: None,
            raw_version: None,
            parsed_version: None,
            discovery: RuntimeDiscoveryMethod::ExplicitPath,
            package_root: None,
            process_ids: Vec::new(),
        }
    }

    #[test]
    fn each_new_posture_signal_produces_its_own_finding() {
        let mut config = RuntimeConfiguration {
            custom_code_extension: Some(true),
            pickle_weight_loading: Some(true),
            cors_wildcard_origin: Some(true),
            custom_chat_template: Some(true),
            revision_pinned: Some(false),
            local_media_access: Some(true),
            network_exposure: PostureState::Enabled,
            ..RuntimeConfiguration::default()
        };
        config.authentication = PostureState::Enabled;
        config.tls = PostureState::Enabled;
        let posture = evaluate_posture(installation(), config, Coverage::complete(0, 0));
        for rule_id in [
            "LF-RUNTIME-POSTURE-CUSTOM-CODE-EXTENSION",
            "LF-RUNTIME-POSTURE-PICKLE-WEIGHT-LOADING",
            "LF-RUNTIME-POSTURE-CORS-WILDCARD",
            "LF-RUNTIME-POSTURE-CUSTOM-CHAT-TEMPLATE",
            "LF-RUNTIME-POSTURE-REVISION-UNPINNED",
            "LF-RUNTIME-POSTURE-LOCAL-MEDIA-ACCESS",
        ] {
            assert!(
                posture
                    .findings
                    .iter()
                    .any(|finding| finding.rule_id.as_deref() == Some(rule_id)),
                "expected {rule_id} to be reported"
            );
        }
    }

    #[test]
    fn cors_wildcard_and_local_media_are_not_flagged_when_not_network_exposed() {
        let config = RuntimeConfiguration {
            cors_wildcard_origin: Some(true),
            local_media_access: Some(true),
            network_exposure: PostureState::Disabled,
            ..RuntimeConfiguration::default()
        };
        let posture = evaluate_posture(installation(), config, Coverage::complete(0, 0));
        assert!(!posture
            .findings
            .iter()
            .any(|finding| finding.rule_id.as_deref() == Some("LF-RUNTIME-POSTURE-CORS-WILDCARD")));
        assert!(!posture
            .findings
            .iter()
            .any(|finding| finding.rule_id.as_deref()
                == Some("LF-RUNTIME-POSTURE-LOCAL-MEDIA-ACCESS")));
    }

    #[test]
    fn cross_tenant_state_exposure_only_flagged_when_network_exposed() {
        let config = RuntimeConfiguration {
            cross_tenant_state_exposure: Some(true),
            network_exposure: PostureState::Disabled,
            ..RuntimeConfiguration::default()
        };
        let posture = evaluate_posture(installation(), config, Coverage::complete(0, 0));
        assert!(!posture
            .findings
            .iter()
            .any(|finding| finding.rule_id.as_deref()
                == Some("LF-RUNTIME-POSTURE-CROSS-TENANT-STATE-EXPOSURE")));

        let config = RuntimeConfiguration {
            cross_tenant_state_exposure: Some(true),
            network_exposure: PostureState::Enabled,
            ..RuntimeConfiguration::default()
        };
        let posture = evaluate_posture(installation(), config, Coverage::complete(0, 0));
        assert!(posture
            .findings
            .iter()
            .any(|finding| finding.rule_id.as_deref()
                == Some("LF-RUNTIME-POSTURE-CROSS-TENANT-STATE-EXPOSURE")));
    }

    #[test]
    fn pinned_revision_is_not_flagged() {
        let config = RuntimeConfiguration {
            revision_pinned: Some(true),
            ..RuntimeConfiguration::default()
        };
        let posture = evaluate_posture(installation(), config, Coverage::complete(0, 0));
        assert!(!posture
            .findings
            .iter()
            .any(|finding| finding.rule_id.as_deref()
                == Some("LF-RUNTIME-POSTURE-REVISION-UNPINNED")));
    }
}
