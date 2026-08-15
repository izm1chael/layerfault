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
