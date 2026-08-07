use crate::formats::artifact::{self, ArtifactReport, ArtifactScanMode};
use crate::policy::{EffectivePolicy, PolicyAction, PolicyContext, PolicyDecision};
use crate::provenance::TrustState;
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use crate::sources::SourceKind;
use anyhow::Result;
use std::path::Path;

#[derive(Debug, Clone, serde::Serialize)]
pub struct ArtifactAdmission {
    pub identity: String,
    pub source: SourceKind,
    pub report: ArtifactReport,
    pub trust_state: TrustState,
    pub trusted_signatures: usize,
    pub signer_fingerprints: Vec<String>,
    pub policy: PolicyDecision,
}

#[derive(Debug, Clone)]
pub struct SigstoreRequest<'a> {
    pub bundle: &'a Path,
    pub identity: &'a str,
    pub issuer: &'a str,
}

pub fn inspect_and_evaluate(
    path: &Path,
    identity: &str,
    source: SourceKind,
    policy: &EffectivePolicy,
    architecture: Option<&str>,
    quantization: Option<&str>,
    sigstore: Option<SigstoreRequest<'_>>,
) -> Result<ArtifactAdmission> {
    let mut report = artifact::inspect(path, ArtifactScanMode::Full)?;
    let mut trust_state = TrustState::Unsigned;
    let mut trusted_signatures = 0_usize;
    let mut signer_fingerprints = Vec::new();

    if let Some(request) = sigstore {
        let evaluation =
            crate::sigstore::verify_blob(path, request.bundle, request.identity, request.issuer)?;
        if evaluation.verified {
            trust_state = TrustState::Trusted;
            trusted_signatures = 1;
            // Sigstore certificate identity is the stable policy-facing signer identity.
            signer_fingerprints.push(format!("sigstore:{}", evaluation.identity));
            report.results.push(LayerScanResult {
                layer_digest: report
                    .sha256
                    .clone()
                    .unwrap_or_else(|| "artifact".to_owned()),
                media_type: "application/vnd.dev.sigstore.bundle".to_owned(),
                check_type: CheckType::Provenance,
                status: ScanStatus::Pass,
                finding_class: FindingClass::Attestation,
                confidence: Confidence::High,
                detail: Some(format!(
                    "Sigstore bundle verified for certificate identity '{}' from issuer '{}'",
                    evaluation.identity, evaluation.issuer
                )),
                matches: vec!["[LF-PROV-SIGSTORE] verified Sigstore bundle".to_owned()],
                duration_ms: 0,
            });
        } else {
            trust_state = TrustState::Invalid;
            report.results.push(LayerScanResult {
                layer_digest: report
                    .sha256
                    .clone()
                    .unwrap_or_else(|| "artifact".to_owned()),
                media_type: "application/vnd.dev.sigstore.bundle".to_owned(),
                check_type: CheckType::Provenance,
                status: ScanStatus::Fail,
                finding_class: FindingClass::Attestation,
                confidence: Confidence::High,
                detail: Some(format!(
                    "Sigstore verification failed: {}",
                    evaluation.detail
                )),
                matches: vec!["[LF-PROV-SIGSTORE-INVALID] invalid Sigstore bundle".to_owned()],
                duration_ms: 0,
            });
        }
    } else {
        report.results.push(LayerScanResult {
            layer_digest: report
                .sha256
                .clone()
                .unwrap_or_else(|| "artifact".to_owned()),
            media_type: "application/vnd.layerfault.artifact".to_owned(),
            check_type: CheckType::Provenance,
            status: ScanStatus::Warn,
            finding_class: FindingClass::Attestation,
            confidence: Confidence::High,
            detail: Some("No artifact provenance bundle was supplied".to_owned()),
            matches: vec!["[LF-PROV-UNSIGNED] artifact is unsigned/unattested".to_owned()],
            duration_ms: 0,
        });
    }

    let context = PolicyContext {
        source: Some(source.as_str().to_owned()),
        format: Some(report.format.as_str().to_owned()),
        architecture: architecture.map(ToOwned::to_owned),
        quantization: quantization.map(ToOwned::to_owned),
        model_size: Some(report.size),
        trusted_signatures,
        signer_fingerprints: signer_fingerprints.clone(),
        now_unix: crate::paths::now_unix(),
    };
    let decision = policy.evaluate_with_context(identity, &report.results, trust_state, &context);

    Ok(ArtifactAdmission {
        identity: identity.to_owned(),
        source,
        report,
        trust_state,
        trusted_signatures,
        signer_fingerprints,
        policy: decision,
    })
}

pub fn exit_code(admissions: &[ArtifactAdmission]) -> i32 {
    let mut integrity = false;
    let mut blocking = false;
    let mut warning = false;
    let mut policy_block = false;
    for admission in admissions {
        for result in &admission.report.results {
            match result.status {
                ScanStatus::Fail if result.finding_class == FindingClass::Integrity => {
                    integrity = true
                }
                ScanStatus::Fail => blocking = true,
                ScanStatus::Warn => warning = true,
                ScanStatus::Pass => {}
            }
        }
        match admission.policy.action {
            PolicyAction::Block => policy_block = true,
            PolicyAction::Warn => warning = true,
            PolicyAction::Allow => {}
        }
    }
    if integrity {
        2
    } else if blocking {
        3
    } else if policy_block {
        4
    } else if warning {
        1
    } else {
        0
    }
}
