mod gate;
mod receipt;
use crate::formats::artifact::{self, ArtifactReport, ArtifactScanMode};
use crate::policy::{EffectivePolicy, PolicyAction, PolicyContext, PolicyDecision};
use crate::provenance::TrustState;
use crate::scanner::{CheckType, Confidence, FindingClass, LayerScanResult, ScanStatus};
use crate::sources::SourceKind;
use anyhow::Result;
pub use gate::{verify_for_execution, ExecutionGateVerification};
pub use receipt::{build_receipt, AdmissionReceiptContext, ReceiptExploitability, ReceiptRuntime};
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
    let budget =
        crate::budget::ScanBudget::new(crate::budget::ScanBudgetProfile::Default.limits())?;
    inspect_and_evaluate_with_budget(
        path,
        identity,
        source,
        policy,
        architecture,
        quantization,
        sigstore,
        &budget,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn inspect_and_evaluate_with_budget(
    path: &Path,
    identity: &str,
    source: SourceKind,
    policy: &EffectivePolicy,
    architecture: Option<&str>,
    quantization: Option<&str>,
    sigstore: Option<SigstoreRequest<'_>>,
    budget: &crate::budget::ScanBudget,
) -> Result<ArtifactAdmission> {
    let mut report = artifact::inspect_with_budget(path, ArtifactScanMode::Full, budget)?;
    let mut trust_state = TrustState::Unsigned;
    let mut trusted_signatures = 0_usize;
    let mut signer_fingerprints = Vec::new();

    if let Some(request) = sigstore {
        let evaluation =
            crate::sigstore::verify_blob(path, request.bundle, request.identity, request.issuer)?;
        let verifier_evidence = format!(
            "verifier={} verifier_sha256={} verifier_version={}",
            evaluation.verifier_path,
            evaluation.verifier_sha256,
            evaluation.verifier_version.as_deref().unwrap_or("unknown")
        );
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
                    "Sigstore bundle verified for certificate identity '{}' from issuer '{}'; {}",
                    evaluation.identity, evaluation.issuer, verifier_evidence
                )),
                matches: vec!["[LF-PROV-SIGSTORE] verified Sigstore bundle".to_owned()],
                duration_ms: 0,
                ..Default::default()
            });
            crate::finding_evidence::ensure_finding_identity(
                report.results.last_mut().expect("just pushed"),
                "LF-PROV-SIGSTORE",
            );
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
                    "Sigstore verification failed: {}; {}",
                    evaluation.detail, verifier_evidence
                )),
                matches: vec!["[LF-PROV-SIGSTORE-INVALID] invalid Sigstore bundle".to_owned()],
                duration_ms: 0,
                ..Default::default()
            });
            crate::finding_evidence::ensure_finding_identity(
                report.results.last_mut().expect("just pushed"),
                "LF-PROV-SIGSTORE-INVALID",
            );
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
            ..Default::default()
        });
        crate::finding_evidence::ensure_finding_identity(
            report.results.last_mut().expect("just pushed"),
            "LF-PROV-UNSIGNED",
        );
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
        runtime_compatibility: None,
        ..PolicyContext::default()
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
    let scanner = crate::decision::SecurityDecision::scanner_finding_exit_code(
        admissions
            .iter()
            .flat_map(|admission| admission.report.results.iter()),
    );
    let policy_block = admissions
        .iter()
        .any(|admission| admission.policy.action == PolicyAction::Block);
    let policy_warn = admissions
        .iter()
        .any(|admission| admission.policy.action == PolicyAction::Warn);
    crate::decision::SecurityDecision::combine_scanner_and_policy_exit_code(
        scanner,
        policy_block,
        policy_warn,
    )
}
